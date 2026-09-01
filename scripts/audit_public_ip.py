#!/usr/bin/env python3
"""Read-only audit of public references to explicitly supplied IP artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import ipaddress
import json
import re
import socket
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


CLASSIFICATIONS = (
    "unreachable",
    "reachable-current",
    "linked",
    "cached-indicator",
    "fork-indicator",
    "probe-error",
)
UNREACHABLE_STATUSES = frozenset((404, 410))
SUCCESS_STATUSES = range(200, 300)
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
USER_AGENT = "public-ip-audit/1.0 (+read-only; no-auth)"


class AuditInputError(ValueError):
    """Raised when explicit audit input is malformed or unsafe."""


class ProbeFailure(RuntimeError):
    """A sanitized probe failure that is safe to include in a report."""


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str = ""
    final_url: str = ""


@dataclass(frozen=True)
class Artifact:
    kind: str
    source: str
    classification: str
    status: int | None = None
    sha256: str | None = None
    detail: str | None = None
    matches: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        return {key: item for key, item in value.items() if item not in (None, (), [])}


def _public_host(hostname: str, *, resolve: bool) -> None:
    if not hostname or hostname.lower() == "localhost":
        raise AuditInputError("URL must identify a public host")
    try:
        addresses = [str(ipaddress.ip_address(hostname))]
    except ValueError:
        addresses = []
    if resolve and not addresses:
        try:
            addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
                }
            )
        except OSError as exc:
            raise ProbeFailure("dns-error") from exc
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                raise AuditInputError("URL must not resolve to a non-public address")
        except ValueError as exc:
            raise AuditInputError("URL resolved to an invalid address") from exc


def validate_public_url(value: str, *, resolve: bool = False) -> str:
    """Validate an HTTP(S) URL without returning credentials or query data."""
    if INVALID_PERCENT_ESCAPE.search(value):
        raise AuditInputError("URL is malformed")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
    except ValueError as exc:
        raise AuditInputError("URL is malformed") from exc
    if parts.scheme.lower() not in ("http", "https") or not hostname:
        raise AuditInputError("only explicit public HTTP(S) URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise AuditInputError("URLs containing credentials are not supported")
    try:
        _ = parts.port
    except ValueError as exc:
        raise AuditInputError("URL has an invalid port") from exc
    _public_host(hostname, resolve=resolve)
    return value


def display_url(value: str) -> str:
    """Return a report-safe URL with userinfo, query, and fragment removed."""
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise AuditInputError("URL is malformed") from exc
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), host.lower(), path, "", ""))


def canonical_url(value: str) -> str:
    try:
        parts = urlsplit(html.unescape(value.strip()))
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        raise AuditInputError("URL is malformed") from exc
    if port and not (
        (parts.scheme.lower() == "http" and port == 80)
        or (parts.scheme.lower() == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    path = parts.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), host, path, parts.query, ""))


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _redacted_url_source(value: str) -> str:
    return "redacted-url:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


class _SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        validate_public_url(newurl, resolve=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NetworkTransport:
    def __init__(self, timeout: float, max_bytes: int) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.opener = build_opener(_SafeRedirectHandler())

    def fetch(self, url: str) -> Response:
        validate_public_url(url, resolve=True)
        request = Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise ProbeFailure("body-too-large")
                return Response(
                    status=response.status,
                    body=body,
                    content_type=response.headers.get("Content-Type", ""),
                    final_url=response.geturl(),
                )
        except HTTPError as exc:
            return Response(
                status=exc.code,
                body=b"",
                content_type=exc.headers.get("Content-Type", "") if exc.headers else "",
                final_url=exc.geturl(),
            )
        except AuditInputError:
            raise
        except ProbeFailure:
            raise
        except (URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, socket.timeout) or isinstance(exc, TimeoutError):
                detail = "timeout"
            elif isinstance(reason, socket.gaierror):
                detail = "dns-error"
            elif isinstance(reason, ConnectionRefusedError):
                detail = "connection-refused"
            else:
                detail = "network-error"
            raise ProbeFailure(detail) from exc


class FixtureTransport:
    def __init__(
        self,
        responses: Mapping[str, Any],
        *,
        fallback: NetworkTransport | None = None,
        max_bytes: int,
    ) -> None:
        self.responses = responses
        self.fallback = fallback
        self.max_bytes = max_bytes

    def fetch(self, url: str) -> Response:
        entry = self.responses.get(url)
        if entry is None:
            if self.fallback is not None:
                return self.fallback.fetch(url)
            raise ProbeFailure("fixture-miss")
        if not isinstance(entry, Mapping):
            raise AuditInputError("fixture responses must be JSON objects")
        if "error" in entry:
            raise ProbeFailure(_fixture_error(entry["error"]))
        try:
            status = int(entry["status"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditInputError("fixture response requires an integer status") from exc
        body = _fixture_body(entry)
        if len(body) > self.max_bytes:
            raise ProbeFailure("body-too-large")
        return Response(
            status=status,
            body=body,
            content_type=str(entry.get("content_type", "")),
            final_url=str(entry.get("final_url", url)),
        )


def _fixture_error(value: Any) -> str:
    allowed = {
        "timeout",
        "dns-error",
        "connection-refused",
        "network-error",
        "tls-error",
    }
    normalized = str(value).lower().replace("_", "-")
    return normalized if normalized in allowed else "network-error"


def _fixture_body(entry: Mapping[str, Any]) -> bytes:
    body_fields = sum(key in entry for key in ("body", "body_base64", "json"))
    if body_fields > 1:
        raise AuditInputError("fixture response must use only one body field")
    if "body_base64" in entry:
        try:
            return base64.b64decode(str(entry["body_base64"]), validate=True)
        except (ValueError, TypeError) as exc:
            raise AuditInputError("fixture body_base64 is invalid") from exc
    if "json" in entry:
        return json.dumps(
            entry["json"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    body = entry.get("body", "")
    if not isinstance(body, str):
        raise AuditInputError("fixture body must be a string")
    return body.encode("utf-8")


def load_fixture(path: Path) -> Mapping[str, Any]:
    data = _load_json(path)
    responses = data.get("responses") if isinstance(data, Mapping) else None
    if not isinstance(responses, Mapping):
        raise AuditInputError("fixture JSON requires a responses object")
    return responses


def classify_url(url: str, transport: Any) -> Artifact:
    try:
        safe_source = display_url(validate_public_url(url))
    except AuditInputError:
        return Artifact(
            "url",
            _redacted_url_source(url),
            "probe-error",
            detail="invalid-url",
        )
    try:
        response = transport.fetch(url)
    except (ProbeFailure, AuditInputError) as exc:
        return Artifact("url", safe_source, "probe-error", detail=str(exc))
    if response.status in UNREACHABLE_STATUSES:
        return Artifact("url", safe_source, "unreachable", status=response.status)
    if response.status in SUCCESS_STATUSES:
        return Artifact(
            "url",
            safe_source,
            "reachable-current",
            status=response.status,
            sha256=body_hash(response.body),
        )
    return Artifact(
        "url",
        safe_source,
        "probe-error",
        status=response.status,
        detail="http-error",
    )


def _repo_name(value: str) -> str:
    candidate = value.strip().removesuffix(".git").strip("/")
    if "://" in candidate:
        parts = urlsplit(validate_public_url(candidate))
        if parts.hostname.lower() != "github.com":
            raise AuditInputError("repository URLs must use github.com")
        candidate = parts.path.strip("/").removesuffix(".git")
    pieces = candidate.split("/")
    if len(pieces) != 2 or any(not piece for piece in pieces):
        raise AuditInputError("repository must be OWNER/NAME or a public GitHub URL")
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", piece) for piece in pieces):
        raise AuditInputError("repository contains unsupported characters")
    return "/".join(pieces)


def classify_repo(repo: str, transport: Any) -> Artifact:
    name = _repo_name(repo)
    api_url = f"https://api.github.com/repos/{name}"
    source = f"https://github.com/{name}"
    try:
        response = transport.fetch(api_url)
    except (ProbeFailure, AuditInputError) as exc:
        return Artifact("repo", source, "probe-error", detail=str(exc))
    if response.status in UNREACHABLE_STATUSES:
        return Artifact("repo", source, "unreachable", status=response.status)
    if response.status not in SUCCESS_STATUSES:
        return Artifact(
            "repo", source, "probe-error", status=response.status, detail="http-error"
        )
    digest = body_hash(response.body)
    try:
        metadata = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return Artifact(
            "repo",
            source,
            "probe-error",
            status=response.status,
            sha256=digest,
            detail="invalid-repository-metadata",
        )
    if not isinstance(metadata, Mapping) or not isinstance(metadata.get("fork"), bool):
        return Artifact(
            "repo",
            source,
            "probe-error",
            status=response.status,
            sha256=digest,
            detail="invalid-repository-metadata",
        )
    classification = "fork-indicator" if metadata["fork"] else "reachable-current"
    return Artifact(
        "repo",
        source,
        classification,
        status=response.status,
        sha256=digest,
    )


def _body_text(response: Response) -> str:
    return response.body.decode("utf-8", errors="replace")


def _find_forbidden_links(
    text: str, forbidden_urls: Sequence[str]
) -> tuple[tuple[str, ...], int]:
    decoded = html.unescape(text)
    extracted: set[str] = set()
    invalid_count = 0
    for match in URL_PATTERN.findall(decoded):
        try:
            extracted.add(canonical_url(match.rstrip(".,);]")))
        except AuditInputError:
            invalid_count += 1
    matches: list[str] = []
    for target in forbidden_urls:
        canonical = canonical_url(target)
        if target in decoded or canonical in extracted:
            matches.append(display_url(target))
    return tuple(sorted(set(matches))), invalid_count


def classify_link_document(
    url: str, forbidden_urls: Sequence[str], transport: Any
) -> Artifact:
    try:
        safe_source = display_url(validate_public_url(url))
    except AuditInputError:
        return Artifact(
            "link-document",
            _redacted_url_source(url),
            "probe-error",
            detail="invalid-url",
        )
    try:
        response = transport.fetch(url)
    except (ProbeFailure, AuditInputError) as exc:
        return Artifact("link-document", safe_source, "probe-error", detail=str(exc))
    if response.status in UNREACHABLE_STATUSES:
        return Artifact(
            "link-document", safe_source, "unreachable", status=response.status
        )
    if response.status not in SUCCESS_STATUSES:
        return Artifact(
            "link-document",
            safe_source,
            "probe-error",
            status=response.status,
            detail="http-error",
        )
    digest = body_hash(response.body)
    matches, invalid_count = _find_forbidden_links(
        _body_text(response), forbidden_urls
    )
    if invalid_count:
        return Artifact(
            "link-document",
            safe_source,
            "probe-error",
            status=response.status,
            sha256=digest,
            detail="malformed-extracted-url",
            matches=matches,
        )
    return Artifact(
        "link-document",
        safe_source,
        "linked" if matches else "reachable-current",
        status=response.status,
        sha256=digest,
        matches=matches,
    )


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditInputError("unable to read JSON input") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditInputError("invalid JSON input") from exc


def _search_items(data: Any) -> list[Mapping[str, Any]]:
    if isinstance(data, list):
        values = data
    elif isinstance(data, Mapping):
        values = data.get("results", data.get("items"))
        if values is None and all(key in data for key in ("url",)):
            values = [data]
    else:
        values = None
    if not isinstance(values, list) or not all(isinstance(item, Mapping) for item in values):
        raise AuditInputError(
            "search-result JSON must be a list or contain a results/items list"
        )
    return list(values)


def _all_scalar_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _all_scalar_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_scalar_strings(item)


def _search_source(item: Mapping[str, Any], label: str) -> tuple[str, bool]:
    for key in ("html_url", "link", "url"):
        value = item.get(key)
        if isinstance(value, str):
            try:
                validate_public_url(value)
                return display_url(value), True
            except AuditInputError:
                return label, False
    return label, True


def _fork_signal(item: Mapping[str, Any]) -> bool:
    if item.get("fork") is True or item.get("is_fork") is True:
        return True
    repository = item.get("repository")
    return isinstance(repository, Mapping) and (
        repository.get("fork") is True or repository.get("is_fork") is True
    )


def _cache_signal(item: Mapping[str, Any], forbidden_urls: Sequence[str]) -> bool:
    cache_keys = {
        "cache",
        "cached",
        "cache_url",
        "cached_url",
        "webcache",
        "is_cached",
    }
    for key, value in item.items():
        if key.lower() in cache_keys and value not in (None, False, ""):
            return True
    strings = tuple(_all_scalar_strings(item))
    return any(target in text for target in forbidden_urls for text in strings)


def classify_search_results(
    path: Path, forbidden_urls: Sequence[str]
) -> list[Artifact]:
    items = _search_items(_load_json(path))
    artifacts: list[Artifact] = []
    for index, item in enumerate(items, start=1):
        label = f"search-result#{index}"
        source, source_is_public = _search_source(item, label)
        if not source_is_public:
            artifacts.append(
                Artifact(
                    "search-result",
                    source,
                    "probe-error",
                    detail="non-public-result-url",
                )
            )
        elif _fork_signal(item):
            artifacts.append(Artifact("search-result", source, "fork-indicator"))
        elif _cache_signal(item, forbidden_urls) or not forbidden_urls:
            artifacts.append(Artifact("search-result", source, "cached-indicator"))
        else:
            artifacts.append(
                Artifact(
                    "search-result",
                    source,
                    "reachable-current",
                    detail="public-search-result",
                )
            )
    return artifacts


def build_report(artifacts: Sequence[Artifact], generated_at: str | None) -> dict[str, Any]:
    counts = Counter(artifact.classification for artifact in artifacts)
    report: dict[str, Any] = {
        "schema_version": 1,
        "summary": {
            "total": len(artifacts),
            "counts": {
                classification: counts.get(classification, 0)
                for classification in CLASSIFICATIONS
            },
        },
        "artifacts": [artifact.to_dict() for artifact in artifacts],
    }
    if generated_at:
        report["generated_at"] = generated_at
    return report


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Public IP Reference Audit",
        "",
        f"Artifacts audited: **{report['summary']['total']}**",
        "",
        "| Classification | Count |",
        "| --- | ---: |",
    ]
    counts = report["summary"]["counts"]
    lines.extend(f"| {name} | {counts[name]} |" for name in CLASSIFICATIONS)
    lines.extend(
        [
            "",
            "| Kind | Source | Classification | Status | SHA-256 | Detail |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for artifact in report["artifacts"]:
        matches = artifact.get("matches", [])
        detail = artifact.get("detail", "")
        if matches:
            detail = "matches: " + ", ".join(matches)
        values = (
            artifact["kind"],
            artifact["source"],
            artifact["classification"],
            str(artifact.get("status", "")),
            artifact.get("sha256", ""),
            detail,
        )
        lines.append("| " + " | ".join(_markdown_cell(value) for value in values) + " |")
    return "\n".join(lines) + "\n"


def _markdown_cell(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ")


def write_reports(
    report: Mapping[str, Any], json_path: Path, markdown_path: Path
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit explicit public URLs, GitHub repositories, and search results."
    )
    parser.add_argument("--url", action="append", default=[], help="public URL to probe")
    parser.add_argument(
        "--repo", action="append", default=[], help="GitHub OWNER/NAME or public URL"
    )
    parser.add_argument(
        "--link-document",
        action="append",
        default=[],
        help="public document URL to scan",
    )
    parser.add_argument(
        "--forbidden-url",
        action="append",
        default=[],
        help="target URL forbidden in link documents and search results",
    )
    parser.add_argument(
        "--search-results",
        action="append",
        default=[],
        type=Path,
        metavar="JSON",
        help="saved public search-result JSON",
    )
    parser.add_argument(
        "--fixture-json",
        type=Path,
        help="deterministic response fixture (never emitted)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="disable network; missing fixture responses become probe-error",
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024)
    parser.add_argument(
        "--json-report", type=Path, default=Path("public-ip-audit.json")
    )
    parser.add_argument(
        "--markdown-report", type=Path, default=Path("public-ip-audit.md")
    )
    parser.add_argument(
        "--generated-at",
        help="optional caller-supplied timestamp; omitted for deterministic reports",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.max_bytes <= 0:
        parser.error("--timeout and --max-bytes must be positive")
    if not (args.url or args.repo or args.link_document or args.search_results):
        parser.error("provide at least one --url, --repo, --link-document, or --search-results")
    if args.link_document and not args.forbidden_url:
        parser.error("--link-document requires at least one --forbidden-url")

    try:
        forbidden = [
            validate_public_url(value, resolve=False) for value in args.forbidden_url
        ]
        network = NetworkTransport(args.timeout, args.max_bytes)
        if args.fixture_json:
            fallback = None if args.offline else network
            transport: Any = FixtureTransport(
                load_fixture(args.fixture_json),
                fallback=fallback,
                max_bytes=args.max_bytes,
            )
        elif args.offline:
            transport = FixtureTransport({}, fallback=None, max_bytes=args.max_bytes)
        else:
            transport = network

        artifacts: list[Artifact] = []
        artifacts.extend(classify_url(url, transport) for url in args.url)
        artifacts.extend(classify_repo(repo, transport) for repo in args.repo)
        artifacts.extend(
            classify_link_document(document, forbidden, transport)
            for document in args.link_document
        )
        for path in args.search_results:
            artifacts.extend(classify_search_results(path, forbidden))
        report = build_report(artifacts, args.generated_at)
        write_reports(report, args.json_report, args.markdown_report)
    except AuditInputError as exc:
        parser.error(str(exc))

    return 1 if any(a.classification == "probe-error" for a in artifacts) else 0


if __name__ == "__main__":
    sys.exit(main())
