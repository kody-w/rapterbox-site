#!/usr/bin/env python3
"""Build and scan the exact public Pages artifact."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
from html import unescape
from html.parser import HTMLParser
import json
import mimetypes
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence
import unicodedata
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree


try:
    from scripts import publication_guard
except ModuleNotFoundError:
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parents[1]))
    from scripts import publication_guard


MANIFEST_FILENAME = "PUBLICATION-MANIFEST.json"
POLICY_FILENAME = publication_guard.POLICY_FILENAME
SCANNER_NAME = "rapterbox-publication-artifact"
SCANNER_VERSION = "1.1.0"
ARTIFACT_BOUNDARY = publication_guard.ARTIFACT_BOUNDARY
PUBLICATION_CLASSES = frozenset(("site-content", "publication-control"))
REPOSITORY_HOSTS_DEFAULT = frozenset(
    (
        "api.github.com",
        "bitbucket.org",
        "dev.azure.com",
        "gitlab.com",
        "github.com",
        "raw.githubusercontent.com",
        "www.github.com",
    )
)
HTML_LINK_ATTRIBUTES = frozenset(("action", "data", "href", "poster", "src"))
LINK_CONTEXT_PRIORITY = {"text": 0, "structured": 1, "navigation": 2}
ABSOLUTE_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
KNOWN_TEXT_SUFFIXES = frozenset(
    (".css", ".csv", ".gs", ".js", ".md", ".py", ".txt", ".xml")
)


class ArtifactError(RuntimeError):
    """A sanitized, fail-closed artifact operation error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    publication_class: str


@dataclass(frozen=True)
class Manifest:
    repository: str
    max_file_bytes: int
    site_hosts: tuple[str, ...]
    allowed_external_origins: tuple[str, ...]
    entries: tuple[ManifestEntry, ...]
    sha256: str

    @property
    def entry_by_path(self) -> dict[str, ManifestEntry]:
        return {entry.path: entry for entry in self.entries}

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(entry.path for entry in self.entries)


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    data: bytes
    sha256: str
    size: int
    signature: tuple[int, ...]


@dataclass(frozen=True)
class Finding:
    gate: str
    rule: str
    path: str
    detector: str

    def to_dict(self) -> dict[str, str]:
        fields = {
            "detector": self.detector,
            "gate": self.gate,
            "path": self.path,
            "rule": self.rule,
        }
        stable = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return {
            **fields,
            "evidence_id": hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16],
        }


@dataclass(frozen=True)
class ExtractedLink:
    raw: str
    context: str


class _DuplicateJsonKey(ValueError):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey
        value[key] = item
    return value


def _decode_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey) as error:
        raise ArtifactError("invalid_json") from error


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path_sort_key(value: str) -> tuple[str, str]:
    return (unicodedata.normalize("NFKC", value).casefold(), value)


def _path_collision_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _validate_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ArtifactError("invalid_manifest_path")
    if "\\" in value:
        raise ArtifactError("invalid_manifest_path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or any(part in ("", ".", "..") for part in posix.parts)
    ):
        raise ArtifactError("manifest_path_escape")
    return value


def _ensure_no_path_collisions(paths: Iterable[str]) -> None:
    seen: dict[str, str] = {}
    for path in sorted(paths, key=_path_sort_key):
        key = _path_collision_key(path)
        if key in seen:
            raise ArtifactError("artifact_path_collision")
        seen[key] = path


def _normalize_origin(value: str) -> str:
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
    except ValueError as error:
        raise ArtifactError("invalid_external_origin") from error
    if (
        parts.scheme.lower() not in ("http", "https")
        or not hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ArtifactError("invalid_external_origin")
    try:
        port = parts.port
    except ValueError as error:
        raise ArtifactError("invalid_external_origin") from error
    host = hostname.casefold()
    authority = f"[{host}]" if ":" in host else host
    if port and not (
        (parts.scheme.lower() == "http" and port == 80)
        or (parts.scheme.lower() == "https" and port == 443)
    ):
        authority = f"{host}:{port}"
    return f"{parts.scheme.lower()}://{authority}"


def load_manifest(path: str | os.PathLike[str]) -> Manifest:
    manifest_path = Path(path)
    try:
        data = manifest_path.read_bytes()
    except OSError as error:
        raise ArtifactError("manifest_unreadable") from error
    document = _decode_json(data)
    if not isinstance(document, Mapping):
        raise ArtifactError("invalid_manifest")
    if document.get("document_type") != "publication-manifest":
        raise ArtifactError("invalid_manifest")
    if document.get("schema_version") != 1:
        raise ArtifactError("unsupported_manifest_schema")
    if document.get("default_disposition") != "deny":
        raise ArtifactError("manifest_must_default_deny")
    if document.get("artifact_boundary") != ARTIFACT_BOUNDARY:
        raise ArtifactError("invalid_artifact_boundary")
    repository = document.get("repository")
    maximum = document.get("max_file_bytes")
    if not isinstance(repository, str) or not repository:
        raise ArtifactError("invalid_manifest_repository")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
        raise ArtifactError("invalid_manifest_size_limit")

    raw_hosts = document.get("site_hosts")
    if not isinstance(raw_hosts, list) or not raw_hosts:
        raise ArtifactError("invalid_site_hosts")
    site_hosts: set[str] = set()
    for host in raw_hosts:
        if (
            not isinstance(host, str)
            or not host
            or "/" in host
            or ":" in host
            or host != host.strip()
        ):
            raise ArtifactError("invalid_site_hosts")
        site_hosts.add(host.casefold())

    raw_origins = document.get("allowed_external_origins")
    if not isinstance(raw_origins, list):
        raise ArtifactError("invalid_external_origins")
    origins = {_normalize_origin(value) for value in raw_origins if isinstance(value, str)}
    if len(origins) != len(raw_origins):
        raise ArtifactError("invalid_external_origins")

    raw_entries = document.get("paths")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ArtifactError("invalid_manifest_paths")
    entries: list[ManifestEntry] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping):
            raise ArtifactError("invalid_manifest_entry")
        if set(raw_entry) != {"class", "path"}:
            raise ArtifactError("invalid_manifest_entry")
        path_value = _validate_relative_path(raw_entry.get("path"))
        publication_class = raw_entry.get("class")
        if publication_class not in PUBLICATION_CLASSES:
            raise ArtifactError("invalid_publication_class")
        entries.append(ManifestEntry(path_value, publication_class))
    _ensure_no_path_collisions(entry.path for entry in entries)

    return Manifest(
        repository=repository,
        max_file_bytes=maximum,
        site_hosts=tuple(sorted(site_hosts)),
        allowed_external_origins=tuple(sorted(origins)),
        entries=tuple(sorted(entries, key=lambda entry: _path_sort_key(entry.path))),
        sha256=_sha256(data),
    )


def _resolve_contract_path(source: Path, value: str | os.PathLike[str]) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = source / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        if os.path.commonpath((os.fspath(source), os.fspath(candidate))) != os.fspath(
            source
        ):
            raise ArtifactError("contract_path_escape")
    except ValueError as error:
        raise ArtifactError("contract_path_escape") from error
    try:
        relative = candidate.relative_to(source).as_posix()
    except ValueError as error:
        raise ArtifactError("contract_path_escape") from error
    _assert_no_symlink_component(source, relative)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ArtifactError("contract_path_unreadable") from error
    return resolved


def _git_output(source: Path, arguments: Sequence[str]) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(source), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ArtifactError("git_unavailable") from error
    if result.returncode:
        raise ArtifactError("git_command_failed")
    return result.stdout


def _git_context(source: Path) -> tuple[set[str], str]:
    top = Path(
        os.fsdecode(_git_output(source, ("rev-parse", "--show-toplevel"))).strip()
    )
    try:
        resolved_top = top.resolve(strict=True)
    except OSError as error:
        raise ArtifactError("git_root_unreadable") from error
    if resolved_top != source:
        raise ArtifactError("source_must_be_git_root")
    tracked = {
        os.fsdecode(value)
        for value in _git_output(source, ("ls-files", "-z")).split(b"\0")
        if value
    }
    commit_sha = os.fsdecode(_git_output(source, ("rev-parse", "HEAD"))).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit_sha):
        raise ArtifactError("invalid_commit_sha")
    return tracked, commit_sha


def _stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _assert_no_symlink_component(root: Path, relative: str) -> None:
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ArtifactError("source_path_unreadable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ArtifactError("source_symlink")


def _read_stable_file(
    root: Path,
    relative: str,
    maximum: int,
    *,
    mutation_hook: Callable[[Path], None] | None = None,
) -> FileSnapshot:
    _assert_no_symlink_component(root, relative)
    path = root / PurePosixPath(relative)
    try:
        before_path = path.lstat()
    except OSError as error:
        raise ArtifactError("source_path_unreadable") from error
    if not stat.S_ISREG(before_path.st_mode):
        raise ArtifactError("unsupported_source_file")
    if before_path.st_size > maximum:
        raise ArtifactError("source_file_too_large")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ArtifactError("source_path_unreadable") from error
    try:
        before_file = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ArtifactError("source_file_too_large")
        data = b"".join(chunks)
        if mutation_hook is not None:
            mutation_hook(path)
        after_file = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    try:
        after_path = path.lstat()
    except OSError as error:
        raise ArtifactError("source_changed_during_copy") from error
    signatures = (
        _stat_signature(before_path),
        _stat_signature(before_file),
        _stat_signature(after_file),
        _stat_signature(after_path),
    )
    if len(set(signatures)) != 1 or len(data) != before_file.st_size:
        raise ArtifactError("source_changed_during_copy")
    return FileSnapshot(
        path=relative,
        data=data,
        sha256=_sha256(data),
        size=len(data),
        signature=signatures[0],
    )


def _outside_source(source: Path, output: Path) -> Path:
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise ArtifactError("output_parent_unreadable") from error
    candidate = parent / output.name
    try:
        overlap = os.path.commonpath((os.fspath(source), os.fspath(candidate)))
    except ValueError as error:
        raise ArtifactError("output_path_invalid") from error
    if overlap in (os.fspath(source), os.fspath(candidate)):
        raise ArtifactError("output_overlaps_source")
    if candidate.exists() or candidate.is_symlink():
        raise ArtifactError("output_already_exists")
    return candidate


def build_artifact(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    *,
    manifest_path: str | os.PathLike[str] = MANIFEST_FILENAME,
    policy_path: str | os.PathLike[str] = POLICY_FILENAME,
    _mutation_hook: Callable[[Path], None] | None = None,
) -> dict[str, Any]:
    try:
        source_root = Path(source).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ArtifactError("source_root_unreadable") from error
    if not source_root.is_dir() or source_root.is_symlink():
        raise ArtifactError("source_root_invalid")

    manifest_file = _resolve_contract_path(source_root, manifest_path)
    policy_file = _resolve_contract_path(source_root, policy_path)
    manifest = load_manifest(manifest_file)
    tracked, commit_sha = _git_context(source_root)
    for contract in (manifest_file, policy_file):
        relative_contract = contract.relative_to(source_root).as_posix()
        if relative_contract not in tracked:
            raise ArtifactError("untracked_contract_file")
    undeclared = sorted(set(manifest.paths) - tracked, key=_path_sort_key)
    if undeclared:
        raise ArtifactError("manifest_path_not_tracked")

    policy_snapshot = _read_stable_file(
        source_root, policy_file.relative_to(source_root).as_posix(), manifest.max_file_bytes
    )
    try:
        policy_document = _decode_json(policy_snapshot.data)
    except ArtifactError as error:
        raise ArtifactError("policy_invalid") from error
    if not isinstance(policy_document, Mapping):
        raise ArtifactError("policy_invalid")

    target = _outside_source(source_root, Path(output))
    snapshots: list[FileSnapshot] = []
    try:
        target.mkdir(mode=0o755)
        for entry in manifest.entries:
            snapshot = _read_stable_file(
                source_root,
                entry.path,
                manifest.max_file_bytes,
                mutation_hook=_mutation_hook,
            )
            destination = target / PurePosixPath(entry.path)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            try:
                with destination.open("xb") as stream:
                    stream.write(snapshot.data)
            except OSError as error:
                raise ArtifactError("artifact_write_failed") from error
            snapshots.append(snapshot)

        final_manifest = _read_stable_file(
            source_root,
            manifest_file.relative_to(source_root).as_posix(),
            manifest.max_file_bytes,
        )
        final_policy = _read_stable_file(
            source_root,
            policy_file.relative_to(source_root).as_posix(),
            manifest.max_file_bytes,
        )
        if final_manifest.sha256 != manifest.sha256:
            raise ArtifactError("manifest_changed_during_copy")
        if final_policy.sha256 != policy_snapshot.sha256:
            raise ArtifactError("policy_changed_during_copy")

        actual = _regular_artifact_paths(target)
        if actual != list(manifest.paths):
            raise ArtifactError("artifact_inventory_mismatch")
        for snapshot in snapshots:
            copied = _read_stable_file(target, snapshot.path, manifest.max_file_bytes)
            if copied.sha256 != snapshot.sha256 or copied.size != snapshot.size:
                raise ArtifactError("artifact_copy_mismatch")
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise

    return {
        "artifact_boundary": ARTIFACT_BOUNDARY,
        "commit_sha": commit_sha,
        "file_count": len(snapshots),
        "manifest_sha256": manifest.sha256,
        "paths": [snapshot.path for snapshot in snapshots],
        "policy_sha256": policy_snapshot.sha256,
        "result": "pass",
        "schema_version": 1,
    }


def _regular_artifact_paths(root: Path) -> list[str]:
    paths: list[str] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        names.sort(key=_path_sort_key)
        filenames.sort(key=_path_sort_key)
        for name in filenames:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            try:
                metadata = path.lstat()
            except OSError as error:
                raise ArtifactError("artifact_inventory_unreadable") from error
            if not stat.S_ISREG(metadata.st_mode):
                raise ArtifactError("artifact_contains_non_regular_file")
            paths.append(relative)
        for name in names:
            path = Path(directory) / name
            try:
                metadata = path.lstat()
            except OSError as error:
                raise ArtifactError("artifact_inventory_unreadable") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise ArtifactError("artifact_contains_symlink")
    paths.sort(key=_path_sort_key)
    _ensure_no_path_collisions(paths)
    return paths


def _glob_regex(pattern: str) -> re.Pattern[str]:
    if not isinstance(pattern, str) or not pattern.startswith("/"):
        raise ArtifactError("invalid_policy_path_pattern")
    expression = ["^"]
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                expression.append(".*")
                index += 2
                continue
            expression.append("[^/]*")
        elif character == "?":
            expression.append("[^/]")
        else:
            expression.append(re.escape(character))
        index += 1
    expression.append("$")
    try:
        return re.compile("".join(expression))
    except re.error as error:
        raise ArtifactError("invalid_policy_path_pattern") from error


def _policy_contract(
    policy_path: Path,
) -> tuple[dict[str, Any], publication_guard.Policy, str, set[str]]:
    try:
        policy_data = policy_path.read_bytes()
    except OSError as error:
        raise ArtifactError("policy_unreadable") from error
    document = _decode_json(policy_data)
    if not isinstance(document, dict):
        raise ArtifactError("policy_invalid")
    try:
        guard_policy, _ = publication_guard._load_policy(policy_path.parent, policy_path)
    except publication_guard.GuardError as error:
        raise ArtifactError("policy_invalid") from error

    path_rules: list[tuple[re.Pattern[str], tuple[str, ...]]] = []
    public_allowed = document.get("public_allowed")
    raw_rules = public_allowed.get("path_rules") if isinstance(public_allowed, dict) else None
    if not isinstance(raw_rules, list):
        raise ArtifactError("policy_path_rules_missing")
    for rule in raw_rules:
        if not isinstance(rule, dict):
            raise ArtifactError("invalid_policy_path_rule")
        patterns = rule.get("patterns")
        categories = rule.get("categories")
        if (
            not isinstance(patterns, list)
            or not patterns
            or not all(isinstance(value, str) for value in patterns)
            or not isinstance(categories, list)
            or not categories
            or not all(isinstance(value, str) for value in categories)
        ):
            raise ArtifactError("invalid_policy_path_rule")
        normalized_categories = tuple(sorted(set(categories)))
        for pattern in patterns:
            path_rules.append((_glob_regex(pattern), normalized_categories))

    exception = document.get("control_file_pattern_exception")
    raw_control_paths = exception.get("paths") if isinstance(exception, dict) else None
    if not isinstance(raw_control_paths, list) or not all(
        isinstance(value, str) and value.startswith("/") for value in raw_control_paths
    ):
        raise ArtifactError("invalid_control_exception")
    control_paths = {_validate_relative_path(value[1:]) for value in raw_control_paths}

    return document, guard_policy, _sha256(policy_data), control_paths


def _path_categories(
    path: str, policy_document: Mapping[str, Any]
) -> tuple[str, ...]:
    public_allowed = policy_document.get("public_allowed")
    raw_rules = public_allowed.get("path_rules") if isinstance(public_allowed, dict) else []
    categories: set[str] = set()
    for rule in raw_rules:
        for pattern in rule["patterns"]:
            if _glob_regex(pattern).fullmatch("/" + path):
                categories.update(rule["categories"])
    return tuple(sorted(categories))


class _ArtifactHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[ExtractedLink] = []
        self._json_script_depth = 0
        self._json_script_parts: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = {key.casefold(): value for key, value in attrs if value is not None}
        for name in HTML_LINK_ATTRIBUTES:
            value = attributes.get(name)
            if value:
                self.links.append(ExtractedLink(value, "navigation"))
        if tag.casefold() == "meta":
            property_name = (
                attributes.get("property") or attributes.get("name") or ""
            ).casefold()
            content = attributes.get("content")
            if content and property_name in ("og:url", "twitter:url"):
                self.links.append(ExtractedLink(content, "navigation"))
            if content and (attributes.get("http-equiv") or "").casefold() == "refresh":
                match = re.search(r"\burl\s*=\s*(.+)$", content, re.IGNORECASE)
                if match:
                    self.links.append(ExtractedLink(match.group(1).strip(), "navigation"))
        if (
            tag.casefold() == "script"
            and (attributes.get("type") or "").casefold() == "application/ld+json"
        ):
            self._json_script_depth += 1
            self._json_script_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "script" and self._json_script_depth:
            self._json_script_depth -= 1
            if not self._json_script_depth:
                data = "".join(self._json_script_parts).encode("utf-8")
                document = _decode_json(data)
                self.links.extend(_links_from_json(document))
                self._json_script_parts = []

    def handle_data(self, data: str) -> None:
        if self._json_script_depth:
            self._json_script_parts.append(data)

    def close(self) -> None:
        super().close()
        if self._json_script_depth:
            raise ArtifactError("invalid_html")


def _looks_like_link_key(key: str | None) -> bool:
    if key is None:
        return False
    normalized = key.casefold()
    return (
        normalized in {
            "@id",
            "action",
            "agent_view",
            "canonical",
            "href",
            "human_equivalent",
            "human_view",
            "prior_art",
            "protocol",
            "protocol_authority",
            "public_boundary",
            "rapp_foundation",
            "src",
            "url",
        }
        or normalized.endswith("_url")
        or normalized.endswith("_uri")
    )


def _absolute_links(value: str, context: str) -> list[ExtractedLink]:
    decoded = unescape(value)
    return [
        ExtractedLink(match.rstrip(".,);}>"), context)
        for match in ABSOLUTE_URL_PATTERN.findall(decoded)
    ]


def _links_from_json(value: Any, key: str | None = None) -> list[ExtractedLink]:
    links: list[ExtractedLink] = []
    if isinstance(value, dict):
        for item_key in sorted(value, key=lambda item: str(item).casefold()):
            links.extend(_links_from_json(value[item_key], str(item_key)))
    elif isinstance(value, list):
        for item in value:
            links.extend(_links_from_json(item, key))
    elif isinstance(value, str):
        absolute = _absolute_links(value, "structured")
        links.extend(absolute)
        if (
            not absolute
            and _looks_like_link_key(key)
            and value.startswith(("/", "./", "../", "#", "//"))
        ):
            links.append(ExtractedLink(value, "structured"))
    return links


def _parse_links(path: str, data: bytes) -> list[ExtractedLink]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArtifactError("artifact_text_not_utf8") from error
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix == ".json":
        return _links_from_json(_decode_json(data))
    if suffix == ".jsonl":
        links: list[ExtractedLink] = []
        for line in data.splitlines():
            if line.strip():
                links.extend(_links_from_json(_decode_json(line)))
        return links
    if suffix in (".html", ".htm"):
        parser = _ArtifactHtmlParser()
        try:
            parser.feed(text)
            parser.close()
        except (ArtifactError, ValueError) as error:
            raise ArtifactError("invalid_html") from error
        links = parser.links
        links.extend(_absolute_links(text, "text"))
        return links
    if suffix == ".xml":
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError as error:
            raise ArtifactError("invalid_xml") from error
        joined = "\n".join(
            [item for item in root.itertext()]
            + [value for element in root.iter() for value in element.attrib.values()]
        )
        return _absolute_links(joined, "structured")
    if suffix in KNOWN_TEXT_SUFFIXES or path in ("CNAME", ".nojekyll"):
        return _absolute_links(text, "text")
    raise ArtifactError("unsupported_artifact_media_type")


def _media_type(path: str) -> str:
    if path == "CNAME":
        return "text/plain"
    if path == ".nojekyll":
        return "text/plain"
    if path.endswith(".jsonl"):
        return "application/x-ndjson"
    guessed, _ = mimetypes.guess_type(path)
    return guessed or "application/octet-stream"


def _safe_url_parts(value: str) -> tuple[str, str, str, str]:
    if INVALID_PERCENT_ESCAPE.search(value):
        raise ArtifactError("invalid_link")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
    except ValueError as error:
        raise ArtifactError("invalid_link") from error
    if (
        parts.scheme.casefold() not in ("http", "https")
        or not hostname
        or "%" in hostname
    ):
        raise ArtifactError("invalid_link")
    if parts.username is not None or parts.password is not None:
        raise ArtifactError("credentialed_link")
    try:
        port = parts.port
    except ValueError as error:
        raise ArtifactError("invalid_link") from error
    scheme = parts.scheme.casefold()
    host = hostname.casefold()
    authority = f"[{host}]" if ":" in host else host
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        authority = f"{host}:{port}"
    origin = f"{scheme}://{authority}"
    path = parts.path or "/"
    display = urlunsplit((scheme, authority, path, "", ""))
    return host, origin, path, display


def _internal_candidate(path: str, inventory: set[str]) -> str | None:
    try:
        decoded = unquote(path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    if "\0" in decoded or "\\" in decoded:
        return None
    parts = PurePosixPath(decoded).parts
    if ".." in parts:
        return None
    relative = decoded.lstrip("/")
    candidates: list[str]
    if not relative:
        candidates = ["index.html"]
    elif decoded.endswith("/"):
        candidates = [relative + "index.html"]
    else:
        candidates = [relative, relative + ".html", relative + "/index.html"]
    return next((candidate for candidate in candidates if candidate in inventory), None)


def _redacted_link(
    source_path: str, raw: str, context: str, classification: str
) -> tuple[dict[str, str], Finding]:
    fingerprint = _sha256(raw.encode("utf-8"))
    record = {
        "classification": classification,
        "context": context,
        "source_path": source_path,
        "target_fingerprint": fingerprint,
    }
    finding = Finding("links", classification, source_path, "redacted_link_target")
    return record, finding


def _classify_link(
    source_path: str,
    link: ExtractedLink,
    *,
    manifest: Manifest,
    inventory: set[str],
    guard_policy: publication_guard.Policy,
) -> tuple[dict[str, str], Finding | None]:
    raw = unescape(link.raw.strip())
    if not raw or any(ord(character) < 32 for character in raw):
        return _redacted_link(source_path, raw, link.context, "invalid_link")
    base = f"https://{manifest.site_hosts[0]}/" + source_path
    try:
        absolute = urljoin(base, raw)
        host, origin, url_path, display = _safe_url_parts(absolute)
    except (ArtifactError, ValueError) as error:
        classification = (
            error.code
            if isinstance(error, ArtifactError)
            and error.code in {"credentialed_link", "invalid_link"}
            else "invalid_link"
        )
        return _redacted_link(source_path, raw, link.context, classification)

    forbidden_hosts = {"0.0.0.0", "127.0.0.1", "::1", "localhost"}
    forbidden_suffixes = (".corp", ".internal", ".lan", ".local")
    if host in forbidden_hosts or host.endswith(forbidden_suffixes):
        return _redacted_link(source_path, raw, link.context, "forbidden_host_link")

    target_hash = _sha256(absolute.encode("utf-8"))
    if host in manifest.site_hosts:
        resolved = _internal_candidate(url_path, inventory)
        if resolved is None and link.context != "text":
            return _redacted_link(
                source_path, raw, link.context, "missing_internal_link_target"
            )
        return (
            {
                "classification": (
                    "internal-artifact-link"
                    if resolved is not None
                    else "documented-internal-url"
                ),
                "context": link.context,
                "source_path": source_path,
                "target": display,
                "target_fingerprint": target_hash,
            },
            None,
        )

    repository_hosts = {
        host_value.casefold() for host_value in guard_policy.repository_hosts
    } or set(REPOSITORY_HOSTS_DEFAULT)
    if host in repository_hosts:
        reference = publication_guard._repository_reference(absolute)
        allowed = {
            publication_guard._normalise_repository_slug(slug)
            for slug in guard_policy.allowed_repository_slugs
        }
        if reference is None or publication_guard._normalise_repository_slug(
            reference[1]
        ) not in allowed:
            return _redacted_link(
                source_path, raw, link.context, "unverified_repository_link"
            )
        return (
            {
                "classification": "allowed-public-repository",
                "context": link.context,
                "source_path": source_path,
                "target": display,
                "target_fingerprint": target_hash,
            },
            None,
        )

    if origin not in manifest.allowed_external_origins:
        return _redacted_link(
            source_path, raw, link.context, "unverified_external_link"
        )
    return (
        {
            "classification": "allowlisted-external-origin",
            "context": link.context,
            "source_path": source_path,
            "target": display,
            "target_fingerprint": target_hash,
        },
        None,
    )


def _artifact_inventory(
    root: Path,
) -> tuple[dict[str, os.stat_result], set[str], list[Finding]]:
    files: dict[str, os.stat_result] = {}
    directories: set[str] = set()
    findings: list[Finding] = []
    stack = [root]
    observed_paths: list[str] = []
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(
                os.scandir(directory), key=lambda entry: _path_sort_key(entry.name)
            )
        except OSError as error:
            raise ArtifactError("artifact_inventory_unreadable") from error
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            observed_paths.append(relative)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                findings.append(
                    Finding("inventory", "unreadable_artifact_path", relative, "lstat")
                )
                continue
            if stat.S_ISLNK(metadata.st_mode):
                findings.append(
                    Finding("inventory", "artifact_symlink", relative, "file_type")
                )
            elif stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                child_directories.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                files[relative] = metadata
            else:
                findings.append(
                    Finding(
                        "inventory",
                        "unsupported_artifact_file_type",
                        relative,
                        "file_type",
                    )
                )
        stack.extend(reversed(child_directories))
    try:
        _ensure_no_path_collisions(observed_paths)
    except ArtifactError:
        findings.append(
            Finding("inventory", "artifact_path_collision", ".", "unicode_casefold")
        )
    return files, directories, findings


def _control_findings(
    path: str,
    data: bytes,
    policy: publication_guard.Policy,
) -> list[Finding]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [Finding("policy", "artifact_text_not_utf8", path, "utf8")]
    control_policy = replace(
        policy,
        forbidden_filenames=(),
        forbidden_filename_patterns=(),
        forbidden_phrases=(),
        forbidden_phrase_patterns=(),
        forbidden_repository_slug_patterns=(),
    )
    return [
        Finding("policy", item.rule, item.path, item.detector)
        for item in publication_guard._line_findings(path, text, control_policy)
    ]


def _deduplicate_links(links: Iterable[ExtractedLink]) -> list[ExtractedLink]:
    selected: dict[str, ExtractedLink] = {}
    for link in links:
        key = link.raw.strip()
        current = selected.get(key)
        if current is None or LINK_CONTEXT_PRIORITY[link.context] > LINK_CONTEXT_PRIORITY[
            current.context
        ]:
            selected[key] = link
    return sorted(
        selected.values(),
        key=lambda item: (
            item.raw.casefold(),
            item.raw,
            -LINK_CONTEXT_PRIORITY[item.context],
        ),
    )


def scan_artifact(
    source: str | os.PathLike[str],
    artifact: str | os.PathLike[str],
    *,
    manifest_path: str | os.PathLike[str] = MANIFEST_FILENAME,
    policy_path: str | os.PathLike[str] = POLICY_FILENAME,
) -> dict[str, Any]:
    try:
        source_root = Path(source).resolve(strict=True)
        artifact_root = Path(artifact).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ArtifactError("scan_root_unreadable") from error
    if not source_root.is_dir() or not artifact_root.is_dir():
        raise ArtifactError("scan_root_invalid")
    manifest_file = _resolve_contract_path(source_root, manifest_path)
    policy_file = _resolve_contract_path(source_root, policy_path)
    manifest = load_manifest(manifest_file)
    tracked, commit_sha = _git_context(source_root)
    if manifest_file.relative_to(source_root).as_posix() not in tracked:
        raise ArtifactError("untracked_contract_file")
    if policy_file.relative_to(source_root).as_posix() not in tracked:
        raise ArtifactError("untracked_contract_file")

    (
        policy_document,
        guard_policy,
        policy_sha256,
        control_paths,
    ) = _policy_contract(policy_file)
    if policy_document.get("repository") != manifest.repository:
        raise ArtifactError("policy_manifest_repository_mismatch")
    expected = manifest.entry_by_path
    for path, entry in expected.items():
        if (path in control_paths) != (
            entry.publication_class == "publication-control"
        ):
            raise ArtifactError("publication_class_mismatch")

    files, directories, findings = _artifact_inventory(artifact_root)
    actual_paths = set(files)
    expected_paths = set(expected)
    for path in sorted(expected_paths - actual_paths, key=_path_sort_key):
        findings.append(
            Finding("inventory", "missing_artifact_path", path, "exact_manifest")
        )
    for path in sorted(actual_paths - expected_paths, key=_path_sort_key):
        findings.append(
            Finding("inventory", "extra_artifact_path", path, "default_deny")
        )
    expected_directories = {
        parent.as_posix()
        for path in expected_paths
        for parent in PurePosixPath(path).parents
        if parent.as_posix() != "."
    }
    for path in sorted(directories - expected_directories, key=_path_sort_key):
        findings.append(
            Finding("inventory", "extra_artifact_directory", path, "default_deny")
        )

    snapshots: dict[str, FileSnapshot] = {}
    links_by_path: dict[str, list[ExtractedLink]] = {}
    for path in sorted(files, key=_path_sort_key):
        if files[path].st_size > manifest.max_file_bytes:
            findings.append(
                Finding("inventory", "artifact_file_too_large", path, "size_limit")
            )
            continue
        try:
            snapshot = _read_stable_file(
                artifact_root, path, manifest.max_file_bytes
            )
        except ArtifactError as error:
            findings.append(
                Finding("inventory", error.code, path, "stable_read")
            )
            continue
        snapshots[path] = snapshot
        categories = _path_categories(path, policy_document)
        if not categories:
            findings.append(
                Finding(
                    "eligibility",
                    "path_not_public_eligible",
                    path,
                    "policy_path_rules",
                )
            )
        try:
            links_by_path[path] = _parse_links(path, snapshot.data)
        except ArtifactError as error:
            findings.append(Finding("parse", error.code, path, "content_parser"))

    guard_paths = sorted(
        (actual_paths | expected_paths) - control_paths, key=_path_sort_key
    )
    try:
        guard_report = publication_guard.scan_repository(
            artifact_root,
            policy_path=policy_file,
            manifest=guard_paths,
            enforce_source_classification=False,
        )
    except publication_guard.GuardError as error:
        raise ArtifactError("publication_policy_scan_failed") from error
    for item in guard_report["findings"]:
        findings.append(
            Finding("policy", item["rule"], item["path"], item["detector"])
        )
    if guard_report["unscanned_paths"]:
        for path in guard_report["unscanned_paths"]:
            findings.append(
                Finding("policy", "publication_policy_unscanned", path, "coverage")
            )

    for path in sorted(control_paths & set(snapshots), key=_path_sort_key):
        source_snapshot = _read_stable_file(
            source_root, path, manifest.max_file_bytes
        )
        if snapshots[path].sha256 != source_snapshot.sha256:
            findings.append(
                Finding(
                    "policy",
                    "publication_control_mismatch",
                    path,
                    "tracked_source_bytes",
                )
            )
        findings.extend(_control_findings(path, snapshots[path].data, guard_policy))

    link_records: list[dict[str, str]] = []
    for path in sorted(links_by_path, key=_path_sort_key):
        for link in _deduplicate_links(links_by_path[path]):
            record, finding = _classify_link(
                path,
                link,
                manifest=manifest,
                inventory=actual_paths,
                guard_policy=guard_policy,
            )
            link_records.append(record)
            if finding is not None:
                findings.append(finding)

    final_files, final_directories, final_findings = _artifact_inventory(artifact_root)
    findings.extend(final_findings)
    if set(final_files) != actual_paths or final_directories != directories:
        findings.append(
            Finding("inventory", "artifact_changed_during_scan", ".", "inventory")
        )
    for path, snapshot in snapshots.items():
        final = final_files.get(path)
        if final is None or _stat_signature(final) != snapshot.signature:
            findings.append(
                Finding(
                    "inventory",
                    "artifact_changed_during_scan",
                    path,
                    "file_metadata",
                )
            )

    unique_findings = {
        (item.gate, item.rule, item.path, item.detector): item for item in findings
    }
    ordered_findings = sorted(
        unique_findings.values(),
        key=lambda item: (
            _path_sort_key(item.path),
            item.gate,
            item.rule,
            item.detector,
        ),
    )
    sensitive_paths = {
        item.path
        for item in ordered_findings
        if item.rule == "forbidden_filename"
        or (item.path not in expected_paths and item.path != ".")
    }
    content_redaction_paths = {
        item.path for item in ordered_findings if item.rule == "forbidden_phrase"
    }

    def evidence_path(path: str) -> str:
        if path not in sensitive_paths:
            return path
        return "redacted-path:" + _sha256(path.encode("utf-8"))[:16]

    rendered_findings = [
        replace(item, path=evidence_path(item.path)).to_dict()
        for item in ordered_findings
    ]
    denied_paths = {item.path for item in ordered_findings}
    coverage_records = []
    for path in sorted(snapshots, key=_path_sort_key):
        entry = expected.get(path)
        coverage_records.append(
            {
                "category": list(_path_categories(path, policy_document)),
                "class": entry.publication_class if entry else "undeclared",
                "media_type": _media_type(path),
                "origin": "generated-artifact",
                "path": evidence_path(path),
                "scanner_status": "deny" if path in denied_paths else "pass",
                "sha256": snapshots[path].sha256,
                "size": snapshots[path].size,
            }
        )
    for record in link_records:
        source_path = record["source_path"]
        record["source_path"] = evidence_path(source_path)
        if source_path in content_redaction_paths:
            record.pop("target", None)
    link_records.sort(
        key=lambda item: (
            _path_sort_key(item["source_path"]),
            item["classification"],
            item.get("target", ""),
            item["target_fingerprint"],
            item["context"],
        )
    )

    gate_counts: dict[str, int] = {}
    for item in ordered_findings:
        gate_counts[item.gate] = gate_counts.get(item.gate, 0) + 1
    gates = ("eligibility", "inventory", "links", "parse", "policy")
    result = "deny" if ordered_findings else "pass"
    return {
        "artifact_boundary": ARTIFACT_BOUNDARY,
        "commit_sha": commit_sha,
        "coverage_records": coverage_records,
        "findings": rendered_findings,
        "generated_artifact_count": len(files),
        "inventory_paths": [
            evidence_path(path) for path in sorted(files, key=_path_sort_key)
        ],
        "links": link_records,
        "manifest_sha256": manifest.sha256,
        "policy_id": policy_document.get("policy_id"),
        "policy_sha256": policy_sha256,
        "policy_version": policy_document.get("policy_version"),
        "repository": manifest.repository,
        "result": result,
        "rule_results": [
            {
                "finding_count": gate_counts.get(gate, 0),
                "gate": gate,
                "result": "deny" if gate_counts.get(gate, 0) else "pass",
            }
            for gate in gates
        ],
        "scan_completed_at": None,
        "scan_counts": {
            "declared_paths": len(expected),
            "findings": len(ordered_findings),
            "links": len(link_records),
            "policy_scanned_paths": guard_report["scanned_path_count"]
            + len(control_paths & set(snapshots)),
            "scanned_paths": len(snapshots),
        },
        "scan_started_at": None,
        "scanner_name": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "schema_version": 1,
        "source_file_count": len(expected),
    }


def _render_json(value: Mapping[str, Any], compact: bool) -> str:
    if compact:
        return json.dumps(
            value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ) + "\n"
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def _write_report(
    report: Mapping[str, Any],
    *,
    output: str | os.PathLike[str] | None,
    compact: bool,
    artifact_root: Path | None = None,
) -> None:
    rendered = _render_json(report, compact)
    if output is None:
        sys.stdout.write(rendered)
        return
    output_path = Path(output)
    if artifact_root is not None:
        try:
            resolved_parent = output_path.parent.resolve(strict=True)
            candidate = resolved_parent / output_path.name
            if os.path.commonpath(
                (os.fspath(artifact_root), os.fspath(candidate))
            ) == os.fspath(artifact_root):
                raise ArtifactError("evidence_inside_artifact")
        except OSError as error:
            raise ArtifactError("evidence_parent_unreadable") from error
    try:
        output_path.write_text(rendered, encoding="utf-8")
    except OSError as error:
        raise ArtifactError("evidence_write_failed") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and scan the exact deny-by-default Pages artifact."
    )
    parser.add_argument("--compact", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "scan", "build-scan"):
        child = subparsers.add_parser(command)
        child.add_argument("--source", default=".")
        child.add_argument("--manifest", default=MANIFEST_FILENAME)
        child.add_argument("--policy", default=POLICY_FILENAME)
        child.add_argument("--artifact", required=True)
        child.add_argument("--evidence")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        artifact_root = Path(args.artifact)
        if args.command == "build":
            report = build_artifact(
                args.source,
                args.artifact,
                manifest_path=args.manifest,
                policy_path=args.policy,
            )
        elif args.command == "scan":
            report = scan_artifact(
                args.source,
                args.artifact,
                manifest_path=args.manifest,
                policy_path=args.policy,
            )
        else:
            build_artifact(
                args.source,
                args.artifact,
                manifest_path=args.manifest,
                policy_path=args.policy,
            )
            report = scan_artifact(
                args.source,
                args.artifact,
                manifest_path=args.manifest,
                policy_path=args.policy,
            )
        _write_report(
            report,
            output=args.evidence,
            compact=args.compact,
            artifact_root=artifact_root.resolve(strict=True),
        )
        return 0 if report["result"] == "pass" else 1
    except ArtifactError as error:
        report = {
            "artifact_boundary": ARTIFACT_BOUNDARY,
            "error": {"code": error.code, "type": "artifact_error"},
            "result": "error",
            "schema_version": 1,
        }
        try:
            _write_report(report, output=args.evidence, compact=args.compact)
        except ArtifactError:
            sys.stderr.write("publication artifact: unable to write safe evidence\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
