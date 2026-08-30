#!/usr/bin/env python3
"""Deterministic guard against publishing sensitive source material.

This scanner emits publication evidence only. It does not emit RAPP or RAPP/1
protocol artifacts and therefore does not claim protocol-frame conformance.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import json
import os
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Sequence
import unicodedata
from urllib.parse import urlparse


POLICY_FILENAME = "PUBLICATION-POLICY.json"
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
ARTIFACT_BOUNDARY = (
    "publication evidence only; emits no RAPP or RAPP/1 protocol artifacts"
)

_FILENAME_KEYS = {
    "blocked_filenames",
    "denied_filenames",
    "deny_filenames",
    "explicit_filenames_case_insensitive",
    "forbidden_filenames",
    "forbidden_files",
    "sensitive_filenames",
}
_PHRASE_KEYS = {
    "blocked_phrases",
    "denied_phrases",
    "deny_phrases",
    "forbidden_phrases",
    "sensitive_phrases",
}
_PRIVATE_REPOSITORY_KEYS = {
    "forbidden_repositories",
    "forbidden_repository_links",
    "forbidden_repository_urls",
    "private_repositories",
    "private_repository_links",
    "private_repository_urls",
    "private_repos",
}
_MAX_FILE_KEYS = {"max_file_bytes", "maximum_file_bytes"}
_ALLOWED_REPOSITORY_KEYS = {"allowed_repository_slugs_case_insensitive"}
_REPOSITORY_HOST_KEYS = {"repository_hosts_case_insensitive"}

_OWNERSHIP_PATTERNS = (
    re.compile(
        r"\b(?:own(?:s|ed|ership)?|equity|stake|share|interest)\b"
        r".{0,48}?\b(?:100(?:\.0+)?|[1-9]?\d(?:\.\d+)?)\s*"
        r"(?:%|\bpercent(?:age)?\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:100(?:\.0+)?|[1-9]?\d(?:\.\d+)?)\s*"
        r"(?:%|\bpercent(?:age)?\b)"
        r".{0,48}?\b(?:owned|ownership|equity|stake|share|interest)\b",
        re.IGNORECASE,
    ),
)

_SENSITIVE_PATTERNS = (
    (
        "private_key",
        re.compile(r"-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}", re.IGNORECASE),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b", re.IGNORECASE),
    ),
    ("openai_token", re.compile(r"\bsk-[A-Za-z0-9]{20,200}\b")),
    ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,100}\b")),
    (
        "stripe_secret_key",
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,200}\b", re.IGNORECASE),
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b", re.IGNORECASE),
    ),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
            r"\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
    (
        "credential_assignment",
        re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|"
            r"passwd|secret)\b\s*[:=]\s*[\"']?"
            r"[A-Za-z0-9_./+=-]{12,}",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_url",
        re.compile(
            r"\b[a-z][a-z0-9+.-]*://[^/\s:@]{1,64}:[^/\s@]{4,128}@",
            re.IGNORECASE,
        ),
    ),
    (
        "connection_string_secret",
        re.compile(
            r"\b(?:AccountKey|SharedAccessKey|ClientSecret)\s*=\s*"
            r"[A-Za-z0-9+/=_-]{12,}",
            re.IGNORECASE,
        ),
    ),
    (
        "webhook_secret",
        re.compile(
            r"https://hooks\.slack\.com/services/"
            r"[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{12,}",
            re.IGNORECASE,
        ),
    ),
    (
        "email_address",
        re.compile(
            r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
            r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
            r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
            r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+",
            re.IGNORECASE,
        ),
    ),
    (
        "us_ssn",
        re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"),
    ),
    (
        "phone_number",
        re.compile(
            r"(?:\b(?:phone|mobile|cell|tel)\b\s*[:=]?\s*)"
            r"(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})"
            r"[\s.-]\d{3}[\s.-]\d{4}\b",
            re.IGNORECASE,
        ),
    ),
)

_URL_PATTERN = re.compile(
    r"(?:https?|ssh)://[^\s<>\"']+|git@[A-Z0-9.-]+:[^\s<>\"']+",
    re.IGNORECASE,
)


class GuardError(Exception):
    """An operational or configuration error that prevents a complete scan."""


@dataclass(frozen=True)
class Policy:
    forbidden_filenames: tuple[str, ...] = ()
    forbidden_filename_patterns: tuple["PolicyPattern", ...] = ()
    forbidden_phrases: tuple[str, ...] = ()
    forbidden_phrase_patterns: tuple["PolicyPattern", ...] = ()
    private_repositories: tuple[str, ...] = ()
    allowed_repository_slugs: tuple[str, ...] = ()
    repository_hosts: tuple[str, ...] = ()
    forbidden_repository_slug_patterns: tuple["PolicyPattern", ...] = ()
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES


@dataclass(frozen=True)
class PolicyPattern:
    identifier: str
    expression: str
    compiled: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    detector: str
    line: int | None = None
    column: int | None = None

    def as_dict(self) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "detector": self.detector,
            "path": self.path,
            "rule": self.rule,
        }
        if self.line is not None:
            evidence["line"] = self.line
        if self.column is not None:
            evidence["column"] = self.column
        stable_fields = json.dumps(
            evidence, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        evidence["evidence_id"] = hashlib.sha256(
            stable_fields.encode("utf-8")
        ).hexdigest()[:16]
        return evidence


def _normalise_key(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _find_policy_values(node: Any, keys: set[str]) -> list[Any]:
    found: list[Any] = []
    if isinstance(node, dict):
        for key in sorted(node, key=lambda item: str(item).casefold()):
            value = node[key]
            if isinstance(key, str) and _normalise_key(key) in keys:
                found.append(value)
            found.extend(_find_policy_values(value, keys))
    elif isinstance(node, list):
        for value in node:
            found.extend(_find_policy_values(value, keys))
    return found


def _as_entries(values: Iterable[Any], entry_keys: Sequence[str], label: str) -> tuple[str, ...]:
    entries: list[str] = []
    for value in values:
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            if isinstance(candidate, str):
                entries.append(candidate)
                continue
            if isinstance(candidate, dict):
                selected = [
                    candidate[key]
                    for key in entry_keys
                    if isinstance(candidate.get(key), str)
                ]
                if selected:
                    entries.extend(selected)
                    continue
            raise GuardError(f"{label} entries must be strings or supported objects")

    cleaned = {entry.strip() for entry in entries if entry.strip()}
    return tuple(sorted(cleaned, key=lambda entry: (entry.casefold(), entry)))


def _as_patterns(values: Iterable[Any], label: str) -> tuple[PolicyPattern, ...]:
    raw_patterns: list[tuple[str, str]] = []
    sequence = 0
    for value in values:
        if isinstance(value, dict) and "patterns" in value:
            candidates = value["patterns"]
        elif isinstance(value, list):
            candidates = value
        else:
            candidates = [value]
        if not isinstance(candidates, list):
            raise GuardError(f"{label} patterns must be a list")
        for candidate in candidates:
            identifier = f"{label}[{sequence}]"
            expression: Any = candidate
            if isinstance(candidate, dict):
                identifier = str(candidate.get("id", identifier))
                expression = candidate.get("regex", candidate.get("pattern"))
            if not isinstance(expression, str) or not expression:
                raise GuardError(f"{label} patterns must contain regular expressions")
            raw_patterns.append((identifier, expression))
            sequence += 1

    patterns: list[PolicyPattern] = []
    for identifier, expression in sorted(
        set(raw_patterns), key=lambda item: (item[0].casefold(), item[0], item[1])
    ):
        try:
            compiled = re.compile(expression, re.IGNORECASE)
        except re.error as error:
            raise GuardError(f"{label} contains an invalid regular expression") from error
        patterns.append(PolicyPattern(identifier, expression, compiled))
    return tuple(patterns)


def _load_policy(root: Path, policy_path: str | os.PathLike[str] | None) -> tuple[Policy, Path | None]:
    explicit = policy_path is not None
    path = Path(policy_path) if explicit else root / POLICY_FILENAME
    if not path.is_absolute():
        path = root / path
    if not path.exists():
        if explicit:
            raise GuardError("the requested policy file does not exist")
        return Policy(), None
    if not path.is_file():
        raise GuardError("the policy path is not a regular file")

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as error:
        raise GuardError("the policy file is not UTF-8 text") from error
    except json.JSONDecodeError as error:
        raise GuardError(
            f"the policy file is invalid JSON at line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(document, dict):
        raise GuardError("the policy document must be a JSON object")

    filenames = _as_entries(
        _find_policy_values(document, _FILENAME_KEYS),
        ("pattern", "filename", "path", "name"),
        "forbidden filename",
    )
    phrases = _as_entries(
        _find_policy_values(document, _PHRASE_KEYS),
        ("phrase", "value", "text"),
        "forbidden phrase",
    )
    repositories = _as_entries(
        _find_policy_values(document, _PRIVATE_REPOSITORY_KEYS),
        ("url", "slug", "repository", "repo", "name"),
        "private repository",
    )
    filename_patterns = _as_patterns(
        _find_policy_values(document, {"filename_patterns"}),
        "forbidden_filename_pattern",
    )
    phrase_patterns = _as_patterns(
        _find_policy_values(document, {"phrase_patterns"}),
        "forbidden_phrase_pattern",
    )
    allowed_repositories = _as_entries(
        _find_policy_values(document, _ALLOWED_REPOSITORY_KEYS),
        ("slug", "repository", "repo", "name"),
        "allowed repository",
    )
    repository_hosts = _as_entries(
        _find_policy_values(document, _REPOSITORY_HOST_KEYS),
        ("host", "name"),
        "repository host",
    )
    forbidden_repository_patterns = _as_patterns(
        _find_policy_values(document, {"forbidden_repository_slug_patterns"}),
        "forbidden_repository_slug_pattern",
    )

    maximums = _find_policy_values(document, _MAX_FILE_KEYS)
    max_file_bytes = DEFAULT_MAX_FILE_BYTES
    if maximums:
        value = maximums[0]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise GuardError("max_file_bytes must be a positive integer")
        max_file_bytes = value

    return (
        Policy(
            forbidden_filenames=filenames,
            forbidden_filename_patterns=filename_patterns,
            forbidden_phrases=phrases,
            forbidden_phrase_patterns=phrase_patterns,
            private_repositories=repositories,
            allowed_repository_slugs=allowed_repositories,
            repository_hosts=repository_hosts,
            forbidden_repository_slug_patterns=forbidden_repository_patterns,
            max_file_bytes=max_file_bytes,
        ),
        path.resolve(),
    )


def _read_manifest(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise GuardError("the manifest could not be read") from error

    stripped = raw.lstrip()
    if stripped.startswith((b"[", b"{")):
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GuardError("the manifest is not valid UTF-8 JSON") from error
        if isinstance(document, dict):
            document = document.get("paths", document.get("files"))
        if not isinstance(document, list) or not all(
            isinstance(item, str) for item in document
        ):
            raise GuardError("a JSON manifest must be a string array or contain paths/files")
        return document

    if b"\0" in raw:
        return [os.fsdecode(chunk) for chunk in raw.split(b"\0") if chunk]
    paths = []
    for chunk in raw.splitlines():
        decoded = os.fsdecode(chunk)
        if decoded:
            paths.append(decoded)
    return paths


def _git_paths(root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(root), "ls-files", "-z"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise GuardError("git could not be executed") from error
    if result.returncode:
        raise GuardError("git ls-files failed; provide --manifest for a fixture root")
    return [os.fsdecode(item) for item in result.stdout.split(b"\0") if item]


def _manifest_paths(
    root: Path,
    manifest: Iterable[str] | str | os.PathLike[str] | None,
) -> list[str]:
    if manifest is None:
        paths = _git_paths(root)
    elif isinstance(manifest, (str, os.PathLike)):
        manifest_path = Path(manifest)
        if not manifest_path.is_absolute():
            manifest_path = root / manifest_path
        paths = _read_manifest(manifest_path)
    else:
        paths = list(manifest)
        if not all(isinstance(path, str) for path in paths):
            raise GuardError("manifest paths must be strings")
    return sorted(set(paths), key=lambda path: (path.casefold(), path))


def _is_absolute_or_traversal(path: str) -> bool:
    native = Path(path)
    windows = PureWindowsPath(path)
    return (
        native.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or ".." in native.parts
        or ".." in windows.parts
        or "\0" in path
    )


def _first_symlink(root: Path, relative: Path) -> Path | None:
    current = root
    for part in relative.parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return None
        except OSError as error:
            raise GuardError("a tracked path could not be inspected") from error
        if stat.S_ISLNK(mode):
            return current
    return None


def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    binary_signatures = (
        b"%PDF-",
        b"\x1f\x8b",
        b"\x7fELF",
        b"\x89PNG\r\n\x1a\n",
        b"GIF87a",
        b"GIF89a",
        b"PK\x03\x04",
        b"\xff\xd8\xff",
    )
    if data.startswith(binary_signatures):
        return True
    if b"\0" in data:
        return True
    permitted_controls = {7, 8, 9, 10, 12, 13, 27}
    suspicious = sum(
        byte < 32 and byte not in permitted_controls for byte in data[:8192]
    )
    return suspicious / min(len(data), 8192) > 0.30


def _filename_matches(path: str, pattern: str) -> bool:
    lowered_path = path.casefold()
    lowered_pattern = pattern.replace("\\", "/").casefold()
    basename = Path(path).name.casefold()
    return fnmatch.fnmatchcase(lowered_path, lowered_pattern) or fnmatch.fnmatchcase(
        basename, lowered_pattern
    )


def _repository_needles(repository: str) -> tuple[str, ...]:
    value = repository.strip().rstrip("/")
    if not value:
        return ()

    slug: str | None = None
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        repo_path = parsed.path.strip("/")
        if repo_path:
            slug = repo_path.removesuffix(".git")
    elif value.startswith("git@") and ":" in value:
        slug = value.split(":", 1)[1].strip("/").removesuffix(".git")
    elif re.fullmatch(r"[^/\s]+/[^/\s]+(?:\.git)?", value):
        slug = value.removesuffix(".git")

    needles = {value.casefold()}
    if slug:
        github_host = "github.com"
        needles.update(
            {
                f"https://{github_host}/{slug}".casefold(),
                f"http://{github_host}/{slug}".casefold(),
                f"ssh://git@{github_host}/{slug}".casefold(),
                ("git@" + f"{github_host}:{slug}").casefold(),
            }
        )
    return tuple(sorted(needles))


def _normalise_repository_slug(slug: str) -> str:
    return slug.strip().strip("/").removesuffix(".git").casefold()


def _repository_reference(value: str) -> tuple[str, str] | None:
    candidate = value.rstrip(".,);]}>")
    if candidate.casefold().startswith("git@") and ":" in candidate:
        authority, path = candidate.split(":", 1)
        host = authority.split("@", 1)[1].casefold()
        slug = path.strip("/").removesuffix(".git")
        return host, slug

    parsed = urlparse(candidate)
    host = (parsed.hostname or "").casefold()
    parts = [part for part in parsed.path.split("/") if part]
    if not host or not parts:
        return None
    if host == "api.github.com" and parts[:1] == ["repos"]:
        parts = parts[1:]
    if host == "raw.githubusercontent.com":
        parts = parts[:2]
    if host == "dev.azure.com" and "_git" in parts:
        git_index = parts.index("_git")
        parts = parts[:git_index] + parts[git_index + 1 : git_index + 2]
    if len(parts) < 2:
        return None
    return host, "/".join(parts[:2]).removesuffix(".git")


def _normalise_policy_text(text: str) -> str:
    normalised = unicodedata.normalize("NFKC", html.unescape(text))
    return " ".join(normalised.split())


def _line_findings(
    path: str,
    text: str,
    policy: Policy,
) -> Iterable[Finding]:
    private_needles = [
        (index, needle)
        for index, repository in enumerate(policy.private_repositories)
        for needle in _repository_needles(repository)
    ]

    for line_number, line in enumerate(text.splitlines(), start=1):
        folded = line.casefold()
        normalised_line = _normalise_policy_text(line)
        for index, phrase in enumerate(policy.forbidden_phrases):
            if _normalise_policy_text(phrase).casefold() in normalised_line.casefold():
                yield Finding(
                    "forbidden_phrase",
                    path,
                    f"policy.forbidden_phrases[{index}]",
                    line_number,
                )

        for pattern in policy.forbidden_phrase_patterns:
            match = pattern.compiled.search(normalised_line)
            if match:
                yield Finding(
                    "forbidden_phrase",
                    path,
                    pattern.identifier,
                    line_number,
                    match.start() + 1,
                )

        for index, needle in private_needles:
            if needle in folded:
                yield Finding(
                    "private_repository_link",
                    path,
                    f"policy.private_repositories[{index}]",
                    line_number,
                )

        allowed_slugs = {
            _normalise_repository_slug(slug)
            for slug in policy.allowed_repository_slugs
        }
        repository_hosts = {host.casefold() for host in policy.repository_hosts}
        for match in _URL_PATTERN.finditer(line):
            reference = _repository_reference(match.group(0))
            if reference is None:
                continue
            host, slug = reference
            if host not in repository_hosts:
                continue
            normalised_slug = _normalise_repository_slug(slug)
            if normalised_slug in allowed_slugs:
                continue
            pattern_match = next(
                (
                    pattern
                    for pattern in policy.forbidden_repository_slug_patterns
                    if pattern.compiled.search(normalised_slug)
                ),
                None,
            )
            detector = (
                pattern_match.identifier
                if pattern_match is not None
                else "repository_visibility_default_deny"
            )
            yield Finding(
                "private_repository_link",
                path,
                detector,
                line_number,
                match.start() + 1,
            )

        for index, pattern in enumerate(_OWNERSHIP_PATTERNS):
            match = pattern.search(line)
            if match:
                yield Finding(
                    "ownership_percentage_claim",
                    path,
                    f"ownership_pattern[{index}]",
                    line_number,
                    match.start() + 1,
                )

        for detector, pattern in _SENSITIVE_PATTERNS:
            match = pattern.search(line)
            if match:
                yield Finding(
                    "sensitive_data_shape",
                    path,
                    detector,
                    line_number,
                    match.start() + 1,
                )


def scan_repository(
    root: str | os.PathLike[str] = ".",
    *,
    policy_path: str | os.PathLike[str] | None = None,
    manifest: Iterable[str] | str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Scan tracked or explicitly manifested paths and return JSON-ready evidence."""

    try:
        resolved_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise GuardError("the scan root does not exist") from error
    if not resolved_root.is_dir():
        raise GuardError("the scan root is not a directory")

    policy, loaded_policy_path = _load_policy(resolved_root, policy_path)
    paths = _manifest_paths(resolved_root, manifest)

    findings: list[Finding] = []
    binary_paths: list[str] = []
    text_paths: list[str] = []
    skipped_paths: list[str] = []
    unscanned_paths: list[str] = []

    for raw_path in paths:
        display_path = raw_path.replace("\\", "/")
        for index, pattern in enumerate(policy.forbidden_filenames):
            if _filename_matches(display_path, pattern):
                findings.append(
                    Finding(
                        "forbidden_filename",
                        display_path,
                        f"policy.forbidden_filenames[{index}]",
                    )
                )
        for pattern in policy.forbidden_filename_patterns:
            if pattern.compiled.search(Path(display_path).name):
                findings.append(
                    Finding(
                        "forbidden_filename",
                        display_path,
                        pattern.identifier,
                    )
                )

        if _is_absolute_or_traversal(raw_path):
            findings.append(Finding("path_escape", display_path, "manifest_path"))
            unscanned_paths.append(display_path)
            continue

        relative = Path(raw_path)
        candidate = resolved_root / relative
        try:
            symlink = _first_symlink(resolved_root, relative)
            if symlink is not None:
                findings.append(
                    Finding("symlink_path", display_path, "path_metadata")
                )
                unscanned_paths.append(display_path)
                continue
            resolved_candidate = candidate.resolve(strict=False)
            if os.path.commonpath(
                [os.fspath(resolved_root), os.fspath(resolved_candidate)]
            ) != os.fspath(resolved_root):
                findings.append(
                    Finding("path_escape", display_path, "resolved_path")
                )
                unscanned_paths.append(display_path)
                continue
        except (OSError, ValueError, GuardError):
            findings.append(Finding("unreadable_path", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            continue

        if loaded_policy_path is not None and resolved_candidate == loaded_policy_path:
            skipped_paths.append(display_path)
            continue

        try:
            mode = candidate.lstat().st_mode
        except FileNotFoundError:
            findings.append(Finding("missing_path", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            continue
        except OSError:
            findings.append(Finding("unreadable_path", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            continue

        if not stat.S_ISREG(mode):
            findings.append(Finding("unsupported_file_type", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            continue

        try:
            with candidate.open("rb") as source:
                data = source.read(policy.max_file_bytes + 1)
        except OSError:
            findings.append(Finding("unreadable_path", display_path, "file_read"))
            unscanned_paths.append(display_path)
            continue

        if len(data) > policy.max_file_bytes:
            findings.append(Finding("file_too_large", display_path, "size_limit"))
            unscanned_paths.append(display_path)
            continue
        if _is_binary(data):
            binary_paths.append(display_path)
            continue

        text_paths.append(display_path)
        text = data.decode("utf-8-sig", errors="replace")
        findings.extend(_line_findings(display_path, text, policy))

    unique_findings = {
        (
            finding.rule,
            finding.path,
            finding.detector,
            finding.line,
            finding.column,
        ): finding
        for finding in findings
    }
    ordered_findings = sorted(
        unique_findings.values(),
        key=lambda finding: (
            finding.path.casefold(),
            finding.path,
            finding.line or 0,
            finding.column or 0,
            finding.rule,
            finding.detector,
        ),
    )

    return {
        "artifact_boundary": ARTIFACT_BOUNDARY,
        "binary_paths": sorted(set(binary_paths), key=lambda path: (path.casefold(), path)),
        "finding_count": len(ordered_findings),
        "findings": [finding.as_dict() for finding in ordered_findings],
        "policy_loaded": loaded_policy_path is not None,
        "result": "deny" if ordered_findings else "pass",
        "scanned_path_count": len(set(binary_paths + text_paths)),
        "schema_version": 1,
        "skipped_paths": sorted(set(skipped_paths), key=lambda path: (path.casefold(), path)),
        "text_paths": sorted(set(text_paths), key=lambda path: (path.casefold(), path)),
        "unscanned_paths": sorted(
            set(unscanned_paths), key=lambda path: (path.casefold(), path)
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan public source paths for publication policy violations."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="repository or fixture root (default: current directory)",
    )
    parser.add_argument(
        "--manifest",
        help="newline, NUL, or JSON path manifest; otherwise use git ls-files",
    )
    parser.add_argument(
        "--policy",
        help=f"policy path (default: {POLICY_FILENAME} under the root when present)",
    )
    parser.add_argument("--output", help="write JSON evidence to this file")
    parser.add_argument(
        "--compact", action="store_true", help="emit compact rather than indented JSON"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = scan_repository(
            args.root,
            policy_path=args.policy,
            manifest=args.manifest,
        )
        exit_code = 1 if report["finding_count"] else 0
    except GuardError as error:
        report = {
            "artifact_boundary": ARTIFACT_BOUNDARY,
            "error": {
                "message": str(error),
                "type": "scan_error",
            },
            "schema_version": 1,
        }
        exit_code = 2

    if args.compact:
        rendered = json.dumps(
            report, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
    else:
        rendered = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True)
    rendered += "\n"

    if args.output:
        output_path = Path(args.output)
        try:
            output_path.write_text(rendered, encoding="utf-8")
        except OSError:
            sys.stderr.write("publication guard: unable to write JSON output\n")
            return 2
    else:
        sys.stdout.write(rendered)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
