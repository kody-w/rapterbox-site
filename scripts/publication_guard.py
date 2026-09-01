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
import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Sequence
import unicodedata
from urllib.parse import unquote, urlparse


POLICY_FILENAME = "PUBLICATION-POLICY.json"
MANIFEST_FILENAME = "PUBLICATION-MANIFEST.json"
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
SCANNER_NAME = "rapterbox-publication-source"
SCANNER_VERSION = "1.2.0"
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
_FORBIDDEN_HOST_KEYS = {"forbidden_hosts_case_insensitive"}
_FORBIDDEN_HOST_SUFFIX_KEYS = {"forbidden_host_suffixes_case_insensitive"}
_SUPPORTED_STRUCTURED_DETECTORS = frozenset(
    (
        "access_tokens",
        "api_tokens",
        "connection_strings",
        "contracts_not_intentionally_published_as_customer_facing_terms",
        "customer_notes",
        "customer_or_account_identifiers",
        "email_address_values",
        "government_identifiers",
        "legal_matter_records",
        "passwords",
        "phone_number_values",
        "postal_address_values",
        "private_keys",
        "privileged_communications",
        "real_secret_values_from_ci_secret_corpus",
        "signatures",
        "submitted_names",
        "waitlist_submission_records",
        "webhook_secrets",
    )
)
_SECRET_STRUCTURED_DETECTORS = frozenset(
    (
        "access_tokens",
        "api_tokens",
        "connection_strings",
        "passwords",
        "private_keys",
        "real_secret_values_from_ci_secret_corpus",
        "webhook_secrets",
    )
)
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
        "secret",
        re.compile(r"-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}", re.IGNORECASE),
    ),
    (
        "aws_access_key",
        "secret",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "github_token",
        "secret",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b", re.IGNORECASE),
    ),
    (
        "openai_token",
        "secret",
        re.compile(r"\bsk-[A-Za-z0-9]{20,200}\b"),
    ),
    (
        "google_api_key",
        "secret",
        re.compile(r"\bAIza[A-Za-z0-9_-]{30,100}\b"),
    ),
    (
        "stripe_secret_key",
        "secret",
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,200}\b", re.IGNORECASE),
    ),
    (
        "slack_token",
        "secret",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b", re.IGNORECASE),
    ),
    (
        "jwt",
        "secret",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
            r"\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
    (
        "credential_assignment",
        "secret",
        re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|"
            r"passwd|secret)\b\s*[:=]\s*[\"']?"
            r"[A-Za-z0-9_./+=-]{12,}",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_url",
        "secret",
        re.compile(
            r"\b[a-z][a-z0-9+.-]*://[^/\s:@]{1,64}:[^/\s@]{4,128}@",
            re.IGNORECASE,
        ),
    ),
    (
        "connection_string_secret",
        "secret",
        re.compile(
            r"\b(?:AccountKey|SharedAccessKey|ClientSecret)\s*=\s*"
            r"[A-Za-z0-9+/=_-]{12,}",
            re.IGNORECASE,
        ),
    ),
    (
        "webhook_secret",
        "secret",
        re.compile(
            r"https://hooks\.slack\.com/services/"
            r"[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{12,}",
            re.IGNORECASE,
        ),
    ),
    (
        "email_address",
        "customer",
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
        "customer",
        re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"),
    ),
    (
        "phone_number",
        "customer",
        re.compile(
            r"(?:\b(?:phone|mobile|cell|tel)\b\s*[:=]?\s*)"
            r"(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})"
            r"[\s.-]\d{3}[\s.-]\d{4}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "postal_address",
        "customer",
        re.compile(
            r"\b(?:address|street)\b\s*[:=]\s*[\"']?\d{1,6}\s+"
            r"[A-Za-z0-9 .'-]{2,80}\s+"
            r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "submitted_customer_record",
        "customer",
        re.compile(
            r"[\"'](?:submitted_at|submission_id|waitlist_submission)[\"']\s*:"
            r".{0,256}[\"'](?:email|phone|note|customer_id|account_id)[\"']\s*:",
            re.IGNORECASE,
        ),
    ),
)

_URL_PATTERN = re.compile(
    r"(?:https?|ssh)://[^\s<>\"']+"
    r"|(?<![A-Z0-9:+.-])//[A-Z0-9.-]+\.[A-Z]{2,}(?:/[^\s<>\"']*)?"
    r"|git@[A-Z0-9.-]+:[^\s<>\"']+",
    re.IGNORECASE,
)
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ZERO_WIDTH_CHARACTERS = dict.fromkeys(
    map(ord, ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"))
)


class GuardError(Exception):
    """An operational or configuration error that prevents a complete scan."""


class _DuplicateJsonKey(ValueError):
    pass


class _InvalidJsonConstant(ValueError):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey
        value[key] = item
    return value


def _reject_json_constant(_: str) -> None:
    raise _InvalidJsonConstant


@dataclass(frozen=True)
class Policy:
    forbidden_filenames: tuple[str, ...] = ()
    forbidden_filename_patterns: tuple["PolicyPattern", ...] = ()
    forbidden_phrases: tuple[str, ...] = ()
    forbidden_phrase_patterns: tuple["PolicyPattern", ...] = ()
    private_repositories: tuple[str, ...] = ()
    allowed_repository_slugs: tuple[str, ...] = ()
    repository_hosts: tuple[str, ...] = ()
    forbidden_hosts: tuple[str, ...] = ()
    forbidden_host_suffixes: tuple[str, ...] = ()
    forbidden_repository_slug_patterns: tuple["PolicyPattern", ...] = ()
    source_default_class: str = "repository-source"
    source_manifest: str | None = None
    source_classification_rules: tuple["SourceClassificationRule", ...] = ()
    structured_detectors: tuple["StructuredDetector", ...] = ()
    structured_max_depth: int = 32
    structured_max_items: int = 10000
    structured_key_decode_passes: int = 2
    structured_allowances: tuple["StructuredAllowance", ...] = ()
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES


@dataclass(frozen=True)
class PolicyPattern:
    identifier: str
    expression: str
    compiled: re.Pattern[str]


@dataclass(frozen=True)
class SourceClassificationRule:
    identifier: str
    patterns: tuple[str, ...]
    classification: str
    content_contract: str
    artifact_disposition: str


@dataclass(frozen=True)
class GitSourceEntry:
    path: str
    mode: str
    object_type: str
    object_id: str


@dataclass(frozen=True)
class StructuredDetector:
    identifier: str
    detect: tuple[str, ...]
    allow_placeholders: bool


@dataclass(frozen=True)
class StructuredAllowance:
    identifier: str
    detectors: tuple[str, ...]
    paths: tuple[str, ...]
    patterns: tuple[re.Pattern[str], ...]
    value_sha256s: tuple[str, ...]


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


def _source_classification_contract(
    document: dict[str, Any],
) -> tuple[str, str | None, tuple[SourceClassificationRule, ...]]:
    contract = document.get("source_tree_classification")
    if contract is None:
        return "repository-source", None, ()
    if not isinstance(contract, dict):
        raise GuardError("source_tree_classification must be an object")

    default_class = contract.get("default_class")
    if not isinstance(default_class, str) or not default_class.strip():
        raise GuardError("source_tree_classification requires a default_class")
    manifest = contract.get("artifact_manifest")
    if manifest is not None and (
        not isinstance(manifest, str)
        or not manifest
        or _is_absolute_or_traversal(manifest)
    ):
        raise GuardError("source_tree_classification has an invalid artifact manifest")
    raw_rules = contract.get("path_rules")
    if not isinstance(raw_rules, list):
        raise GuardError("source_tree_classification requires path_rules")

    rules: list[SourceClassificationRule] = []
    valid_contracts = {
        "full",
        "self-reference-safe",
        "synthetic-test-input",
        "nondeploy-operational-contact",
    }
    valid_dispositions = {
        "must-be-absent",
        "publication-control",
    }
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise GuardError("source classification rules must be objects")
        patterns = raw_rule.get("patterns")
        classification = raw_rule.get("class")
        content_contract = raw_rule.get("content_contract", "full")
        artifact_disposition = raw_rule.get(
            "artifact_disposition", "must-be-absent"
        )
        if (
            not isinstance(patterns, list)
            or not patterns
            or not all(
                isinstance(pattern, str)
                and pattern.startswith("/")
                and "\0" not in pattern
                for pattern in patterns
            )
            or not isinstance(classification, str)
            or not classification.strip()
            or content_contract not in valid_contracts
            or artifact_disposition not in valid_dispositions
        ):
            raise GuardError("source classification rule is invalid")
        rules.append(
            SourceClassificationRule(
                identifier=f"source_tree_classification.path_rules[{index}]",
                patterns=tuple(sorted(set(patterns), key=lambda value: value.casefold())),
                classification=classification,
                content_contract=content_contract,
                artifact_disposition=artifact_disposition,
            )
        )
    return default_class, manifest, tuple(rules)


def _structured_contract(
    document: dict[str, Any],
) -> tuple[
    tuple[StructuredDetector, ...],
    int,
    int,
    int,
    tuple[StructuredAllowance, ...],
]:
    public_forbidden = document.get("public_forbidden")
    raw_detectors = (
        public_forbidden.get("structured_data_detectors")
        if isinstance(public_forbidden, dict)
        else None
    )
    if raw_detectors is None:
        return (), 32, 10000, 2, ()
    if not isinstance(raw_detectors, list) or not raw_detectors:
        raise GuardError("structured_data_detectors must be a non-empty list")

    detectors: list[StructuredDetector] = []
    seen_ids: set[str] = set()
    declared: set[str] = set()
    for index, raw in enumerate(raw_detectors):
        if (
            not isinstance(raw, dict)
            or raw.get("action") != "deny"
            or not isinstance(raw.get("id"), str)
            or not raw["id"]
            or not isinstance(raw.get("detect"), list)
            or not raw["detect"]
            or not all(isinstance(item, str) and item for item in raw["detect"])
            or not isinstance(raw.get("allow_placeholders", False), bool)
        ):
            raise GuardError("structured_data_detectors contains an invalid entry")
        identifier = raw["id"]
        if identifier in seen_ids:
            raise GuardError("structured_data_detectors contains duplicate ids")
        detects = tuple(raw["detect"])
        if len(set(detects)) != len(detects):
            raise GuardError("structured_data_detectors contains duplicate detectors")
        unsupported = set(detects) - _SUPPORTED_STRUCTURED_DETECTORS
        if unsupported or declared.intersection(detects):
            raise GuardError("structured_data_detectors contains unsupported detectors")
        seen_ids.add(identifier)
        declared.update(detects)
        detectors.append(
            StructuredDetector(
                identifier=identifier,
                detect=detects,
                allow_placeholders=raw.get("allow_placeholders", False),
            )
        )

    controls = document.get("structured_data_enforcement")
    if not isinstance(controls, dict):
        raise GuardError("structured_data_enforcement is required")
    maximum_depth = controls.get("maximum_nesting_depth")
    maximum_items = controls.get("maximum_collection_items")
    decode_passes = controls.get("encoded_key_decoding_passes")
    if (
        isinstance(maximum_depth, bool)
        or not isinstance(maximum_depth, int)
        or not 1 <= maximum_depth <= 128
        or isinstance(maximum_items, bool)
        or not isinstance(maximum_items, int)
        or not 1 <= maximum_items <= 1000000
        or isinstance(decode_passes, bool)
        or not isinstance(decode_passes, int)
        or not 0 <= decode_passes <= 4
    ):
        raise GuardError("structured_data_enforcement limits are invalid")

    raw_normalization = controls.get("key_normalization")
    expected_normalization = [
        "unicode_nfkc",
        "decode_html_entities",
        "percent_decode",
        "remove_zero_width",
        "split_camel_case",
        "collapse_non_alphanumeric",
    ]
    if raw_normalization != expected_normalization:
        raise GuardError("structured_data_enforcement key normalization is invalid")

    allowances: list[StructuredAllowance] = []
    allowance_ids: set[str] = set()
    for section in ("approved_placeholders", "approved_business_contacts"):
        raw_allowances = controls.get(section, [])
        if not isinstance(raw_allowances, list):
            raise GuardError("structured data allowances must be lists")
        for raw in raw_allowances:
            if (
                not isinstance(raw, dict)
                or not isinstance(raw.get("id"), str)
                or not raw["id"]
                or not isinstance(raw.get("detectors"), list)
                or not raw["detectors"]
                or not all(
                    isinstance(item, str) and item in declared
                    for item in raw["detectors"]
                )
                or not isinstance(raw.get("paths"), list)
                or not raw["paths"]
                or not all(
                    isinstance(path, str)
                    and path.startswith("/")
                    and "\0" not in path
                    for path in raw["paths"]
                )
            ):
                raise GuardError("structured data allowance is invalid")
            identifier = raw["id"]
            if identifier in allowance_ids:
                raise GuardError("structured data allowance ids must be unique")
            allowance_ids.add(identifier)
            expressions = raw.get("patterns", [])
            fingerprints = raw.get("value_sha256s", [])
            if (
                not isinstance(expressions, list)
                or not all(isinstance(item, str) and item for item in expressions)
                or not isinstance(fingerprints, list)
                or not all(
                    isinstance(item, str)
                    and re.fullmatch(r"[0-9a-f]{64}", item) is not None
                    for item in fingerprints
                )
                or (not expressions and not fingerprints)
            ):
                raise GuardError("structured data allowance values are invalid")
            compiled: list[re.Pattern[str]] = []
            for expression in expressions:
                try:
                    compiled.append(re.compile(expression, re.IGNORECASE))
                except re.error as error:
                    raise GuardError(
                        "structured data allowance contains an invalid expression"
                    ) from error
            allowances.append(
                StructuredAllowance(
                    identifier=identifier,
                    detectors=tuple(sorted(set(raw["detectors"]))),
                    paths=tuple(
                        sorted(set(raw["paths"]), key=lambda item: item.casefold())
                    ),
                    patterns=tuple(compiled),
                    value_sha256s=tuple(sorted(set(fingerprints))),
                )
            )
    return (
        tuple(detectors),
        maximum_depth,
        maximum_items,
        decode_passes,
        tuple(allowances),
    )


def _policy_from_document(document: dict[str, Any]) -> Policy:
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
    forbidden_hosts = _as_entries(
        _find_policy_values(document, _FORBIDDEN_HOST_KEYS),
        ("host", "name"),
        "forbidden host",
    )
    forbidden_host_suffixes = _as_entries(
        _find_policy_values(document, _FORBIDDEN_HOST_SUFFIX_KEYS),
        ("suffix", "name"),
        "forbidden host suffix",
    )
    (
        source_default_class,
        source_manifest,
        source_classification_rules,
    ) = _source_classification_contract(document)
    (
        structured_detectors,
        structured_max_depth,
        structured_max_items,
        structured_key_decode_passes,
        structured_allowances,
    ) = _structured_contract(document)

    maximums = _find_policy_values(document, _MAX_FILE_KEYS)
    max_file_bytes = DEFAULT_MAX_FILE_BYTES
    if maximums:
        value = maximums[0]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise GuardError("max_file_bytes must be a positive integer")
        max_file_bytes = value

    return Policy(
        forbidden_filenames=filenames,
        forbidden_filename_patterns=filename_patterns,
        forbidden_phrases=phrases,
        forbidden_phrase_patterns=phrase_patterns,
        private_repositories=repositories,
        allowed_repository_slugs=allowed_repositories,
        repository_hosts=repository_hosts,
        forbidden_hosts=forbidden_hosts,
        forbidden_host_suffixes=forbidden_host_suffixes,
        forbidden_repository_slug_patterns=forbidden_repository_patterns,
        source_default_class=source_default_class,
        source_manifest=source_manifest,
        source_classification_rules=source_classification_rules,
        structured_detectors=structured_detectors,
        structured_max_depth=structured_max_depth,
        structured_max_items=structured_max_items,
        structured_key_decode_passes=structured_key_decode_passes,
        structured_allowances=structured_allowances,
        max_file_bytes=max_file_bytes,
    )


def _decode_policy_data(data: bytes) -> tuple[dict[str, Any], Policy]:
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as error:
        raise GuardError("the policy file is not UTF-8 text") from error
    except (_DuplicateJsonKey, _InvalidJsonConstant) as error:
        raise GuardError("the policy file contains duplicate JSON keys") from error
    except json.JSONDecodeError as error:
        raise GuardError(
            f"the policy file is invalid JSON at line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(document, dict):
        raise GuardError("the policy document must be a JSON object")
    return document, _policy_from_document(document)


def _load_policy(
    root: Path, policy_path: str | os.PathLike[str] | None
) -> tuple[Policy, Path | None]:
    explicit = policy_path is not None
    path = Path(policy_path) if explicit else root / POLICY_FILENAME
    if not path.is_absolute():
        path = root / path
    if not path.exists():
        if explicit:
            raise GuardError("the requested policy file does not exist")
        return Policy(), None
    try:
        relative_policy = Path(os.path.abspath(path)).relative_to(root)
    except ValueError:
        relative_policy = None
    if relative_policy is not None and _first_symlink(root, relative_policy) is not None:
        raise GuardError("the policy path must not contain symlinks")
    try:
        metadata = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise GuardError("the policy path could not be inspected") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GuardError("the policy path is not a regular file")
    if metadata.st_size > DEFAULT_MAX_FILE_BYTES:
        raise GuardError("the policy file is too large")
    _, policy = _decode_policy_data(data)
    return policy, path.resolve()


def _read_manifest(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise GuardError("the manifest could not be read") from error
    if len(raw) > DEFAULT_MAX_FILE_BYTES:
        raise GuardError("the manifest is too large")

    stripped = raw.lstrip()
    if stripped.startswith((b"[", b"{")):
        try:
            document = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_json_object,
                parse_constant=_reject_json_constant,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            _DuplicateJsonKey,
            _InvalidJsonConstant,
        ) as error:
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


def _git_head_context(
    root: Path,
) -> tuple[str, dict[str, GitSourceEntry]] | None:
    try:
        top = subprocess.run(
            ["git", "-C", os.fspath(root), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        commit = subprocess.run(
            ["git", "-C", os.fspath(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise GuardError("git could not be executed") from error
    if top.returncode or commit.returncode:
        return None
    try:
        if Path(top.stdout.strip()).resolve(strict=True) != root:
            return None
    except OSError as error:
        raise GuardError("the Git root could not be resolved") from error
    commit_sha = commit.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40,64}", commit_sha) is None:
        raise GuardError("the Git commit is invalid")
    tree = subprocess.run(
        ["git", "-C", os.fspath(root), "ls-tree", "-rz", "--full-tree", commit_sha],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if tree.returncode:
        raise GuardError("the Git tree could not be read")
    entries: dict[str, GitSourceEntry] = {}
    for raw in tree.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, raw_path = raw.split(b"\t", 1)
            raw_mode, raw_type, raw_object = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8")
            mode = raw_mode.decode("ascii")
            object_type = raw_type.decode("ascii")
            object_id = raw_object.decode("ascii")
        except (UnicodeDecodeError, ValueError) as error:
            raise GuardError("the Git tree is invalid") from error
        entries[path] = GitSourceEntry(path, mode, object_type, object_id)
    return commit_sha, entries


def _git_blob(root: Path, entry: GitSourceEntry, maximum: int) -> bytes:
    if entry.object_type != "blob" or entry.mode not in {"100644", "100755"}:
        raise GuardError("a selected Git path is not a regular file")
    result = subprocess.run(
        ["git", "-C", os.fspath(root), "cat-file", "blob", entry.object_id],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise GuardError("a selected Git blob could not be read")
    if len(result.stdout) > maximum:
        raise GuardError("a selected Git blob is too large")
    return result.stdout


def _git_worktree_mode(mode: int) -> str:
    return "100755" if mode & 0o111 else "100644"


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


def _source_manifest_classes(
    root: Path,
    manifest: Iterable[str] | str | os.PathLike[str] | None,
) -> tuple[dict[str, str], str | None]:
    if not isinstance(manifest, (str, os.PathLike)):
        return {}, None
    manifest_path = Path(manifest)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    try:
        data = manifest_path.read_bytes()
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        _InvalidJsonConstant,
    ):
        return {}, None
    if (
        not isinstance(document, dict)
        or document.get("document_type") != "publication-source-manifest"
        or not isinstance(document.get("source_classes"), list)
    ):
        return {}, None
    classes: dict[str, str] = {}
    for group in document["source_classes"]:
        if (
            not isinstance(group, dict)
            or not isinstance(group.get("class"), str)
            or not isinstance(group.get("paths"), list)
            or not all(isinstance(path, str) for path in group["paths"])
        ):
            raise GuardError("the source manifest classification is invalid")
        for path in group["paths"]:
            if path in classes:
                raise GuardError("the source manifest classification overlaps")
            classes[path] = group["class"]
    return classes, hashlib.sha256(data).hexdigest()


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
    lowered_path = _normalise_match_text(path).casefold()
    lowered_pattern = _normalise_match_text(pattern.replace("\\", "/")).casefold()
    basename = Path(_normalise_match_text(path)).name.casefold()
    return fnmatch.fnmatchcase(lowered_path, lowered_pattern) or fnmatch.fnmatchcase(
        basename, lowered_pattern
    )


def _repository_needles(repository: str) -> tuple[str, ...]:
    value = repository.strip().rstrip("/")
    if not value:
        return ()

    slug: str | None = None
    try:
        parsed = urlparse(value)
    except ValueError as error:
        raise GuardError("a repository policy value is malformed") from error
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
    return (
        _normalise_match_text(unquote(slug))
        .strip()
        .strip("/")
        .removesuffix(".git")
        .casefold()
    )


def _repository_reference(value: str) -> tuple[str, str] | None:
    candidate = value.rstrip(".,);}>")
    if candidate.casefold().startswith("git@") and ":" in candidate:
        authority, path = candidate.split(":", 1)
        host = authority.split("@", 1)[1].casefold()
        slug = unquote(path).strip("/").removesuffix(".git")
        return host, slug

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    try:
        host = (parsed.hostname or "").casefold()
    except ValueError:
        return None
    try:
        decoded_path = unquote(parsed.path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    parts = [part for part in decoded_path.split("/") if part]
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
    normalised = _normalise_match_text(text)
    return " ".join(normalised.split())


def _normalise_match_text(text: str) -> str:
    normalised = text
    for _ in range(2):
        decoded = html.unescape(normalised)
        if decoded == normalised:
            break
        normalised = decoded
    return unicodedata.normalize("NFKC", normalised).translate(
        _ZERO_WIDTH_CHARACTERS
    )


def _source_rule_matches(path: str, pattern: str) -> bool:
    normalized_path = "/" + _normalise_match_text(path).lstrip("/")
    normalized_pattern = _normalise_match_text(pattern)
    return fnmatch.fnmatchcase(
        normalized_path.casefold(), normalized_pattern.casefold()
    )


def _source_classification(
    path: str,
    policy: Policy,
    artifact_entries: dict[str, str],
) -> tuple[str, str, str]:
    matches = [
        rule
        for rule in policy.source_classification_rules
        if any(_source_rule_matches(path, pattern) for pattern in rule.patterns)
    ]
    if len(matches) > 1:
        raise GuardError("a source path matches multiple classification rules")
    if matches:
        rule = matches[0]
        return (
            rule.classification,
            rule.content_contract,
            rule.artifact_disposition,
        )
    if path in artifact_entries:
        return f"deploy-{artifact_entries[path]}", "full", "declared-artifact"
    return policy.source_default_class, "full", "must-be-absent"


def _artifact_manifest_entries(root: Path, policy: Policy) -> dict[str, str]:
    if policy.source_manifest is None:
        return {}
    path = root / policy.source_manifest
    try:
        if _first_symlink(root, Path(policy.source_manifest)) is not None:
            raise GuardError("the artifact manifest must not be a symlink")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise GuardError("the artifact manifest is not a regular file")
        if metadata.st_size > DEFAULT_MAX_FILE_BYTES:
            raise GuardError("the artifact manifest is too large")
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except GuardError:
        raise
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        _InvalidJsonConstant,
    ) as error:
        raise GuardError("the artifact manifest is unreadable or invalid") from error
    entries = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise GuardError("the artifact manifest paths are invalid")
    classified: dict[str, str] = {}
    collision_keys: dict[str, str] = {}
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"class", "path"}
            or not isinstance(entry["path"], str)
            or not isinstance(entry["class"], str)
            or _is_absolute_or_traversal(entry["path"])
        ):
            raise GuardError("the artifact manifest contains an invalid path")
        candidate = entry["path"].replace("\\", "/")
        key = unicodedata.normalize("NFKC", candidate).casefold()
        if key in collision_keys:
            raise GuardError("the artifact manifest contains a path collision")
        collision_keys[key] = candidate
        classified[candidate] = entry["class"]
    return classified


def _path_collision_members(paths: Iterable[str]) -> set[str]:
    groups: dict[str, list[str]] = {}
    for path in paths:
        key = unicodedata.normalize("NFKC", path.replace("\\", "/")).casefold()
        groups.setdefault(key, []).append(path)
    return {
        path
        for group in groups.values()
        if len(group) > 1
        for path in group
    }


def _media_type(path: str, is_binary: bool) -> str:
    guessed, _ = mimetypes.guess_type(path)
    if guessed:
        return guessed
    return "application/octet-stream" if is_binary else "text/plain"


def _normalise_structured_key(value: str, decode_passes: int) -> str:
    normalized = unicodedata.normalize("NFKC", html.unescape(value)).translate(
        _ZERO_WIDTH_CHARACTERS
    )
    for _ in range(decode_passes):
        if _INVALID_PERCENT_ESCAPE.search(normalized):
            break
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = unicodedata.normalize(
            "NFKC", html.unescape(decoded)
        ).translate(_ZERO_WIDTH_CHARACTERS)
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", normalized)
    return re.sub(r"[^a-z0-9]+", "_", normalized.casefold()).strip("_")


def _allowance_matches_path(path: str, patterns: Sequence[str]) -> bool:
    return any(_source_rule_matches(path, pattern) for pattern in patterns)


def _structured_value_allowed(
    policy: Policy,
    path: str,
    detector: str,
    value: Any,
) -> bool:
    if value is None or value == "":
        return True
    if not isinstance(value, (str, int, float)):
        return False
    rendered = str(value).strip()
    candidates = {rendered, rendered.strip("\"'")}
    for allowance in policy.structured_allowances:
        if (
            detector in allowance.detectors
            and _allowance_matches_path(path, allowance.paths)
            and (
                any(
                    hashlib.sha256(candidate.encode("utf-8")).hexdigest()
                    in allowance.value_sha256s
                    for candidate in candidates
                )
                or any(
                    pattern.fullmatch(candidate)
                    for pattern in allowance.patterns
                    for candidate in candidates
                )
            )
        ):
            return True
    return False


def _structured_scalar_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _key_matches(key: str, aliases: set[str]) -> bool:
    return key in aliases


_STRUCTURED_KEY_ALIASES = {
    "private_keys": {
        "private_key",
        "private_key_pem",
        "ssh_private_key",
        "signing_private_key",
    },
    "api_tokens": {
        "api_key",
        "api_secret",
        "api_token",
        "client_api_key",
    },
    "access_tokens": {
        "access_token",
        "auth_token",
        "bearer_token",
        "oauth_token",
        "refresh_token",
    },
    "passwords": {"password", "passwd", "passphrase", "pwd"},
    "connection_strings": {
        "connection_string",
        "database_url",
        "db_connection",
        "db_url",
        "jdbc_url",
    },
    "webhook_secrets": {
        "signing_secret",
        "webhook_key",
        "webhook_secret",
        "webhook_token",
    },
    "email_address_values": {"email", "email_address", "mail"},
    "phone_number_values": {
        "cell",
        "cell_phone",
        "mobile",
        "mobile_phone",
        "phone",
        "phone_number",
        "phones",
        "telephone",
    },
    "postal_address_values": {
        "address",
        "address_line",
        "address_line_1",
        "address_line_2",
        "mailing_address",
        "postal_address",
        "street",
        "street_address",
    },
    "customer_notes": {
        "customer_note",
        "customer_notes",
        "submitted_note",
        "waitlist_note",
    },
    "customer_or_account_identifiers": {
        "account_id",
        "contact_id",
        "customer_id",
        "external_customer_id",
        "subscriber_id",
        "user_account_id",
    },
    "submitted_names": {
        "contact_name",
        "customer_name",
        "first_name",
        "full_name",
        "last_name",
        "submitted_name",
    },
    "privileged_communications": {
        "attorney_client",
        "privileged_communication",
        "privileged_message",
    },
    "legal_matter_records": {
        "case_number",
        "legal_matter",
        "legal_matter_id",
        "matter_number",
    },
    "contracts_not_intentionally_published_as_customer_facing_terms": {
        "contract",
        "contract_body",
        "executed_agreement",
        "private_contract",
    },
    "signatures": {
        "digital_signature",
        "signature",
        "signature_value",
        "signed_by",
    },
    "government_identifiers": {
        "driver_license",
        "government_id",
        "national_id",
        "passport",
        "passport_number",
        "social_security_number",
        "ssn",
        "tax_id",
    },
}
_CUSTOMER_CONTEXT_KEYS = {
    "applicant",
    "contact",
    "customer",
    "intake",
    "lead",
    "person",
    "signup",
    "submission",
    "subscriber",
    "waitlist",
    "waitlist_submission",
}
_SUBMISSION_METADATA_KEYS = {
    "created_at",
    "submitted_at",
    "submission_id",
    "timestamp",
}
_EMAIL_VALUE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)
_PHONE_VALUE = re.compile(
    r"^(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}$"
)
_PRIVATE_KEY_VALUE = re.compile(
    r"-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}", re.IGNORECASE
)
_CONNECTION_VALUE = re.compile(
    r"(?:AccountKey|SharedAccessKey|ClientSecret|Password)\s*=",
    re.IGNORECASE,
)
_WEBHOOK_VALUE = re.compile(
    r"https://hooks\.slack\.com/services/", re.IGNORECASE
)


def _structured_detector_match(
    detector: str,
    *,
    path: str,
    key: str,
    value: Any,
    ancestors: tuple[str, ...],
    object_keys: set[str],
) -> bool:
    text = _structured_scalar_text(value)
    aliases = _STRUCTURED_KEY_ALIASES.get(detector, set())
    key_match = any(_key_matches(candidate, aliases) for candidate in (key, *ancestors))
    customer_context = bool(
        set(ancestors) & _CUSTOMER_CONTEXT_KEYS
        or object_keys & _CUSTOMER_CONTEXT_KEYS
        or object_keys
        & {
            "email",
            "email_address",
            "phone",
            "phone_number",
            "customer_id",
            "account_id",
        }
    )
    if detector == "private_keys":
        return key_match or bool(text and _PRIVATE_KEY_VALUE.search(text))
    if detector in {
        "api_tokens",
        "access_tokens",
        "passwords",
        "connection_strings",
        "webhook_secrets",
    }:
        if key_match:
            return True
        if detector == "connection_strings":
            return bool(text and _CONNECTION_VALUE.search(text))
        if detector == "webhook_secrets":
            return bool(text and _WEBHOOK_VALUE.search(text))
        return False
    if detector == "real_secret_values_from_ci_secret_corpus":
        return bool(
            text
            and any(
                category == "secret" and pattern.search(text)
                for _, category, pattern in _SENSITIVE_PATTERNS
            )
        )
    if detector == "email_address_values":
        return bool(text and (_EMAIL_VALUE.fullmatch(text) or key_match))
    if detector == "phone_number_values":
        return bool(text and (key_match or _PHONE_VALUE.fullmatch(text)))
    if detector == "postal_address_values":
        return bool(text and key_match)
    if detector == "customer_notes":
        return bool(text and (key_match or (key in {"note", "notes"} and customer_context)))
    if detector == "customer_or_account_identifiers":
        return bool(text and key_match)
    if detector == "submitted_names":
        return bool(
            text
            and (
                key_match
                or (key == "name" and customer_context)
            )
        )
    if detector == "waitlist_submission_records":
        return bool(
            text
            and (
                "waitlist_submission" in ancestors
                or "waitlist_submission" in object_keys
                or (
                    object_keys & _SUBMISSION_METADATA_KEYS
                    and object_keys
                    & {
                        "email",
                        "email_address",
                        "phone",
                        "phone_number",
                        "customer_id",
                        "account_id",
                    }
                )
            )
        )
    if detector in {
        "privileged_communications",
        "legal_matter_records",
        "signatures",
        "government_identifiers",
    }:
        return bool(text and key_match)
    if detector == "contracts_not_intentionally_published_as_customer_facing_terms":
        public_terms_path = path.casefold().startswith(("terms/", "privacy/"))
        return bool(text and key_match and not public_terms_path)
    return False


def _decode_structured(path: str, data: bytes) -> list[Any]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise GuardError("structured data is not UTF-8") from error
    try:
        if path.casefold().endswith(".jsonl"):
            records = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                records.append(
                    json.loads(
                        line,
                        object_pairs_hook=_json_object,
                        parse_constant=_reject_json_constant,
                    )
                )
            return records
        return [
            json.loads(
                text,
                object_pairs_hook=_json_object,
                parse_constant=_reject_json_constant,
            )
        ]
    except (_DuplicateJsonKey, _InvalidJsonConstant, json.JSONDecodeError) as error:
        raise GuardError("structured data is invalid") from error


def _structured_findings(
    path: str,
    data: bytes,
    policy: Policy,
) -> Iterable[Finding]:
    if not policy.structured_detectors or not path.casefold().endswith((".json", ".jsonl")):
        return
    try:
        roots = _decode_structured(path, data)
    except GuardError:
        yield Finding("invalid_structured_data", path, "strict_json_parser")
        return

    detector_settings = {
        detector: group.allow_placeholders
        for group in policy.structured_detectors
        for detector in group.detect
    }
    visited = 0

    def walk(
        node: Any,
        *,
        depth: int,
        key: str,
        ancestors: tuple[str, ...],
        object_keys: set[str],
    ) -> Iterable[Finding]:
        nonlocal visited
        if depth > policy.structured_max_depth:
            yield Finding("structured_data_limit", path, "maximum_nesting_depth")
            return
        if isinstance(node, dict):
            normalized_keys = {
                _normalise_structured_key(item, policy.structured_key_decode_passes)
                for item in node
            }
            visited += len(node)
            if visited > policy.structured_max_items:
                yield Finding("structured_data_limit", path, "maximum_collection_items")
                return
            for raw_key, child in node.items():
                normalized_key = _normalise_structured_key(
                    raw_key, policy.structured_key_decode_passes
                )
                yield from walk(
                    child,
                    depth=depth + 1,
                    key=normalized_key,
                    ancestors=ancestors + ((key,) if key else ()),
                    object_keys=normalized_keys,
                )
            return
        if isinstance(node, list):
            visited += len(node)
            if visited > policy.structured_max_items:
                yield Finding("structured_data_limit", path, "maximum_collection_items")
                return
            for child in node:
                yield from walk(
                    child,
                    depth=depth + 1,
                    key=key,
                    ancestors=ancestors,
                    object_keys=object_keys,
                )
            return

        for detector in sorted(detector_settings):
            if not _structured_detector_match(
                detector,
                path=path,
                key=key,
                value=node,
                ancestors=ancestors,
                object_keys=object_keys,
            ):
                continue
            if (
                detector_settings[detector]
                and _structured_value_allowed(policy, path, detector, node)
            ):
                continue
            if (
                detector in _SECRET_STRUCTURED_DETECTORS
                and _structured_value_allowed(policy, path, detector, node)
            ):
                continue
            yield Finding("structured_data_violation", path, detector)

    for root in roots:
        yield from walk(
            root,
            depth=0,
            key="",
            ancestors=(),
            object_keys=set(),
        )


def _line_findings(
    path: str,
    text: str,
    policy: Policy,
    *,
    content_contract: str = "full",
) -> Iterable[Finding]:
    definitions_only = content_contract in {
        "self-reference-safe",
        "synthetic-test-input",
    }
    synthetic_input = content_contract == "synthetic-test-input"
    private_needles = [
        (index, needle)
        for index, repository in enumerate(policy.private_repositories)
        for needle in _repository_needles(repository)
    ]
    allowed_slugs = {
        _normalise_repository_slug(slug)
        for slug in policy.allowed_repository_slugs
    }
    repository_hosts = {host.casefold() for host in policy.repository_hosts}
    forbidden_hosts = {host.casefold() for host in policy.forbidden_hosts}
    forbidden_suffixes = tuple(
        suffix.casefold() for suffix in policy.forbidden_host_suffixes
    )

    for line_number, line in enumerate(text.splitlines(), start=1):
        normalized = _normalise_match_text(line)
        folded = normalized.casefold()
        normalised_line = _normalise_policy_text(line)
        if not definitions_only:
            for index, phrase in enumerate(policy.forbidden_phrases):
                if (
                    _normalise_policy_text(phrase).casefold()
                    in normalised_line.casefold()
                ):
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

            for index, pattern in enumerate(_OWNERSHIP_PATTERNS):
                match = pattern.search(normalized)
                if match:
                    yield Finding(
                        "ownership_percentage_claim",
                        path,
                        f"ownership_pattern[{index}]",
                        line_number,
                        match.start() + 1,
                    )

        if not synthetic_input:
            url_lines = [normalized]
            if (
                re.search(r"%[0-9A-Fa-f]{2}", normalized)
                and not _INVALID_PERCENT_ESCAPE.search(normalized)
            ):
                decoded_line = unquote(normalized)
                if decoded_line != normalized:
                    url_lines.append(decoded_line)
            seen_urls: set[str] = set()
            for match in (
                match
                for candidate_line in url_lines
                for match in _URL_PATTERN.finditer(candidate_line)
            ):
                raw = match.group(0).rstrip(".,);}>")
                canonical_candidate = (
                    unquote(raw)
                    if not _INVALID_PERCENT_ESCAPE.search(raw)
                    else raw
                )
                if canonical_candidate in seen_urls:
                    continue
                seen_urls.add(canonical_candidate)
                if _INVALID_PERCENT_ESCAPE.search(raw):
                    yield Finding(
                        "malformed_url",
                        path,
                        "invalid_percent_encoding",
                        line_number,
                        match.start() + 1,
                    )
                    continue
                try:
                    parsed = urlparse(raw)
                    hostname = (parsed.hostname or "").casefold()
                    _ = parsed.port
                except ValueError:
                    yield Finding(
                        "malformed_url",
                        path,
                        "url_parser",
                        line_number,
                        match.start() + 1,
                    )
                    continue
                if parsed.username is not None or parsed.password is not None:
                    yield Finding(
                        "sensitive_data_shape",
                        path,
                        "credential_url",
                        line_number,
                        match.start() + 1,
                    )
                if hostname in forbidden_hosts or any(
                    hostname.endswith(suffix) for suffix in forbidden_suffixes
                ):
                    yield Finding(
                        "forbidden_url_host",
                        path,
                        "url_policy.forbidden_host",
                        line_number,
                        match.start() + 1,
                    )

                reference = _repository_reference(raw)
                if reference is not None:
                    host, slug = reference
                    if host in repository_hosts:
                        normalised_slug = _normalise_repository_slug(slug)
                        if normalised_slug not in allowed_slugs:
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

                decoded_path = unquote(parsed.path)
                basename = PureWindowsPath(decoded_path.replace("/", "\\")).name
                if any(
                    _filename_matches(basename, pattern)
                    for pattern in policy.forbidden_filenames
                ) or any(
                    pattern.compiled.search(_normalise_match_text(basename))
                    for pattern in policy.forbidden_filename_patterns
                ):
                    yield Finding(
                        "forbidden_downloadable_document",
                        path,
                        "url_path_forbidden_filename",
                        line_number,
                        match.start() + 1,
                    )

        for detector, category, pattern in _SENSITIVE_PATTERNS:
            match = pattern.search(normalized)
            if match:
                structured_detector = {
                    "email_address": "email_address_values",
                    "phone_number": "phone_number_values",
                    "postal_address": "postal_address_values",
                }.get(detector, detector)
                if _structured_value_allowed(
                    policy, path, structured_detector, match.group(0)
                ):
                    continue
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
    policy_data: bytes | None = None,
    manifest: Iterable[str] | str | os.PathLike[str] | None = None,
    enforce_source_classification: bool = True,
) -> dict[str, Any]:
    """Scan tracked or explicitly manifested paths and return JSON-ready evidence."""

    try:
        resolved_root = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise GuardError("the scan root does not exist") from error
    if not resolved_root.is_dir():
        raise GuardError("the scan root is not a directory")

    if policy_data is None:
        policy, loaded_policy_path = _load_policy(resolved_root, policy_path)
        loaded_policy_data = (
            loaded_policy_path.read_bytes() if loaded_policy_path is not None else None
        )
    else:
        if policy_path is not None:
            raise GuardError("policy_path and policy_data are mutually exclusive")
        _, policy = _decode_policy_data(policy_data)
        loaded_policy_data = policy_data
        loaded_policy_path = resolved_root / ".git-policy-object"
    paths = _manifest_paths(resolved_root, manifest)
    source_manifest_classes, source_manifest_sha256 = _source_manifest_classes(
        resolved_root, manifest
    )
    git_context = _git_head_context(resolved_root)
    commit_sha = git_context[0] if git_context is not None else None
    git_entries = git_context[1] if git_context is not None else {}
    policy_document: dict[str, Any] = {}
    policy_sha256 = None
    if loaded_policy_data is not None:
        policy_document, _ = _decode_policy_data(loaded_policy_data)
        policy_sha256 = hashlib.sha256(loaded_policy_data).hexdigest()
    artifact_entries = (
        _artifact_manifest_entries(resolved_root, policy)
        if enforce_source_classification
        else {}
    )
    artifact_manifest_sha256 = None
    if enforce_source_classification and policy.source_manifest is not None:
        try:
            artifact_manifest_sha256 = hashlib.sha256(
                (resolved_root / policy.source_manifest).read_bytes()
            ).hexdigest()
        except OSError as error:
            raise GuardError("the artifact manifest could not be hashed") from error

    findings: list[Finding] = []
    binary_paths: list[str] = []
    text_paths: list[str] = []
    skipped_paths: list[str] = []
    unscanned_paths: list[str] = []
    coverage: dict[str, dict[str, Any]] = {}
    classifications: dict[str, tuple[str, str, str]] = {}
    collision_members = _path_collision_members(paths)
    for collision_path in sorted(
        collision_members, key=lambda path: (path.casefold(), path)
    ):
        findings.append(
            Finding(
                "path_collision",
                collision_path.replace("\\", "/"),
                "unicode_nfkc_casefold",
            )
        )

    for raw_path in paths:
        display_path = raw_path.replace("\\", "/")
        git_entry = git_entries.get(display_path)
        classification, content_contract, artifact_disposition = (
            _source_classification(display_path, policy, artifact_entries)
        )
        if (
            loaded_policy_path is not None
            and not policy.source_classification_rules
            and (resolved_root / Path(raw_path)).resolve(strict=False)
            == loaded_policy_path
        ):
            classification = "publication-control"
            content_contract = "self-reference-safe"
        classifications[display_path] = (
            classification,
            content_contract,
            artifact_disposition,
        )
        artifact_class = artifact_entries.get(display_path)
        if artifact_disposition == "must-be-absent" and artifact_class is not None:
            findings.append(
                Finding(
                    "nondeploy_path_in_artifact_manifest",
                    display_path,
                    "source_classification",
                )
            )
        if artifact_disposition == "publication-control" and artifact_class != (
            "publication-control"
        ):
            findings.append(
                Finding(
                    "publication_control_manifest_mismatch",
                    display_path,
                    "source_classification",
                )
            )

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
            if pattern.compiled.search(
                _normalise_match_text(Path(display_path).name)
            ):
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
            coverage[display_path] = {
                "category": classification,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": "unknown",
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "deny",
                "sha256": None,
                "size": None,
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
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
                coverage[display_path] = {
                    "category": classification,
                    "git_blob_id": git_entry.object_id if git_entry else None,
                    "git_mode": git_entry.mode if git_entry else None,
                    "media_type": "symlink",
                    "origin": (
                        "tracked-source" if manifest is None else "selected-source"
                    ),
                    "path": display_path,
                    "scanner_status": "deny",
                    "sha256": None,
                    "size": None,
                    "source_manifest_class": source_manifest_classes.get(display_path),
                }
                continue
            resolved_candidate = candidate.resolve(strict=False)
            if os.path.commonpath(
                [os.fspath(resolved_root), os.fspath(resolved_candidate)]
            ) != os.fspath(resolved_root):
                findings.append(
                    Finding("path_escape", display_path, "resolved_path")
                )
                unscanned_paths.append(display_path)
                coverage[display_path] = {
                    "category": classification,
                    "git_blob_id": git_entry.object_id if git_entry else None,
                    "git_mode": git_entry.mode if git_entry else None,
                    "media_type": "unknown",
                    "origin": (
                        "tracked-source" if manifest is None else "selected-source"
                    ),
                    "path": display_path,
                    "scanner_status": "deny",
                    "sha256": None,
                    "size": None,
                    "source_manifest_class": source_manifest_classes.get(display_path),
                }
                continue
        except (OSError, ValueError, GuardError):
            findings.append(Finding("unreadable_path", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            coverage[display_path] = {
                "category": classification,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": "unknown",
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "deny",
                "sha256": None,
                "size": None,
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
            continue

        try:
            mode = candidate.lstat().st_mode
        except FileNotFoundError:
            findings.append(Finding("missing_path", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            coverage[display_path] = {
                "category": classification,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": "missing",
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "deny",
                "sha256": None,
                "size": None,
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
            continue
        except OSError:
            findings.append(Finding("unreadable_path", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            coverage[display_path] = {
                "category": classification,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": "unknown",
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "deny",
                "sha256": None,
                "size": None,
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
            continue

        if not stat.S_ISREG(mode):
            findings.append(Finding("unsupported_file_type", display_path, "path_metadata"))
            unscanned_paths.append(display_path)
            coverage[display_path] = {
                "category": classification,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": "special",
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "deny",
                "sha256": None,
                "size": None,
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
            continue

        try:
            with candidate.open("rb") as source:
                data = source.read(policy.max_file_bytes + 1)
        except OSError:
            findings.append(Finding("unreadable_path", display_path, "file_read"))
            unscanned_paths.append(display_path)
            coverage[display_path] = {
                "category": classification,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": "unknown",
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "deny",
                "sha256": None,
                "size": None,
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
            continue

        if len(data) > policy.max_file_bytes:
            findings.append(Finding("file_too_large", display_path, "size_limit"))
            unscanned_paths.append(display_path)
            coverage[display_path] = {
                "category": classification,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": _media_type(display_path, False),
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "deny",
                "sha256": None,
                "size": len(data),
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
            continue
        if git_context is not None:
            if git_entry is None:
                findings.append(
                    Finding("source_path_not_in_commit", display_path, "git_tree")
                )
            else:
                try:
                    committed_data = _git_blob(
                        resolved_root, git_entry, policy.max_file_bytes
                    )
                except GuardError:
                    findings.append(
                        Finding("source_git_object_invalid", display_path, "git_object")
                    )
                else:
                    if (
                        committed_data != data
                        or _git_worktree_mode(mode) != git_entry.mode
                    ):
                        findings.append(
                            Finding(
                                "worktree_diverges_from_commit",
                                display_path,
                                "git_object",
                            )
                        )
        if _is_binary(data):
            binary_paths.append(display_path)
            findings.extend(
                _line_findings(
                    display_path,
                    data.decode("utf-8", errors="replace"),
                    policy,
                    content_contract=content_contract,
                )
            )
            findings.extend(_structured_findings(display_path, data, policy))
            coverage[display_path] = {
                "category": classification,
                "content_contract": content_contract,
                "git_blob_id": git_entry.object_id if git_entry else None,
                "git_mode": git_entry.mode if git_entry else None,
                "media_type": _media_type(display_path, True),
                "origin": (
                    "tracked-source" if manifest is None else "selected-source"
                ),
                "path": display_path,
                "scanner_status": "pass",
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "source_manifest_class": source_manifest_classes.get(display_path),
            }
            continue

        text_paths.append(display_path)
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            findings.append(Finding("invalid_utf8", display_path, "utf8_decoder"))
            text = data.decode("utf-8-sig", errors="replace")
        findings.extend(
            _line_findings(
                display_path,
                text,
                policy,
                content_contract=content_contract,
            )
        )
        findings.extend(_structured_findings(display_path, data, policy))
        coverage[display_path] = {
            "category": classification,
            "content_contract": content_contract,
            "git_blob_id": git_entry.object_id if git_entry else None,
            "git_mode": git_entry.mode if git_entry else None,
            "media_type": _media_type(display_path, False),
            "origin": "tracked-source" if manifest is None else "selected-source",
            "path": display_path,
            "scanner_status": "pass",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "source_manifest_class": source_manifest_classes.get(display_path),
        }

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
    sensitive_paths = {
        finding.path
        for finding in ordered_findings
        if finding.rule
        in {
            "forbidden_filename",
            "path_collision",
            "path_escape",
        }
    }

    def evidence_path(path: str) -> str:
        if path not in sensitive_paths:
            return path
        return "redacted-path:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]

    denied_paths = {finding.path for finding in ordered_findings}
    coverage_records = []
    for path in sorted(coverage, key=lambda value: (value.casefold(), value)):
        record = dict(coverage[path])
        _, _, artifact_disposition = classifications[path]
        record["artifact_disposition"] = artifact_disposition
        record["artifact_manifest_class"] = artifact_entries.get(path)
        record["path"] = evidence_path(path)
        if path in denied_paths:
            record["scanner_status"] = "deny"
        coverage_records.append(record)

    return {
        "artifact_boundary": ARTIFACT_BOUNDARY,
        "binary_paths": [
            evidence_path(path)
            for path in sorted(
                set(binary_paths), key=lambda value: (value.casefold(), value)
            )
        ],
        "commit_sha": commit_sha,
        "coverage_records": coverage_records,
        "finding_count": len(ordered_findings),
        "findings": [
            Finding(
                finding.rule,
                evidence_path(finding.path),
                finding.detector,
                finding.line,
                finding.column,
            ).as_dict()
            for finding in ordered_findings
        ],
        "policy_loaded": loaded_policy_path is not None,
        "generated_artifact_count": 0,
        "manifest_sha256": artifact_manifest_sha256,
        "payload_sha256": None,
        "policy_id": policy_document.get("policy_id"),
        "policy_sha256": policy_sha256,
        "policy_version": policy_document.get("policy_version"),
        "repository": policy_document.get("repository"),
        "result": "deny" if ordered_findings else "pass",
        "rule_results": [
            {
                "finding_count": len(ordered_findings),
                "gate": "source",
                "result": "deny" if ordered_findings else "pass",
            }
        ],
        "scan_completed_at": None,
        "scan_counts": {
            "classified_paths": len(classifications),
            "findings": len(ordered_findings),
            "scanned_paths": len(set(binary_paths + text_paths)),
            "selected_paths": len(paths),
            "unscanned_paths": len(set(unscanned_paths)),
        },
        "scanned_path_count": len(set(binary_paths + text_paths)),
        "schema_version": 1,
        "scan_started_at": None,
        "scanner_name": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "skipped_paths": [
            evidence_path(path)
            for path in sorted(
                set(skipped_paths), key=lambda value: (value.casefold(), value)
            )
        ],
        "source_file_count": len(paths),
        "source_manifest_sha256": source_manifest_sha256,
        "text_paths": [
            evidence_path(path)
            for path in sorted(
                set(text_paths), key=lambda value: (value.casefold(), value)
            )
        ],
        "unscanned_paths": [
            evidence_path(path)
            for path in sorted(
                set(unscanned_paths), key=lambda value: (value.casefold(), value)
            )
        ],
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
