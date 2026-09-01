#!/usr/bin/env python3
"""Validate private-safe publication evidence before any upload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence

if __package__:
    from . import publication_artifact
    from . import publication_guard
else:
    import publication_artifact
    import publication_guard


ARTIFACT_BOUNDARY = publication_artifact.ARTIFACT_BOUNDARY
SOURCE_MANIFEST_FILENAME = "PUBLICATION-SOURCE-MANIFEST.json"
SHA_PATTERN = re.compile(r"[0-9a-f]{40,64}")
RAPP_FRAME_ONLY_KEYS = {
    "frame_hash",
    "payload",
    "payload_hash",
    "prev_wave",
    "sig",
    "stream_id",
}
PRIVATE_VALUE_KEYS = {
    "body",
    "candidate_source",
    "content",
    "detected_text",
    "fixture_body",
    "matched_customer_value",
    "matched_legal_value",
    "matched_secret_value",
    "password",
    "private_content_excerpt",
    "private_link",
    "private_repository_slug",
    "private_repository_url",
    "secret",
    "secret_value",
    "source_bytes",
    "source_content",
    "token",
}


class EvidenceError(Exception):
    """A safe, stable validation failure code."""


def _fail(code: str) -> None:
    raise EvidenceError(code)


def _load_json(path: Path, code: str) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(code)
    if not isinstance(document, Mapping):
        _fail(code)
    return document


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        _fail("bound_file_unreadable")
    return digest.hexdigest()


def _git_commit(source: Path) -> str:
    result = subprocess.run(
        ["git", "-C", os.fspath(source), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip()
    if result.returncode or not SHA_PATTERN.fullmatch(commit):
        _fail("commit_unavailable")
    return commit


def _inside(candidate: Path, directory: Path) -> bool:
    try:
        return os.path.commonpath((os.fspath(candidate), os.fspath(directory))) == os.fspath(
            directory
        )
    except ValueError:
        return False


def _assert_private_safe(value: Any) -> None:
    if isinstance(value, Mapping):
        keys = {str(key).casefold().replace("-", "_") for key in value}
        if RAPP_FRAME_ONLY_KEYS & keys:
            _fail("rapp_frame_material")
        if PRIVATE_VALUE_KEYS & keys:
            _fail("private_material_field")
        for key in sorted(value, key=lambda item: str(item)):
            _assert_private_safe(value[key])
    elif isinstance(value, list):
        for item in value:
            _assert_private_safe(item)

    rendered = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if '"spec":"rapp/1"' in rendered.casefold():
        _fail("rapp_frame_material")


def load_source_manifest(path: Path) -> Mapping[str, Any]:
    document = _load_json(path, "source_manifest_invalid")
    if (
        document.get("document_type") != "publication-source-manifest"
        or document.get("schema_version") != 1
        or document.get("default_disposition") != "deny"
        or document.get("artifact_boundary") != ARTIFACT_BOUNDARY
    ):
        _fail("source_manifest_invalid")
    files = document.get("files")
    classes = document.get("source_classes")
    if (
        not isinstance(files, list)
        or not files
        or not all(isinstance(path, str) and path for path in files)
        or files != sorted(set(files), key=lambda path: (path.casefold(), path))
        or not isinstance(classes, list)
    ):
        _fail("source_manifest_invalid")
    by_class: dict[str, list[str]] = {}
    classified_paths: list[str] = []
    for entry in classes:
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"class", "paths", "scanner"}
            or not isinstance(entry.get("class"), str)
            or not isinstance(entry.get("scanner"), str)
            or not isinstance(entry.get("paths"), list)
            or not all(isinstance(path, str) and path for path in entry["paths"])
        ):
            _fail("source_manifest_invalid")
        paths = entry["paths"]
        if paths != sorted(set(paths), key=lambda path: (path.casefold(), path)):
            _fail("source_manifest_invalid")
        if entry["class"] in by_class:
            _fail("source_manifest_invalid")
        by_class[entry["class"]] = paths
        classified_paths.extend(paths)
    if (
        not by_class.get("publication-candidate")
        or sorted(classified_paths, key=lambda path: (path.casefold(), path)) != files
        or len(classified_paths) != len(set(classified_paths))
    ):
        _fail("source_manifest_candidate_mismatch")
    return document


def validate_source_evidence(
    *,
    source: Path,
    manifest_path: Path,
    evidence_path: Path,
) -> dict[str, int]:
    source = source.resolve(strict=True)
    evidence_path = evidence_path.resolve(strict=True)
    if _inside(evidence_path, source):
        _fail("source_evidence_inside_checkout")
    manifest = load_source_manifest(manifest_path.resolve(strict=True))
    evidence = _load_json(evidence_path, "source_evidence_invalid")
    _assert_private_safe(evidence)

    files = manifest["files"]
    expected_keys = {
        "artifact_boundary",
        "binary_paths",
        "coverage_records",
        "finding_count",
        "findings",
        "policy_loaded",
        "result",
        "scan_completed_at",
        "scan_counts",
        "scan_started_at",
        "scanned_path_count",
        "scanner_name",
        "scanner_version",
        "schema_version",
        "skipped_paths",
        "source_file_count",
        "text_paths",
        "unscanned_paths",
    }
    if set(evidence) != expected_keys:
        _fail("source_evidence_schema")
    if (
        evidence.get("artifact_boundary") != ARTIFACT_BOUNDARY
        or evidence.get("schema_version") != 1
        or evidence.get("result") != "pass"
        or evidence.get("finding_count") != 0
        or evidence.get("findings") != []
        or evidence.get("unscanned_paths") != []
        or evidence.get("skipped_paths") != []
        or evidence.get("policy_loaded") is not True
        or evidence.get("scan_started_at") is not None
        or evidence.get("scan_completed_at") is not None
        or evidence.get("scanner_name") != publication_guard.SCANNER_NAME
        or evidence.get("scanner_version") != publication_guard.SCANNER_VERSION
        or evidence.get("source_file_count") != len(files)
    ):
        _fail("source_evidence_not_pass")
    scanned = evidence.get("text_paths")
    binary = evidence.get("binary_paths")
    if not isinstance(scanned, list) or not isinstance(binary, list):
        _fail("source_evidence_schema")
    if sorted(scanned + binary, key=lambda path: (path.casefold(), path)) != files:
        _fail("source_evidence_inventory")
    if evidence.get("scanned_path_count") != len(files):
        _fail("source_evidence_count")

    counts = evidence.get("scan_counts")
    if counts != {
        "classified_paths": len(files),
        "findings": 0,
        "scanned_paths": len(files),
        "selected_paths": len(files),
        "unscanned_paths": 0,
    }:
        _fail("source_evidence_count")

    records = evidence.get("coverage_records")
    record_keys = {
        "artifact_disposition",
        "artifact_manifest_class",
        "category",
        "content_contract",
        "media_type",
        "origin",
        "path",
        "scanner_status",
        "sha256",
        "size",
    }
    if not isinstance(records, list) or len(records) != len(files):
        _fail("source_evidence_coverage")
    record_paths: list[str] = []
    for record in records:
        if (
            not isinstance(record, Mapping)
            or set(record) != record_keys
            or not isinstance(record.get("path"), str)
            or record.get("origin") != "selected-source"
            or record.get("scanner_status") != "pass"
            or not isinstance(record.get("category"), str)
            or not isinstance(record.get("content_contract"), str)
            or not isinstance(record.get("media_type"), str)
            or not isinstance(record.get("artifact_disposition"), str)
            or (
                record.get("artifact_manifest_class") is not None
                and not isinstance(record.get("artifact_manifest_class"), str)
            )
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or not isinstance(record.get("size"), int)
            or record["size"] < 0
        ):
            _fail("source_evidence_coverage")
        record_paths.append(record["path"])
    if record_paths != files:
        _fail("source_evidence_coverage")
    return {"source_file_count": len(files)}


def _policy_binding(policy_path: Path) -> tuple[str, str, str, str]:
    policy = _load_json(policy_path, "policy_invalid")
    policy_id = policy.get("policy_id")
    policy_version = policy.get("policy_version")
    repository = policy.get("repository")
    if not all(isinstance(item, str) and item for item in (policy_id, policy_version, repository)):
        _fail("policy_invalid")
    return policy_id, policy_version, repository, _sha256(policy_path)


def validate_artifact_evidence(
    *,
    source: Path,
    artifact: Path,
    evidence_path: Path,
    expected_commit: str,
    manifest_name: str = publication_artifact.MANIFEST_FILENAME,
    policy_name: str = publication_artifact.POLICY_FILENAME,
) -> dict[str, int | str]:
    source = source.resolve(strict=True)
    artifact = artifact.resolve(strict=True)
    evidence_path = evidence_path.resolve(strict=True)
    if _inside(artifact, source):
        _fail("artifact_inside_checkout")
    if _inside(evidence_path, artifact):
        _fail("evidence_inside_artifact")
    if not SHA_PATTERN.fullmatch(expected_commit):
        _fail("expected_commit_invalid")

    manifest_path = (source / manifest_name).resolve(strict=True)
    policy_path = (source / policy_name).resolve(strict=True)
    manifest = publication_artifact.load_manifest(manifest_path)
    policy_id, policy_version, repository, policy_sha256 = _policy_binding(policy_path)
    current_commit = _git_commit(source)
    if expected_commit != current_commit:
        _fail("commit_binding_mismatch")

    evidence = _load_json(evidence_path, "artifact_evidence_invalid")
    _assert_private_safe(evidence)
    if evidence.get("result") != "pass" or evidence.get("findings") != []:
        _fail("artifact_evidence_not_pass")
    if (
        evidence.get("artifact_boundary") != ARTIFACT_BOUNDARY
        or evidence.get("schema_version") != 1
        or evidence.get("commit_sha") != expected_commit
        or evidence.get("manifest_sha256") != manifest.sha256
        or evidence.get("policy_sha256") != policy_sha256
        or evidence.get("policy_id") != policy_id
        or evidence.get("policy_version") != policy_version
        or evidence.get("repository") != repository
        or evidence.get("repository") != manifest.repository
    ):
        _fail("artifact_evidence_binding")

    inventory = evidence.get("inventory_paths")
    coverage = evidence.get("coverage_records")
    links = evidence.get("links")
    counts = evidence.get("scan_counts")
    rules = evidence.get("rule_results")
    expected_paths = list(manifest.paths)
    if inventory != expected_paths or not inventory:
        _fail("artifact_evidence_inventory")
    if (
        evidence.get("generated_artifact_count") != len(expected_paths)
        or evidence.get("source_file_count") != len(expected_paths)
        or not isinstance(coverage, list)
        or len(coverage) != len(expected_paths)
    ):
        _fail("artifact_evidence_count")
    if not isinstance(counts, Mapping) or not isinstance(links, list):
        _fail("artifact_evidence_schema")
    if (
        counts.get("declared_paths") != len(expected_paths)
        or counts.get("scanned_paths") != len(expected_paths)
        or counts.get("findings") != 0
        or counts.get("links") != len(links)
    ):
        _fail("artifact_evidence_coverage")
    expected_gates = {"eligibility", "inventory", "links", "parse", "policy"}
    if (
        not isinstance(rules, list)
        or {item.get("gate") for item in rules if isinstance(item, Mapping)}
        != expected_gates
        or any(
            not isinstance(item, Mapping)
            or item.get("result") != "pass"
            or item.get("finding_count") != 0
            for item in rules
        )
    ):
        _fail("artifact_evidence_rules")

    entries = manifest.entry_by_path
    records: dict[str, Mapping[str, Any]] = {}
    for record in coverage:
        if not isinstance(record, Mapping) or not isinstance(record.get("path"), str):
            _fail("artifact_evidence_coverage")
        records[record["path"]] = record
    if sorted(records, key=lambda path: (path.casefold(), path)) != expected_paths:
        _fail("artifact_evidence_coverage")
    for path in expected_paths:
        record = records[path]
        candidate = artifact / path
        try:
            metadata = candidate.lstat()
        except OSError:
            _fail("artifact_file_unreadable")
        if not candidate.is_file() or candidate.is_symlink():
            _fail("artifact_file_invalid")
        if (
            record.get("scanner_status") != "pass"
            or record.get("origin") != "generated-artifact"
            or record.get("class") != entries[path].publication_class
            or not isinstance(record.get("category"), list)
            or not record["category"]
            or record.get("sha256") != _sha256(candidate)
            or record.get("size") != metadata.st_size
        ):
            _fail("artifact_evidence_file_binding")
    for link in links:
        if (
            not isinstance(link, Mapping)
            or link.get("source_path") not in records
            or not isinstance(link.get("target_fingerprint"), str)
            or not link["target_fingerprint"]
            or not isinstance(link.get("classification"), str)
            or not isinstance(link.get("context"), str)
        ):
            _fail("artifact_evidence_link_coverage")

    try:
        recomputed = publication_artifact.scan_artifact(
            source,
            artifact,
            manifest_path=manifest_name,
            policy_path=policy_name,
        )
    except publication_artifact.ArtifactError:
        _fail("artifact_rescan_failed")
    if evidence != recomputed:
        _fail("artifact_evidence_stale")
    return {
        "artifact_count": len(expected_paths),
        "commit_sha": expected_commit,
        "link_count": len(links),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("source")
    source.add_argument("--source", default=".")
    source.add_argument("--manifest", default=SOURCE_MANIFEST_FILENAME)
    source.add_argument("--evidence", required=True)

    artifact = subparsers.add_parser("artifact")
    artifact.add_argument("--source", default=".")
    artifact.add_argument("--manifest", default=publication_artifact.MANIFEST_FILENAME)
    artifact.add_argument("--policy", default=publication_artifact.POLICY_FILENAME)
    artifact.add_argument("--artifact", required=True)
    artifact.add_argument("--evidence", required=True)
    artifact.add_argument("--expected-commit", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "source":
            result = validate_source_evidence(
                source=Path(args.source),
                manifest_path=Path(args.manifest),
                evidence_path=Path(args.evidence),
            )
            print(
                "publication source evidence validated: "
                f"source_file_count={result['source_file_count']}"
            )
        else:
            result = validate_artifact_evidence(
                source=Path(args.source),
                artifact=Path(args.artifact),
                evidence_path=Path(args.evidence),
                expected_commit=args.expected_commit,
                manifest_name=args.manifest,
                policy_name=args.policy,
            )
            print(
                "publication artifact evidence validated: "
                f"artifact_count={result['artifact_count']} "
                f"link_count={result['link_count']} "
                f"commit={result['commit_sha']}"
            )
    except (EvidenceError, OSError, RuntimeError, ValueError):
        sys.stderr.write("publication evidence validation failed\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
