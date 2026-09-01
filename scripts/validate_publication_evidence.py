#!/usr/bin/env python3
"""Validate private-safe publication evidence before any upload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
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
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=publication_guard._json_object,
            parse_constant=publication_guard._reject_json_constant,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        publication_guard._DuplicateJsonKey,
        publication_guard._InvalidJsonConstant,
    ):
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


def _source_manifest_from_data(data: bytes) -> Mapping[str, Any]:
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=publication_guard._json_object,
            parse_constant=publication_guard._reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        publication_guard._DuplicateJsonKey,
        publication_guard._InvalidJsonConstant,
    ):
        _fail("source_manifest_invalid")
    if not isinstance(document, Mapping):
        _fail("source_manifest_invalid")
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


def load_source_manifest(path: Path) -> Mapping[str, Any]:
    try:
        data = path.read_bytes()
    except OSError:
        _fail("source_manifest_invalid")
    return _source_manifest_from_data(data)


def _git_contract(
    source: Path,
    relative: str,
    entries: Mapping[str, publication_artifact.GitTreeEntry],
    *,
    maximum: int = publication_guard.DEFAULT_MAX_FILE_BYTES,
) -> tuple[publication_artifact.GitTreeEntry, bytes]:
    entry = entries.get(relative)
    if entry is None:
        _fail("git_contract_missing")
    try:
        data = publication_artifact._git_blob_data(source, entry, maximum)
    except publication_artifact.ArtifactError:
        _fail("git_contract_invalid")
    return entry, data


def validate_source_evidence(
    *,
    source: Path,
    manifest_path: Path,
    evidence_path: Path,
    expected_commit: str,
) -> dict[str, int | str]:
    source = source.resolve(strict=True)
    evidence_path = evidence_path.resolve(strict=True)
    if _inside(evidence_path, source):
        _fail("source_evidence_inside_checkout")
    if not SHA_PATTERN.fullmatch(expected_commit):
        _fail("expected_commit_invalid")
    try:
        candidate_manifest = manifest_path
        if not candidate_manifest.is_absolute():
            candidate_manifest = source / candidate_manifest
        candidate_manifest = Path(os.path.abspath(candidate_manifest))
        manifest_relative = candidate_manifest.relative_to(source).as_posix()
    except ValueError:
        _fail("source_manifest_invalid")
    try:
        git_entries, current_commit = publication_artifact._git_context(source)
    except publication_artifact.ArtifactError:
        _fail("commit_unavailable")
    if current_commit != expected_commit:
        _fail("commit_binding_mismatch")
    _, manifest_data = _git_contract(source, manifest_relative, git_entries)
    manifest = _source_manifest_from_data(manifest_data)
    _, policy_data = _git_contract(
        source, publication_guard.POLICY_FILENAME, git_entries
    )
    try:
        policy_document, policy = publication_guard._decode_policy_data(policy_data)
    except publication_guard.GuardError:
        _fail("policy_invalid")
    artifact_manifest_name = policy.source_manifest
    if not artifact_manifest_name:
        _fail("policy_invalid")
    _, artifact_manifest_data = _git_contract(
        source, artifact_manifest_name, git_entries
    )
    try:
        artifact_manifest = publication_artifact._manifest_from_data(
            artifact_manifest_data
        )
    except publication_artifact.ArtifactError:
        _fail("source_manifest_invalid")
    artifact_entries = {
        entry.path: entry.publication_class for entry in artifact_manifest.entries
    }
    evidence = _load_json(evidence_path, "source_evidence_invalid")
    _assert_private_safe(evidence)

    files = manifest["files"]
    expected_keys = {
        "artifact_boundary",
        "binary_paths",
        "commit_sha",
        "coverage_records",
        "finding_count",
        "findings",
        "generated_artifact_count",
        "manifest_sha256",
        "payload_sha256",
        "policy_loaded",
        "policy_id",
        "policy_sha256",
        "policy_version",
        "repository",
        "result",
        "rule_results",
        "scan_completed_at",
        "scan_counts",
        "scan_started_at",
        "scanned_path_count",
        "scanner_name",
        "scanner_version",
        "schema_version",
        "skipped_paths",
        "source_file_count",
        "source_manifest_sha256",
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
        or evidence.get("generated_artifact_count") != 0
        or evidence.get("manifest_sha256")
        != hashlib.sha256(artifact_manifest_data).hexdigest()
        or evidence.get("payload_sha256") is not None
        or evidence.get("commit_sha") != expected_commit
        or evidence.get("policy_id") != policy_document.get("policy_id")
        or evidence.get("policy_version") != policy_document.get("policy_version")
        or evidence.get("repository") != policy_document.get("repository")
        or evidence.get("policy_sha256") != hashlib.sha256(policy_data).hexdigest()
        or evidence.get("source_manifest_sha256")
        != hashlib.sha256(manifest_data).hexdigest()
        or manifest.get("repository") != policy_document.get("repository")
        or evidence.get("rule_results")
        != [{"finding_count": 0, "gate": "source", "result": "pass"}]
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
        "git_blob_id",
        "git_mode",
        "media_type",
        "origin",
        "path",
        "scanner_status",
        "sha256",
        "size",
        "source_manifest_class",
    }
    if not isinstance(records, list) or len(records) != len(files):
        _fail("source_evidence_coverage")
    record_paths: list[str] = []
    manifest_classes = {
        path: entry["class"]
        for entry in manifest["source_classes"]
        for path in entry["paths"]
    }
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
            or not isinstance(record.get("git_blob_id"), str)
            or SHA_PATTERN.fullmatch(record["git_blob_id"]) is None
            or record.get("git_mode") not in {"100644", "100755"}
            or record.get("source_manifest_class")
            != manifest_classes.get(record.get("path"))
        ):
            _fail("source_evidence_coverage")
        path = record["path"]
        git_entry = git_entries.get(path)
        if (
            git_entry is None
            or record["git_blob_id"] != git_entry.object_id
            or record["git_mode"] != git_entry.mode
        ):
            _fail("source_evidence_git_binding")
        try:
            blob = publication_artifact._git_blob_data(
                source, git_entry, publication_guard.DEFAULT_MAX_FILE_BYTES
            )
        except publication_artifact.ArtifactError:
            _fail("source_evidence_git_binding")
        expected_classification, expected_contract, expected_disposition = (
            publication_guard._source_classification(
                path, policy, artifact_entries
            )
        )
        if (
            record["sha256"] != hashlib.sha256(blob).hexdigest()
            or record["size"] != len(blob)
            or record["category"] != expected_classification
            or record["content_contract"] != expected_contract
            or record["artifact_disposition"] != expected_disposition
            or record["artifact_manifest_class"] != artifact_entries.get(path)
        ):
            _fail("source_evidence_git_binding")
        record_paths.append(record["path"])
    if record_paths != files:
        _fail("source_evidence_coverage")
    return {"commit_sha": expected_commit, "source_file_count": len(files)}


def _validate_pages_payload(
    *,
    payload: Path,
    evidence: Mapping[str, Any],
    records: Mapping[str, Mapping[str, Any]],
    expected_paths: list[str],
) -> None:
    if evidence.get("payload_member_count") != len(expected_paths):
        _fail("payload_count_mismatch")
    observed: list[str] = []
    try:
        with tarfile.open(payload, mode="r:") as archive:
            for member in archive.getmembers():
                name = member.name
                if (
                    not member.isfile()
                    or not name
                    or name.startswith("/")
                    or "\\" in name
                    or ".." in Path(name).parts
                    or name in observed
                    or name not in records
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                ):
                    _fail("payload_member_invalid")
                record = records[name]
                expected_mode = int(str(record.get("git_mode")), 8) & 0o777
                stream = archive.extractfile(member)
                if stream is None:
                    _fail("payload_member_invalid")
                data = stream.read()
                if (
                    member.mode != expected_mode
                    or member.size != record.get("size")
                    or hashlib.sha256(data).hexdigest() != record.get("sha256")
                ):
                    _fail("payload_member_binding")
                observed.append(name)
    except (OSError, tarfile.TarError, ValueError):
        _fail("payload_invalid")
    if observed != expected_paths:
        _fail("payload_inventory_mismatch")


def validate_artifact_evidence(
    *,
    source: Path,
    artifact: Path | None,
    payload: Path,
    evidence_path: Path,
    expected_commit: str,
    manifest_name: str = publication_artifact.MANIFEST_FILENAME,
    policy_name: str = publication_artifact.POLICY_FILENAME,
) -> dict[str, int | str]:
    source = source.resolve(strict=True)
    artifact = artifact.resolve(strict=True) if artifact is not None else None
    payload = payload.resolve(strict=True)
    evidence_path = evidence_path.resolve(strict=True)
    if artifact is not None and _inside(artifact, source):
        _fail("artifact_inside_checkout")
    if artifact is not None and _inside(evidence_path, artifact):
        _fail("evidence_inside_artifact")
    if _inside(payload, source) or payload.name != "artifact.tar":
        _fail("payload_location_invalid")
    if not SHA_PATTERN.fullmatch(expected_commit):
        _fail("expected_commit_invalid")

    try:
        git_entries, current_commit = publication_artifact._git_context(source)
    except publication_artifact.ArtifactError:
        _fail("commit_unavailable")
    if expected_commit != current_commit:
        _fail("commit_binding_mismatch")
    _, manifest_data = _git_contract(source, manifest_name, git_entries)
    _, policy_data = _git_contract(source, policy_name, git_entries)
    _, source_manifest_data = _git_contract(
        source, SOURCE_MANIFEST_FILENAME, git_entries
    )
    try:
        manifest = publication_artifact._manifest_from_data(manifest_data)
        policy_document, _ = publication_guard._decode_policy_data(policy_data)
    except (publication_artifact.ArtifactError, publication_guard.GuardError):
        _fail("policy_invalid")
    policy_id = policy_document.get("policy_id")
    policy_version = policy_document.get("policy_version")
    repository = policy_document.get("repository")
    policy_sha256 = hashlib.sha256(policy_data).hexdigest()
    if not all(
        isinstance(item, str) and item
        for item in (policy_id, policy_version, repository)
    ):
        _fail("policy_invalid")

    evidence = _load_json(evidence_path, "artifact_evidence_invalid")
    _assert_private_safe(evidence)
    if evidence.get("result") != "pass" or evidence.get("findings") != []:
        _fail("artifact_evidence_not_pass")
    if (
        evidence.get("artifact_boundary") != ARTIFACT_BOUNDARY
        or evidence.get("schema_version") != 1
        or evidence.get("commit_sha") != expected_commit
        or evidence.get("manifest_sha256") != hashlib.sha256(manifest_data).hexdigest()
        or evidence.get("policy_sha256") != policy_sha256
        or evidence.get("policy_id") != policy_id
        or evidence.get("policy_version") != policy_version
        or evidence.get("repository") != repository
        or evidence.get("repository") != manifest.repository
        or evidence.get("source_manifest_sha256")
        != hashlib.sha256(source_manifest_data).hexdigest()
        or evidence.get("payload_format") != "github-pages-artifact.tar"
        or evidence.get("payload_sha256") != _sha256(payload)
        or evidence.get("payload_size") != payload.stat().st_size
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
        git_entry = git_entries.get(path)
        if git_entry is None:
            _fail("artifact_evidence_git_binding")
        try:
            git_data = publication_artifact._git_blob_data(
                source, git_entry, manifest.max_file_bytes
            )
        except publication_artifact.ArtifactError:
            _fail("artifact_evidence_git_binding")
        if (
            record.get("scanner_status") != "pass"
            or record.get("origin") != "generated-artifact"
            or record.get("class") != entries[path].publication_class
            or not isinstance(record.get("category"), list)
            or not record["category"]
            or record.get("git_blob_id") != git_entry.object_id
            or record.get("git_mode") != git_entry.mode
            or record.get("sha256") != hashlib.sha256(git_data).hexdigest()
            or record.get("size") != len(git_data)
        ):
            _fail("artifact_evidence_file_binding")
        if artifact is not None:
            candidate = artifact / path
            try:
                metadata = candidate.lstat()
            except OSError:
                _fail("artifact_file_unreadable")
            if not candidate.is_file() or candidate.is_symlink():
                _fail("artifact_file_invalid")
            actual_mode = "100755" if metadata.st_mode & 0o111 else "100644"
            if (
                record.get("sha256") != _sha256(candidate)
                or record.get("size") != metadata.st_size
                or record.get("git_mode") != actual_mode
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

    _validate_pages_payload(
        payload=payload,
        evidence=evidence,
        records=records,
        expected_paths=expected_paths,
    )
    if artifact is not None:
        try:
            recomputed = publication_artifact.scan_artifact(
                source,
                artifact,
                manifest_path=manifest_name,
                policy_path=policy_name,
            )
        except publication_artifact.ArtifactError:
            _fail("artifact_rescan_failed")
        sealed_fields = {
            "payload_format",
            "payload_member_count",
            "payload_sha256",
            "payload_size",
        }
        unsealed_evidence = {
            key: value for key, value in evidence.items() if key not in sealed_fields
        }
        if unsealed_evidence != recomputed:
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
    source.add_argument("--expected-commit", required=True)

    artifact = subparsers.add_parser("artifact")
    artifact.add_argument("--source", default=".")
    artifact.add_argument("--manifest", default=publication_artifact.MANIFEST_FILENAME)
    artifact.add_argument("--policy", default=publication_artifact.POLICY_FILENAME)
    artifact.add_argument("--artifact")
    artifact.add_argument("--payload", required=True)
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
                expected_commit=args.expected_commit,
            )
            print(
                "publication source evidence validated: "
                f"source_file_count={result['source_file_count']} "
                f"commit={result['commit_sha']}"
            )
        else:
            result = validate_artifact_evidence(
                source=Path(args.source),
                artifact=Path(args.artifact) if args.artifact else None,
                payload=Path(args.payload),
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
