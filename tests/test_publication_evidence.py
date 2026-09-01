from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.fspath(ROOT))

from scripts import publication_artifact
from scripts import publication_guard
from scripts import validate_publication_evidence


class PublicationEvidenceTests(unittest.TestCase):
    work = Path(__file__).parent / ".publication-evidence-work"

    def setUp(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def git(self, source: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", os.fspath(source), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def commit_source(self, source: Path) -> str:
        self.git(source, "init", "--quiet")
        self.git(source, "add", "-A")
        self.git(
            source,
            "-c",
            "user.name=Evidence Test",
            "-c",
            "user.email=evidence-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )
        return self.git(source, "rev-parse", "HEAD")

    def artifact_source(self) -> tuple[Path, str]:
        source = self.work / "source"
        source.mkdir()
        manifest = publication_artifact.load_manifest(
            ROOT / publication_artifact.MANIFEST_FILENAME
        )
        for relative in (
            publication_artifact.MANIFEST_FILENAME,
            publication_artifact.POLICY_FILENAME,
            *manifest.paths,
        ):
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return source, self.commit_source(source)

    def built_evidence(
        self,
    ) -> tuple[Path, Path, Path, str, dict[str, object]]:
        source, commit = self.artifact_source()
        artifact = self.work / "artifact"
        evidence_path = self.work / "artifact-evidence.json"
        publication_artifact.build_artifact(source, artifact)
        evidence = publication_artifact.scan_artifact(source, artifact)
        evidence_path.write_text(
            publication_artifact._render_json(evidence, compact=True),
            encoding="utf-8",
        )
        return source, artifact, evidence_path, commit, evidence

    def test_source_manifest_classifies_exact_publication_candidates(self) -> None:
        source_manifest = validate_publication_evidence.load_source_manifest(
            ROOT / validate_publication_evidence.SOURCE_MANIFEST_FILENAME
        )
        artifact_manifest = publication_artifact.load_manifest(
            ROOT / publication_artifact.MANIFEST_FILENAME
        )
        candidates = [
            entry.path
            for entry in artifact_manifest.entries
            if entry.publication_class == "site-content"
        ]
        controls = [
            entry.path
            for entry in artifact_manifest.entries
            if entry.publication_class == "publication-control"
        ]
        by_class = {
            entry["class"]: entry["paths"]
            for entry in source_manifest["source_classes"]
        }
        tracked = subprocess.run(
            [
                "git",
                "-C",
                os.fspath(ROOT),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            check=True,
            capture_output=True,
        ).stdout.decode().split("\0")[:-1]

        self.assertEqual(
            sorted(tracked, key=lambda path: (path.casefold(), path)),
            source_manifest["files"],
        )
        self.assertEqual(candidates, by_class["publication-candidate"])
        self.assertEqual(controls, by_class["publication-control"])

    def test_valid_source_evidence_is_complete_and_outside_source(self) -> None:
        source = self.work / "source"
        source.mkdir()
        shutil.copy2(ROOT / "PUBLICATION-POLICY.json", source)
        (source / "safe.txt").write_text("safe public source\n", encoding="utf-8")
        manifest = {
            "artifact_boundary": publication_artifact.ARTIFACT_BOUNDARY,
            "default_disposition": "deny",
            "document_type": "publication-source-manifest",
            "files": ["safe.txt"],
            "repository": "kody-w/rapterbox-site",
            "schema_version": 1,
            "source_classes": [
                {
                    "class": "publication-candidate",
                    "paths": ["safe.txt"],
                    "scanner": "scripts/publication_guard.py",
                }
            ],
        }
        manifest_path = source / validate_publication_evidence.SOURCE_MANIFEST_FILENAME
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        evidence_path = self.work / "source-evidence.json"

        exit_code = publication_guard.main(
            [
                "--root",
                os.fspath(source),
                "--policy",
                "PUBLICATION-POLICY.json",
                "--manifest",
                os.fspath(manifest_path),
                "--output",
                os.fspath(evidence_path),
                "--compact",
            ]
        )
        result = validate_publication_evidence.validate_source_evidence(
            source=source,
            manifest_path=manifest_path,
            evidence_path=evidence_path,
        )

        self.assertEqual(0, exit_code)
        self.assertEqual({"source_file_count": 1}, result)

    def test_valid_artifact_evidence_is_exactly_bound(self) -> None:
        source, artifact, evidence_path, commit, evidence = self.built_evidence()

        result = validate_publication_evidence.validate_artifact_evidence(
            source=source,
            artifact=artifact,
            evidence_path=evidence_path,
            expected_commit=commit,
        )

        self.assertEqual(31, result["artifact_count"])
        self.assertEqual(len(evidence["links"]), result["link_count"])
        self.assertGreater(result["link_count"], 0)
        self.assertEqual(commit, result["commit_sha"])

    def test_rejects_findings_stale_links_and_rapp_payload_material(self) -> None:
        source, artifact, evidence_path, commit, evidence = self.built_evidence()
        mutations = []

        finding = copy.deepcopy(evidence)
        finding["result"] = "deny"
        finding["findings"] = [{"gate": "policy"}]
        mutations.append(finding)

        stale_links = copy.deepcopy(evidence)
        stale_links["links"] = stale_links["links"][:-1]
        mutations.append(stale_links)

        payload = copy.deepcopy(evidence)
        payload["payload"] = {"candidate_source": "not allowed"}
        mutations.append(payload)

        for mutation in mutations:
            with self.subTest():
                evidence_path.write_text(
                    json.dumps(mutation, sort_keys=True),
                    encoding="utf-8",
                )
                with self.assertRaises(validate_publication_evidence.EvidenceError):
                    validate_publication_evidence.validate_artifact_evidence(
                        source=source,
                        artifact=artifact,
                        evidence_path=evidence_path,
                        expected_commit=commit,
                    )

    def test_rejects_wrong_commit_artifact_mutation_and_evidence_overlap(self) -> None:
        source, artifact, evidence_path, commit, evidence = self.built_evidence()
        with self.assertRaises(validate_publication_evidence.EvidenceError):
            validate_publication_evidence.validate_artifact_evidence(
                source=source,
                artifact=artifact,
                evidence_path=evidence_path,
                expected_commit="0" * 40,
            )

        (artifact / "index.html").write_text("mutated\n", encoding="utf-8")
        with self.assertRaises(validate_publication_evidence.EvidenceError):
            validate_publication_evidence.validate_artifact_evidence(
                source=source,
                artifact=artifact,
                evidence_path=evidence_path,
                expected_commit=commit,
            )

        overlap_path = artifact / "evidence.json"
        overlap_path.write_text(json.dumps(evidence), encoding="utf-8")
        with self.assertRaises(validate_publication_evidence.EvidenceError):
            validate_publication_evidence.validate_artifact_evidence(
                source=source,
                artifact=artifact,
                evidence_path=overlap_path,
                expected_commit=commit,
            )


if __name__ == "__main__":
    unittest.main()
