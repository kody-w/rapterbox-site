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
    handoff_path = ROOT / "docs" / "PUBLICATION-OPERATOR-HANDOFF.json"

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
            "user.email=" + "evidence-test" + "@" + "example.invalid",
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

    def built_source_evidence(
        self,
    ) -> tuple[Path, Path, Path, dict[str, object]]:
        source = self.work / "source"
        source.mkdir()
        (source / "PUBLICATION-POLICY.json").write_text(
            json.dumps(
                {
                    "policy_id": "fixture/source-evidence",
                    "policy_version": "1.0.0",
                    "repository": "fixture/source-evidence",
                }
            ),
            encoding="utf-8",
        )
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
        self.assertEqual(0, exit_code)
        return source, manifest_path, evidence_path, json.loads(
            evidence_path.read_text(encoding="utf-8")
        )

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
        self.assertIn(
            "docs/PUBLICATION-OPERATOR-HANDOFF.json",
            by_class["publication-tooling"],
        )
        self.assertNotIn(
            "docs/PUBLICATION-OPERATOR-HANDOFF.json",
            artifact_manifest.paths,
        )

    def test_operator_handoff_is_exact_nondeploy_state(self) -> None:
        handoff = json.loads(self.handoff_path.read_text(encoding="utf-8"))

        self.assertEqual(
            {
                "schema",
                "classification",
                "release_frame",
                "integration_base",
                "deployment",
                "publication_evidence",
                "required_check",
                "operator_actions",
                "history_rewrite",
            },
            set(handoff),
        )
        self.assertEqual("publication-tooling", handoff["classification"])
        self.assertEqual("nondeploy", handoff["deployment"])
        self.assertEqual("Publication gate", handoff["required_check"]["context"])
        self.assertTrue(handoff["required_check"]["strict"])
        self.assertFalse(handoff["publication_evidence"]["rapp_frame"])
        self.assertFalse(
            handoff["publication_evidence"]["claims_rapp_1_conformance"]
        )
        actions = {item["id"]: item for item in handoff["operator_actions"]}
        self.assertEqual(
            {
                "pages-build-source",
                "protect-main",
                "restrict-pages-environment",
                "gitguardian-rappid-disposition",
            },
            set(actions),
        )
        self.assertTrue(
            all(item["state"] == "needs-operator-apply" for item in actions.values())
        )
        self.assertEqual(
            "Publication gate",
            actions["protect-main"]["required_check"],
        )
        self.assertFalse(
            actions["restrict-pages-environment"]["custom_branch_policies"]
        )
        self.assertFalse(
            actions["gitguardian-rappid-disposition"]["disable_scanning"]
        )
        self.assertEqual("blocked", handoff["history_rewrite"]["state"])

    def test_valid_source_evidence_is_complete_and_outside_source(self) -> None:
        source, manifest_path, evidence_path, _ = self.built_source_evidence()
        result = validate_publication_evidence.validate_source_evidence(
            source=source,
            manifest_path=manifest_path,
            evidence_path=evidence_path,
        )

        self.assertEqual({"source_file_count": 1}, result)

    def test_rejects_source_coverage_and_count_drift(self) -> None:
        source, manifest_path, evidence_path, evidence = self.built_source_evidence()
        mutations = []

        bad_count = copy.deepcopy(evidence)
        bad_count["scan_counts"]["classified_paths"] = 0
        mutations.append(bad_count)

        bad_coverage = copy.deepcopy(evidence)
        bad_coverage["coverage_records"][0]["path"] = "other.txt"
        mutations.append(bad_coverage)

        for mutation in mutations:
            with self.subTest():
                evidence_path.write_text(
                    json.dumps(mutation, sort_keys=True),
                    encoding="utf-8",
                )
                with self.assertRaises(validate_publication_evidence.EvidenceError):
                    validate_publication_evidence.validate_source_evidence(
                        source=source,
                        manifest_path=manifest_path,
                        evidence_path=evidence_path,
                    )

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
