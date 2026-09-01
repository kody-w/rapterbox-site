from __future__ import annotations

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


class PublicationArtifactTests(unittest.TestCase):
    work = Path(__file__).parent / ".publication-artifact-work"

    def setUp(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def manifest_document(
        self,
        paths: list[tuple[str, str]],
        *,
        max_file_bytes: int = 5 * 1024 * 1024,
    ) -> dict[str, object]:
        return {
            "document_type": "publication-manifest",
            "schema_version": 1,
            "repository": "kody-w/rapterbox-site",
            "default_disposition": "deny",
            "artifact_boundary": publication_artifact.ARTIFACT_BOUNDARY,
            "max_file_bytes": max_file_bytes,
            "site_hosts": ["rapterbox.com"],
            "allowed_external_origins": ["https://example.com"],
            "paths": [
                {"path": path, "class": publication_class}
                for path, publication_class in paths
            ],
        }

    def git(self, source: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", os.fspath(source), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )

    def commit_source(self, source: Path) -> None:
        self.git(source, "init", "--quiet")
        self.git(source, "add", "-A")
        self.git(
            source,
            "-c",
            "user.name=Artifact Test",
            "-c",
            "user.email=" + "artifact-test" + "@" + "example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )

    def fixture_source(
        self,
        *,
        paths: list[tuple[str, str]] | None = None,
        contents: dict[str, str | bytes] | None = None,
        max_file_bytes: int = 5 * 1024 * 1024,
    ) -> Path:
        source = self.work / "source"
        source.mkdir()
        shutil.copy2(ROOT / "PUBLICATION-POLICY.json", source)
        paths = paths or [("index.html", "site-content")]
        if contents is None:
            contents = {"index.html": "<!doctype html><title>Safe</title>\n"}
        for relative, content in contents.items():
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                destination.write_bytes(content)
            else:
                destination.write_text(content, encoding="utf-8")
        (source / publication_artifact.MANIFEST_FILENAME).write_text(
            json.dumps(
                self.manifest_document(paths, max_file_bytes=max_file_bytes),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self.commit_source(source)
        return source

    def current_source(self) -> Path:
        source = self.work / "current-source"
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
        self.commit_source(source)
        return source

    def build(self, source: Path) -> Path:
        artifact = self.work / "artifact"
        report = publication_artifact.build_artifact(source, artifact)
        self.assertEqual("pass", report["result"])
        return artifact

    def rules(self, report: dict[str, object]) -> set[str]:
        return {finding["rule"] for finding in report["findings"]}

    def test_current_exact_artifact_builds_and_scans_cleanly(self) -> None:
        source = self.current_source()
        artifact = self.build(source)

        report = publication_artifact.scan_artifact(source, artifact)

        self.assertEqual("pass", report["result"])
        self.assertEqual(31, report["generated_artifact_count"])
        self.assertEqual(31, report["scan_counts"]["scanned_paths"])
        self.assertEqual(
            publication_artifact.load_manifest(
                source / publication_artifact.MANIFEST_FILENAME
            ).paths,
            tuple(report["inventory_paths"]),
        )
        self.assertFalse((artifact / ".github").exists())
        self.assertFalse((artifact / "scripts").exists())
        self.assertFalse((artifact / "tests").exists())
        self.assertFalse((artifact / "waitlist").exists())
        categories = {
            record["path"]: record["category"] for record in report["coverage_records"]
        }
        self.assertEqual(["product-summary"], categories["holo/index.html"])
        self.assertEqual(
            ["customer-facing-terms", "product-summary"],
            categories["values/index.html"],
        )
        self.assertEqual(
            ["product-summary", "public-site-operation"],
            categories["support/index.html"],
        )

    def test_generated_forbidden_filename_and_extra_are_denied_without_echo(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)
        forbidden_name = "CODE" + "_RED.md"
        (artifact / forbidden_name).write_text("safe body\n", encoding="utf-8")

        report = publication_artifact.scan_artifact(source, artifact)

        self.assertEqual("deny", report["result"])
        self.assertIn("extra_artifact_path", self.rules(report))
        self.assertIn("forbidden_filename", self.rules(report))
        self.assertNotIn(forbidden_name, json.dumps(report))

    def test_generated_private_doctrine_phrase_is_denied_without_echo(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)
        phrase = "private" + " doctrine"
        (artifact / "index.html").write_text(phrase + "\n", encoding="utf-8")

        report = publication_artifact.scan_artifact(source, artifact)

        self.assertIn("forbidden_phrase", self.rules(report))
        self.assertNotIn(phrase, json.dumps(report).casefold())

    def test_generated_ownership_percentage_is_denied_without_echo(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)
        claim = "owns " + "51" + "% of the venture"
        (artifact / "index.html").write_text(claim + "\n", encoding="utf-8")

        report = publication_artifact.scan_artifact(source, artifact)

        self.assertIn("ownership_percentage_claim", self.rules(report))
        self.assertNotIn("51%", json.dumps(report))

    def test_generated_unverified_repository_link_is_redacted_and_denied(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)
        slug = "unknown-owner/" + "private-repo"
        url = "https://github.com/" + slug
        (artifact / "index.html").write_text(
            '<a href="' + url + '">repository</a>\n', encoding="utf-8"
        )

        report = publication_artifact.scan_artifact(source, artifact)

        self.assertIn("private_repository_link", self.rules(report))
        self.assertIn("unverified_repository_link", self.rules(report))
        rendered = json.dumps(report)
        self.assertNotIn(slug, rendered)
        self.assertNotIn(url, rendered)

    def test_generated_secret_and_pii_shapes_are_denied_without_values(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)
        secret = "api_" + "key = " + '"' + ("s" * 20) + '"'
        email = "person" + "@" + "example.test"
        (artifact / "index.html").write_text(
            secret + "\n" + email + "\n", encoding="utf-8"
        )

        report = publication_artifact.scan_artifact(source, artifact)

        sensitive = {
            finding["detector"]
            for finding in report["findings"]
            if finding["rule"] == "sensitive_data_shape"
        }
        self.assertEqual({"credential_assignment", "email_address"}, sensitive)
        rendered = json.dumps(report)
        self.assertNotIn(secret, rendered)
        self.assertNotIn(email, rendered)

    def test_builder_rejects_symlink_escape_and_manifest_traversal(self) -> None:
        outside = self.work / "outside.html"
        outside.write_text("outside\n", encoding="utf-8")
        source = self.fixture_source(
            paths=[("escape.html", "site-content")],
            contents={},
        )
        (source / "escape.html").symlink_to(outside)
        self.git(source, "add", "escape.html")

        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "source_symlink"
        ):
            publication_artifact.build_artifact(source, self.work / "artifact")

        manifest_path = source / publication_artifact.MANIFEST_FILENAME
        manifest = self.manifest_document([("../outside.html", "site-content")])
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "manifest_path_escape"
        ):
            publication_artifact.load_manifest(manifest_path)

    def test_scanner_rejects_generated_symlink_escape(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)
        outside = self.work / "outside.html"
        outside.write_text("outside\n", encoding="utf-8")
        (artifact / "index.html").unlink()
        (artifact / "index.html").symlink_to(outside)

        report = publication_artifact.scan_artifact(source, artifact)

        self.assertIn("artifact_symlink", self.rules(report))
        self.assertIn("missing_artifact_path", self.rules(report))

    def test_undeclared_extra_and_missing_declared_path_are_denied(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)
        (artifact / "extra.txt").write_text("safe\n", encoding="utf-8")
        extra_report = publication_artifact.scan_artifact(source, artifact)
        self.assertIn("extra_artifact_path", self.rules(extra_report))

        shutil.rmtree(artifact)
        artifact = self.build(source)
        (artifact / "index.html").unlink()
        missing_report = publication_artifact.scan_artifact(source, artifact)
        self.assertIn("missing_artifact_path", self.rules(missing_report))

    def test_builder_rejects_untracked_missing_and_oversized_paths(self) -> None:
        source = self.fixture_source(
            paths=[("untracked.html", "site-content")],
            contents={},
        )
        (source / "untracked.html").write_text("safe\n", encoding="utf-8")
        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "manifest_path_not_tracked"
        ):
            publication_artifact.build_artifact(source, self.work / "artifact")

        self.git(source, "add", "untracked.html")
        (source / "untracked.html").unlink()
        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "source_path_unreadable"
        ):
            publication_artifact.build_artifact(source, self.work / "artifact")

        shutil.rmtree(source)
        source = self.fixture_source(
            paths=[("large.html", "site-content")],
            contents={"large.html": "x" * 25000},
            max_file_bytes=20000,
        )
        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "source_file_too_large"
        ):
            publication_artifact.build_artifact(source, self.work / "artifact")

    def test_manifest_rejects_case_and_unicode_collisions(self) -> None:
        source = self.fixture_source()
        manifest_path = source / publication_artifact.MANIFEST_FILENAME
        for paths in (
            [("index.html", "site-content"), ("INDEX.HTML", "site-content")],
            [("caf\u00e9.html", "site-content"), ("cafe\u0301.html", "site-content")],
        ):
            with self.subTest(paths=paths):
                manifest_path.write_text(
                    json.dumps(self.manifest_document(paths)), encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    publication_artifact.ArtifactError, "artifact_path_collision"
                ):
                    publication_artifact.load_manifest(manifest_path)

    def test_builder_detects_source_mutation_and_rejects_output_overlap(self) -> None:
        source = self.fixture_source()
        mutated = False

        def mutate(path: Path) -> None:
            nonlocal mutated
            if not mutated and path.name == "index.html":
                mutated = True
                path.write_text("changed during copy\n", encoding="utf-8")

        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "source_changed_during_copy"
        ):
            publication_artifact.build_artifact(
                source,
                self.work / "artifact",
                _mutation_hook=mutate,
            )
        self.assertFalse((self.work / "artifact").exists())

        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "output_overlaps_source"
        ):
            publication_artifact.build_artifact(source, source / "artifact")

        existing = self.work / "existing-artifact"
        existing.mkdir()
        with self.assertRaisesRegex(
            publication_artifact.ArtifactError, "output_already_exists"
        ):
            publication_artifact.build_artifact(source, existing)

    def test_invalid_generated_json_fails_closed(self) -> None:
        source = self.fixture_source(
            paths=[("agent.json", "site-content")],
            contents={"agent.json": "{}\n"},
        )
        artifact = self.build(source)
        (artifact / "agent.json").write_text('{"broken":', encoding="utf-8")

        report = publication_artifact.scan_artifact(source, artifact)

        self.assertEqual("deny", report["result"])
        self.assertIn("invalid_json", self.rules(report))

    def test_evidence_is_byte_deterministic_and_not_a_rapp_frame(self) -> None:
        source = self.fixture_source()
        artifact = self.build(source)

        first = publication_artifact.scan_artifact(source, artifact)
        second = publication_artifact.scan_artifact(source, artifact)
        first_bytes = publication_artifact._render_json(first, compact=True).encode()
        second_bytes = publication_artifact._render_json(second, compact=True).encode()

        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(publication_artifact.ARTIFACT_BOUNDARY, first["artifact_boundary"])
        self.assertNotIn('"spec":"rapp/1"', first_bytes.decode())
        self.assertNotIn('"payload"', first_bytes.decode())

    def test_build_scan_cli_writes_private_safe_evidence_outside_artifact(self) -> None:
        source = self.fixture_source()
        artifact = self.work / "cli-artifact"
        evidence = self.work / "evidence.json"
        command = [
            sys.executable,
            os.fspath(ROOT / "scripts" / "publication_artifact.py"),
            "--compact",
            "build-scan",
            "--source",
            os.fspath(source),
            "--artifact",
            os.fspath(artifact),
            "--evidence",
            os.fspath(evidence),
        ]

        result = subprocess.run(command, check=False, capture_output=True, text=True)

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        report = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual("pass", report["result"])
        self.assertFalse((artifact / evidence.name).exists())


if __name__ == "__main__":
    unittest.main()
