from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.fspath(REPOSITORY_ROOT))

from scripts import publication_guard


class PublicationGuardSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture_parent = REPOSITORY_ROOT / "tests" / ".publication-guard-fixtures"
        fixture_parent.mkdir(exist_ok=True)
        self._temporary_directory = tempfile.TemporaryDirectory(dir=fixture_parent)
        self.root = Path(self._temporary_directory.name) / "root"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()
        fixture_parent = REPOSITORY_ROOT / "tests" / ".publication-guard-fixtures"
        if fixture_parent.exists() and not any(fixture_parent.iterdir()):
            fixture_parent.rmdir()

    def write(self, relative: str, content: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def write_policy(self, policy: dict[str, object]) -> Path:
        path = self.root / publication_guard.POLICY_FILENAME
        path.write_text(json.dumps(policy), encoding="utf-8")
        return path

    def rules(self, report: dict[str, object]) -> list[str]:
        return [finding["rule"] for finding in report["findings"]]

    def test_clean_text_and_binary_paths_are_classified_deterministically(self) -> None:
        self.write("src/app.py", "print('public and safe')\n")
        self.write("assets/pixel.bin", b"\x00\x01\x02\xff")
        manifest = ["src/app.py", "assets/pixel.bin"]

        first = publication_guard.scan_repository(self.root, manifest=manifest)
        second = publication_guard.scan_repository(
            self.root, manifest=list(reversed(manifest))
        )

        self.assertEqual(first, second)
        self.assertEqual(first["finding_count"], 0)
        self.assertEqual(first["text_paths"], ["src/app.py"])
        self.assertEqual(first["binary_paths"], ["assets/pixel.bin"])
        self.assertFalse(first["policy_loaded"])

    def test_public_rapp_boundary_is_preserved_without_claiming_protocol_output(self) -> None:
        self.write(
            "public-boundary.txt",
            "RAPP is the external public open-source foundation.\n"
            "RAPP/1 is the protocol authority.\n",
        )

        report = publication_guard.scan_repository(
            self.root, manifest=["public-boundary.txt"]
        )

        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(
            report["artifact_boundary"],
            "publication evidence only; emits no RAPP or RAPP/1 protocol artifacts",
        )
        self.assertNotIn("frame", report)
        self.assertNotIn("payload", report)

    def test_llc_stake_claim_about_rapp_is_rejected(self) -> None:
        self.write(
            "ownership-claim.txt",
            "RapterBox LLC "
            + "owns "
            + "51%"
            + " of RAPP.\n",
        )

        report = publication_guard.scan_repository(
            self.root, manifest=["ownership-claim.txt"]
        )

        self.assertEqual(self.rules(report), ["ownership_percentage_claim"])
        self.assertNotIn("51%", json.dumps(report))

    def test_policy_rules_are_case_insensitive_and_policy_is_not_self_scanned(self) -> None:
        forbidden_phrase = "Internal " + "Founding Doctrine"
        private_slug = "wildhaven/" + "private-foundation"
        self.write_policy(
            {
                "publication": {
                    "forbidden_filenames": ["*.PeM", {"pattern": "private/*"}],
                    "forbidden_phrases": [{"phrase": forbidden_phrase}],
                    "private_repositories": [{"slug": private_slug}],
                }
            }
        )
        self.write("certs/SERVER.pem", "not a real certificate\n")
        self.write("private/notes.txt", "ordinary text\n")
        self.write(
            "src/readme.txt",
            forbidden_phrase.swapcase()
            + "\n"
            + "https://github.com/"
            + private_slug.upper()
            + "\n",
        )
        manifest = [
            publication_guard.POLICY_FILENAME,
            "src/readme.txt",
            "private/notes.txt",
            "certs/SERVER.pem",
        ]

        report = publication_guard.scan_repository(self.root, manifest=manifest)

        self.assertTrue(report["policy_loaded"])
        self.assertEqual(report["skipped_paths"], [publication_guard.POLICY_FILENAME])
        self.assertEqual(
            sorted(self.rules(report)),
            [
                "forbidden_filename",
                "forbidden_filename",
                "forbidden_phrase",
                "private_repository_link",
            ],
        )
        rendered = json.dumps(report)
        self.assertNotIn(forbidden_phrase, rendered)
        self.assertNotIn(private_slug, rendered)

    def test_policy_regex_schema_and_repository_default_deny_are_supported(self) -> None:
        allowed_slug = "public-owner/" + "public-repo"
        self.write_policy(
            {
                "public_forbidden": {
                    "explicit_filenames_case_insensitive": ["never.txt"],
                    "filename_patterns": {
                        "patterns": [
                            r"^code[ ._-]*red(?:[ ._-].*)?\.md$",
                        ]
                    },
                    "phrase_patterns": {
                        "patterns": [
                            {
                                "id": "forbidden-doctrine",
                                "regex": r"\bprivate[\s_-]*doctrine\b",
                            }
                        ]
                    },
                },
                "url_policy": {
                    "repository_hosts_case_insensitive": ["github.com"],
                    "allowed_repository_slugs_case_insensitive": [allowed_slug],
                    "forbidden_repository_slug_patterns": {
                        "patterns": [
                            {
                                "id": "private-repository-name",
                                "regex": r"(?:^|/)private[._-]*doctrine(?:$|/)",
                            }
                        ]
                    },
                },
            }
        )
        forbidden_name = "CoDe_" + "Red-notes.md"
        repository_prefix = "https://github.com/"
        self.write(forbidden_name, "safe\n")
        self.write(
            "links.txt",
            "private" + "_doctrine\n"
            + repository_prefix
            + allowed_slug
            + "\n"
            + repository_prefix
            + "private-"
            + "doctrine/source\n"
            + repository_prefix
            + "unknown/private\n",
        )

        report = publication_guard.scan_repository(
            self.root, manifest=[forbidden_name, "links.txt"]
        )

        self.assertEqual(
            sorted(self.rules(report)),
            [
                "forbidden_filename",
                "forbidden_phrase",
                "forbidden_phrase",
                "private_repository_link",
                "private_repository_link",
            ],
        )
        detectors = {finding["detector"] for finding in report["findings"]}
        self.assertIn("forbidden-doctrine", detectors)
        self.assertIn("private-repository-name", detectors)
        self.assertIn("repository_visibility_default_deny", detectors)

    def test_numeric_stake_claims_are_detected_in_both_orders(self) -> None:
        self.write(
            "claims.txt",
            "The company "
            + "owns "
            + "51%"
            + " of the venture.\n"
            + "A "
            + "49%"
            + " ownership interest remains.\n",
        )

        report = publication_guard.scan_repository(
            self.root, manifest=["claims.txt"]
        )

        findings = [
            finding
            for finding in report["findings"]
            if finding["rule"] == "ownership_percentage_claim"
        ]
        self.assertEqual([finding["line"] for finding in findings], [1, 2])

    def test_secret_and_pii_shapes_are_reported_without_values(self) -> None:
        values = {
            "private_key": "-----BEGIN " + "PRIVATE KEY-----",
            "aws_access_key": "AK" + "IA" + ("A" * 16),
            "github_token": "gh" + "p_" + ("a" * 24),
            "openai_token": "s" + "k-" + ("a" * 24),
            "google_api_key": "AI" + "za" + ("A" * 35),
            "stripe_secret_key": "sk_" + "live_" + ("a" * 24),
            "slack_token": "xo" + "xb-" + ("1" * 12),
            "jwt": "ey" + "J" + ("a" * 10) + "." + ("b" * 10) + "." + ("c" * 10),
            "credential_assignment": "api_" + "key = " + '"' + ("s" * 20) + '"',
            "credential_url": "https://" + "user:" + "password123@" + "example.test/data",
            "connection_string_secret": "Account" + "Key=" + ("A" * 24),
            "webhook_secret": (
                "https://hooks."
                + "slack.com/services/"
                + ("A" * 8)
                + "/"
                + ("B" * 8)
                + "/"
                + ("C" * 16)
            ),
            "email_address": "person" + "@" + "example.test",
            "us_ssn": "123" + "-45-" + "6789",
            "phone_number": "phone: " + "(212) " + "555-0199",
        }
        for index, value in enumerate(values.values()):
            self.write(f"src/value-{index}.txt", value + "\n")

        report = publication_guard.scan_repository(
            self.root,
            manifest=[f"src/value-{index}.txt" for index in range(len(values))],
        )

        detectors = {
            finding["detector"]
            for finding in report["findings"]
            if finding["rule"] == "sensitive_data_shape"
        }
        self.assertEqual(detectors, set(values))
        rendered = json.dumps(report)
        for value in values.values():
            self.assertNotIn(value, rendered)

    def test_symlinks_and_manifest_escapes_are_refused_without_following(self) -> None:
        outside = self.root.parent / "outside.txt"
        outside.write_text("person" + "@" + "outside.test", encoding="utf-8")
        symlink = self.root / "escape.txt"
        try:
            symlink.symlink_to(outside)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable")

        report = publication_guard.scan_repository(
            self.root,
            manifest=["escape.txt", "../outside.txt", os.fspath(outside)],
        )

        self.assertEqual(
            sorted(self.rules(report)),
            ["path_escape", "path_escape", "symlink_path"],
        )
        self.assertNotIn("sensitive_data_shape", self.rules(report))
        self.assertEqual(
            report["unscanned_paths"],
            sorted(
                ["escape.txt", "../outside.txt", os.fspath(outside)],
                key=lambda path: (path.casefold(), path),
            ),
        )

    def test_missing_and_oversized_paths_fail_closed(self) -> None:
        self.write_policy({"max_file_bytes": 8})
        self.write("large.txt", "ninebytes!")

        report = publication_guard.scan_repository(
            self.root, manifest=["large.txt", "missing.txt"]
        )

        self.assertEqual(sorted(self.rules(report)), ["file_too_large", "missing_path"])
        self.assertEqual(report["scanned_path_count"], 0)
        self.assertEqual(report["unscanned_paths"], ["large.txt", "missing.txt"])

    def test_non_utf8_text_is_inspected_safely(self) -> None:
        phrase = "do " + "not publish"
        self.write_policy({"forbidden_phrases": [phrase]})
        self.write("legacy.txt", b"\xffDO NOT PUBLISH\n")

        report = publication_guard.scan_repository(
            self.root, manifest=["legacy.txt"]
        )

        self.assertEqual(self.rules(report), ["forbidden_phrase"])
        self.assertEqual(report["text_paths"], ["legacy.txt"])

    def test_newline_nul_and_json_manifests_are_supported(self) -> None:
        self.write("a.txt", "safe\n")
        self.write("b.txt", "safe\n")
        manifests = {
            "lines.manifest": b"a.txt\nb.txt\n",
            "nul.manifest": b"a.txt\0b.txt\0",
            "array.json": json.dumps(["a.txt", "b.txt"]).encode(),
            "object.json": json.dumps({"paths": ["a.txt", "b.txt"]}).encode(),
        }
        for name, content in manifests.items():
            with self.subTest(name=name):
                manifest_path = self.write(name, content)
                report = publication_guard.scan_repository(
                    self.root, manifest=manifest_path
                )
                self.assertEqual(report["finding_count"], 0)
                self.assertEqual(report["text_paths"], ["a.txt", "b.txt"])

    def test_git_ls_files_scans_tracked_paths_and_ignores_untracked_paths(self) -> None:
        self.write("tracked.txt", "safe\n")
        self.write("untracked.txt", "person" + "@" + "untracked.test\n")
        subprocess.run(
            ["git", "init", "--quiet", os.fspath(self.root)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "-C", os.fspath(self.root), "add", "tracked.txt"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        report = publication_guard.scan_repository(self.root)

        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["text_paths"], ["tracked.txt"])

    def test_cli_returns_one_and_emits_stable_redacted_json_on_findings(self) -> None:
        phrase = "confidential " + "blueprint"
        self.write_policy({"forbidden_phrases": [phrase]})
        self.write("source.txt", phrase.upper() + "\n")
        manifest = self.write(
            "manifest.json",
            json.dumps({"files": ["source.txt"]}),
        )
        command = [
            sys.executable,
            os.fspath(REPOSITORY_ROOT / "scripts" / "publication_guard.py"),
            "--root",
            os.fspath(self.root),
            "--manifest",
            os.fspath(manifest),
            "--compact",
        ]

        first = subprocess.run(command, check=False, capture_output=True, text=True)
        second = subprocess.run(command, check=False, capture_output=True, text=True)

        self.assertEqual(first.returncode, 1)
        self.assertEqual(first.stderr, "")
        self.assertEqual(first.stdout, second.stdout)
        self.assertNotIn(phrase, first.stdout.lower())
        report = json.loads(first.stdout)
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["rule"], "forbidden_phrase")

    def test_cli_returns_zero_when_clean_and_two_for_configuration_errors(self) -> None:
        self.write("safe.txt", "safe\n")
        manifest = self.write("manifest.txt", "safe.txt\n")
        base_command = [
            sys.executable,
            os.fspath(REPOSITORY_ROOT / "scripts" / "publication_guard.py"),
            "--root",
            os.fspath(self.root),
            "--manifest",
            os.fspath(manifest),
        ]

        clean = subprocess.run(base_command, check=False, capture_output=True, text=True)
        invalid = subprocess.run(
            base_command + ["--policy", "missing-policy.json"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(clean.returncode, 0)
        self.assertEqual(json.loads(clean.stdout)["finding_count"], 0)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(json.loads(invalid.stdout)["error"]["type"], "scan_error")

    def test_output_file_receives_json_without_echoing_to_stdout(self) -> None:
        self.write("safe.txt", "safe\n")
        manifest = self.write("manifest.txt", "safe.txt\n")
        output = self.root / "evidence.json"

        exit_code = publication_guard.main(
            [
                "--root",
                os.fspath(self.root),
                "--manifest",
                os.fspath(manifest),
                "--output",
                os.fspath(output),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.read_text())["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
