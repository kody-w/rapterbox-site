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

    def test_binary_paths_still_receive_real_secret_checks(self) -> None:
        value = "gh" + "p_" + ("b" * 24)
        self.write("assets/packed.bin", b"\x00" + value.encode() + b"\x00")

        report = publication_guard.scan_repository(
            self.root, manifest=["assets/packed.bin"]
        )

        self.assertIn("sensitive_data_shape", self.rules(report))
        self.assertEqual(["assets/packed.bin"], report["binary_paths"])
        self.assertNotIn(value, json.dumps(report))

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

    def test_policy_rules_are_case_insensitive_and_policy_is_self_scanned_safely(self) -> None:
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
        self.assertEqual(report["skipped_paths"], [])
        policy_record = next(
            record
            for record in report["coverage_records"]
            if record["path"] == publication_guard.POLICY_FILENAME
        )
        self.assertEqual("publication-control", policy_record["category"])
        self.assertEqual("self-reference-safe", policy_record["content_contract"])
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

    def test_unicode_filename_aliases_and_path_collisions_fail_closed(self) -> None:
        self.write_policy(
            {
                "public_forbidden": {
                    "filename_patterns": {
                        "patterns": [
                            r"^code[ ._-]*red(?:[ ._-].*)?\.md$",
                        ]
                    }
                }
            }
        )
        forbidden_name = "\uff23\uff2f\uff24\uff25\uff3f\uff32\uff25\uff24.md"
        self.write(forbidden_name, "safe\n")
        self.write("Alias.txt", "safe\n")
        self.write("caf\u00e9.txt", "safe\n")
        manifest = [
            forbidden_name,
            "Alias.txt",
            "alias.TXT",
            "caf\u00e9.txt",
            "cafe\u0301.txt",
        ]

        report = publication_guard.scan_repository(self.root, manifest=manifest)

        self.assertIn("forbidden_filename", self.rules(report))
        self.assertEqual(self.rules(report).count("path_collision"), 4)
        rendered = json.dumps(report)
        self.assertNotIn(forbidden_name, rendered)
        self.assertNotIn("Alias.txt", rendered)
        self.assertNotIn("alias.TXT", rendered)

    def test_all_private_doctrine_phrases_survive_unicode_and_html_obfuscation(self) -> None:
        patterns = [
            ("forbidden-code-red", r"\bcode[\s_-]*red\b"),
            (
                "forbidden-llc-constitution",
                r"\b(?:the\s+)?llc[\s_-]*constitution\b",
            ),
            (
                "forbidden-ten-commandments",
                r"\b(?:the\s+)?ten[\s_-]*commandments\b",
            ),
            (
                "forbidden-private-doctrine",
                r"\bprivate[\s_-]*doctrine\b",
            ),
            (
                "forbidden-ownership-administration",
                r"\bownership[\s_-]*administration\b",
            ),
            (
                "forbidden-print-ready-doctrine",
                r"\bprint[\s_-]*ready[\s_-]*doctrine\b",
            ),
        ]
        self.write_policy(
            {
                "public_forbidden": {
                    "phrase_patterns": {
                        "patterns": [
                            {"id": identifier, "regex": expression}
                            for identifier, expression in patterns
                        ]
                    }
                }
            }
        )
        values = [
            "Co&#100;e R\u200bed",
            "LLC&#32;Constitution",
            "Ten\u200b Commandments",
            "private&#32;doctrine",
            "ownership&#32;administration",
            "print-ready&#32;doctrine",
        ]
        self.write("encoded.txt", "\n".join(values) + "\n")

        report = publication_guard.scan_repository(
            self.root, manifest=["encoded.txt"]
        )

        detectors = {
            finding["detector"]
            for finding in report["findings"]
            if finding["rule"] == "forbidden_phrase"
        }
        self.assertEqual({identifier for identifier, _ in patterns}, detectors)
        rendered = json.dumps(report).casefold()
        for value in values:
            self.assertNotIn(value.casefold(), rendered)

    def test_obfuscated_ownership_percentages_are_detected_in_both_orders(self) -> None:
        self.write(
            "claims.txt",
            "The company owns \uff15\uff11&#37; of the venture.\n"
            "A 49&#32;percent ownership interest remains.\n",
        )

        report = publication_guard.scan_repository(
            self.root, manifest=["claims.txt"]
        )

        findings = [
            finding
            for finding in report["findings"]
            if finding["rule"] == "ownership_percentage_claim"
        ]
        self.assertEqual([1, 2], [finding["line"] for finding in findings])

    def test_downloadable_doctrine_and_hostile_urls_are_redacted_and_denied(self) -> None:
        allowed = "known/public"
        self.write_policy(
            {
                "public_forbidden": {
                    "filename_patterns": {
                        "patterns": [
                            r"^(?:private[ ._-]*)?doctrine(?:[ ._-].*)?\.pdf$",
                        ]
                    }
                },
                "url_policy": {
                    "forbidden_hosts_case_insensitive": ["localhost", "::1"],
                    "forbidden_host_suffixes_case_insensitive": [".internal"],
                    "repository_hosts_case_insensitive": ["github.com"],
                    "allowed_repository_slugs_case_insensitive": [allowed],
                },
            }
        )
        candidates = [
            "https://example.test/private-doctrine.pdf",
            "https&#58;//github&#46;com/unknown/private",
            "https%3A%2F%2Fgithub.com%2Funknown%2Fencoded",
            "//github.com/unknown/scheme-relative",
            "https://" + "operator@" + "example.test/path",
            "https://[not-ipv6/path",
            "https://example.test/%GG",
            "http://[::1]/",
            "https://service.internal/path",
        ]
        self.write("links.txt", "\n".join(candidates) + "\n")

        first = publication_guard.scan_repository(
            self.root, manifest=["links.txt"]
        )
        second = publication_guard.scan_repository(
            self.root, manifest=["links.txt"]
        )

        self.assertEqual(first, second)
        self.assertIn("forbidden_downloadable_document", self.rules(first))
        self.assertIn("private_repository_link", self.rules(first))
        self.assertIn("sensitive_data_shape", self.rules(first))
        self.assertEqual(2, self.rules(first).count("malformed_url"))
        self.assertEqual(2, self.rules(first).count("forbidden_url_host"))
        rendered = json.dumps(first)
        for candidate in candidates:
            self.assertNotIn(candidate, rendered)

    def test_valid_public_ipv6_url_does_not_crash_or_fail(self) -> None:
        self.write_policy(
            {
                "url_policy": {
                    "forbidden_hosts_case_insensitive": ["::1"],
                }
            }
        )
        self.write("ipv6.txt", "https://[2606:4700:4700::1111]/dns-query\n")

        report = publication_guard.scan_repository(
            self.root, manifest=["ipv6.txt"]
        )

        self.assertEqual("pass", report["result"])
        self.assertEqual(0, report["finding_count"])

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
            "postal_address": "address: " + "123 Main Street",
            "submitted_customer_record": (
                '{"submission_' + 'id":"fixture","email":"person'
                + "@"
                + 'example.test"}'
            ),
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

    def test_structured_json_traversal_denies_encoded_keys_arrays_and_customer_shapes(
        self,
    ) -> None:
        self.write(
            publication_guard.POLICY_FILENAME,
            (REPOSITORY_ROOT / publication_guard.POLICY_FILENAME).read_bytes(),
        )
        sensitive = {
            "pass%77ord": "short-real-value",
            "nested": [
                {
                    "api&#95;key": "another-real-value",
                    "customer": {
                        "name": "Submitted Person",
                        "phones": ["2125550199"],
                        "address": {"street": "123 Main Street"},
                        "customerId": "customer-real-123",
                    },
                }
            ],
        }
        self.write("submitted.json", json.dumps(sensitive))

        report = publication_guard.scan_repository(
            self.root,
            manifest=["submitted.json"],
            enforce_source_classification=False,
        )

        detectors = {
            finding["detector"]
            for finding in report["findings"]
            if finding["rule"] == "structured_data_violation"
        }
        self.assertTrue(
            {
                "passwords",
                "api_tokens",
                "submitted_names",
                "phone_number_values",
                "postal_address_values",
                "customer_or_account_identifiers",
            }
            <= detectors
        )
        rendered = json.dumps(report)
        for value in (
            "short-real-value",
            "another-real-value",
            "Submitted Person",
            "2125550199",
            "123 Main Street",
            "customer-real-123",
        ):
            self.assertNotIn(value, rendered)

    def test_structured_json_and_jsonl_parse_failures_fail_closed(self) -> None:
        self.write(
            publication_guard.POLICY_FILENAME,
            (REPOSITORY_ROOT / publication_guard.POLICY_FILENAME).read_bytes(),
        )
        self.write("duplicate.json", '{"key":1,"key":2}\n')
        self.write("invalid.jsonl", '{"ok":true}\n{"broken":\n')
        self.write("nonstandard.json", '{"value":NaN}\n')

        report = publication_guard.scan_repository(
            self.root,
            manifest=["duplicate.json", "invalid.jsonl", "nonstandard.json"],
            enforce_source_classification=False,
        )

        self.assertEqual(
            3, self.rules(report).count("invalid_structured_data")
        )

    def test_operational_contact_exceptions_are_exact_and_placeholders_are_narrow(
        self,
    ) -> None:
        self.write(
            publication_guard.POLICY_FILENAME,
            (REPOSITORY_ROOT / publication_guard.POLICY_FILENAME).read_bytes(),
        )
        approved = "wildhavenhomesllc" + "@" + "gmail.com"
        real_customer = "submitted-person" + "@" + "example.test"
        self.write("waitlist/Code.gs", approved + "\n")
        self.write("waitlist/other.gs", real_customer + "\n")
        self.write(
            "agent.json",
            json.dumps(
                {
                    "access_token": "<ACCESS_TOKEN>",
                    "fields": {
                        "email": "string, required",
                        "phone": "string, optional",
                    },
                }
            ),
        )

        report = publication_guard.scan_repository(
            self.root,
            manifest=["waitlist/Code.gs", "waitlist/other.gs", "agent.json"],
            enforce_source_classification=False,
        )

        findings_by_path = {
            finding["path"]: finding for finding in report["findings"]
        }
        self.assertNotIn("waitlist/Code.gs", findings_by_path)
        self.assertNotIn("agent.json", findings_by_path)
        self.assertEqual(
            "sensitive_data_shape",
            findings_by_path["waitlist/other.gs"]["rule"],
        )
        serialized = json.dumps(report)
        self.assertNotIn(approved, serialized)
        self.assertNotIn(real_customer, serialized)

    def test_real_secret_still_fails_in_synthetic_control_input(self) -> None:
        self.write_policy(
            {
                "source_tree_classification": {
                    "default_class": "repository-source",
                    "path_rules": [
                        {
                            "patterns": ["/tests/synthetic.py"],
                            "class": "synthetic-test-input",
                            "content_contract": "synthetic-test-input",
                            "artifact_disposition": "must-be-absent",
                        }
                    ],
                }
            }
        )
        value = "api_" + "key = " + ("x" * 20)
        self.write("tests/synthetic.py", value + "\n")

        report = publication_guard.scan_repository(
            self.root, manifest=["tests/synthetic.py"]
        )

        self.assertIn("sensitive_data_shape", self.rules(report))
        self.assertNotIn(value, json.dumps(report))

    def test_nondeploy_classification_is_proven_against_artifact_manifest(self) -> None:
        policy = {
            "source_tree_classification": {
                "default_class": "repository-source",
                "artifact_manifest": publication_guard.MANIFEST_FILENAME,
                "path_rules": [
                    {
                        "patterns": ["/tests/synthetic.py"],
                        "class": "synthetic-test-input",
                        "content_contract": "synthetic-test-input",
                        "artifact_disposition": "must-be-absent",
                    }
                ],
            }
        }
        self.write_policy(policy)
        self.write("tests/synthetic.py", "safe\n")
        self.write(
            publication_guard.MANIFEST_FILENAME,
            json.dumps(
                {
                    "paths": [
                        {"path": "tests/synthetic.py", "class": "site-content"}
                    ]
                }
            ),
        )

        report = publication_guard.scan_repository(
            self.root, manifest=["tests/synthetic.py"]
        )

        self.assertEqual(
            ["nondeploy_path_in_artifact_manifest"], self.rules(report)
        )

    def test_selected_untracked_source_is_scanned_when_explicitly_manifested(self) -> None:
        self.write("tracked.txt", "safe\n")
        value = "gh" + "p_" + ("z" * 24)
        self.write("selected.txt", value + "\n")
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

        default_report = publication_guard.scan_repository(self.root)
        selected_report = publication_guard.scan_repository(
            self.root, manifest=["selected.txt"]
        )

        self.assertEqual("pass", default_report["result"])
        self.assertIn("sensitive_data_shape", self.rules(selected_report))
        self.assertNotIn(value, json.dumps(selected_report))

    def test_special_files_fail_closed_without_being_opened(self) -> None:
        self.write("directory/child.txt", "safe\n")
        special = self.root / "pipe"
        try:
            os.mkfifo(special)
        except (AttributeError, NotImplementedError, OSError):
            self.skipTest("named pipes are unavailable")

        report = publication_guard.scan_repository(
            self.root, manifest=["directory", "pipe"]
        )

        self.assertEqual(
            ["unsupported_file_type", "unsupported_file_type"],
            self.rules(report),
        )
        self.assertEqual(2, len(report["unscanned_paths"]))

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
        self.assertEqual(len(report["unscanned_paths"]), 3)
        self.assertIn("escape.txt", report["unscanned_paths"])
        self.assertEqual(
            sum(path.startswith("redacted-path:") for path in report["unscanned_paths"]),
            2,
        )
        self.assertNotIn("../outside.txt", json.dumps(report))
        self.assertNotIn(os.fspath(outside), json.dumps(report))

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

        self.assertEqual(self.rules(report), ["invalid_utf8", "forbidden_phrase"])
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

    def test_current_repository_is_clean_fully_classified_and_content_free(self) -> None:
        report = publication_guard.scan_repository(
            REPOSITORY_ROOT,
            policy_path=REPOSITORY_ROOT / publication_guard.POLICY_FILENAME,
        )
        tracked_count = len(
            subprocess.check_output(
                ["git", "-C", os.fspath(REPOSITORY_ROOT), "ls-files", "-z"]
            )
            .rstrip(b"\0")
            .split(b"\0")
        )

        self.assertEqual("pass", report["result"])
        self.assertEqual(0, report["finding_count"])
        self.assertEqual(tracked_count, report["source_file_count"])
        self.assertEqual(
            tracked_count, report["scan_counts"]["classified_paths"]
        )
        self.assertEqual([], report["skipped_paths"])
        records = {
            record["path"]: record for record in report["coverage_records"]
        }
        self.assertEqual(
            "publication-control",
            records[publication_guard.POLICY_FILENAME]["category"],
        )
        self.assertEqual(
            "guardrail-synthetic-test-input",
            records["tests/test_publication_guard_source.py"]["category"],
        )
        self.assertEqual(
            "must-be-absent",
            records["tests/test_publication_guard_source.py"][
                "artifact_disposition"
            ],
        )
        self.assertIsNone(
            records["tests/test_publication_guard_source.py"][
                "artifact_manifest_class"
            ]
        )
        self.assertEqual(
            "nondeploy-waitlist-implementation",
            records["waitlist/Code.gs"]["category"],
        )
        self.assertEqual(publication_guard.ARTIFACT_BOUNDARY, report["artifact_boundary"])
        serialized = json.dumps(report)
        self.assertNotIn('"spec": "rapp/1"', serialized)
        self.assertNotIn('"payload"', serialized)

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

    def test_policy_and_manifest_parse_failures_are_sanitized(self) -> None:
        policy_path = self.write(
            publication_guard.POLICY_FILENAME,
            '{"forbidden_phrases": [',
        )
        with self.assertRaisesRegex(publication_guard.GuardError, "invalid JSON"):
            publication_guard.scan_repository(
                self.root,
                policy_path=policy_path,
                manifest=[],
            )

        self.write(
            publication_guard.POLICY_FILENAME,
            '{"max_file_bytes":8,"max_file_bytes":16}',
        )
        with self.assertRaisesRegex(publication_guard.GuardError, "duplicate JSON keys"):
            publication_guard.scan_repository(self.root, manifest=[])

        self.write_policy(
            {
                "public_forbidden": {
                    "phrase_patterns": {"patterns": ["("]},
                }
            }
        )
        with self.assertRaisesRegex(
            publication_guard.GuardError, "invalid regular expression"
        ):
            publication_guard.scan_repository(self.root, manifest=[])

        self.write_policy({})
        bad_manifest = self.write("bad.manifest", b"{\xff")
        with self.assertRaisesRegex(publication_guard.GuardError, "valid UTF-8 JSON"):
            publication_guard.scan_repository(
                self.root,
                manifest=bad_manifest,
            )

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
