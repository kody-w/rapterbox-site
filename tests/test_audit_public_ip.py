from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "audit_public_ip.py"
SPEC = importlib.util.spec_from_file_location("audit_public_ip", MODULE_PATH)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class PublicIpAuditTests(unittest.TestCase):
    work = Path(__file__).parent / ".audit-test-work"

    def setUp(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def fixture_transport(self, responses):
        return audit.FixtureTransport(responses, fallback=None, max_bytes=1024 * 1024)

    def write_json(self, name: str, value) -> Path:
        path = self.work / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_404_sentinel_body_is_unreachable_and_not_hashed(self) -> None:
        url = "https://example.com/removed"
        transport = self.fixture_transport(
            {url: {"status": 404, "body": "200 OK - cached sentinel body"}}
        )

        artifact = audit.classify_url(url, transport)

        self.assertEqual("unreachable", artifact.classification)
        self.assertEqual(404, artifact.status)
        self.assertIsNone(artifact.sha256)

    def test_reachable_body_is_hashed_without_emitting_body(self) -> None:
        url = "https://example.com/current"
        body = b"public artifact"
        transport = self.fixture_transport(
            {url: {"status": 200, "body": body.decode()}}
        )

        artifact = audit.classify_url(url, transport)
        serialized = artifact.to_dict()

        self.assertEqual("reachable-current", artifact.classification)
        self.assertEqual(hashlib.sha256(body).hexdigest(), artifact.sha256)
        self.assertNotIn(body.decode(), json.dumps(serialized))

    def test_network_failure_is_probe_error_not_finding(self) -> None:
        url = "https://example.com/failure"
        transport = self.fixture_transport({url: {"error": "timeout"}})

        artifact = audit.classify_url(url, transport)

        self.assertEqual("probe-error", artifact.classification)
        self.assertEqual("timeout", artifact.detail)
        self.assertIsNone(artifact.status)

    def test_link_document_detects_forbidden_url_and_hashes_document(self) -> None:
        document = "https://links.example.org/index.html"
        forbidden = "https://example.com/foundational-ip"
        body = f'<a href="{forbidden}">historical copy</a>'
        transport = self.fixture_transport(
            {document: {"status": 200, "body": body}}
        )

        artifact = audit.classify_link_document(document, [forbidden], transport)

        self.assertEqual("linked", artifact.classification)
        self.assertEqual((forbidden,), artifact.matches)
        self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), artifact.sha256)
        self.assertNotIn("historical copy", json.dumps(artifact.to_dict()))

    def test_repo_metadata_distinguishes_forks_and_current_repos(self) -> None:
        responses = {
            "https://api.github.com/repos/acme/fork": {
                "status": 200,
                "json": {"fork": True},
            },
            "https://api.github.com/repos/acme/current": {
                "status": 200,
                "json": {"fork": False},
            },
        }
        transport = self.fixture_transport(responses)

        fork = audit.classify_repo("acme/fork", transport)
        current = audit.classify_repo("https://github.com/acme/current", transport)

        self.assertEqual("fork-indicator", fork.classification)
        self.assertEqual("reachable-current", current.classification)
        self.assertIsNotNone(fork.sha256)
        self.assertIsNotNone(current.sha256)

    def test_search_results_support_common_shapes_without_emitting_snippets(self) -> None:
        forbidden = "https://example.com/removed"
        path = self.write_json(
            "search.json",
            {
                "items": [
                    {
                        "link": "https://cache.example.net/result",
                        "cached_url": "https://cache.example.net/copy",
                        "snippet": "private-looking text must not enter the report",
                    },
                    {
                        "html_url": "https://github.com/acme/copy",
                        "repository": {"fork": True},
                    },
                    {
                        "url": "http://127.0.0.1/internal",
                        "snippet": forbidden,
                    },
                ]
            },
        )

        artifacts = audit.classify_search_results(path, [forbidden])
        serialized = json.dumps([item.to_dict() for item in artifacts])

        self.assertEqual(
            ["cached-indicator", "fork-indicator", "probe-error"],
            [item.classification for item in artifacts],
        )
        self.assertNotIn("private-looking text", serialized)
        self.assertNotIn("127.0.0.1", serialized)

    def test_private_and_credentialed_urls_are_rejected(self) -> None:
        for value in (
            "http://127.0.0.1/secret",
            "http://10.0.0.1/secret",
            "https://" + "user:" + "password@" + "example.com/private",
            "https://[" + "not-ipv6/path",
            "https://example.com/%" + "GG",
            "file:///private/data",
        ):
            with self.subTest(value=value):
                with self.assertRaises(audit.AuditInputError):
                    audit.validate_public_url(value)

    def test_offline_cli_writes_deterministic_json_and_markdown(self) -> None:
        target = "https://example.com/removed"
        document = "https://links.example.org/index.html"
        fixture = self.write_json(
            "fixture.json",
            {
                "responses": {
                    target: {"status": 410, "body": "gone sentinel"},
                    document: {
                        "status": 200,
                        "body": f"See {target}",
                    },
                    "https://api.github.com/repos/acme/copy": {
                        "status": 200,
                        "json": {"fork": True},
                    },
                }
            },
        )
        search = self.write_json(
            "results.json",
            [{"url": "https://cache.example.net/hit", "snippet": target}],
        )
        first_json = self.work / "first.json"
        first_md = self.work / "first.md"
        second_json = self.work / "second.json"
        second_md = self.work / "second.md"
        common = [
            "--url",
            target,
            "--repo",
            "acme/copy",
            "--link-document",
            document,
            "--forbidden-url",
            target,
            "--search-results",
            str(search),
            "--fixture-json",
            str(fixture),
            "--offline",
        ]

        first_exit = audit.main(
            common + ["--json-report", str(first_json), "--markdown-report", str(first_md)]
        )
        second_exit = audit.main(
            common
            + ["--json-report", str(second_json), "--markdown-report", str(second_md)]
        )

        self.assertEqual(0, first_exit)
        self.assertEqual(0, second_exit)
        self.assertEqual(first_json.read_bytes(), second_json.read_bytes())
        self.assertEqual(first_md.read_bytes(), second_md.read_bytes())
        report = json.loads(first_json.read_text())
        self.assertEqual(4, report["summary"]["total"])
        self.assertEqual(1, report["summary"]["counts"]["unreachable"])
        self.assertEqual(1, report["summary"]["counts"]["linked"])
        self.assertEqual(1, report["summary"]["counts"]["cached-indicator"])
        self.assertEqual(1, report["summary"]["counts"]["fork-indicator"])
        self.assertNotIn("gone sentinel", first_json.read_text())

    def test_offline_fixture_miss_writes_report_and_returns_failure(self) -> None:
        fixture = self.write_json("fixture.json", {"responses": {}})
        json_report = self.work / "report.json"
        markdown_report = self.work / "report.md"

        exit_code = audit.main(
            [
                "--url",
                "https://example.com/missing-fixture",
                "--fixture-json",
                str(fixture),
                "--offline",
                "--json-report",
                str(json_report),
                "--markdown-report",
                str(markdown_report),
            ]
        )

        self.assertEqual(1, exit_code)
        report = json.loads(json_report.read_text())
        self.assertEqual("probe-error", report["artifacts"][0]["classification"])
        self.assertEqual("fixture-miss", report["artifacts"][0]["detail"])

    def test_audit_report_is_not_a_rapp_protocol_frame(self) -> None:
        report = audit.build_report(
            [
                audit.Artifact(
                    kind="url",
                    source="https://example.com/",
                    classification="unreachable",
                    status=404,
                )
            ],
            generated_at=None,
        )

        self.assertEqual(
            {"schema_version", "summary", "artifacts"},
            set(report),
        )
        serialized = json.dumps(report)
        self.assertNotIn('"rapp/1"', serialized)
        self.assertNotIn('"data_slush"', serialized)


if __name__ == "__main__":
    unittest.main()
