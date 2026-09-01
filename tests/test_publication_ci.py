from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import validate_publication_workflow


class PublicationWorkflowTests(unittest.TestCase):
    workflow_path = ROOT / ".github" / "workflows" / "release-pages.yml"

    def document(self) -> dict[str, object]:
        return dict(validate_publication_workflow.load_workflow(self.workflow_path))

    def gate_steps(self, document: dict[str, object]) -> list[dict[str, object]]:
        return document["jobs"]["gate"]["steps"]

    def named_step(
        self, document: dict[str, object], name: str
    ) -> dict[str, object]:
        return next(step for step in self.gate_steps(document) if step["name"] == name)

    def assert_rejected(self, document: dict[str, object]) -> None:
        with self.assertRaises(validate_publication_workflow.WorkflowError):
            validate_publication_workflow.validate_workflow_document(document)

    def test_workflow_parses_and_satisfies_publication_contract(self) -> None:
        pins = validate_publication_workflow.validate_workflow_document(self.document())

        self.assertEqual(
            {
                "actions/checkout",
                "actions/deploy-pages",
                "actions/setup-python",
                "actions/upload-artifact",
            },
            set(pins),
        )
        self.assertTrue(all(len(sha) == 40 for sha in pins.values()))

    def test_rejects_mutable_actions_credentials_and_continue_on_error(self) -> None:
        mutations = []

        mutable = copy.deepcopy(self.document())
        self.gate_steps(mutable)[0]["uses"] = "actions/checkout@v7"
        mutations.append(mutable)

        credentials = copy.deepcopy(self.document())
        self.named_step(credentials, "Check out exact commit")["with"][
            "persist-credentials"
        ] = "true"
        mutations.append(credentials)

        continued = copy.deepcopy(self.document())
        self.named_step(continued, "Build, scan, and seal exact Pages payload")[
            "continue-on-error"
        ] = True
        mutations.append(continued)

        for document in mutations:
            with self.subTest():
                self.assert_rejected(document)

    def test_rejects_permissions_timeouts_and_stale_concurrency(self) -> None:
        permissions = copy.deepcopy(self.document())
        permissions["permissions"]["contents"] = "write"

        timeout = copy.deepcopy(self.document())
        timeout["jobs"]["gate"].pop("timeout-minutes")

        concurrency = copy.deepcopy(self.document())
        concurrency["concurrency"]["cancel-in-progress"] = False

        stale_group = copy.deepcopy(self.document())
        stale_group["concurrency"]["group"] = "publication-pages"

        for document in (permissions, timeout, concurrency, stale_group):
            with self.subTest():
                self.assert_rejected(document)

    def test_rejects_root_upload_pr_deploy_and_skipped_dependency(self) -> None:
        root_upload = copy.deepcopy(self.document())
        self.named_step(root_upload, "Upload exact Pages artifact")["with"]["path"] = "."

        pr_deploy = copy.deepcopy(self.document())
        pr_deploy["jobs"]["deploy"]["if"] = "${{ needs.gate.outputs.checked_commit == github.sha }}"

        skipped_dependency = copy.deepcopy(self.document())
        skipped_dependency["jobs"]["deploy"]["needs"] = []

        always_deploy = copy.deepcopy(self.document())
        always_deploy["jobs"]["deploy"]["if"] = "${{ always() }}"

        for document in (root_upload, pr_deploy, skipped_dependency, always_deploy):
            with self.subTest():
                self.assert_rejected(document)

    def test_rejects_unbound_evidence_and_path_overlap(self) -> None:
        unbound = copy.deepcopy(self.document())
        evidence_step = self.named_step(
            unbound, "Validate generated artifact and payload evidence"
        )
        evidence_step["run"] = evidence_step["run"].replace(
            ' --expected-commit "$GITHUB_SHA"', ""
        )

        overlap = copy.deepcopy(self.document())
        overlap["env"]["PUBLICATION_EVIDENCE"] = overlap["env"]["PAGES_STAGE"] + (
            "/evidence.json"
        )

        source_overlap = copy.deepcopy(self.document())
        source_overlap["env"]["SOURCE_EVIDENCE"] = source_overlap["env"][
            "PAGES_PAYLOAD"
        ]

        wrong_artifact = copy.deepcopy(self.document())
        wrong_artifact["jobs"]["deploy"]["steps"][0]["with"]["artifact_name"] = (
            "github-pages"
        )

        for document in (unbound, overlap, source_overlap, wrong_artifact):
            with self.subTest():
                self.assert_rejected(document)

    def test_rejects_mutable_step_between_final_payload_verification_and_upload(
        self,
    ) -> None:
        document = copy.deepcopy(self.document())
        steps = self.gate_steps(document)
        upload_index = next(
            index
            for index, step in enumerate(steps)
            if step["name"] == "Upload exact Pages artifact"
        )
        steps.insert(upload_index, {"name": "Mutable substitution", "run": "true"})

        self.assert_rejected(document)


if __name__ == "__main__":
    unittest.main()
