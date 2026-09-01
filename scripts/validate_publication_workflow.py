#!/usr/bin/env python3
"""Validate the immutable, least-privilege publication workflow contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping, Sequence


ACTION_PATTERN = re.compile(r"(?P<name>[^@\s]+)@(?P<sha>[0-9a-f]{40})")
DEFAULT_WORKFLOW = ".github/workflows/release-pages.yml"
EXPECTED_ACTIONS = {
    "actions/checkout",
    "actions/deploy-pages",
    "actions/setup-python",
    "actions/upload-artifact",
}
DEFAULT_BRANCH_GUARDS = (
    "github.event_name == 'push'",
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
    "github.ref_protected == true",
    "github.sha == github.event.after",
)


class WorkflowError(Exception):
    """A stable workflow contract failure."""


def _fail(code: str) -> None:
    raise WorkflowError(code)


def load_workflow(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("workflow_not_json_yaml")
    if not isinstance(document, Mapping):
        _fail("workflow_invalid")
    return document


def _jobs(document: Mapping[str, Any]) -> Mapping[str, Any]:
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping):
        _fail("jobs_missing")
    return jobs


def _steps(job: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    steps = job.get("steps")
    if not isinstance(steps, list) or not all(isinstance(step, Mapping) for step in steps):
        _fail("steps_missing")
    return steps


def _step_by_name(steps: list[Mapping[str, Any]], name: str) -> Mapping[str, Any]:
    matches = [step for step in steps if step.get("name") == name]
    if len(matches) != 1:
        _fail("required_step_missing")
    return matches[0]


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, Mapping):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def _expanded_runner_path(value: str) -> PurePosixPath:
    replacements = {
        "${{ runner.temp }}": "/runner-temp",
        "${{ github.run_id }}": "1",
        "${{ github.run_attempt }}": "1",
        "${{ github.sha }}": "a" * 40,
    }
    for source, replacement in replacements.items():
        value = value.replace(source, replacement)
    if "${{" in value or not value.startswith("/runner-temp/"):
        _fail("runner_path_invalid")
    return PurePosixPath(value)


def validate_workflow_document(document: Mapping[str, Any]) -> dict[str, str]:
    triggers = document.get("on")
    if not isinstance(triggers, Mapping) or not {"push", "pull_request"} <= set(triggers):
        _fail("triggers_incomplete")
    if document.get("permissions") != {"contents": "read"}:
        _fail("workflow_permissions")
    concurrency = document.get("concurrency")
    if (
        not isinstance(concurrency, Mapping)
        or concurrency.get("cancel-in-progress") is not True
        or "github.ref" not in str(concurrency.get("group", ""))
    ):
        _fail("concurrency_invalid")
    if _contains_key(document, "continue-on-error"):
        _fail("continue_on_error_forbidden")

    jobs = _jobs(document)
    if set(jobs) != {"gate", "deploy"}:
        _fail("jobs_invalid")
    gate = jobs["gate"]
    deploy = jobs["deploy"]
    if not isinstance(gate, Mapping) or not isinstance(deploy, Mapping):
        _fail("jobs_invalid")
    for job in (gate, deploy):
        timeout = job.get("timeout-minutes")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 20:
            _fail("timeout_invalid")
    if gate.get("runs-on") != "ubuntu-24.04":
        _fail("runner_not_bounded")
    if deploy.get("needs") != ["gate"]:
        _fail("deploy_dependency")
    if deploy.get("permissions") != {
        "contents": "read",
        "id-token": "write",
        "pages": "write",
    }:
        _fail("deploy_permissions")
    environment = deploy.get("environment")
    if not isinstance(environment, Mapping) or environment.get("name") != "github-pages":
        _fail("pages_environment")
    deploy_if = str(deploy.get("if", ""))
    if not all(guard in deploy_if for guard in DEFAULT_BRANCH_GUARDS):
        _fail("deploy_branch_guard")
    if "needs.gate.outputs.checked_commit == github.sha" not in deploy_if:
        _fail("deploy_commit_unbound")

    pins: dict[str, str] = {}
    action_uses: dict[str, int] = {}
    for job in jobs.values():
        for step in _steps(job):
            if "uses" not in step:
                continue
            match = ACTION_PATTERN.fullmatch(str(step["uses"]))
            if not match:
                _fail("mutable_action")
            name = match.group("name")
            sha = match.group("sha")
            if name in pins and pins[name] != sha:
                _fail("inconsistent_action_pin")
            pins[name] = sha
            action_uses[name] = action_uses.get(name, 0) + 1
    if (
        set(pins) != EXPECTED_ACTIONS
        or action_uses.get("actions/upload-artifact") != 2
        or any(
            action_uses.get(name) != 1
            for name in EXPECTED_ACTIONS - {"actions/upload-artifact"}
        )
    ):
        _fail("action_set_invalid")

    steps = _steps(gate)
    names = [str(step.get("name", "")) for step in steps]
    required_order = [
        "Check out exact commit",
        "Set up deterministic Python",
        "Verify checked commit and runtime",
        "Scan classified publication source",
        "Validate source evidence against Git objects",
        "Verify release claims and metadata",
        "Run publication gate tests",
        "Build, scan, and seal exact Pages payload",
        "Validate generated artifact and payload evidence",
        "Bind gated commit",
        "Upload private publication evidence",
        "Final verify immutable Pages payload",
        "Upload exact Pages artifact",
    ]
    try:
        indices = [names.index(name) for name in required_order]
    except ValueError:
        _fail("required_step_missing")
    if indices != sorted(indices):
        _fail("gate_order_invalid")
    if names.index("Validate source evidence against Git objects") != names.index(
        "Scan classified publication source"
    ) + 1:
        _fail("source_evidence_not_immediate")
    if names.index(
        "Validate generated artifact and payload evidence"
    ) != names.index("Build, scan, and seal exact Pages payload") + 1:
        _fail("artifact_evidence_not_immediate")

    checkout = _step_by_name(steps, "Check out exact commit")
    checkout_with = checkout.get("with")
    if (
        not isinstance(checkout_with, Mapping)
        or checkout_with.get("persist-credentials") != "false"
        or checkout_with.get("ref") != "${{ github.sha }}"
    ):
        _fail("checkout_unbound")
    setup = _step_by_name(steps, "Set up deterministic Python")
    setup_with = setup.get("with")
    if (
        not isinstance(setup_with, Mapping)
        or setup_with.get("python-version") != "3.12.11"
        or setup_with.get("check-latest") != "false"
    ):
        _fail("python_not_deterministic")

    source_scan = str(_step_by_name(steps, "Scan classified publication source").get("run", ""))
    for fragment in (
        "scripts/publication_guard.py",
        "--manifest PUBLICATION-SOURCE-MANIFEST.json",
        '--output "$SOURCE_EVIDENCE"',
    ):
        if fragment not in source_scan:
            _fail("source_scan_wiring")
    source_validation = str(
        _step_by_name(steps, "Validate source evidence against Git objects").get(
            "run", ""
        )
    )
    for fragment in (
        "validate_publication_evidence.py source",
        '--manifest PUBLICATION-SOURCE-MANIFEST.json',
        '--evidence "$SOURCE_EVIDENCE"',
        '--expected-commit "$GITHUB_SHA"',
    ):
        if fragment not in source_validation:
            _fail("source_evidence_unbound")

    build_scan = str(
        _step_by_name(steps, "Build, scan, and seal exact Pages payload").get(
            "run", ""
        )
    )
    for fragment in (
        "scripts/publication_artifact.py",
        "build-scan",
        '--source .',
        '--artifact "$PAGES_STAGE"',
        '--payload "$PAGES_PAYLOAD"',
        '--evidence "$PUBLICATION_EVIDENCE"',
    ):
        if fragment not in build_scan:
            _fail("artifact_build_wiring")
    validate_evidence = str(
        _step_by_name(
            steps, "Validate generated artifact and payload evidence"
        ).get("run", "")
    )
    for fragment in (
        "validate_publication_evidence.py artifact",
        '--artifact "$PAGES_STAGE"',
        '--payload "$PAGES_PAYLOAD"',
        '--evidence "$PUBLICATION_EVIDENCE"',
        '--expected-commit "$GITHUB_SHA"',
    ):
        if fragment not in validate_evidence:
            _fail("evidence_unbound")

    env = document.get("env")
    if not isinstance(env, Mapping):
        _fail("paths_missing")
    pages_stage = env.get("PAGES_STAGE")
    pages_path = env.get("PAGES_PAYLOAD")
    evidence_path = env.get("PUBLICATION_EVIDENCE")
    source_evidence_path = env.get("SOURCE_EVIDENCE")
    if not all(
        isinstance(path, str)
        for path in (pages_stage, pages_path, evidence_path, source_evidence_path)
    ):
        _fail("paths_missing")
    pages_resolved = _expanded_runner_path(pages_path)
    stage_resolved = _expanded_runner_path(pages_stage)
    if pages_resolved.name != "artifact.tar" or stage_resolved == pages_resolved:
        _fail("pages_payload_path_invalid")
    for value in (evidence_path, source_evidence_path):
        resolved = _expanded_runner_path(value)
        if (
            resolved == pages_resolved
            or pages_resolved in resolved.parents
            or resolved == stage_resolved
            or stage_resolved in resolved.parents
        ):
            _fail("artifact_evidence_overlap")

    evidence_upload = _step_by_name(steps, "Upload private publication evidence")
    evidence_with = evidence_upload.get("with")
    if (
        not isinstance(evidence_with, Mapping)
        or evidence_with.get("name") != "publication-evidence-${{ github.sha }}"
        or evidence_with.get("path")
        != "${{ env.SOURCE_EVIDENCE }}\n${{ env.PUBLICATION_EVIDENCE }}"
        or evidence_with.get("if-no-files-found") != "error"
        or evidence_with.get("include-hidden-files") != "false"
        or evidence_with.get("overwrite") != "false"
        or not isinstance(evidence_with.get("retention-days"), int)
        or not 1 <= evidence_with["retention-days"] <= 14
    ):
        _fail("evidence_upload_invalid")

    pages_upload = _step_by_name(steps, "Upload exact Pages artifact")
    pages_with = pages_upload.get("with")
    pages_if = str(pages_upload.get("if", ""))
    if (
        not isinstance(pages_with, Mapping)
        or pages_with.get("path") != "${{ env.PAGES_PAYLOAD }}"
        or pages_with.get("name") != "github-pages-${{ github.sha }}"
        or pages_with.get("retention-days") != 1
        or pages_with.get("include-hidden-files") != "false"
        or pages_with.get("compression-level") != 0
        or pages_with.get("if-no-files-found") != "error"
        or pages_with.get("overwrite") != "false"
        or not all(guard in pages_if for guard in DEFAULT_BRANCH_GUARDS)
    ):
        _fail("pages_upload_invalid")
    if str(pages_with.get("path", "")).strip() in {".", "./", "${{ github.workspace }}"}:
        _fail("root_upload_forbidden")
    final_verify = _step_by_name(steps, "Final verify immutable Pages payload")
    final_if = str(final_verify.get("if", ""))
    if not all(guard in final_if for guard in DEFAULT_BRANCH_GUARDS):
        _fail("final_payload_branch_guard")
    final_run = str(final_verify.get("run", ""))
    for fragment in (
        'rm -rf -- "$PAGES_STAGE"',
        'test ! -e "$PAGES_STAGE"',
        "git diff --quiet HEAD -- .",
        "git diff --cached --quiet HEAD -- .",
        'git status --porcelain=v1 --untracked-files=all',
        "validate_publication_evidence.py artifact",
        '--payload "$PAGES_PAYLOAD"',
        '--evidence "$PUBLICATION_EVIDENCE"',
        '--expected-commit "$GITHUB_SHA"',
    ):
        if fragment not in final_run:
            _fail("final_payload_verification_invalid")
    if "--artifact" in final_run:
        _fail("final_payload_verification_mutable")
    if names.index("Upload exact Pages artifact") != names.index(
        "Final verify immutable Pages payload"
    ) + 1:
        _fail("untrusted_step_after_final_verification")

    outputs = gate.get("outputs")
    if (
        not isinstance(outputs, Mapping)
        or outputs.get("checked_commit") != "${{ steps.bind.outputs.checked_commit }}"
        or outputs.get("pages_artifact_name")
        != "${{ steps.bind.outputs.pages_artifact_name }}"
    ):
        _fail("gate_output_unbound")
    deploy_steps = _steps(deploy)
    deploy_step = _step_by_name(deploy_steps, "Deploy exact gated artifact")
    deploy_with = deploy_step.get("with")
    if (
        not isinstance(deploy_with, Mapping)
        or deploy_with.get("artifact_name") != "${{ needs.gate.outputs.pages_artifact_name }}"
        or deploy_with.get("preview") != "false"
    ):
        _fail("deploy_artifact_unbound")
    return dict(sorted(pins.items()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        pins = validate_workflow_document(load_workflow(Path(args.workflow)))
    except WorkflowError:
        sys.stderr.write("publication workflow validation failed\n")
        return 1
    for name, sha in pins.items():
        print(f"{name}@{sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
