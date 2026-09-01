#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK_ROOT=$(dirname -- "$ROOT")/.guardrail-check-$(basename -- "$ROOT")-$$
ARTIFACT=$WORK_ROOT/artifact
SOURCE_EVIDENCE=$WORK_ROOT/source-evidence.json
ARTIFACT_EVIDENCE=$WORK_ROOT/artifact-evidence.json

cleanup() {
  rm -rf -- "$WORK_ROOT"
  find "$ROOT" -type d -name __pycache__ -prune -exec rm -rf -- {} +
}
trap cleanup EXIT HUP INT TERM

mkdir -p -- "$WORK_ROOT"
cd -- "$ROOT"
export PYTHONDONTWRITEBYTECODE=1

python3 release-pages-selftest.py
python3 scripts/publication_guard.py \
  --root . \
  --policy PUBLICATION-POLICY.json \
  --output "$SOURCE_EVIDENCE" \
  --compact
python3 scripts/publication_artifact.py \
  --compact \
  build-scan \
  --source . \
  --artifact "$ARTIFACT" \
  --evidence "$ARTIFACT_EVIDENCE"
python3 -m unittest -v tests/test_audit_public_ip.py
python3 -m unittest discover -s tests -p 'test_publication_*.py' -v

python3 - "$SOURCE_EVIDENCE" "$ARTIFACT_EVIDENCE" <<'PY'
import json
import sys

source = json.load(open(sys.argv[1], encoding="utf-8"))
artifact = json.load(open(sys.argv[2], encoding="utf-8"))
print(
    "Guardrail checks passed: "
    f"source={source['finding_count']} findings/"
    f"{source['scanned_path_count']} files; "
    f"artifact={artifact['scan_counts']['findings']} findings/"
    f"{artifact['generated_artifact_count']} files/"
    f"{artifact['scan_counts']['links']} links"
)
PY
