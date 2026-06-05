"""Regression coverage for the SBOM workflow post-release path."""

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SBOM_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sbom.yml"


def _read_workflow() -> str:
    return SBOM_WORKFLOW.read_text(encoding="utf-8")


def _job_block(text: str, job_name: str) -> str:
    match = re.search(
        rf"^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, f"missing {job_name} job"
    return match.group("body")


def _aggregate_script(text: str) -> str:
    job = _job_block(text, "sbom")
    match = re.search(
        r"^\s+- name: Aggregate\n\s+run: \|\n(?P<script>.*)",
        job,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match, "missing Aggregate run script"
    return match.group("script")


def test_workflow_run_aggregate_skips_non_success_upstream_builds():
    script = _aggregate_script(_read_workflow())

    assert "github.event.workflow_run.conclusion" in script
    assert re.search(
        r"github\.event\.workflow_run\.conclusion\s*}}\s*\"\s*!=\s*\"success\"",
        script,
    )
    assert re.search(r"upstream build.*skip", script, flags=re.IGNORECASE | re.DOTALL)
    assert "exit 0" in script


def test_sbom_images_timeout_allows_heavyweight_image_scans():
    sbom_images = _job_block(_read_workflow(), "sbom-images")
    match = re.search(r"^\s+timeout-minutes:\s*(\d+)\s*$", sbom_images, flags=re.MULTILINE)

    assert match, "sbom-images must set an explicit timeout"
    assert int(match.group(1)) >= 60
