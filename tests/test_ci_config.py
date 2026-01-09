from pathlib import Path

import pytest
import yaml


def test_ci_cd_workflow_does_not_contain_release_job() -> None:
    """
    Verifies that the `release` job has been removed from `.github/workflows/ci-cd.yml`
    to prevent duplicate publishing logic.
    """
    workflow_path = Path(".github/workflows/ci-cd.yml")
    if not workflow_path.exists():
        pytest.skip("CI/CD workflow file not found")

    with open(workflow_path, "r") as f:
        workflow = yaml.safe_load(f)

    jobs = workflow.get("jobs", {})

    # Edge Case: Verify 'release' job is strictly absent
    assert "release" not in jobs, "The 'release' job should not exist in ci-cd.yml. It belongs in publish.yml."

    # Edge Case: Verify no other job depends on 'release' (dangling dependency)
    for job_name, job_def in jobs.items():
        if "needs" in job_def:
            needs = job_def["needs"]
            if isinstance(needs, str):
                needs = [needs]
            assert "release" not in needs, f"Job '{job_name}' depends on removed job 'release'"


def test_publish_workflow_handles_release() -> None:
    """
    Verifies that `.github/workflows/publish.yml` exists and is responsible for releases.
    """
    workflow_path = Path(".github/workflows/publish.yml")
    if not workflow_path.exists():
        pytest.skip("Publish workflow file not found")

    with open(workflow_path, "r") as f:
        workflow = yaml.safe_load(f)

    # PyYAML 1.1 parses unquoted 'on' as boolean True.
    # We check for 'on' (string) or True (boolean) keys.
    on_trigger = workflow.get("on")
    if on_trigger is None:
        on_trigger = workflow.get(True)

    assert on_trigger is not None, "Publish workflow is missing 'on' trigger"

    assert "release" in on_trigger or (isinstance(on_trigger, dict) and "release" in on_trigger.keys()), (
        "Publish workflow should trigger on release events"
    )
