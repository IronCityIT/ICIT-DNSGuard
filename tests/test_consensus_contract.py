"""The scan workflow's call into the shared AI engine matches the engine's contract.

The contract is not assumed. ``tests/fixtures/consensus_engine_contract.json`` is
a snapshot of the ``on.workflow_call`` block of
``IronCityIT/consensus-engine/.github/workflows/analyze.yml``, taken at the commit
recorded inside it — the same commit the caller pins. Bumping the pin without
regenerating the snapshot fails here, and so does any caller edit that drifts
from what the engine declares:

* a required input or secret that is not passed;
* an input or secret the engine does not declare (including ``secrets: inherit``,
  which hands over every secret this repository holds);
* a ``needs.<engine job>.outputs.<name>`` the engine does not produce;
* a ``uses:`` ref that is a moving branch rather than a 40-character commit SHA.

To move to a newer engine: read its ``analyze.yml`` on main, regenerate the
snapshot from that file at that commit, update the pin, and let this test say
what else has to change.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "dns-analysis.yml"
FIXTURE = ROOT / "tests" / "fixtures" / "consensus_engine_contract.json"

ENGINE_PREFIX = "IronCityIT/consensus-engine/"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_REF_RE = re.compile(r"^\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$")
EXPRESSION_RE = re.compile(r"^\s*\$\{\{.*\}\}\s*$", re.DOTALL)


def load_contract() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def load_workflow() -> tuple[dict[str, Any], str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    return yaml.safe_load(text), text


def engine_jobs(workflow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        job_id: job
        for job_id, job in (workflow.get("jobs") or {}).items()
        if str(job.get("uses", "")).startswith(ENGINE_PREFIX)
    }


def _type_matches(declared: str, value: Any) -> bool:
    """A literal must match the declared type; an expression is checked at runtime."""
    if isinstance(value, str) and EXPRESSION_RE.match(value):
        return True
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, str)


def contract_violations(
    job_id: str, job: dict[str, Any], contract: dict[str, Any], workflow_text: str
) -> list[str]:
    """Every way ``job`` disagrees with ``contract``. Empty means it matches."""
    problems: list[str] = []
    source = contract["source"]

    uses = str(job.get("uses", ""))
    path, _, ref = uses.removeprefix(ENGINE_PREFIX).partition("@")
    if path != source["path"]:
        problems.append(f"{job_id}: calls {path!r}, the snapshot is of {source['path']!r}")
    if not SHA_RE.match(ref):
        problems.append(f"{job_id}: ref {ref!r} is not a 40-character commit SHA")
    elif ref != source["commit"]:
        problems.append(
            f"{job_id}: pins {ref}, the contract snapshot is of {source['commit']}"
            " - regenerate the fixture from the pinned commit"
        )

    declared_inputs: dict[str, Any] = contract["inputs"]
    passed_inputs: dict[str, Any] = job.get("with") or {}
    for name, spec in declared_inputs.items():
        if spec["required"] and name not in passed_inputs:
            problems.append(f"{job_id}: required input {name!r} is not passed")
    for name, value in passed_inputs.items():
        if name not in declared_inputs:
            problems.append(f"{job_id}: input {name!r} is not declared by the engine")
        elif not _type_matches(declared_inputs[name]["type"], value):
            problems.append(
                f"{job_id}: input {name!r} is {value!r}, declared {declared_inputs[name]['type']}"
            )

    declared_secrets: dict[str, Any] = contract["secrets"]
    passed_secrets = job.get("secrets") or {}
    if passed_secrets == "inherit":
        problems.append(
            f"{job_id}: 'secrets: inherit' passes every repository secret;"
            " name the declared ones instead"
        )
        passed_secrets = {}
    for name, spec in declared_secrets.items():
        if spec["required"] and name not in passed_secrets:
            problems.append(f"{job_id}: required secret {name!r} is not passed")
    for name, value in passed_secrets.items():
        if name not in declared_secrets:
            problems.append(f"{job_id}: secret {name!r} is not declared by the engine")
        if not SECRET_REF_RE.match(str(value)):
            problems.append(f"{job_id}: secret {name!r} is not a ${{{{ secrets.NAME }}}} reference")

    declared_outputs = set(contract["outputs"])
    consumed = set(
        re.findall(rf"needs\.{re.escape(job_id)}\.outputs\.([A-Za-z0-9_-]+)", workflow_text)
    )
    for name in sorted(consumed - declared_outputs):
        problems.append(f"{job_id}: reads output {name!r}, which the engine does not declare")

    return problems


# --- the real caller ---------------------------------------------------------------


def test_scan_workflow_calls_the_engine() -> None:
    workflow, _ = load_workflow()
    assert engine_jobs(workflow), "dns-analysis.yml no longer calls consensus-engine"


def test_engine_call_matches_the_contract() -> None:
    workflow, text = load_workflow()
    contract = load_contract()
    problems = [
        problem
        for job_id, job in engine_jobs(workflow).items()
        for problem in contract_violations(job_id, job, contract, text)
    ]
    assert problems == []


def test_fixture_passes_the_repo_json_rules() -> None:
    raw = FIXTURE.read_bytes()
    assert raw[:1] == b"{"
    assert raw[-2:] == b"}\n"
    subprocess.run(
        [sys.executable, "-m", "json.tool", str(FIXTURE)],
        check=True,
        capture_output=True,
    )


def test_fixture_records_its_source_commit() -> None:
    source = load_contract()["source"]
    assert source["repository"] == "IronCityIT/consensus-engine"
    assert SHA_RE.match(source["commit"])


# --- the checker catches each kind of drift ----------------------------------------

SHA = "a" * 40
CONTRACT: dict[str, Any] = {
    "source": {"path": ".github/workflows/analyze.yml", "commit": SHA},
    "inputs": {
        "findings_json": {"required": True, "type": "string"},
        "post_to_api": {"required": False, "type": "boolean"},
    },
    "secrets": {"GROQ_API_KEY": {"required": True}, "GEMINI_API_KEY": {"required": False}},
    "outputs": ["consensus_b64"],
}


def _job(**overrides: Any) -> dict[str, Any]:
    job: dict[str, Any] = {
        "uses": f"{ENGINE_PREFIX}.github/workflows/analyze.yml@{SHA}",
        "with": {"findings_json": "${{ needs.analyze.outputs.findings_b64 }}"},
        "secrets": {"GROQ_API_KEY": "${{ secrets.GROQ_API_KEY }}"},
    }
    job.update(overrides)
    return job


def test_a_matching_call_has_no_violations() -> None:
    text = "x: ${{ needs.engine.outputs.consensus_b64 }}"
    assert contract_violations("engine", _job(), CONTRACT, text) == []


@pytest.mark.parametrize(
    ("overrides", "text", "expected"),
    [
        ({"with": {}}, "", "required input 'findings_json' is not passed"),
        (
            {"with": {"findings_json": "x", "target": "example.com"}},
            "",
            "input 'target' is not declared",
        ),
        (
            {"with": {"findings_json": "x", "post_to_api": "yes"}},
            "",
            "input 'post_to_api' is 'yes', declared boolean",
        ),
        ({"secrets": {}}, "", "required secret 'GROQ_API_KEY' is not passed"),
        ({"secrets": "inherit"}, "", "'secrets: inherit' passes every repository secret"),
        (
            {
                "secrets": {
                    "GROQ_API_KEY": "${{ secrets.GROQ_API_KEY }}",
                    "VIRUSTOTAL_API_KEY": "${{ secrets.VIRUSTOTAL_API_KEY }}",
                }
            },
            "",
            "secret 'VIRUSTOTAL_API_KEY' is not declared",
        ),
        (
            {"secrets": {"GROQ_API_KEY": "gsk-literal-value"}},
            "",
            "secret 'GROQ_API_KEY' is not a ${{ secrets.NAME }} reference",
        ),
        ({}, "${{ needs.engine.outputs.result_b64 }}", "reads output 'result_b64'"),
        (
            {"uses": f"{ENGINE_PREFIX}.github/workflows/analyze.yml@main"},
            "",
            "ref 'main' is not a 40-character commit SHA",
        ),
        (
            {"uses": f"{ENGINE_PREFIX}.github/workflows/analyze.yml@{'b' * 40}"},
            "",
            "the contract snapshot is of " + SHA,
        ),
        (
            {"uses": f"{ENGINE_PREFIX}.github/workflows/other.yml@{SHA}"},
            "",
            "calls '.github/workflows/other.yml'",
        ),
    ],
)
def test_each_kind_of_drift_is_reported(
    overrides: dict[str, Any], text: str, expected: str
) -> None:
    problems = contract_violations("engine", _job(**overrides), CONTRACT, text)
    assert any(expected in problem for problem in problems), problems
