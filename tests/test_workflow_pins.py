"""Every third-party action in the workflows is pinned to a full commit SHA.

A tag such as `v4` can be moved to different code after it was reviewed, and
that code would run with whatever the job holds: client data and API keys in the
scan workflow. A commit SHA cannot be moved. The version comment is required too,
because a bare SHA tells a reviewer nothing about what is being upgraded.

The workflows are read as parsed YAML nodes rather than with a line regex, so
quoting or flow style (`{uses: ...}`) cannot hide a reference from the check.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"

PINNED_REF = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}")
VERSION_COMMENT = re.compile(r"\s+# v[0-9]+\.[0-9]+\.[0-9]+\s*")

SHA = "0123456789abcdef0123456789abcdef01234567"
ENGINE = "IronCityIT/consensus-engine/.github/workflows/analyze.yml@main"


class Use(NamedTuple):
    line: int
    action: str
    trailing: str  # what follows the value on its line: the comment, if any


def is_allowed(action: str, trailing: str) -> bool:
    """Local path, first-party reference, or a full SHA with its exact version."""
    if action.startswith(("./", "IronCityIT/")):
        return True
    return bool(PINNED_REF.fullmatch(action) and VERSION_COMMENT.fullmatch(trailing))


def find_uses(text: str) -> list[Use]:
    """Every `uses:` value in a workflow, with its line number and comment."""

    def walk(node: yaml.Node | None) -> Iterator[Use]:
        if isinstance(node, yaml.SequenceNode):
            for item in node.value:
                yield from walk(item)
        elif isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if key.value == "uses" and isinstance(value, yaml.ScalarNode):
                    trailing = text[value.end_mark.index :].partition("\n")[0]
                    yield Use(value.start_mark.line + 1, value.value, trailing)
                else:
                    yield from walk(value)

    return list(walk(yaml.compose(text, Loader=yaml.SafeLoader)))


def unpinned(name: str, text: str) -> list[str]:
    """One `file:line: action` entry for each reference that breaks the rule."""
    return [
        f"{name}:{use.line}: {use.action}{use.trailing}"
        for use in find_uses(text)
        if not is_allowed(use.action, use.trailing)
    ]


def workflow_texts() -> dict[str, str]:
    paths = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    return {path.name: path.read_text(encoding="utf-8") for path in paths}


def workflow_with(step: str) -> str:
    return f"jobs:\n  build:\n    steps:\n      - {step}\n"


def test_every_third_party_action_is_pinned():
    problems = [
        problem for name, text in workflow_texts().items() for problem in unpinned(name, text)
    ]
    assert not problems, "pin these as owner/repo@<40-hex-sha> # vX.Y.Z:\n" + "\n".join(problems)


def test_the_check_is_looking_at_real_references():
    """An empty glob or a walker that finds nothing must not read as a pass."""
    assert [use for text in workflow_texts().values() for use in find_uses(text)]


@pytest.mark.parametrize(
    "step",
    [
        pytest.param("uses: actions/checkout@v4", id="major tag"),
        pytest.param("uses: actions/checkout@v4.4.0 # v4.4.0", id="exact tag is still movable"),
        pytest.param("uses: actions/checkout@main # v4.4.0", id="branch"),
        pytest.param("uses: actions/checkout", id="no ref"),
        pytest.param(f"uses: actions/checkout@{SHA[:7]} # v4.4.0", id="short sha"),
        pytest.param(f"uses: actions/checkout@{SHA.upper()} # v4.4.0", id="uppercase sha"),
        pytest.param(f"uses: actions/checkout@{SHA}0 # v4.4.0", id="sha too long"),
        pytest.param(f"uses: actions/checkout@{SHA}", id="no version comment"),
        pytest.param(f"uses: actions/checkout@{SHA} # v4", id="comment is only a major"),
        pytest.param(f"uses: actions/checkout@{SHA} # pinned", id="comment is not a version"),
        pytest.param("uses: docker://alpine:3.20", id="docker image tag"),
        pytest.param("uses: NotIronCityIT/tool@main", id="lookalike owner"),
        pytest.param('"uses": "actions/checkout@v4"', id="quoted"),
        pytest.param("{uses: actions/checkout@v4}", id="flow style"),
    ],
)
def test_rejects(step):
    problems = unpinned("ci.yml", workflow_with(step))
    assert len(problems) == 1
    assert problems[0].startswith("ci.yml:4: ")


@pytest.mark.parametrize(
    "step",
    [
        pytest.param(f"uses: actions/checkout@{SHA} # v4.4.0", id="pinned"),
        pytest.param(f"uses: github/codeql-action/init@{SHA} # v3.1.2", id="pinned subpath"),
        pytest.param("uses: ./.github/actions/setup", id="local path"),
        pytest.param(f"uses: {ENGINE}", id="first-party reusable workflow"),
    ],
)
def test_accepts(step):
    text = workflow_with(step)
    assert len(find_uses(text)) == 1
    assert unpinned("ci.yml", text) == []


def test_failure_names_file_line_and_action():
    text = workflow_with("uses: actions/checkout@v4")
    assert unpinned("ci.yml", text) == ["ci.yml:4: actions/checkout@v4"]


def test_job_level_reusable_workflow_is_checked():
    text = "jobs:\n  call:\n    uses: someone/else/.github/workflows/x.yml@main\n"
    assert unpinned("ci.yml", text) == ["ci.yml:3: someone/else/.github/workflows/x.yml@main"]
