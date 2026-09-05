"""The registry is the single source of truth for CLI and dashboard alike, so the
catalogue it produces is a contract: names stay stable, groups resolve, and every
module declares what it can be pointed at."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import registry
from base import SEVERITIES, ScanModule

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def reg():
    return registry.discover("modules")


def test_every_module_is_discovered(reg):
    assert reg, "no modules discovered"
    for name, module in reg.items():
        assert isinstance(module, ScanModule)
        assert module.name == name
        assert module.description, f"{name} has no client-facing description"
        assert module.target_kinds, f"{name} declares no target kinds"
        assert module.groups, f"{name} belongs to no group"


def test_descriptions_never_name_underlying_tooling(reg):
    """White-label rule: a description reaches the client dashboard verbatim."""
    banned = ("nuclei", "zap", "wazuh", "prowler", "puppeteer", "checkdmarc", "dnsperf", "crt.sh")
    for module in reg.values():
        lowered = module.description.lower()
        for term in banned:
            assert term not in lowered, (
                f"{module.name} names {term!r} in a client-facing description"
            )


def test_groups_resolve_to_modules(reg):
    for group in registry.all_groups(reg):
        assert registry.select(reg, group=group), f"group {group!r} resolves to nothing"


def test_unknown_module_selection_is_rejected(reg):
    with pytest.raises(KeyError):
        registry.select(reg, modules=["no_such_module"])


def test_catalog_shape_matches_dashboard_contract(reg):
    catalog = registry.catalog(reg)
    assert len(catalog) == len(reg)
    for entry in catalog:
        assert set(entry) >= {"name", "description", "groups", "kind"}
        assert entry["kind"] == "scan"
        assert entry["target_kinds"]
    # Sorted by name so the dashboard renders deterministically.
    assert [e["name"] for e in catalog] == sorted(e["name"] for e in catalog)


def test_severities_are_ordered_lowest_to_highest():
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")


def _cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "cli.py", *args],
        cwd=ROOT / "module_framework",
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_lists_modules_as_json():
    proc = _cli("--list-modules")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["modules"] and payload["groups"]


def test_cli_dry_run_touches_no_network():
    """--dry-run must validate selection and targets and then stop. This is the
    guard that lets the pipeline exercise the whole JSON contract safely."""
    proc = _cli(
        "--dry-run", "--group", "quick", "--targets", "example.com,10.0.0.0/30", "--client", "acme"
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["dry_run"] is True
    assert payload["findings"] == []
    assert payload["client"] == "acme"
    assert payload["target_count"] == 3  # example.com + 2 usable host IPs
    assert payload["modules_run"]


def test_cli_rejects_empty_target_set():
    proc = _cli("--group", "quick", "--targets", ",,")
    assert proc.returncode == 2
