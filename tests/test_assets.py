"""The asset inventory: what of the client's is on the internet.

`AssetSink` was built with the framework and then wired to nothing — defined in
`base.py`, referenced by no module and created by no runner, so every scan
produced an empty inventory and nobody noticed because nothing read it.

It is worth having rather than deleting. "Here is your external surface" is a
question clients ask directly, and reconstructing it from a list of *problems*
gives you only the hosts that happen to have something wrong with them.

The property that justifies a sink rather than a list is deduplication with
merge: two modules find the same host, and the inventory should say both of the
things they each learned rather than whichever ran last.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from base import Asset, AssetSink, sink_from

ROOT = Path(__file__).resolve().parent.parent


def asset(value="www.acme.example", source="subdomain_discovery", **attributes):
    return Asset(
        kind="host", value=value, source=source, target="acme.example", attributes=attributes
    )


# ── deduplication and merge ──────────────────────────────────────────────────


def test_the_same_host_from_two_modules_is_one_entry():
    sink = AssetSink()
    sink.add(asset(addresses=["192.0.2.1"]))
    sink.add(asset(source="alias_takeover", alias_verdict="resolves"))
    assert len(sink) == 1


def test_both_modules_contributions_survive_the_merge():
    """Whichever ran last must not erase what the other learned — that would
    make the inventory depend on module ordering."""
    sink = AssetSink()
    sink.add(asset(addresses=["192.0.2.1"]))
    sink.add(asset(source="alias_takeover", alias_verdict="claimable_service"))

    attributes = sink.assets[0].attributes
    assert attributes["addresses"] == ["192.0.2.1"]
    assert attributes["alias_verdict"] == "claimable_service"


def test_the_merged_entry_credits_both_modules():
    sink = AssetSink()
    sink.add(asset())
    sink.add(asset(source="alias_takeover"))
    assert sink.assets[0].source == "alias_takeover,subdomain_discovery"


def test_the_same_host_in_different_case_is_the_same_host():
    """DNS is case-insensitive. Two entries for WWW and www would be two rows
    for one machine."""
    sink = AssetSink()
    sink.add(asset(value="www.acme.example"))
    sink.add(asset(value="WWW.acme.example"))
    assert len(sink) == 1


def test_different_kinds_of_thing_are_different_assets():
    sink = AssetSink()
    sink.add(Asset(kind="host", value="ns1.acme.example", source="m", target="acme.example"))
    sink.add(Asset(kind="ip", value="ns1.acme.example", source="m", target="acme.example"))
    assert len(sink) == 2


def test_the_inventory_is_deterministically_ordered():
    sink = AssetSink()
    for value in ("z.acme.example", "a.acme.example", "m.acme.example"):
        sink.add(asset(value=value))
    assert [a.value for a in sink.assets] == [
        "a.acme.example",
        "m.acme.example",
        "z.acme.example",
    ]


def test_every_entry_carries_a_stable_fingerprint():
    """Change detection over the inventory needs the same property findings
    have: the same asset must fingerprint the same next week."""
    first = AssetSink()
    first.add(asset(addresses=["192.0.2.1"]))
    second = AssetSink()
    second.add(asset(addresses=["198.51.100.9"]))
    assert first.to_list()[0]["fingerprint"] == second.to_list()[0]["fingerprint"]


# ── a module run bare still works ────────────────────────────────────────────


def test_a_module_run_without_a_sink_gets_a_throwaway_one():
    """A module that only worked when a runner remembered to hand it a sink is
    a module that breaks the first time somebody runs it alone."""
    sink = sink_from({})
    assert isinstance(sink, AssetSink)
    sink.add(asset())
    assert len(sink) == 1


def test_a_junk_sink_on_the_context_is_ignored_rather_than_crashing():
    assert isinstance(sink_from({"assets": "not a sink"}), AssetSink)


# ── it reaches the report ────────────────────────────────────────────────────


def test_the_report_carries_the_inventory():
    from dnsguard.report import build

    inventory = AssetSink()
    inventory.add(asset(addresses=["192.0.2.1"]))
    report = build([], "acme.example", assets=inventory.to_list())
    assert report["assets"][0]["value"] == "www.acme.example"


def test_a_report_without_an_inventory_carries_an_empty_one():
    """Absent, not missing: a consumer should not have to guess whether the key
    exists."""
    from dnsguard.report import build

    assert build([], "acme.example")["assets"] == []


# ── both entry points populate it ────────────────────────────────────────────


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "cli.py", *args],
        cwd=str(ROOT / "module_framework"),
        capture_output=True,
        text=True,
    )


def test_the_multi_target_entry_point_emits_an_inventory_key():
    """`cli.py` has its own output shape. A dry run touches no network and still
    has to carry the key, so every downstream consumer exercises one shape."""
    proc = run_cli("--group", "quick", "--targets", "example.com", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert "assets" in json.loads(proc.stdout)


def test_the_single_domain_entry_point_emits_an_inventory_key(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            "tools/scan.py",
            "--domain",
            "example.com",
            "--dry-run",
            "-o",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    written = list(tmp_path.glob("*.json"))
    assert written, proc.stdout
    assert "assets" in json.loads(written[0].read_text(encoding="utf-8"))


# ── the modules actually contribute ──────────────────────────────────────────


def test_discovery_contributes_every_live_host(monkeypatch):
    from modules import subdomain_discovery
    from targets import parse_targets

    monkeypatch.setattr(subdomain_discovery, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(
        subdomain_discovery, "_crtsh_names", lambda *a, **k: ({"old.example.com"}, "ok")
    )

    def fake_query(_res, name, rtype):
        if rtype == "A" and name in ("www.example.com", "old.example.com"):
            return ["192.0.2.1"]
        return []

    monkeypatch.setattr(subdomain_discovery, "query", fake_query)

    sink = AssetSink()
    subdomain_discovery.SubdomainDiscovery().run(
        parse_targets(["example.com"])[0], {"assets": sink}
    )
    assert {a.value for a in sink.assets} == {"www.example.com", "old.example.com"}
    assert all(a.kind == "host" for a in sink.assets)


@pytest.mark.parametrize("verdict_key", ["alias_destination", "alias_verdict"])
def test_takeover_records_where_each_alias_leads(monkeypatch, verdict_key):
    from modules.alias_takeover import AliasTakeover

    from tests.test_takeover import FakeDns, install, one

    dns = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["icit.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        }
    )
    install(monkeypatch, dns, {"vpn.example.com"})
    sink = AssetSink()
    AliasTakeover().run(one("example.com"), {"assets": sink})

    entry = next(a for a in sink.assets if a.value == "vpn.example.com")
    assert verdict_key in entry.attributes
