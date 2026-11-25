"""Discovery on a domain with wildcard DNS.

A wildcard record answers for every name, so the probe list "finds" all of its
guesses: admin, db, backup and the rest. None of that is evidence the host
exists. These tests hold both directions: an answer that is only the wildcard is
not reported as a host, and a host there is independent evidence for is never
lost to the filter.

Nothing here resolves a real name.
"""

from __future__ import annotations

import itertools
import re

import pytest
from base import AssetSink
from modules import alias_takeover, subdomain_discovery
from modules.alias_takeover import AliasTakeover
from modules.subdomain_discovery import PROBE_NAMES, SubdomainDiscovery
from targets import parse_targets

WILDCARD_TITLE = "Wildcard DNS is in use"
SENSITIVE_TITLE = "Internal-sounding hosts are reachable from the internet"
INVENTORY_TITLE = "Public host inventory collected"
CONTROL = re.compile(r"^dnsguard-control-[0-9a-f]{12}\.example\.com$")


class WildcardDns:
    """example.com, with explicit records and optionally a wildcard.

    A name with any explicit record is never answered by the wildcard, which is
    how a real zone behaves. `wildcard` maps a record type to either the values
    or a callable producing them, so an answer can vary between lookups.
    """

    def __init__(self, wildcard=None, records=None):
        self.wildcard = wildcard or {}
        self.records = records or {}
        self.asked: list[str] = []

    def query(self, _res, name, rtype):
        self.asked.append(name)
        if name in self.records:
            return list(self.records[name].get(rtype, []))
        if not name.endswith(".example.com"):
            return []
        answer = self.wildcard.get(rtype, [])
        return list(answer() if callable(answer) else answer)


def install(monkeypatch, dns, transparency=()):
    for module in (subdomain_discovery, alias_takeover):
        monkeypatch.setattr(module, "make_resolver", lambda *a, **k: object())
        monkeypatch.setattr(module, "query", dns.query)
        monkeypatch.setattr(module, "_crtsh_names", lambda *a, **k: (set(transparency), "ok"))
        monkeypatch.setattr(module, "_default_session", lambda: object())
    # Alias destinations are not what is under test; they all resolve.
    monkeypatch.setattr(alias_takeover, "resolution", lambda *a, **k: ("ok", ["192.0.2.80"]))


def discover(ctx=None):
    """Run discovery; return its findings by title, and the inventoried hosts."""
    ctx = {} if ctx is None else ctx
    sink = ctx.setdefault("assets", AssetSink())
    findings = SubdomainDiscovery().run(parse_targets(["example.com"])[0], ctx)
    assets = {a.value for a in sink.assets if "subdomain_discovery" in a.source}
    return {f.title: f for f in findings}, assets


def hosts(finding):
    return {h["host"] for h in finding.evidence["hosts"]}


def assert_nothing_guessed_is_reported(findings, assets):
    assert SENSITIVE_TITLE not in findings
    assert "Large public footprint" not in findings
    assert hosts(findings[INVENTORY_TITLE]) == set()
    assert assets == set()
    assert WILDCARD_TITLE in findings


# ── guesses the wildcard answered are not hosts ──────────────────────────────


def test_a_wildcard_address_does_not_invent_hosts(monkeypatch):
    install(monkeypatch, WildcardDns({"A": ["192.0.2.10"]}))
    assert_nothing_guessed_is_reported(*discover())


@pytest.mark.parametrize("addresses", [["192.0.2.10"], []], ids=["resolving", "no address"])
def test_a_wildcard_alias_does_not_invent_hosts(monkeypatch, addresses):
    install(monkeypatch, WildcardDns({"CNAME": ["sites.example.net."], "A": addresses}))
    assert_nothing_guessed_is_reported(*discover())


def test_alias_comparison_ignores_case_and_the_trailing_dot(monkeypatch):
    spellings = itertools.cycle(["Sites.Example.NET.", "sites.example.net"])
    # Three controls consume the first three spellings; candidates get both.
    install(monkeypatch, WildcardDns({"CNAME": lambda: [next(spellings)]}))
    assert_nothing_guessed_is_reported(*discover())


def test_a_wildcard_that_rotates_between_addresses_does_not_invent_hosts(monkeypatch):
    """One control would see one address and take the other two for real hosts."""
    addresses = itertools.cycle(["192.0.2.10", "192.0.2.11", "192.0.2.12"])
    install(monkeypatch, WildcardDns({"A": lambda: [next(addresses)]}))
    assert_nothing_guessed_is_reported(*discover())


# ── genuine hosts survive ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "record",
    [
        {"A": ["198.51.100.7"]},
        {"A": ["192.0.2.10", "198.51.100.7"]},
        {"A": ["192.0.2.10"], "CNAME": ["panel.example.net."]},
    ],
    ids=["different address", "one address in common", "its own alias"],
)
def test_a_host_that_answers_differently_is_still_flagged(monkeypatch, record):
    install(
        monkeypatch,
        WildcardDns({"A": ["192.0.2.10"]}, records={"admin.example.com": record}),
    )
    findings, assets = discover()
    assert hosts(findings[SENSITIVE_TITLE]) == {"admin.example.com"}
    assert hosts(findings[INVENTORY_TITLE]) == {"admin.example.com"}
    assert assets == {"admin.example.com"}
    assert findings[WILDCARD_TITLE].evidence == {"indistinguishable_names": len(PROBE_NAMES) - 1}


def test_a_name_in_certificate_transparency_is_kept_even_if_it_matches(monkeypatch):
    """Somebody obtained a certificate for it. That is evidence the guess list
    does not have, so sharing the wildcard's address is not a reason to drop it."""
    install(
        monkeypatch,
        WildcardDns({"A": ["192.0.2.10"]}),
        transparency={"admin.example.com", "payroll.example.com"},
    )
    findings, assets = discover()
    assert hosts(findings[SENSITIVE_TITLE]) == {"admin.example.com"}
    assert hosts(findings[INVENTORY_TITLE]) == {"admin.example.com", "payroll.example.com"}
    assert assets == {"admin.example.com", "payroll.example.com"}


def test_transparency_names_survive_when_takeover_runs_first(monkeypatch):
    """Whichever module runs first writes the shared cache, so both have to
    record where a name came from."""
    install(
        monkeypatch,
        WildcardDns({"A": ["192.0.2.10"]}),
        transparency={"admin.example.com"},
    )
    ctx: dict = {"assets": AssetSink()}
    AliasTakeover().run(parse_targets(["example.com"])[0], ctx)

    def must_not_be_called(*_a, **_k):
        raise AssertionError("the cached candidates were not reused")

    monkeypatch.setattr(subdomain_discovery, "_crtsh_names", must_not_be_called)
    findings, assets = discover(ctx)
    assert hosts(findings[SENSITIVE_TITLE]) == {"admin.example.com"}
    assert assets == {"admin.example.com"}


def test_transparency_names_survive_a_second_run_from_the_cache(monkeypatch):
    install(
        monkeypatch,
        WildcardDns({"A": ["192.0.2.10"]}),
        transparency={"admin.example.com"},
    )
    ctx: dict = {}
    discover(ctx)
    findings, _ = discover(ctx)
    assert hosts(findings[SENSITIVE_TITLE]) == {"admin.example.com"}


def test_a_cache_without_provenance_is_tolerated(monkeypatch):
    """A name that is not on the probe list can only have come from elsewhere,
    so it is kept even when the cache does not say so."""
    install(monkeypatch, WildcardDns({"A": ["192.0.2.10"]}))
    findings, assets = discover(
        {
            "alias_candidates": {
                "root": "example.com",
                "names": ["admin.example.com", "payroll.example.com"],
                "coverage": {"probe_names": 1, "certificate_transparency": "ok"},
            }
        }
    )
    assert assets == {"payroll.example.com"}
    assert findings[WILDCARD_TITLE].evidence == {"indistinguishable_names": 1}


# ── what the client is told ──────────────────────────────────────────────────


def test_the_client_is_told_what_could_not_be_determined(monkeypatch):
    install(monkeypatch, WildcardDns({"A": ["192.0.2.10"]}))
    findings, _ = discover()
    notice = findings[WILDCARD_TITLE]
    assert notice.severity == "info"
    # Not a pass, and not something downstream may read as one.
    assert notice.confidence == "inconclusive"
    assert f"{len(PROBE_NAMES)} guessed name(s)" in notice.detail
    assert "would not be distinguishable" in notice.detail
    assert "not a clean result" in notice.detail

    inventory = findings[INVENTORY_TITLE]
    assert inventory.confidence == "possible"
    assert f"{len(PROBE_NAMES)} guessed name(s)" in inventory.detail


def test_the_notice_names_no_tool_or_provider(monkeypatch):
    install(monkeypatch, WildcardDns({"CNAME": ["sites.hosting-provider.example.net."]}))
    notice = discover()[0][WILDCARD_TITLE]
    text = f"{notice.title} {notice.detail} {notice.remediation} {notice.evidence}".lower()
    for leaked in ("crt.sh", "crtsh", "dnspython", "hosting-provider"):
        assert leaked not in text


# ── the control itself ───────────────────────────────────────────────────────


def test_three_distinct_random_names_directly_under_the_host_are_the_control(monkeypatch):
    dns = WildcardDns()
    install(monkeypatch, dns)
    discover()
    first = {name for name in dns.asked if CONTROL.match(name)}
    assert len(first) == 3

    dns.asked.clear()
    discover()
    assert first.isdisjoint(dns.asked)


# ── no wildcard ──────────────────────────────────────────────────────────────


def test_without_a_wildcard_the_output_is_unchanged(monkeypatch):
    install(
        monkeypatch,
        WildcardDns(
            records={
                "www.example.com": {"A": ["192.0.2.1"]},
                "admin.example.com": {"A": ["192.0.2.1"]},
                "blog.example.com": {"CNAME": ["Blog.Example.net."]},
                "payroll.example.com": {"A": ["192.0.2.2"]},
            }
        ),
        transparency={"payroll.example.com"},
    )
    sink = AssetSink()
    findings = SubdomainDiscovery().run(parse_targets(["example.com"])[0], {"assets": sink})

    def row(label, addresses, aliases, source):
        return {
            "host": f"{label}.example.com",
            "addresses": addresses,
            "aliases": aliases,
            "source": source,
            "label": label,
        }

    admin = row("admin", ["192.0.2.1"], [], "probe")
    live = [
        admin,
        row("blog", [], ["Blog.Example.net"], "probe"),
        row("payroll", ["192.0.2.2"], [], "certificate-transparency"),
        row("www", ["192.0.2.1"], [], "probe"),
    ]
    assert [(f.severity, f.title, f.detail, f.evidence, f.confidence) for f in findings] == [
        (
            "medium",
            SENSITIVE_TITLE,
            "1 host(s) whose names indicate non-production or administrative use resolve "
            "publicly. These are routinely the least patched and least monitored systems an "
            "organisation runs.",
            {
                "hosts": [admin],
                "remediation": "Put these behind the VPN or remove the public records.",
            },
            "confirmed",
        ),
        (
            "info",
            INVENTORY_TITLE,
            "4 host(s) resolve under example.com, from 57 name(s) (56 conventional, 1 from "
            "certificate transparency).",
            {
                "hosts": live,
                "coverage": {
                    "probe_names": 56,
                    "certificate_transparency": "ok",
                    "certificate_transparency_names": 1,
                },
            },
            "confirmed",
        ),
    ]
    assert [(a.value, a.attributes) for a in sink.assets] == [
        (
            r["host"],
            {
                "addresses": r["addresses"],
                "aliases": r["aliases"],
                "discovered_by": r["source"],
            },
        )
        for r in live
    ]
