"""Certificate-issuance protection, judged the way a certificate authority judges it.

RFC 8659 has an authority climb from the name towards the root and obey the
closest CAA record set it meets. The zone audit used to ask only "is there a CAA
record at this exact name", which was wrong three ways: a subdomain covered by
its parent was reported as unprotected, a record set that restricts nothing
passed, and a lookup that failed was reported as a missing record.

The resolver is a stub raising dnspython's own exceptions, so the module's real
lookup helpers run. Nothing here resolves a real name.
"""

from __future__ import annotations

import types

import dns.exception
import dns.resolver
import pytest
from modules import dns_records
from modules.dns_records import audit_zone
from targets import parse_targets

from dnsguard.clock import FrozenClock
from dnsguard.fleetfix import NON_DISRUPTIVE_TITLES, build_work_order, is_disruptive
from dnsguard.report import build

UNRESTRICTED = "Any certificate authority may issue certificates for this domain"
EMPTY_ZONE = "Domain publishes no DNS records"
INVENTORY = "Zone inventory collected"

LETS_ENCRYPT = '0 issue "letsencrypt.org"'
IODEF = '0 iodef "mailto:security@example.com"'

TIMEOUT = dns.exception.Timeout
NXDOMAIN = dns.resolver.NXDOMAIN
NO_ANSWER = dns.resolver.NoAnswer


class Answer(list):
    """The parts of a dnspython answer the lookup helpers read."""

    def __init__(self, values, ttl=3600):
        super().__init__(values)
        self.rrset = types.SimpleNamespace(ttl=ttl)


class StubResolver:
    """Answers from a table, and raises what dnspython raises for the rest.

    A table value is a list of record strings, or an exception class to raise.
    """

    def __init__(self, table):
        self.table = table
        self.caa_queries = []

    def resolve(self, name, rtype):
        if rtype == "CAA":
            self.caa_queries.append(name)
        result = self.table.get((name, rtype), NO_ANSWER)
        if isinstance(result, list):
            return Answer(result)
        raise result


def zone(host):
    """A healthy zone with no CAA, so CAA is the only thing left to report on."""
    return {
        (host, "A"): ["192.0.2.1"],
        (host, "NS"): ["ns1.example.net.", "ns2.example.net."],
    }


def scan(monkeypatch, host, caa=None, *, target=None, base=None):
    table = dict(zone(host) if base is None else base)
    for name, result in (caa or {}).items():
        table[(name, "CAA")] = result
    stub = StubResolver(table)
    monkeypatch.setattr(dns_records, "make_resolver", lambda *a, **k: stub)
    findings = dns_records.DnsRecords().run(parse_targets([target or host])[0], {})
    return findings, stub


def titles(findings):
    return [f.title for f in findings]


def unrestricted(findings):
    return [f for f in findings if f.title == UNRESTRICTED]


def inconclusive(findings):
    return [f for f in findings if f.confidence == "inconclusive"]


def the_one(findings):
    rows = unrestricted(findings)
    assert len(rows) == 1, titles(findings)
    assert rows[0].severity == "low"
    assert rows[0].confidence == "confirmed"
    return rows[0]


def inventory_of(findings):
    return next(f for f in findings if f.title == INVENTORY).evidence["records"]


# ── where the record is ──────────────────────────────────────────────────────


def test_own_restricting_caa_is_no_finding_and_needs_no_climb(monkeypatch):
    findings, stub = scan(monkeypatch, "example.com", {"example.com": [LETS_ENCRYPT]})
    assert titles(findings) == [INVENTORY]
    assert stub.caa_queries == ["example.com"]
    assert [r["value"] for r in inventory_of(findings) if r["type"] == "CAA"]


def test_parent_caa_protects_a_subdomain(monkeypatch):
    findings, stub = scan(monkeypatch, "www.example.com", {"example.com": [LETS_ENCRYPT]})
    assert titles(findings) == [INVENTORY]
    assert stub.caa_queries[-1] == "example.com", "the climb stops at the first set found"


def test_the_parents_records_stay_out_of_this_hosts_inventory(monkeypatch):
    findings, _ = scan(monkeypatch, "www.example.com", {"example.com": [LETS_ENCRYPT]})
    assert {r["type"] for r in inventory_of(findings)} == {"A", "NS"}
    assert {r["name"] for r in inventory_of(findings)} == {"www.example.com"}


def test_the_climb_passes_names_that_do_not_exist_and_reaches_the_tld(monkeypatch):
    findings, stub = scan(
        monkeypatch,
        "a.b.example.com",
        {"b.example.com": NXDOMAIN, "example.com": NO_ANSWER, "com": [LETS_ENCRYPT]},
    )
    assert titles(findings) == [INVENTORY]
    assert list(dict.fromkeys(stub.caa_queries)) == [
        "a.b.example.com",
        "b.example.com",
        "example.com",
        "com",
    ]


def test_no_caa_anywhere_is_the_existing_low_finding(monkeypatch):
    findings, stub = scan(monkeypatch, "www.example.com")
    row = the_one(findings)
    assert row.detail.startswith("No CAA record is published")
    assert row.evidence["remediation"]
    assert not inconclusive(findings)
    assert stub.caa_queries[-1] == "com", "the climb includes the TLD"
    assert not {"", "."} & set(stub.caa_queries), "and never asks the root"


def test_a_closer_unrestricting_set_hides_a_restricting_parent(monkeypatch):
    findings, stub = scan(
        monkeypatch,
        "www.example.com",
        {"www.example.com": [IODEF], "example.com": [LETS_ENCRYPT]},
    )
    row = the_one(findings)
    assert row.evidence["caa_owner"] == "www.example.com"
    assert row.evidence["caa_records"] == [IODEF.strip('"')]
    assert "example.com" not in stub.caa_queries, "sets are never merged across levels"


def test_a_closer_inherited_set_hides_one_further_up(monkeypatch):
    findings, _ = scan(
        monkeypatch,
        "a.b.example.com",
        {"b.example.com": [IODEF], "example.com": [LETS_ENCRYPT]},
    )
    assert the_one(findings).evidence["caa_owner"] == "b.example.com"


def test_an_inherited_set_that_restricts_nothing_names_its_owner(monkeypatch):
    findings, _ = scan(monkeypatch, "www.example.com", {"example.com": [IODEF]})
    row = the_one(findings)
    assert row.target == "www.example.com"
    assert row.evidence["caa_owner"] == "example.com"
    assert "example.com" in row.detail
    assert "contains no issue restriction" in row.detail


@pytest.mark.parametrize(
    "target", ["https://www.example.com/login?next=1", "https://www.example.com./"]
)
def test_a_url_target_inherits_like_a_hostname(monkeypatch, target):
    host = "www.example.com." if target.endswith("./") else "www.example.com"
    findings, _ = scan(
        monkeypatch, host, {"example.com": [LETS_ENCRYPT]}, target=target, base=zone(host)
    )
    assert titles(findings) == [INVENTORY]


def test_a_url_target_with_no_caa_anywhere_is_still_reported(monkeypatch):
    findings, _ = scan(monkeypatch, "www.example.com", target="https://www.example.com/")
    assert the_one(findings).target == "www.example.com"


# ── whether the record restricts anything ────────────────────────────────────


@pytest.mark.parametrize(
    "records",
    [
        [LETS_ENCRYPT],
        ['0 issue ";"'],
        ['0 issue ""'],
        ['0 ISSUE "letsencrypt.org"'],
        ['0 issue "letsencrypt.org'],  # the trailing quote already stripped
        ["0 issue letsencrypt.org"],
        ['128 issue "letsencrypt.org"'],
        ['128 futureproperty "value"'],
        ['255 futureproperty "value"'],
        [IODEF, '0 issuewild ";"', LETS_ENCRYPT],
        ["not a caa record", LETS_ENCRYPT],
    ],
)
@pytest.mark.parametrize("owner", ["www.example.com", "example.com"])
def test_sets_that_restrict_ordinary_issuance(monkeypatch, owner, records):
    findings, _ = scan(monkeypatch, "www.example.com", {owner: records})
    assert titles(findings) == [INVENTORY]


@pytest.mark.parametrize(
    "records",
    [
        [IODEF],
        ['128 iodef "mailto:security@example.com"'],
        ['0 issuewild "letsencrypt.org"'],
        ['128 issuewild ";"'],
        ['128 ISSUEWILD ";"'],
        ['0 futureproperty "value"'],
        ['127 futureproperty "value"'],
    ],
)
@pytest.mark.parametrize("owner", ["www.example.com", "example.com"])
def test_sets_that_restrict_nothing(monkeypatch, owner, records):
    findings, _ = scan(monkeypatch, "www.example.com", {owner: records})
    row = the_one(findings)
    assert row.evidence["caa_owner"] == owner
    assert len(row.evidence["caa_records"]) == len(records)
    assert row.evidence["remediation"]
    assert "CAA record exists" in row.detail
    assert "contains no issue restriction" in row.detail


@pytest.mark.parametrize(
    "value",
    ["", "   ", "garbage", "issue letsencrypt.org", "x issue y", "999 issue y", "² issue y"]
    + ["-1 issue y", r"\# 4 00056973", "0", '128 "', "128 bad-tag y"],
)
@pytest.mark.parametrize("owner", ["www.example.com", "example.com"])
def test_an_unparseable_value_neither_raises_nor_counts_as_protection(monkeypatch, owner, value):
    findings, _ = scan(monkeypatch, "www.example.com", {owner: [value]})
    assert the_one(findings).evidence["caa_owner"] == owner


# ── when the question could not be answered ──────────────────────────────────


@pytest.mark.parametrize("failure", [TIMEOUT, dns.resolver.NoNameservers])
@pytest.mark.parametrize("failing", ["www.example.com", "example.com", "com"])
def test_a_failed_lookup_is_inconclusive_not_a_missing_record(monkeypatch, failing, failure):
    findings, _ = scan(monkeypatch, "www.example.com", {failing: failure})
    assert not unrestricted(findings)
    rows = inconclusive(findings)
    assert len(rows) == 1
    assert rows[0].severity == "info"
    assert "CAA" in rows[0].title
    assert "could not be checked" in rows[0].title
    assert failing in rows[0].detail


def test_a_failure_below_a_parents_set_is_still_inconclusive(monkeypatch):
    """The name that failed may hold a set that overrides the parent's, so the
    parent's answer cannot stand in for it."""
    findings, stub = scan(
        monkeypatch, "www.example.com", {"www.example.com": TIMEOUT, "example.com": [IODEF]}
    )
    assert not unrestricted(findings)
    assert len(inconclusive(findings)) == 1
    assert "example.com" not in stub.caa_queries


def test_a_failure_above_the_closest_set_does_not_matter(monkeypatch):
    findings, _ = scan(
        monkeypatch, "www.example.com", {"example.com": [LETS_ENCRYPT], "com": TIMEOUT}
    )
    assert titles(findings) == [INVENTORY]


# ── the rest of the product still holds ──────────────────────────────────────


@pytest.mark.parametrize("caa", [{}, {"example.com": [IODEF]}, {"www.example.com": TIMEOUT}])
def test_an_empty_zone_is_the_only_finding(monkeypatch, caa):
    findings, _ = scan(monkeypatch, "www.example.com", caa, base={})
    assert [t for t in titles(findings) if t != INVENTORY] == [EMPTY_ZONE]
    assert inventory_of(findings) == []
    assert titles(audit_zone("dns_records", "www.example.com", [])) == [EMPTY_ZONE]


def test_audit_zone_without_the_new_argument_behaves_as_before():
    def rec(rtype, value="v"):
        return {"name": "example.com", "type": rtype, "value": value, "ttl": 3600, "purpose": ""}

    healthy = [rec("A"), rec("NS"), rec("NS")]
    row = the_one(audit_zone("dns_records", "example.com", healthy))
    assert row.detail.startswith("No CAA record is published")
    assert audit_zone("dns_records", "example.com", [*healthy, rec("CAA", IODEF)]) == []


def test_the_new_finding_dispatches_and_leaves_the_client_inventory_alone(monkeypatch):
    """The client's record inventory is read from the first finding carrying a
    `records` key, so the CAA evidence must not use that name."""
    findings, _ = scan(monkeypatch, "www.example.com", {"example.com": [IODEF]})
    row = the_one(findings)
    assert row.title in NON_DISRUPTIVE_TITLES
    assert is_disruptive(row) is False
    assert "records" not in row.evidence

    order = build_work_order(row, "acme", "hq", FrozenClock())
    assert order.evidence["caa_owner"] == "example.com"

    inventory = build(findings, "www.example.com")["records"]
    assert {r["record_type"] for r in inventory} == {"A", "NS"}
