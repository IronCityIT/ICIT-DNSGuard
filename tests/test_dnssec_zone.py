"""DNSSEC is judged on the zone that serves the scanned host, and only that zone.

DNSKEY and DS exist at a zone apex, so asking for them at `www.example.com` finds
nothing however well example.com is signed. These tests cover both directions of
getting the zone wrong: telling a signed client they are unsigned, and crediting
a client with a parent's or a third party's signatures.

Only the resolver is stubbed, so the real lookup helpers run. Nothing here
resolves a real name.
"""

from __future__ import annotations

import dns.exception
import dns.resolver
import pytest
from modules import dnssec_audit
from targets import parse_targets

from dnsguard.report import build

UNSIGNED = ("low", "Domain answers are not signed")
UNTRUSTED = ("medium", "Signing is configured but not trusted")
SIGNED = ("info", "Domain answers are signed and trusted")


def zone(name: str, keys: int = 0, ds: int = 0) -> dict[tuple[str, str], list[str]]:
    """The apex records of one zone."""
    records = {(name, "SOA"): [f"ns1.{name}. hostmaster.{name}. 1 2 3 4 5"]}
    if keys:
        records[(name, "DNSKEY")] = [f"key-{i}" for i in range(keys)]
    if ds:
        records[(name, "DS")] = [f"ds-{i}" for i in range(ds)]
    return records


class StubResolver:
    """Answers from a fixture, raising what the real resolver raises.

    A name with no records of its own and nothing beneath it is NXDOMAIN; a name
    that exists without the requested type is NoAnswer. Every type but CNAME
    follows an alias, because that is how another owner's zone gets returned.
    """

    def __init__(
        self,
        *record_sets: dict[tuple[str, str], list[str]],
        failing: set[tuple[str, str]] | None = None,
    ) -> None:
        self.records = {key: values for records in record_sets for key, values in records.items()}
        self.failing = failing or set()
        self.asked: list[tuple[str, str]] = []

    def resolve(self, name: str, rtype: str) -> list[str]:
        self.asked.append((name, rtype))
        if (name, rtype) in self.failing:
            raise dns.exception.Timeout
        owner = name.rstrip(".")
        while rtype != "CNAME" and (owner, "CNAME") in self.records:
            owner = self.records[(owner, "CNAME")][0]
        if (owner, rtype) in self.records:
            return self.records[(owner, rtype)]
        if any(known == owner or known.endswith("." + owner) for known, _ in self.records):
            raise dns.resolver.NoAnswer
        raise dns.resolver.NXDOMAIN


def host(name: str) -> dict[tuple[str, str], list[str]]:
    return {(name, "A"): ["192.0.2.10"]}


def alias(name: str, destination: str) -> dict[tuple[str, str], list[str]]:
    return {(name, "CNAME"): [destination]}


# Always signed, and never the right answer: it is here so that any test whose
# walk climbs too far fails by reporting the parent's signatures.
COM = zone("com", keys=7, ds=7)
CO_UK = {**zone("uk", keys=8, ds=8), **zone("co.uk", keys=9, ds=9)}


def audit(monkeypatch, resolver: StubResolver, target: str):
    monkeypatch.setattr(dnssec_audit, "make_resolver", lambda *a, **k: resolver)
    findings = dnssec_audit.DnssecAudit().run(parse_targets([target])[0], {})
    assert len(findings) == 1
    return findings[0]


def verdict(finding) -> tuple[str, str]:
    return finding.severity, finding.title


# ── the scanned name is the apex ─────────────────────────────────────────────


def test_an_apex_domain_is_reported_as_before(monkeypatch):
    resolver = StubResolver(COM, zone("example.com", keys=2, ds=1))
    finding = audit(monkeypatch, resolver, "example.com")
    assert verdict(finding) == SIGNED
    assert finding.target == "example.com"
    assert finding.detail == "2 signing key(s) published with a complete delegation chain."
    assert finding.evidence == {"dnskey_count": 2, "ds_count": 1}


# ── the scanned name is inside the zone ──────────────────────────────────────


@pytest.mark.parametrize(
    ("target", "scanned"),
    [
        ("www.example.com", "www.example.com"),
        ("https://www.example.com/", "www.example.com"),
        ("https://www.example.com:8443/path?q=1", "www.example.com"),
        # host_of keeps a URL's trailing dot; it must not add a label to the walk.
        ("https://www.example.com./", "www.example.com."),
    ],
)
def test_a_host_in_a_signed_zone_reports_the_zone(monkeypatch, target, scanned):
    resolver = StubResolver(COM, zone("example.com", keys=2, ds=1), host("www.example.com"))
    finding = audit(monkeypatch, resolver, target)
    assert verdict(finding) == SIGNED
    # The stored fingerprint is built from this, so it stays the scanned host.
    assert finding.target == scanned
    assert finding.asset == scanned
    assert finding.evidence == {"dnskey_count": 2, "ds_count": 1, "zone": "example.com"}
    assert "the example.com zone" in finding.detail


def test_a_host_in_an_unsigned_zone_is_unsigned(monkeypatch):
    resolver = StubResolver(COM, zone("example.com"), host("www.example.com"))
    finding = audit(monkeypatch, resolver, "www.example.com")
    assert verdict(finding) == UNSIGNED
    assert finding.target == "www.example.com"
    assert finding.evidence["zone"] == "example.com"
    assert finding.evidence["remediation"]
    assert "the example.com zone" in finding.detail


def test_a_host_in_a_signed_but_undelegated_zone_is_untrusted(monkeypatch):
    resolver = StubResolver(COM, zone("example.com", keys=3), host("www.example.com"))
    finding = audit(monkeypatch, resolver, "www.example.com")
    assert verdict(finding) == UNTRUSTED
    assert finding.target == "www.example.com"
    assert finding.evidence["dnskey_count"] == 3
    assert "ds_count" not in finding.evidence
    assert finding.evidence["zone"] == "example.com"
    assert "the example.com zone" in finding.detail


def test_a_deep_host_climbs_to_its_zone(monkeypatch):
    resolver = StubResolver(COM, zone("example.com", keys=2, ds=1), host("a.b.c.d.example.com"))
    finding = audit(monkeypatch, resolver, "a.b.c.d.example.com")
    assert verdict(finding) == SIGNED
    assert finding.evidence["zone"] == "example.com"


# ── somebody else's signatures are not the client's ──────────────────────────


@pytest.mark.parametrize("target", ["app.example.com", "www.app.example.com"])
def test_a_delegated_unsigned_child_is_not_credited_with_its_parent(monkeypatch, target):
    resolver = StubResolver(
        COM,
        zone("example.com", keys=2, ds=1),
        zone("app.example.com"),
        host("www.app.example.com"),
    )
    finding = audit(monkeypatch, resolver, target)
    assert verdict(finding) == UNSIGNED
    assert finding.evidence.get("zone", target) == "app.example.com"


def test_an_alias_to_a_signed_third_party_does_not_sign_the_client(monkeypatch):
    resolver = StubResolver(
        COM,
        zone("example.com"),
        alias("www.example.com", "provider.net"),
        zone("provider.net", keys=4, ds=4),
    )
    finding = audit(monkeypatch, resolver, "www.example.com")
    assert verdict(finding) == UNSIGNED
    assert finding.evidence["zone"] == "example.com"
    assert "provider.net" not in finding.detail


def test_an_alias_to_an_unsigned_third_party_does_not_unsign_the_client(monkeypatch):
    resolver = StubResolver(
        COM,
        zone("example.com", keys=2, ds=1),
        alias("www.example.com", "provider.net"),
        zone("provider.net"),
    )
    finding = audit(monkeypatch, resolver, "www.example.com")
    assert verdict(finding) == SIGNED
    assert finding.evidence == {"dnskey_count": 2, "ds_count": 1, "zone": "example.com"}


def test_an_alias_whose_destination_is_gone_still_reports_the_client_zone(monkeypatch):
    resolver = StubResolver(
        COM, zone("example.com", keys=2, ds=1), alias("old.example.com", "gone.provider.net")
    )
    finding = audit(monkeypatch, resolver, "old.example.com")
    assert verdict(finding) == SIGNED
    assert finding.evidence["zone"] == "example.com"


def test_an_unanswered_alias_lookup_does_not_trust_the_zone_behind_it(monkeypatch):
    """Not knowing whether a name is an alias is not knowing whose zone answered."""
    resolver = StubResolver(
        COM,
        zone("example.com", keys=2, ds=1),
        host("www.example.com"),
        failing={("example.com", "CNAME")},
    )
    finding = audit(monkeypatch, resolver, "www.example.com")
    assert "zone" not in finding.evidence
    assert resolver.asked[-2:] == [("www.example.com", "DNSKEY"), ("www.example.com", "DS")]


# ── the walk stops where it stops knowing ────────────────────────────────────


def test_a_host_that_does_not_exist_is_not_credited_with_its_parent(monkeypatch):
    resolver = StubResolver(COM, zone("example.com", keys=2, ds=1))
    finding = audit(monkeypatch, resolver, "nope.example.com")
    assert verdict(finding) == UNSIGNED
    assert finding.target == "nope.example.com"
    assert "zone" not in finding.evidence


@pytest.mark.parametrize("target", ["example.co.uk", "www.example.co.uk"])
def test_a_failed_lookup_does_not_credit_a_public_suffix(monkeypatch, target):
    resolver = StubResolver(
        CO_UK,
        zone("example.co.uk"),
        host("www.example.co.uk"),
        failing={("example.co.uk", "SOA")},
    )
    finding = audit(monkeypatch, resolver, target)
    assert verdict(finding) == UNSIGNED
    assert "zone" not in finding.evidence
    assert not [name for name, _ in resolver.asked if name in ("co.uk", "uk")]


@pytest.mark.parametrize("target", ["www.example.com", "https://www.example.com./"])
def test_a_bare_top_level_domain_is_never_tested(monkeypatch, target):
    resolver = StubResolver(COM, host("www.example.com"))
    finding = audit(monkeypatch, resolver, target)
    assert verdict(finding) == UNSIGNED
    assert "zone" not in finding.evidence
    assert not [name for name, _ in resolver.asked if name.rstrip(".") == "com"]


def test_a_single_label_host_is_not_walked(monkeypatch):
    resolver = StubResolver(host("fileserver"))
    assert verdict(audit(monkeypatch, resolver, "fileserver")) == UNSIGNED
    assert resolver.asked == [("fileserver", "DNSKEY"), ("fileserver", "DS")]


# ── what the dashboard reads ─────────────────────────────────────────────────


def test_the_report_marks_a_signed_www_host_as_implemented(monkeypatch):
    resolver = StubResolver(COM, zone("example.com", keys=2, ds=1), host("www.example.com"))
    finding = audit(monkeypatch, resolver, "www.example.com")
    dnssec = build([finding], "www.example.com")["dnssec"]
    assert dnssec["implemented"] is True
    assert dnssec["signed"] is True
    assert dnssec["delegation_present"] is True
    assert dnssec["issues"] == []
