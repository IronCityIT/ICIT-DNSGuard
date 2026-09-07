"""Module behaviour, exercised without touching the network.

Each module's decision logic is separated from its lookups, so the tests drive
the logic directly (pure parsers, pure audits) or stub the one lookup helper the
module imported. Nothing here resolves a real name.
"""

from __future__ import annotations

import pytest
from modules import dmarc_audit, dns_records, dnssec_audit, spf_audit, subdomain_discovery
from modules._dns import host_of
from modules.dmarc_audit import parse_dmarc
from modules.dns_records import audit_zone, classify_txt
from modules.spf_audit import parse_spf
from targets import parse_targets


def one(value: str):
    return parse_targets([value])[0]


def severities(findings):
    return sorted({f.severity for f in findings})


def titles(findings):
    return [f.title for f in findings]


# ── host_of ──────────────────────────────────────────────────────────────────


def test_host_of_extracts_the_name_from_every_target_shape():
    assert host_of(one("Example.com")) == "example.com"
    assert host_of(one("https://App.Example.com/path?q=1")) == "app.example.com"
    assert host_of(one("fileserver")) == "fileserver"


# ── SPF ──────────────────────────────────────────────────────────────────────


def test_parse_spf_reads_qualifier_lookups_and_includes():
    parsed = parse_spf("v=spf1 include:_spf.google.com include:sendgrid.net mx -all")
    assert parsed["qualifier"] == "-all"
    assert parsed["strength"] == "hard fail"
    assert parsed["lookup_count"] == 3
    assert parsed["includes"] == ["_spf.google.com", "sendgrid.net"]


def test_parse_spf_handles_a_record_with_no_all_mechanism():
    parsed = parse_spf("v=spf1 ip4:192.0.2.0/24")
    assert parsed["qualifier"] == ""
    assert parsed["strength"] == "unspecified"
    assert parsed["lookup_count"] == 0


def test_bare_a_and_mx_mechanisms_count_toward_the_lookup_budget():
    """The previous implementation only matched "a:"/"mx:", so a record using the
    bare forms was reported as cheaper than it is."""
    assert parse_spf("v=spf1 a mx -all")["lookup_count"] == 2
    assert parse_spf("v=spf1 ~a ?mx +include:x.example -all")["lookup_count"] == 3
    assert parse_spf("v=spf1 redirect=_spf.example.com")["lookup_count"] == 1
    assert parse_spf("v=spf1 ip4:192.0.2.1 ip6:2001:db8::1 -all")["lookup_count"] == 0


def test_spf_missing_record_is_high(monkeypatch):
    monkeypatch.setattr(spf_audit, "find_txt", lambda *a, **k: "")
    monkeypatch.setattr(spf_audit, "make_resolver", lambda *a, **k: object())
    findings = spf_audit.SpfAudit().run(one("example.com"), {})
    assert severities(findings) == ["high"]
    assert "No sender authorisation policy" in findings[0].title


def test_spf_pass_all_is_critical(monkeypatch):
    monkeypatch.setattr(spf_audit, "find_txt", lambda *a, **k: "v=spf1 +all")
    monkeypatch.setattr(spf_audit, "make_resolver", lambda *a, **k: object())
    findings = spf_audit.SpfAudit().run(one("example.com"), {})
    assert "critical" in severities(findings)


def test_spf_over_lookup_budget_is_high(monkeypatch):
    record = "v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(12)) + " -all"
    monkeypatch.setattr(spf_audit, "find_txt", lambda *a, **k: record)
    monkeypatch.setattr(spf_audit, "make_resolver", lambda *a, **k: object())
    findings = spf_audit.SpfAudit().run(one("example.com"), {})
    assert any("lookup budget" in t for t in titles(findings))
    assert "high" in severities(findings)


def test_spf_strict_record_reports_info_only(monkeypatch):
    monkeypatch.setattr(
        spf_audit, "find_txt", lambda *a, **k: "v=spf1 include:_spf.google.com -all"
    )
    monkeypatch.setattr(spf_audit, "make_resolver", lambda *a, **k: object())
    findings = spf_audit.SpfAudit().run(one("example.com"), {})
    assert severities(findings) == ["info"]


# ── DMARC ────────────────────────────────────────────────────────────────────


def test_parse_dmarc_reads_every_tag_it_acts_on():
    parsed = parse_dmarc(
        "v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@x.com,mailto:b@x.com"
    )
    assert parsed["policy"] == "reject"
    assert parsed["subdomain_policy"] == "quarantine"
    assert parsed["pct"] == 50
    assert parsed["rua"] == ["mailto:a@x.com", "mailto:b@x.com"]


def test_parse_dmarc_defaults_an_unknown_policy_to_none():
    assert parse_dmarc("v=DMARC1; p=bogus")["policy"] == "none"


def test_dmarc_missing_is_high(monkeypatch):
    monkeypatch.setattr(dmarc_audit, "find_txt", lambda *a, **k: "")
    monkeypatch.setattr(dmarc_audit, "make_resolver", lambda *a, **k: object())
    findings = dmarc_audit.DmarcAudit().run(one("example.com"), {})
    assert severities(findings) == ["high"]


def test_dmarc_monitor_only_and_no_reporting_raises_both(monkeypatch):
    monkeypatch.setattr(dmarc_audit, "find_txt", lambda *a, **k: "v=DMARC1; p=none")
    monkeypatch.setattr(dmarc_audit, "make_resolver", lambda *a, **k: object())
    findings = dmarc_audit.DmarcAudit().run(one("example.com"), {})
    assert set(titles(findings)) == {
        "Mail authentication policy is monitor-only",
        "Mail authentication reports go nowhere",
    }


def test_dmarc_partial_rollout_is_flagged(monkeypatch):
    monkeypatch.setattr(
        dmarc_audit, "find_txt", lambda *a, **k: "v=DMARC1; p=reject; pct=25; rua=mailto:a@x.com"
    )
    monkeypatch.setattr(dmarc_audit, "make_resolver", lambda *a, **k: object())
    findings = dmarc_audit.DmarcAudit().run(one("example.com"), {})
    assert any("partially applied" in t for t in titles(findings))


# ── DNSSEC ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("dnskey", "ds", "severity", "fragment"),
    [
        ([], [], "low", "not signed"),
        (["key"], [], "medium", "not trusted"),
        (["key"], ["ds"], "info", "signed and trusted"),
    ],
)
def test_dnssec_states(monkeypatch, dnskey, ds, severity, fragment):
    monkeypatch.setattr(dnssec_audit, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(
        dnssec_audit, "query", lambda _res, _name, rtype: dnskey if rtype == "DNSKEY" else ds
    )
    findings = dnssec_audit.DnssecAudit().run(one("example.com"), {})
    assert findings[0].severity == severity
    assert fragment in findings[0].title


# ── Zone audit ───────────────────────────────────────────────────────────────


def rec(rtype, value="v", ttl=3600):
    return {"name": "example.com", "type": rtype, "value": value, "ttl": ttl, "purpose": ""}


def test_empty_zone_is_a_single_high_finding():
    findings = audit_zone("dns_records", "example.com", [])
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_zone_without_address_records_is_flagged():
    findings = audit_zone("dns_records", "example.com", [rec("NS"), rec("NS"), rec("CAA")])
    assert any("does not resolve to an address" in t for t in titles(findings))


def test_single_nameserver_is_a_single_point_of_failure():
    findings = audit_zone("dns_records", "example.com", [rec("A"), rec("NS")])
    assert any("Single point of failure" in t for t in titles(findings))


def test_two_nameservers_are_not_flagged():
    findings = audit_zone("dns_records", "example.com", [rec("A"), rec("NS"), rec("NS")])
    assert not any("Single point of failure" in t for t in titles(findings))


def test_missing_caa_is_low():
    findings = audit_zone("dns_records", "example.com", [rec("A"), rec("NS"), rec("NS")])
    caa = [f for f in findings if "certificate authority" in f.title.lower()]
    assert len(caa) == 1
    assert caa[0].severity == "low"


def test_long_ttl_blocks_fast_failover():
    findings = audit_zone(
        "dns_records", "example.com", [rec("A", ttl=86400), rec("NS"), rec("NS"), rec("CAA")]
    )
    assert any("cannot be re-pointed quickly" in t for t in titles(findings))


def test_very_short_ttl_is_informational():
    findings = audit_zone(
        "dns_records", "example.com", [rec("A", ttl=30), rec("NS"), rec("NS"), rec("CAA")]
    )
    assert any("Very short record lifetime" in t for t in titles(findings))


def test_txt_records_are_classified_for_the_client_report():
    assert classify_txt("v=spf1 -all").startswith("Sender authorisation")
    assert classify_txt("v=DMARC1; p=none").startswith("Mail authentication")
    assert classify_txt("v=DKIM1; k=rsa").startswith("Mail signing")
    assert classify_txt("google-site-verification=abc") == "Text record"


def test_dns_records_module_reports_the_inventory(monkeypatch):
    collected = [rec("A"), rec("NS"), rec("NS"), rec("CAA")]
    monkeypatch.setattr(dns_records.DnsRecords, "collect", lambda self, host, ctx: collected)
    findings = dns_records.DnsRecords().run(one("example.com"), {})
    inventory = [f for f in findings if f.title == "Zone inventory collected"]
    assert len(inventory) == 1
    assert inventory[0].evidence["records"] == collected


# ── Subdomain discovery ──────────────────────────────────────────────────────


def test_dangling_alias_is_high(monkeypatch):
    monkeypatch.setattr(subdomain_discovery, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(
        subdomain_discovery, "_crtsh_names", lambda *a, **k: ({"old.example.com"}, "ok")
    )

    def fake_query(_res, name, rtype):
        if name == "old.example.com" and rtype == "CNAME":
            return ["deprovisioned.hosting.example.net."]
        if name == "www.example.com" and rtype == "A":
            return ["192.0.2.1"]
        return []

    monkeypatch.setattr(subdomain_discovery, "query", fake_query)
    findings = subdomain_discovery.SubdomainDiscovery().run(one("example.com"), {})
    dangling = [f for f in findings if "do not resolve" in f.title]
    assert len(dangling) == 1
    assert dangling[0].severity == "high"


def test_sensitive_hostnames_are_flagged(monkeypatch):
    monkeypatch.setattr(subdomain_discovery, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(subdomain_discovery, "_crtsh_names", lambda *a, **k: (set(), "ok"))

    def fake_query(_res, name, rtype):
        if rtype == "A" and name in ("admin.example.com", "staging.example.com"):
            return ["192.0.2.9"]
        return []

    monkeypatch.setattr(subdomain_discovery, "query", fake_query)
    findings = subdomain_discovery.SubdomainDiscovery().run(one("example.com"), {})
    sensitive = [f for f in findings if "Internal-sounding" in f.title]
    assert len(sensitive) == 1
    assert {h["host"] for h in sensitive[0].evidence["hosts"]} == {
        "admin.example.com",
        "staging.example.com",
    }


def test_certificate_transparency_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(subdomain_discovery, "make_resolver", lambda *a, **k: object())
    called = []
    monkeypatch.setattr(
        subdomain_discovery, "_crtsh_names", lambda *a, **k: (called.append(1) or set(), "ok")
    )
    monkeypatch.setattr(subdomain_discovery, "query", lambda *a, **k: [])
    subdomain_discovery.SubdomainDiscovery().run(
        one("example.com"), {"use_certificate_transparency": False}
    )
    assert called == []


# ── Reputation ───────────────────────────────────────────────────────────────


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class FakeSession:
    """Returns a canned response per URL fragment, or raises for one."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected request to {url}")


def vt_stats(malicious):
    return {
        "data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "harmless": 60}}}
    }


def test_reputation_without_a_provider_says_unchecked_not_clean(monkeypatch):
    from modules import reputation_lookup

    findings = reputation_lookup.ReputationLookup().run(one("example.com"), {"reputation_keys": {}})
    assert len(findings) == 1
    assert "not consulted" in findings[0].title
    assert findings[0].evidence["consulted"] is False


def test_reputation_flags_a_bad_address(monkeypatch):
    from modules import reputation_lookup

    monkeypatch.setattr(reputation_lookup, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(reputation_lookup, "query", lambda *a, **k: ["192.0.2.66"])
    session = FakeSession(
        {
            "/domains/": FakeResponse(vt_stats(0)),
            "/ip_addresses/": FakeResponse(vt_stats(12)),
            "abuseipdb": FakeResponse({"data": {"abuseConfidenceScore": 95, "totalReports": 40}}),
        }
    )
    findings = reputation_lookup.ReputationLookup().run(
        one("example.com"),
        {"http": session, "reputation_keys": {"virustotal": "k1", "abuseipdb": "k2"}},
    )
    flagged = [f for f in findings if "negative reputation" in f.title]
    assert len(flagged) == 1
    assert flagged[0].severity == "high"
    providers = {v["provider"] for v in flagged[0].evidence["verdicts"]}
    assert providers == {"virustotal", "abuseipdb"}


def test_a_clean_lookup_raises_nothing(monkeypatch):
    from modules import reputation_lookup

    monkeypatch.setattr(reputation_lookup, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(reputation_lookup, "query", lambda *a, **k: ["192.0.2.1"])
    session = FakeSession(
        {
            "/domains/": FakeResponse(vt_stats(0)),
            "/ip_addresses/": FakeResponse(vt_stats(0)),
        }
    )
    findings = reputation_lookup.ReputationLookup().run(
        one("example.com"), {"http": session, "reputation_keys": {"virustotal": "k1"}}
    )
    assert severities(findings) == ["info"]
    assert all("negative" not in f.title for f in findings)


def test_a_provider_outage_is_reported_as_partial_not_clean(monkeypatch):
    """Absence of a verdict must never read as a clean verdict."""
    from modules import reputation_lookup

    monkeypatch.setattr(reputation_lookup, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(reputation_lookup, "query", lambda *a, **k: ["192.0.2.1"])
    session = FakeSession(
        {
            "/domains/": FakeResponse({}, status_code=429),
            "/ip_addresses/": ConnectionError("provider unreachable"),
        }
    )
    findings = reputation_lookup.ReputationLookup().run(
        one("example.com"), {"http": session, "reputation_keys": {"virustotal": "k1"}}
    )
    partial = [f for f in findings if "could not be consulted" in f.title]
    assert len(partial) == 1
    assert partial[0].evidence["unavailable"] == ["virustotal"]
    assert partial[0].evidence["consulted"] == 0


def test_no_api_key_ever_reaches_a_finding(monkeypatch):
    import json

    from modules import reputation_lookup

    monkeypatch.setattr(reputation_lookup, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(reputation_lookup, "query", lambda *a, **k: ["192.0.2.1"])
    session = FakeSession(
        {
            "/domains/": FakeResponse(vt_stats(0)),
            "/ip_addresses/": FakeResponse(vt_stats(0)),
        }
    )
    findings = reputation_lookup.ReputationLookup().run(
        one("example.com"),
        {"http": session, "reputation_keys": {"virustotal": "super-secret-key"}},
    )
    serialised = json.dumps([f.to_dict() for f in findings])
    assert "super-secret-key" not in serialised
