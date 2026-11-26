"""Reputation coverage: what was actually asked, and never "checked" when nothing answered.

Offline only. HTTP goes to a fake session and DNS to a stubbed query(); every
address is from the documentation ranges (192.0.2.0/24, 2001:db8::/32) and every
key is a dummy string.
"""

from __future__ import annotations

from modules import reputation_lookup
from targets import parse_targets


def one(value: str):
    return parse_targets([value])[0]


def titles(findings):
    return [f.title for f in findings]


def by_title(findings, title):
    return [f for f in findings if f.title == title]


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class FakeSession:
    """Returns a canned response per URL fragment, or raises for one. Records every call."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[tuple[str, dict]] = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        for fragment, response in self.routes.items():
            if fragment in url:
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected request to {url}")

    def checked_addresses(self):
        """Addresses sent to the address-reputation endpoint, in request order."""
        return [kw["params"]["ipAddress"] for url, kw in self.calls if "abuseipdb" in url]


def vt_stats(malicious):
    return {
        "data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "harmless": 60}}}
    }


def abuse(score):
    return FakeResponse({"data": {"abuseConfidenceScore": score, "totalReports": 1}})


def stub_dns(monkeypatch, records):
    """Stub query(): `records` maps rtype -> values. Returns the list of rtypes asked for."""
    asked: list[str] = []

    def fake_query(_res, _name, rtype):
        asked.append(rtype)
        return list(records.get(rtype, []))

    monkeypatch.setattr(reputation_lookup, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(reputation_lookup, "query", fake_query)
    return asked


def run(target, session, keys):
    return reputation_lookup.ReputationLookup().run(
        one(target), {"http": session, "reputation_keys": keys}
    )


# ── defect 1: zero verdicts must not read as "checked" ───────────────────────


def test_every_provider_failing_is_not_reported_as_checked(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"]})
    session = FakeSession(
        {
            "/domains/": FakeResponse({}, status_code=429),
            "/ip_addresses/": ConnectionError("provider unreachable"),
            "abuseipdb": FakeResponse({}, status_code=429),
        }
    )
    findings = run("example.com", session, {"virustotal": "dummy-1", "abuseipdb": "dummy-2"})

    assert "Reputation checked" not in titles(findings)
    unchecked = by_title(findings, "Reputation could not be checked")
    assert len(unchecked) == 1
    assert unchecked[0].severity == "info"
    assert "not a clean result" in unchecked[0].detail
    evidence = unchecked[0].evidence
    assert evidence["consulted"] is False
    assert evidence["verdicts"] == []
    assert evidence["addresses"] == ["192.0.2.1"]
    assert evidence["providers_configured"] == ["abuseipdb", "virustotal"]

    partial = by_title(findings, "Some reputation providers could not be consulted")
    assert len(partial) == 1
    assert partial[0].evidence == {"unavailable": ["abuseipdb", "virustotal"], "consulted": 0}


def test_address_provider_with_no_addresses_is_not_reported_as_checked(monkeypatch):
    stub_dns(monkeypatch, {})
    session = FakeSession({})
    findings = run("example.com", session, {"abuseipdb": "dummy-2"})

    assert session.calls == []
    assert titles(findings) == ["Reputation could not be checked"]
    evidence = findings[0].evidence
    assert evidence["consulted"] is False
    assert evidence["verdicts"] == []
    assert evidence["addresses"] == []
    assert evidence["providers_configured"] == ["abuseipdb"]


# ── defect 2: a provider that gives no verdict is not "configured" ───────────


def test_only_a_non_verdict_provider_is_reported_as_not_consulted(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"]})
    session = FakeSession({})
    findings = run("example.com", session, {"ipstack": "dummy-3"})

    assert session.calls == []
    assert len(findings) == 1
    assert findings[0].title == "Reputation providers were not consulted"
    assert findings[0].evidence["consulted"] is False
    assert findings[0].evidence["providers_configured"] == []


def test_a_non_verdict_provider_is_kept_out_of_providers_configured(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"]})
    session = FakeSession({"abuseipdb": abuse(0)})
    findings = run("example.com", session, {"abuseipdb": "dummy-2", "ipstack": "dummy-3"})

    checked = by_title(findings, "Reputation checked")
    assert len(checked) == 1
    assert checked[0].evidence["providers_configured"] == ["abuseipdb"]


# ── defect 3: IPv6 addresses are checked too ─────────────────────────────────


def test_an_ipv6_only_host_with_a_flagged_address_is_raised(monkeypatch):
    asked = stub_dns(monkeypatch, {"AAAA": ["2001:db8::66"]})
    session = FakeSession(
        {
            "/domains/": FakeResponse(vt_stats(0)),
            "/ip_addresses/2001:db8::66": FakeResponse(vt_stats(12)),
        }
    )
    findings = run("example.com", session, {"virustotal": "dummy-1"})

    assert "AAAA" in asked
    flagged = by_title(findings, "Infrastructure has a negative reputation")
    assert len(flagged) == 1
    assert [v["target"] for v in flagged[0].evidence["verdicts"]] == ["2001:db8::66"]


def test_an_address_returned_for_a_and_aaaa_is_checked_once(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"], "AAAA": ["192.0.2.1"]})
    session = FakeSession({"abuseipdb": abuse(0)})
    findings = run("example.com", session, {"abuseipdb": "dummy-2"})

    assert session.checked_addresses() == ["192.0.2.1"]
    checked = by_title(findings, "Reputation checked")
    assert checked[0].evidence["addresses"] == ["192.0.2.1"]


def test_both_families_are_checked_in_a_stable_order(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]})
    session = FakeSession({"abuseipdb": abuse(0)})
    findings = run("example.com", session, {"abuseipdb": "dummy-2"})

    assert session.checked_addresses() == ["192.0.2.1", "2001:db8::1"]
    assert by_title(findings, "Reputation checked")[0].evidence["addresses"] == [
        "192.0.2.1",
        "2001:db8::1",
    ]


# ── defect 4: the address cap is disclosed and keeps both families ───────────


def test_the_address_cap_keeps_both_families_and_records_what_was_dropped(monkeypatch):
    v4 = [f"192.0.2.{n}" for n in range(1, 8)]
    v6 = ["2001:db8::1", "2001:db8::2"]
    stub_dns(monkeypatch, {"A": v4, "AAAA": v6})
    session = FakeSession({"abuseipdb": abuse(0)})
    findings = run("example.com", session, {"abuseipdb": "dummy-2"})

    checked_addresses = session.checked_addresses()
    assert len(checked_addresses) == reputation_lookup.MAX_ADDRESSES == 5
    assert len(set(checked_addresses)) == 5
    assert any(":" in a for a in checked_addresses)
    assert any("." in a for a in checked_addresses)

    summary = by_title(findings, "Reputation checked")
    assert len(summary) == 1
    assert summary[0].evidence["addresses"] == checked_addresses
    assert summary[0].evidence["addresses_not_checked"] == 4
    assert "4" in summary[0].detail
    assert "not checked" in summary[0].detail


def test_no_addresses_dropped_means_no_not_checked_count(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"]})
    session = FakeSession({"abuseipdb": abuse(0)})
    findings = run("example.com", session, {"abuseipdb": "dummy-2"})

    assert "addresses_not_checked" not in by_title(findings, "Reputation checked")[0].evidence


# ── behaviour that must not change ───────────────────────────────────────────


def test_a_clean_lookup_with_one_provider_is_one_checked_finding(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"]})
    session = FakeSession(
        {"/domains/": FakeResponse(vt_stats(0)), "/ip_addresses/": FakeResponse(vt_stats(0))}
    )
    findings = run("example.com", session, {"virustotal": "dummy-1"})

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].title == "Reputation checked"


def test_one_provider_answering_is_checked_but_partial(monkeypatch):
    stub_dns(monkeypatch, {"A": ["192.0.2.1"]})
    session = FakeSession(
        {
            "/domains/": FakeResponse(vt_stats(0)),
            "/ip_addresses/": FakeResponse(vt_stats(0)),
            "abuseipdb": FakeResponse({}, status_code=429),
        }
    )
    findings = run("example.com", session, {"virustotal": "dummy-1", "abuseipdb": "dummy-2"})

    assert "Reputation checked" in titles(findings)
    assert "Reputation could not be checked" not in titles(findings)
    partial = by_title(findings, "Some reputation providers could not be consulted")
    assert len(partial) == 1
    assert partial[0].evidence == {"unavailable": ["abuseipdb"], "consulted": 2}


def test_an_ip_target_is_checked_directly_without_dns(monkeypatch):
    def no_dns(*_a, **_k):
        raise AssertionError("query() must not be called for an IP target")

    monkeypatch.setattr(reputation_lookup, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(reputation_lookup, "query", no_dns)
    session = FakeSession({"abuseipdb": abuse(0)})
    findings = run("192.0.2.10", session, {"abuseipdb": "dummy-2"})

    assert session.checked_addresses() == ["192.0.2.10"]
    assert titles(findings) == ["Reputation checked"]


def test_no_dummy_key_reaches_a_finding(monkeypatch):
    import json

    stub_dns(monkeypatch, {"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]})
    session = FakeSession(
        {
            "/domains/": FakeResponse({}, status_code=429),
            "/ip_addresses/": ConnectionError("down"),
            "abuseipdb": FakeResponse({}, status_code=429),
        }
    )
    findings = run(
        "example.com", session, {"virustotal": "dummy-vt-key", "abuseipdb": "dummy-abuse-key"}
    )
    serialised = json.dumps([f.to_dict() for f in findings])
    assert "dummy-vt-key" not in serialised
    assert "dummy-abuse-key" not in serialised
