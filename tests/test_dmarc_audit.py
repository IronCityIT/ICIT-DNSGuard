"""DMARC policy discovery and what it means for the host that was scanned.

Two ways this module used to be wrong, each with its own section below: it called
a domain enforcing while its subdomains were exempt, and it told the owner of a
subdomain that no policy existed when the parent domain's record covered it.

`find_txt` is replaced with a dict lookup keyed by query name. Nothing here
resolves a real name.
"""

from __future__ import annotations

import pytest
from modules import dmarc_audit
from targets import Target, parse_targets

from dnsguard.report import build

RUA = "rua=mailto:a@example.com"

ENFORCING = "Mail authentication policy is enforcing"
EXEMPT = "Subdomains are exempt from the mail authentication policy"
MISSING = "No mail authentication policy published"
MONITOR = "Mail authentication policy is monitor-only"
PARTIAL = "Mail authentication policy is only partially applied"
UNREPORTED = "Mail authentication reports go nowhere"


@pytest.fixture
def scan(monkeypatch):
    """Run the module against a fake zone. `scan.queried` is every name asked for."""

    def run(target, zone):
        run.queried = []

        def find_txt(_res, name, _prefix):
            run.queried.append(name)
            return zone.get(name, "")

        monkeypatch.setattr(dmarc_audit, "find_txt", find_txt)
        monkeypatch.setattr(dmarc_audit, "make_resolver", lambda *a, **k: object())
        if isinstance(target, str):
            target = parse_targets([target])[0]
        return dmarc_audit.DmarcAudit().run(target, {})

    run.queried = []
    return run


def summary(findings):
    return [(f.severity, f.title) for f in findings]


# ── the host's own record: subdomain exemption ───────────────────────────────


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
@pytest.mark.parametrize("exempt", ["none", "NONE"])
def test_own_policy_that_exempts_subdomains_is_not_enforcing(scan, policy, exempt):
    findings = scan(
        "example.com", {"_dmarc.example.com": f"v=DMARC1; p={policy}; sp={exempt}; {RUA}"}
    )
    assert summary(findings) == [("medium", EXEMPT)]
    assert findings[0].detail
    evidence = findings[0].evidence
    assert evidence["remediation"]
    # The host itself is still protected, and consumers read that from `policy`.
    assert evidence["policy"] == policy
    assert evidence["subdomain_policy"] == "none"
    assert evidence["policy_source"] == "_dmarc.example.com"
    assert evidence["inherited"] is False


@pytest.mark.parametrize(
    "sp",
    [
        pytest.param("sp=reject; ", id="reject"),
        pytest.param("sp=quarantine; ", id="quarantine"),
        pytest.param("", id="absent"),
        pytest.param("sp=; ", id="empty"),
        pytest.param("sp=bogus; ", id="invalid"),
    ],
)
def test_own_policy_that_covers_subdomains_is_enforcing(scan, sp):
    findings = scan("example.com", {"_dmarc.example.com": f"v=DMARC1; p=reject; {sp}{RUA}"})
    assert summary(findings) == [("info", ENFORCING)]
    assert findings[0].evidence["policy"] == "reject"


def test_own_monitor_only_policy_does_not_also_raise_the_subdomain_gap(scan):
    findings = scan("example.com", {"_dmarc.example.com": f"v=DMARC1; p=none; sp=none; {RUA}"})
    assert summary(findings) == [("medium", MONITOR)]


def test_subdomain_gap_is_reported_alongside_other_issues(scan):
    findings = scan("example.com", {"_dmarc.example.com": "v=DMARC1; p=reject; sp=none; pct=25"})
    assert summary(findings) == [("low", PARTIAL), ("medium", EXEMPT), ("low", UNREPORTED)]


# ── inheritance: the effective policy ────────────────────────────────────────


@pytest.mark.parametrize(
    ("tags", "effective"),
    [
        pytest.param("p=reject", "reject", id="no-sp"),
        pytest.param("p=reject; sp=bogus", "reject", id="invalid-sp"),
        pytest.param("p=reject; sp=quarantine", "quarantine", id="weaker-sp"),
        pytest.param("p=none; sp=reject", "reject", id="stronger-sp"),
    ],
)
def test_inherited_policy_is_reported_as_enforcing(scan, tags, effective):
    findings = scan("www.example.com", {"_dmarc.example.com": f"v=DMARC1; {tags}; {RUA}"})
    assert summary(findings) == [("info", ENFORCING)]
    assert findings[0].target == "www.example.com"
    assert effective in findings[0].detail
    assert "example.com" in findings[0].detail
    evidence = findings[0].evidence
    assert evidence["policy"] == effective
    assert evidence["policy_source"] == "_dmarc.example.com"
    assert evidence["inherited"] is True


@pytest.mark.parametrize(
    ("tags", "tag"),
    [
        pytest.param("p=reject; sp=none", "sp=none", id="exempted-by-sp"),
        pytest.param("p=none", "p=none", id="no-sp"),
        pytest.param("p=none; sp=bogus", "p=none", id="invalid-sp"),
    ],
)
def test_inherited_none_is_monitor_only(scan, tags, tag):
    findings = scan("www.example.com", {"_dmarc.example.com": f"v=DMARC1; {tags}; {RUA}"})
    assert summary(findings) == [("medium", MONITOR)]
    # The tag actually responsible: telling the owner of p=reject that they
    # publish p=none sends them to the wrong setting.
    assert tag in findings[0].detail
    assert findings[0].evidence["policy"] == "none"
    assert findings[0].evidence["remediation"]


def test_inherited_partial_rollout_is_still_flagged(scan):
    findings = scan("www.example.com", {"_dmarc.example.com": f"v=DMARC1; p=reject; pct=25; {RUA}"})
    assert summary(findings) == [("low", PARTIAL)]


def test_inherited_exemption_does_not_render_as_reject_in_the_report(scan):
    """The dashboard goes green on `dmarc_policy == "reject"`."""
    findings = scan(
        "www.example.com", {"_dmarc.example.com": f"v=DMARC1; p=reject; sp=none; {RUA}"}
    )
    email = build(findings, "www.example.com")["email_security"]
    assert email["dmarc_valid"] is True
    assert email["dmarc_policy"] == "none"
    assert email["dmarc_issues"] == [MONITOR]


# ── discovery: which names are asked, and which wins ─────────────────────────


@pytest.mark.parametrize(
    "target", ["https://portal.example.com/login?next=1", "https://portal.example.com.:8443/"]
)
def test_url_target_inherits_from_its_parent_domain(scan, target):
    findings = scan(target, {"_dmarc.example.com": f"v=DMARC1; p=reject; {RUA}"})
    assert summary(findings) == [("info", ENFORCING)]
    assert findings[0].evidence["policy_source"] == "_dmarc.example.com"
    assert findings[0].evidence["inherited"] is True


def test_own_record_takes_precedence_over_the_parent(scan):
    findings = scan(
        "www.example.com",
        {
            "_dmarc.www.example.com": f"v=DMARC1; p=none; sp=reject; {RUA}",
            "_dmarc.example.com": f"v=DMARC1; p=reject; {RUA}",
        },
    )
    assert summary(findings) == [("medium", MONITOR)]
    assert findings[0].evidence["policy_source"] == "_dmarc.www.example.com"
    assert findings[0].evidence["inherited"] is False
    assert scan.queried == ["_dmarc.www.example.com"]


def test_nearest_parent_wins(scan):
    findings = scan(
        "a.b.example.com",
        {
            "_dmarc.b.example.com": f"v=DMARC1; p=quarantine; {RUA}",
            "_dmarc.example.com": f"v=DMARC1; p=reject; {RUA}",
        },
    )
    assert findings[0].evidence["policy"] == "quarantine"
    assert scan.queried == ["_dmarc.a.b.example.com", "_dmarc.b.example.com"]


@pytest.mark.parametrize("target", ["example.com", "www.example.com", "https://a.example.com./"])
def test_no_record_anywhere_is_high_and_never_asks_the_tld(scan, target):
    """A record at the bare TLD must not be picked up either, so one is planted."""
    findings = scan(target, {"_dmarc.com": f"v=DMARC1; p=reject; {RUA}"})
    assert summary(findings) == [("high", MISSING)]
    assert findings[0].evidence["record"] == ""
    assert findings[0].evidence["remediation"]
    assert scan.queried[-1].rstrip(".") == "_dmarc.example.com"
    assert "_dmarc.com" not in [name.rstrip(".") for name in scan.queried]


def test_walk_moves_up_one_label_at_a_time(scan):
    scan("a.b.example.com", {})
    assert scan.queried == ["_dmarc.a.b.example.com", "_dmarc.b.example.com", "_dmarc.example.com"]


def test_walk_stops_at_the_lookup_cap(scan):
    host = ".".join(f"l{i}" for i in range(20)) + ".example.com"
    findings = scan(host, {"_dmarc.example.com": f"v=DMARC1; p=reject; {RUA}"})
    assert len(scan.queried) == 8
    assert scan.queried[0] == f"_dmarc.{host}"
    assert summary(findings) == [("high", MISSING)]


def test_record_on_the_last_permitted_lookup_is_used(scan):
    host = "a.b.c.d.e.f.g.example.com"
    findings = scan(host, {"_dmarc.example.com": f"v=DMARC1; p=reject; {RUA}"})
    assert len(scan.queried) == 8
    assert summary(findings) == [("info", ENFORCING)]


@pytest.mark.parametrize("target", ["https://192.0.2.10/", "fileserver"])
def test_names_without_a_parent_domain_are_asked_once(scan, target):
    """Octets are not labels: 192.0.2.10 has no parent called 0.2.10."""
    findings = scan(target, {})
    assert summary(findings) == [("high", MISSING)]
    assert len(scan.queried) == 1


def test_target_without_a_host_is_not_queried(scan):
    assert scan(Target(raw="", kind="url", value="https://"), {}) == []
    assert scan.queried == []
