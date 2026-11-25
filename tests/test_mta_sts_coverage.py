"""MTA-STS in enforce mode: does the policy name the servers that receive the mail?

`mode: enforce` tells a sender to refuse any mail server the policy does not
list. A policy that omits a live MX is therefore not a weaker form of protection,
it is lost mail — and the module used to report it as "Encrypted mail transport
is enforced" without ever looking at the MX records.

The second half is the client report's `mta_sts` and `tls_rpt` flags, which read
evidence keys the module never set, so both were False for every client.

Nothing here touches the network: the resolver and the HTTPS fetch are injected.
"""

from __future__ import annotations

import dns.rdata
import dns.resolver
import pytest
from modules import transport_security_audit as tsa
from modules.transport_security_audit import TransportSecurityAudit
from targets import parse_targets

from dnsguard.report import build

STS_RECORD = "v=STSv1; id=20260907T000000;"
TLS_RPT_RECORD = "v=TLSRPTv1; rua=mailto:x@example.com"

ENFORCED = "Encrypted mail transport is enforced"
SOME_OMITTED = "The MTA-STS policy omits some of the domain's mail servers"
ALL_OMITTED = "The MTA-STS policy omits all of the domain's mail servers"
NO_MX_LINES = "The MTA-STS policy lists no mail servers"


class FakeResolver:
    """Answers TXT and MX for example.com. `mx` is a list of records, or an
    exception to raise instead of answering."""

    def __init__(self, mx, sts=STS_RECORD, tls_rpt=TLS_RPT_RECORD):
        self.mx = mx
        self.txt = {"_mta-sts.example.com": sts, "_smtp._tls.example.com": tls_rpt}

    def resolve(self, name, rtype):
        if rtype == "TXT" and self.txt.get(name):
            return [dns.rdata.from_text("IN", "TXT", f'"{self.txt[name]}"')]
        if rtype == "MX" and name == "example.com":
            if isinstance(self.mx, Exception):
                raise self.mx
            return [dns.rdata.from_text("IN", "MX", record) for record in self.mx]
        raise dns.resolver.NoAnswer


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, text, status_code=200, raises=False):
        self.response = FakeResponse(status_code, text)
        self.raises = raises

    def get(self, _url, timeout=None):
        if self.raises:
            raise OSError("connection refused")
        return self.response


def policy_text(*patterns, mode="enforce", max_age=1209600):
    lines = ["version: STSv1", f"mode: {mode}"]
    lines += [f"mx: {pattern}" for pattern in patterns]
    lines.append(f"max_age: {max_age}")
    return "\n".join(lines) + "\n"


def run(monkeypatch, *, patterns=("mail.example.com",), mx=("10 mail.example.com.",), **kw):
    session = kw.pop("session", None) or FakeSession(policy_text(*patterns))
    resolver = FakeResolver(mx, **kw)
    monkeypatch.setattr(tsa, "make_resolver", lambda *a, **k: resolver)
    return TransportSecurityAudit().run(parse_targets(["example.com"])[0], {"http": session})


def titles(findings):
    return [f.title for f in findings]


def titled(findings, title):
    matched = [f for f in findings if f.title == title]
    assert len(matched) == 1, f"expected exactly one {title!r}, got {titles(findings)}"
    return matched[0]


def email_flags(findings):
    email = build(findings, "example.com")["email_security"]
    return email["mta_sts"], email["tls_rpt"]


# ── matching, RFC 8461 section 4.1 ───────────────────────────────────────────


@pytest.mark.parametrize(
    ("pattern", "record"),
    [
        pytest.param("mail.example.com", "10 mail.example.com.", id="exact"),
        pytest.param("*.example.com", "10 mx1.example.com.", id="wildcard"),
        pytest.param("MAIL.Example.COM", "10 mail.example.com.", id="policy-case"),
        pytest.param("mail.example.com", "10 MAIL.EXAMPLE.COM.", id="record-case"),
        pytest.param("mail.example.com.", "10 mail.example.com.", id="policy-trailing-dot"),
        pytest.param("*.Example.com.", "10 mx1.EXAMPLE.com.", id="wildcard-case-and-dot"),
    ],
)
def test_a_listed_mail_server_is_covered(monkeypatch, pattern, record):
    findings = run(monkeypatch, patterns=[pattern], mx=[record])
    assert titles(findings) == [ENFORCED]
    evidence = findings[0].evidence
    assert evidence["mx_hosts"] == [record.split()[1].rstrip(".").lower()]
    assert evidence["mx_unlisted"] == []


@pytest.mark.parametrize(
    ("pattern", "record"),
    [
        pytest.param("*.example.com", "10 a.b.example.com.", id="wildcard-two-labels"),
        pytest.param("*.example.com", "10 example.com.", id="wildcard-no-label"),
        pytest.param("*.example.com", "10 mx.notexample.com.", id="wildcard-suffix-only"),
        pytest.param("mail.example.com", "10 xmail.example.com.", id="exact-suffix-only"),
        pytest.param("mail.*.com", "10 mail.example.com.", id="wildcard-not-left-most"),
        pytest.param("*", "10 mail.example.com.", id="bare-wildcard"),
    ],
)
def test_an_unlisted_mail_server_is_not_covered(monkeypatch, pattern, record):
    findings = run(monkeypatch, patterns=[pattern], mx=[record])
    assert titles(findings) == [ALL_OMITTED]


# ── mismatches ───────────────────────────────────────────────────────────────


def test_a_partial_mismatch_names_the_servers_that_are_refused(monkeypatch):
    findings = run(
        monkeypatch,
        mx=["10 mail.example.com.", "20 backup.example.net."],
    )
    assert titles(findings) == [ENFORCED, SOME_OMITTED]
    finding = titled(findings, SOME_OMITTED)
    assert finding.severity == "medium"
    assert finding.category == "email"
    assert "backup.example.net" in finding.detail
    assert "mail.example.com" not in finding.detail, "a listed host is not part of the problem"
    assert finding.remediation
    assert finding.evidence["mx_hosts"] == ["mail.example.com", "backup.example.net"]
    assert finding.evidence["mx_unlisted"] == ["backup.example.net"]


def test_a_full_mismatch_replaces_the_reassuring_finding(monkeypatch):
    """Every compliant sender refuses to deliver. Calling that "enforced" is
    true, and is the worst possible thing to tell the client."""
    findings = run(
        monkeypatch,
        patterns=["old.example.org"],
        mx=["10 mail.example.com.", "20 backup.example.net."],
    )
    finding = titled(findings, ALL_OMITTED)
    assert ENFORCED not in titles(findings)
    assert finding.severity == "high"
    assert finding.category == "email"
    assert "mail.example.com" in finding.detail and "backup.example.net" in finding.detail
    assert finding.remediation
    assert finding.evidence["mx_unlisted"] == ["mail.example.com", "backup.example.net"]


def test_a_mismatch_that_gets_worse_is_the_same_finding(monkeypatch):
    """Partial to full is an escalation. Two fingerprints would report it to the
    client as one problem resolved and another one found."""
    mx = ["10 mail.example.com.", "20 backup.example.net."]
    partial = titled(run(monkeypatch, mx=mx), SOME_OMITTED)
    full = titled(run(monkeypatch, patterns=["old.example.org"], mx=mx), ALL_OMITTED)
    assert partial.fingerprint() == full.fingerprint()


@pytest.mark.parametrize("text", [policy_text(), policy_text("")], ids=["absent", "blank"])
def test_an_enforce_policy_with_no_mx_is_invalid(monkeypatch, text):
    """RFC 8461 section 3.2 requires at least one mx outside mode: none. A sender
    discards a policy it cannot use, so nothing is enforced."""
    findings = run(monkeypatch, session=FakeSession(text))
    assert titles(findings) == [NO_MX_LINES]
    assert findings[0].severity == "medium"
    assert findings[0].remediation
    assert findings[0].evidence["mx_hosts"] == ["mail.example.com"]
    assert findings[0].evidence["mx_unlisted"] == ["mail.example.com"]


# ── nothing to compare against ───────────────────────────────────────────────

UNCHECKABLE = [
    pytest.param(dns.resolver.LifetimeTimeout(timeout=10, errors=[]), id="timeout"),
    pytest.param(dns.resolver.NoNameservers(), id="servfail"),
    pytest.param(dns.resolver.NoAnswer(), id="no-mx"),
    pytest.param(dns.resolver.NXDOMAIN(), id="nxdomain"),
    pytest.param(["0 ."], id="null-mx"),
]


@pytest.mark.parametrize("mx", UNCHECKABLE)
def test_no_claim_is_made_about_coverage_that_could_not_be_checked(monkeypatch, mx):
    """A lookup that failed is not evidence that a server is unlisted, and a
    domain with no mail servers has none to omit."""
    findings = run(monkeypatch, patterns=["old.example.org"], mx=mx)
    assert titles(findings) == [ENFORCED]
    assert findings[0].evidence["mx_hosts"] == []
    assert findings[0].evidence["mx_unlisted"] == []


@pytest.mark.parametrize("mode", ["testing", "none"])
def test_coverage_is_only_judged_in_enforce_mode(monkeypatch, mode):
    session = FakeSession(policy_text("old.example.org", mode=mode))
    findings = run(monkeypatch, session=session)
    assert not {SOME_OMITTED, ALL_OMITTED, NO_MX_LINES} & set(titles(findings))


# ── the client report's flags, built end to end ──────────────────────────────


def test_both_flags_are_true_for_a_working_domain(monkeypatch):
    assert email_flags(run(monkeypatch)) == (True, True)


def test_a_partly_covered_domain_keeps_credit(monkeypatch):
    findings = run(monkeypatch, mx=["10 mail.example.com.", "20 backup.example.net."])
    assert email_flags(findings) == (True, True)


@pytest.mark.parametrize("mx", UNCHECKABLE)
def test_a_domain_whose_coverage_could_not_be_checked_keeps_credit(monkeypatch, mx):
    assert email_flags(run(monkeypatch, mx=mx)) == (True, True)


@pytest.mark.parametrize(
    "kw",
    [
        pytest.param({"sts": ""}, id="no-record"),
        pytest.param({"session": FakeSession("", status_code=404)}, id="policy-missing"),
        pytest.param({"session": FakeSession("", raises=True)}, id="policy-unreachable"),
        pytest.param({"session": FakeSession("version: STSv1\n")}, id="policy-without-mode"),
        pytest.param(
            {"session": FakeSession(policy_text("mail.example.com", mode="testing"))},
            id="testing",
        ),
        pytest.param(
            {"session": FakeSession(policy_text("mail.example.com", mode="none"))}, id="none"
        ),
        pytest.param({"session": FakeSession(policy_text())}, id="no-mx-lines"),
        pytest.param({"patterns": ["old.example.org"]}, id="every-mx-omitted"),
    ],
)
def test_mta_sts_gets_no_credit_when_it_is_not_working(monkeypatch, kw):
    """And TLS-RPT, which is published throughout, keeps its own."""
    assert email_flags(run(monkeypatch, **kw)) == (False, True)


def test_a_missing_tls_rpt_record_does_not_cost_mta_sts_its_credit(monkeypatch):
    assert email_flags(run(monkeypatch, tls_rpt="")) == (True, False)


def test_both_flags_are_false_when_neither_is_published(monkeypatch):
    assert email_flags(run(monkeypatch, sts="", tls_rpt="")) == (False, False)


def test_every_finding_carries_both_flags(monkeypatch):
    """Including the TLS-RPT one, and including the max_age one."""
    session = FakeSession(policy_text("mail.example.com", max_age=600))
    findings = run(
        monkeypatch,
        session=session,
        mx=["10 mail.example.com.", "20 backup.example.net."],
        tls_rpt="",
    )
    assert len(findings) == 4, titles(findings)
    for finding in findings:
        assert finding.evidence["mta_sts"] is True, finding.title
        assert finding.evidence["tls_rpt"] is False, finding.title


def test_a_present_tls_rpt_record_still_produces_no_finding(monkeypatch):
    assert titles(run(monkeypatch)) == [ENFORCED]
