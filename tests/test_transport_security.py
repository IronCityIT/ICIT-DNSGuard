"""MTA-STS: the half that decides anything is the half that is hard to see.

The TXT record at `_mta-sts.<domain>` carries a version and an id and nothing
else. `mode: enforce | testing | none` lives in a policy file fetched over HTTPS,
and this module used to report "encrypted mail transport is enforced and
reported" on the strength of the record alone.

Three states were therefore reported as enforced while protecting nothing:
a policy in `testing`, a policy in `none`, and a record with no policy behind it
at all. Each has a test below, because each fails in the reassuring direction —
the same shape as the DNSSEC module reporting a zone as signed on a DNSKEY with
no DS behind it.

Nothing here touches the network: the DNS lookup and the HTTPS fetch are both
injected.
"""

from __future__ import annotations

import pytest
from modules import transport_security_audit as tsa
from modules.transport_security_audit import TransportSecurityAudit, parse_policy
from targets import parse_targets

RECORD = "v=STSv1; id=20260907T000000;"


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class FakeSession:
    """Answers the policy fetch. `raises` models the case that must never be
    read as evidence of anything: we could not find out."""

    def __init__(self, response=None, raises=False):
        self.response = response
        self.raises = raises
        self.urls: list[str] = []

    def get(self, url, timeout=None):
        self.urls.append(url)
        if self.raises:
            raise OSError("connection refused")
        return self.response


def policy_text(mode="enforce", max_age=1209600, mx=("mail.example.com",)):
    lines = ["version: STSv1", f"mode: {mode}"]
    lines += [f"mx: {name}" for name in mx]
    lines.append(f"max_age: {max_age}")
    return "\n".join(lines) + "\n"


def run(
    monkeypatch, *, record=RECORD, tls_rpt="v=TLSRPTv1; rua=mailto:x@example.com", session=None
):
    monkeypatch.setattr(tsa, "make_resolver", lambda *a, **k: object())

    def fake_find_txt(_res, name, prefix):
        if name.startswith("_mta-sts.") and prefix.startswith("v=STSv1"):
            return record
        if name.startswith("_smtp._tls.") and prefix.startswith("v=TLSRPTv1"):
            return tls_rpt
        return ""

    monkeypatch.setattr(tsa, "find_txt", fake_find_txt)
    ctx = {"http": session or FakeSession(FakeResponse(text=policy_text()))}
    return TransportSecurityAudit().run(parse_targets(["example.com"])[0], ctx)


def titles(findings):
    return [f.title for f in findings]


def one(findings, fragment):
    matched = [f for f in findings if fragment.lower() in f.title.lower()]
    assert len(matched) == 1, f"expected exactly one {fragment!r} finding, got {titles(findings)}"
    return matched[0]


# ── the three states that used to read as "enforced" ─────────────────────────


def test_a_policy_in_testing_mode_is_not_enforced(monkeypatch):
    """Testing is the rollout stage where senders report failures and deliver
    anyway. A domain can sit in it for years, and reporting it as enforced is
    how it stays there."""
    session = FakeSession(FakeResponse(text=policy_text(mode="testing")))
    findings = run(monkeypatch, session=session)
    finding = one(findings, "not yet enforced")
    assert finding.severity == "low"
    assert finding.evidence["mode"] == "testing"
    assert not [f for f in findings if f.title == "Encrypted mail transport is enforced"]


def test_a_policy_in_none_mode_is_switched_off(monkeypatch):
    """mode: none exists to disable MTA-STS. The record is advertising an
    opt-out."""
    session = FakeSession(FakeResponse(text=policy_text(mode="none")))
    finding = one(run(monkeypatch, session=session), "explicitly switched off")
    assert finding.severity == "low"


def test_a_record_with_no_policy_behind_it_protects_nothing(monkeypatch):
    """A sender fetches the policy, fails, and falls back to opportunistic TLS.
    The record provides no protection while appearing to."""
    session = FakeSession(FakeResponse(status_code=404))
    finding = one(run(monkeypatch, session=session), "advertised but not published")
    assert finding.severity == "medium"
    assert "falls back" in finding.detail


# ── what enforcement actually looks like ─────────────────────────────────────


def test_a_policy_in_enforce_mode_is_enforced(monkeypatch):
    findings = run(monkeypatch)
    finding = one(findings, "Encrypted mail transport is enforced")
    assert finding.severity == "info"
    assert finding.evidence["mode"] == "enforce"
    assert finding.evidence["mx"] == ["mail.example.com"]


def test_no_record_at_all_is_still_reported(monkeypatch):
    finding = one(run(monkeypatch, record=""), "is not enforced")
    assert finding.severity == "low"
    assert finding.remediation


def test_the_policy_is_fetched_from_the_right_place(monkeypatch):
    """RFC 8461 fixes the location. A fetch from anywhere else would be reading
    somebody else's policy."""
    session = FakeSession(FakeResponse(text=policy_text()))
    run(monkeypatch, session=session)
    assert session.urls == ["https://mta-sts.example.com/.well-known/mta-sts.txt"]


# ── not knowing is its own answer ────────────────────────────────────────────


def test_an_unreachable_policy_is_inconclusive_not_a_pass(monkeypatch):
    """A timeout is not evidence that a domain is unprotected, and it is not
    evidence that it is protected either. Reporting either would manufacture a
    finding out of our own connectivity."""
    findings = run(monkeypatch, session=FakeSession(raises=True))
    finding = one(findings, "could not be established")
    assert finding.confidence == "inconclusive"
    assert "unassessed rather than clean" in finding.detail


def test_a_policy_with_no_usable_mode_is_reported(monkeypatch):
    """A sender that cannot parse the policy applies none of it, so a malformed
    policy is closer to no policy than to a working one."""
    session = FakeSession(FakeResponse(text="version: STSv1\nmx: mail.example.com\n"))
    finding = one(run(monkeypatch, session=session), "does not state a usable mode")
    assert finding.severity == "medium"


@pytest.mark.parametrize("mode", ["ENFORCE", "Enforce", "enforce"])
def test_the_mode_is_read_case_insensitively(monkeypatch, mode):
    session = FakeSession(FakeResponse(text=policy_text(mode=mode)))
    assert one(run(monkeypatch, session=session), "is enforced").evidence["mode"] == "enforce"


# ── max_age ──────────────────────────────────────────────────────────────────


def test_a_short_lived_policy_is_flagged(monkeypatch):
    """A sender caches the policy for max_age. An attacker who can keep the
    policy host unreachable for slightly longer returns the domain to
    unprotected delivery."""
    session = FakeSession(FakeResponse(text=policy_text(max_age=600)))
    findings = run(monkeypatch, session=session)
    assert one(findings, "expires quickly").severity == "low"
    assert one(findings, "Encrypted mail transport is enforced"), "still enforced, just brittle"


def test_a_long_lived_policy_is_not_flagged(monkeypatch):
    session = FakeSession(FakeResponse(text=policy_text(max_age=1209600)))
    assert not [f for f in run(monkeypatch, session=session) if "expires quickly" in f.title]


# ── TLS-RPT ──────────────────────────────────────────────────────────────────


def test_a_missing_tls_rpt_record_is_reported(monkeypatch):
    finding = one(run(monkeypatch, tls_rpt=""), "failures are not reported")
    assert finding.severity == "info"


def test_a_present_tls_rpt_record_produces_no_finding(monkeypatch):
    assert not [f for f in run(monkeypatch) if "not reported" in f.title]


# ── the parser ───────────────────────────────────────────────────────────────


def test_repeated_mx_lines_are_all_kept():
    parsed = parse_policy("version: STSv1\nmode: enforce\nmx: a.example\nmx: b.example\n")
    assert parsed["mx"] == ["a.example", "b.example"]


def test_unknown_keys_are_kept_rather_than_dropped():
    """A policy carrying something this parser has not been taught about is
    still evidence; discarding it would make the report look more certain than
    the data."""
    assert parse_policy("mode: enforce\nsomething: else\n")["something"] == "else"


@pytest.mark.parametrize("text", ["", "   \n\n", "not a policy at all", "# comment only"])
def test_junk_parses_to_no_mode_rather_than_raising(text):
    assert parse_policy(text).get("mode") is None


def test_whitespace_around_values_is_ignored():
    assert parse_policy("  mode :   enforce  \n")["mode"] == "enforce"


# ── the module's own contract ────────────────────────────────────────────────


def test_the_description_does_not_promise_more_than_it_checks():
    text = TransportSecurityAudit().description.lower()
    assert "in force" in text or "enforced" in text


def test_a_target_with_no_host_produces_nothing(monkeypatch):
    monkeypatch.setattr(tsa, "host_of", lambda _t: "")
    assert TransportSecurityAudit().run(object(), {}) == []
