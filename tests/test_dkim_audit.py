"""DKIM key classification.

Two client-facing answers were wrong: a revoked key (an empty p=, which parked
domains publish as a wildcard) read as working mail signing, and a valid key
that omitted the optional v= tag read as no signing at all.

Answers are real TXT rdata rather than strings, so the suite exercises whatever
presentation form the shared lookup helper produces.
"""

from __future__ import annotations

import base64

import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest
from dns.rdtypes.ANY.TXT import TXT
from modules import dkim_audit
from modules._dns import DKIM_SELECTORS
from modules.dkim_audit import DkimAudit
from targets import Target

from dnsguard.report import build

HOST = "example.com"
# The size of a 2048-bit RSA public key (over 255 characters once encoded, so it
# cannot fit in one TXT string) and of an Ed25519 one.
KEY = base64.b64encode(bytes(i % 251 for i in range(294))).decode()
SHORT_KEY = base64.b64encode(bytes(range(32))).decode()

REVOKED = "v=DKIM1; p="
USABLE = f"v=DKIM1; k=rsa; p={KEY}"


def label(value):
    """Short test ids: a whole key in every test name makes failures unreadable."""
    return str(value).replace(KEY, "<key>")[:48] or "empty"


def txt(value):
    """TXT rdata for a record given as one string, or as a tuple of strings."""
    parts = (value,) if isinstance(value, str) else value
    chunks = [p[i : i + 255] for p in parts for i in range(0, len(p) or 1, 255)]
    return TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [c.encode() for c in chunks])


class StubResolver:
    """Answers TXT for `<selector>._domainkey.example.com` and nothing else."""

    def __init__(self, records, wildcard=()):
        self.records = {f"{s}._domainkey.{HOST}": values for s, values in records.items()}
        self.wildcard = wildcard

    def resolve(self, name, rtype):
        assert rtype == "TXT"
        assert name.endswith(f"._domainkey.{HOST}")
        values = self.records.get(name, self.wildcard)
        if not values:
            raise dns.resolver.NXDOMAIN
        return [txt(v) for v in values]


@pytest.fixture
def audit(monkeypatch):
    def run(records=None, wildcard=(), ctx=None):
        stub = StubResolver(records or {}, wildcard)
        monkeypatch.setattr(dkim_audit, "make_resolver", lambda *a, **k: stub)
        findings = DkimAudit().run(Target(raw=HOST, kind="domain", value=HOST), ctx or {})
        assert len(findings) == 1
        return findings[0]

    return run


# ── revoked keys ─────────────────────────────────────────────────────────────


def test_a_wildcard_revoked_key_is_not_working_mail_signing(audit):
    finding = audit(wildcard=[REVOKED])
    assert finding.severity == "high"
    assert finding.title == "Every mail signing key found has been revoked"
    assert finding.evidence["revoked_selectors"] == sorted(DKIM_SELECTORS)
    assert finding.evidence["selectors_probed"] == len(DKIM_SELECTORS)
    assert finding.evidence["remediation"]
    assert "selectors" not in finding.evidence, "the report reads this as DKIM configured"


@pytest.mark.parametrize(
    "record",
    [
        "v=DKIM1; p=",
        "v=DKIM1;p=;",
        "v=DKIM1; k=rsa; p= ; t=s",
        "V=dkim1; P=",
        ("v=DKIM1; p=", ""),
        ("v=DKIM1; ", "p="),
    ],
    ids=label,
)
def test_every_spelling_of_an_empty_key_is_revoked(audit, record):
    finding = audit({"google": [record]})
    assert finding.severity == "high"
    assert finding.evidence["revoked_selectors"] == ["google"]


def test_only_usable_selectors_are_listed_when_some_are_revoked(audit):
    finding = audit({"s2": [USABLE], "google": [USABLE], "k1": [REVOKED], "dkim": [REVOKED]})
    assert finding.severity == "info"
    assert finding.title == "Mail signing keys are published"
    assert finding.detail == "Signing keys found under 2 selector(s)."
    assert finding.evidence["selectors"] == ["google", "s2"]
    assert finding.evidence["revoked_selectors"] == ["dkim", "k1"]


@pytest.mark.parametrize(
    "records", [[REVOKED, USABLE], [USABLE, REVOKED]], ids=["revoked-first", "usable-first"]
)
def test_a_usable_key_outranks_a_revoked_one_at_the_same_selector(audit, records):
    finding = audit({"google": records})
    assert finding.severity == "info"
    assert finding.evidence["selectors"] == ["google"]
    assert "revoked_selectors" not in finding.evidence


# ── usable keys ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "record",
    [
        f"k=rsa; p={KEY}",
        f"p={KEY}",
        f"k=ed25519; p={SHORT_KEY}",
        f"k=ed25519; p={SHORT_KEY.rstrip('=')}",
        f"k=rsa; t=s; p={KEY};",
    ],
    ids=label,
)
def test_a_key_without_the_optional_version_tag_is_found(audit, record):
    finding = audit({"google": [record]})
    assert finding.severity == "info"
    assert finding.evidence == {
        "selectors": ["google"],
        "selectors_probed": len(DKIM_SELECTORS),
    }


@pytest.mark.parametrize("prefix", ["v=DKIM1; k=rsa; ", "k=rsa; "])
def test_a_long_key_split_across_strings_is_found(audit, prefix):
    record = f"{prefix}p={KEY}"
    assert len(record) > 255, "must not fit in one TXT string"
    for at in (len(prefix) - 1, len(prefix), len(prefix) + 1, len(prefix) + 2, 200):
        finding = audit({"google": [(record[:at], record[at:])]})
        assert finding.evidence.get("selectors") == ["google"], at


@pytest.mark.parametrize(
    "value",
    [
        f"k=rsa; p={KEY[:200]}{KEY[200:]}",
        f'k=rsa; p={KEY[:200]}" "{KEY[200:]}',
        f'"k=rsa; p={KEY[:200]}" "{KEY[200:]}"',
        f"k=rsa; p={KEY[:200]} {KEY[200:]}",
        f'k=rsa; " "p={KEY}',
    ],
    ids=["joined", "unjoined", "outer-quotes", "spaced", "split-before-tag"],
)
def test_classification_does_not_depend_on_how_strings_were_joined(value):
    """The lookup helper may or may not join a record's strings."""
    assert dkim_audit.classify_record(value) == "usable"


@pytest.mark.parametrize(
    "record",
    [f"v=dkim1; k=RSA; p={KEY}", f"V=DKIM1; K=RSA; P={KEY}", f"v = DkIm1 ; p = {KEY}"],
    ids=label,
)
def test_tag_case_and_spacing_do_not_matter(audit, record):
    assert audit({"google": [record]}).evidence.get("selectors") == ["google"]


# ── not keys ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 include:_spf.google.com -all",
        "v=DMARC1; p=reject; rua=mailto:d@example.com",
        "v=DMARC1; p=",
        f"v=DMARC1; p={KEY}",
        f"v=DKIM2; p={KEY}",
        # DMARC policies that happen to be valid base64 once v= is missing.
        "p=none",
        "p=quarantine; pct=100",
        "k=rsa; p=",
        f"k=rsa; p={KEY[:60]}!{KEY[60:]}",
        "v=DKIM1; k=rsa",
        # A repeated tag invalidates the whole record.
        f"v=DKIM1; p=; p={KEY}",
        "google-site-verification=abcdefghijklmnopqrstuvwxyz0123456789",
        KEY,
        "",
    ],
    ids=label,
)
def test_other_text_at_a_selector_name_is_never_a_key(audit, record):
    finding = audit({"google": [record]})
    assert finding.title == "No mail signing keys found"


def test_other_text_beside_a_key_does_not_hide_it(audit):
    finding = audit({"google": ["v=spf1 -all", USABLE]})
    assert finding.evidence["selectors"] == ["google"]


def test_no_records_at_all_keeps_the_existing_finding(audit):
    finding = audit()
    assert finding.severity == "high"
    assert finding.title == "No mail signing keys found"
    assert finding.evidence == {
        "selectors_probed": len(DKIM_SELECTORS),
        "remediation": "Enable DKIM signing with your mail provider and publish the selector record it gives you.",
    }


# ── run context ──────────────────────────────────────────────────────────────


def test_context_selectors_replace_the_defaults(audit):
    finding = audit({"custom": [USABLE], "google": [USABLE]}, ctx={"dkim_selectors": ["custom"]})
    assert finding.evidence == {"selectors": ["custom"], "selectors_probed": 1}


def test_context_nameservers_reach_the_resolver(monkeypatch):
    seen = []

    def fake_make_resolver(nameservers=None):
        seen.append(nameservers)
        return StubResolver({"google": [USABLE]})

    monkeypatch.setattr(dkim_audit, "make_resolver", fake_make_resolver)
    target = Target(raw=HOST, kind="domain", value=HOST)
    DkimAudit().run(target, {"nameservers": ["192.0.2.53"]})
    assert seen == [["192.0.2.53"]]


# ── the client report ────────────────────────────────────────────────────────


def test_the_report_gives_no_credit_for_revoked_keys(audit):
    email = build([audit(wildcard=[REVOKED])], HOST)["email_security"]
    assert email["dkim_configured"] is False
    assert email["dkim_selectors"] == []
    assert email["dkim_issues"] == ["Every mail signing key found has been revoked"]
    assert email["overall_score"] == 0


@pytest.mark.parametrize("record", [USABLE, f"k=rsa; p={KEY}"], ids=label)
def test_the_report_gives_full_credit_for_a_usable_key(audit, record):
    email = build([audit({"google": [record]})], HOST)["email_security"]
    assert email["dkim_configured"] is True
    assert email["dkim_selectors"] == ["google"]
    assert email["dkim_issues"] == []
    assert email["overall_score"] == 100
