"""TXT values reach the modules the way RFC 7208 section 3.3 says to read them.

One DNS character-string holds at most 255 bytes, so a longer TXT record is
published as several quoted strings that must be joined with nothing in between.
These tests build real rdata and answer from a stub resolver, so the lookup
helpers under test are the real ones and nothing touches the network.
"""

from __future__ import annotations

from types import SimpleNamespace

import dns.rdata
import pytest
from modules import dmarc_audit, dns_records, spf_audit
from modules._dns import find_txt, query, query_ttl, resolution
from modules.dmarc_audit import parse_dmarc
from modules.spf_audit import parse_spf
from targets import parse_targets

HOST = "example.com"
TTL = 300

SPLIT_SPF_HOSTNAME = '"v=spf1 include:_spf.exa" "mple.net mx -all"'
SPLIT_SPF_ALL = '"v=spf1 include:_spf.example.net -a" "ll"'
SPLIT_DMARC = '"v=DMARC1; p=rej" "ect; rua=mailto:dmarc@exa" "mple.net"'


class Answer(list):
    """Iterates like a resolver answer and carries the rrset TTL."""

    rrset = SimpleNamespace(ttl=TTL)


class StubResolver:
    """Answers from {(name, rtype): [presentation text]} built as real rdata."""

    def __init__(self, zone):
        self.zone = zone

    def resolve(self, name, rtype):
        # A KeyError stands in for "no such record", as any exception does.
        return Answer(dns.rdata.from_text("IN", rtype, t) for t in self.zone[(name, rtype)])


def txt(*values, name=HOST):
    return StubResolver({(name, "TXT"): list(values)})


def run(monkeypatch, module, scan, resolver):
    monkeypatch.setattr(module, "make_resolver", lambda *a, **k: resolver)
    return scan().run(parse_targets([HOST])[0], {})


# ── SPF ──────────────────────────────────────────────────────────────────────


def test_spf_split_mid_hostname_is_one_clean_value():
    record = find_txt(txt("unrelated", SPLIT_SPF_HOSTNAME), HOST, "v=spf1")
    assert record == "v=spf1 include:_spf.example.net mx -all"
    parsed = parse_spf(record)
    assert parsed["includes"] == ["_spf.example.net"]
    assert parsed["lookup_count"] == 2
    assert parsed["qualifier"] == "-all"


def test_spf_split_inside_the_version_tag_is_still_found():
    assert find_txt(txt('"v=sp" "f1 -all"'), HOST, "v=spf1") == "v=spf1 -all"


def test_spf_split_inside_all_is_audited_as_enforcing(monkeypatch):
    findings = run(monkeypatch, spf_audit, spf_audit.SpfAudit, txt(SPLIT_SPF_ALL))
    assert [(f.severity, f.title) for f in findings] == [
        ("info", "Sender authorisation policy is enforcing")
    ]


def test_spf_split_inside_pass_all_is_still_critical(monkeypatch):
    """The join must not only ever make a record look better."""
    findings = run(monkeypatch, spf_audit, spf_audit.SpfAudit, txt('"v=spf1 +a" "ll"'))
    assert "critical" in {f.severity for f in findings}


# ── DMARC ────────────────────────────────────────────────────────────────────


def test_dmarc_split_inside_policy_and_rua(monkeypatch):
    resolver = txt(SPLIT_DMARC, name=f"_dmarc.{HOST}")
    parsed = parse_dmarc(find_txt(resolver, f"_dmarc.{HOST}", "v=dmarc1"))
    assert parsed["policy"] == "reject"
    assert parsed["rua"] == ["mailto:dmarc@example.net"]

    findings = run(monkeypatch, dmarc_audit, dmarc_audit.DmarcAudit, resolver)
    assert [(f.severity, f.title) for f in findings] == [
        ("info", "Mail authentication policy is enforcing")
    ]


# ── joining ──────────────────────────────────────────────────────────────────


def test_a_space_the_publisher_put_at_the_boundary_is_preserved():
    resolver = txt('"v=spf1 include:_spf.example.net " "-all"')
    assert query(resolver, HOST, "TXT") == ["v=spf1 include:_spf.example.net -all"]


def test_a_character_split_across_strings_is_decoded_after_joining():
    assert query(txt(r'"caf\195" "\169"'), HOST, "TXT") == ["café"]


def test_bytes_that_are_not_utf8_are_replaced_rather_than_raising():
    assert query(txt(r'"a\255" "b"'), HOST, "TXT") == ["a�b"]


def test_separate_txt_records_are_not_joined_to_each_other():
    assert query(txt('"one"', '"two" "three"'), HOST, "TXT") == ["one", "twothree"]


def test_every_lookup_helper_returns_the_joined_value():
    expected = ["v=spf1 include:_spf.example.net -all"]
    resolver = txt(SPLIT_SPF_ALL)
    assert query(resolver, HOST, "TXT") == expected
    assert query_ttl(resolver, HOST, "TXT") == (expected, TTL)
    assert resolution(resolver, HOST, "TXT") == ("ok", expected)


def test_the_zone_inventory_shows_no_stray_quotes(monkeypatch):
    monkeypatch.setattr(dns_records, "make_resolver", lambda *a, **k: txt(SPLIT_SPF_ALL))
    records = dns_records.DnsRecords().collect(HOST, {})
    assert [(r["type"], r["value"], r["purpose"]) for r in records] == [
        ("TXT", "v=spf1 include:_spf.example.net -all", "Sender authorisation (SPF)")
    ]


# ── unchanged behaviour ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("rtype", "text", "expected"),
    [
        ("TXT", '"v=spf1 include:_spf.example.net -all"', "v=spf1 include:_spf.example.net -all"),
        ("A", "192.0.2.1", "192.0.2.1"),
        ("MX", "10 mail.example.com.", "10 mail.example.com."),
        # Only the outer quote goes, exactly as before. Not pretty, but CAA
        # rendering is not what this change is about.
        ("CAA", '0 issue "ca.example.net"', '0 issue "ca.example.net'),
    ],
)
def test_single_string_txt_and_other_types_are_unchanged(rtype, text, expected):
    resolver = StubResolver({(HOST, rtype): [text]})
    assert query(resolver, HOST, rtype) == [expected]
    assert query_ttl(resolver, HOST, rtype) == ([expected], TTL)
    assert resolution(resolver, HOST, rtype) == ("ok", [expected])


def test_answers_that_are_plain_strings_are_unchanged():
    class Plain:
        def resolve(self, *_a, **_k):
            return ['"192.0.2.1"', "bare"]

    assert query(Plain(), HOST, "TXT") == ["192.0.2.1", "bare"]


def test_a_missing_txt_record_is_still_absence():
    assert find_txt(StubResolver({}), HOST, "v=spf1") == ""
    assert query_ttl(StubResolver({}), HOST, "TXT") == ([], 0)
