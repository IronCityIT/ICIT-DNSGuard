"""Folding the AI consensus into a report, and what must not travel with it.

The engine ran on every scan, answered, and the store step wrote
`consensus: {status: "success"}` and discarded the analysis. The dashboard's AI
panel looks for `ai_consensus`, found nothing, and hid itself — so four providers
were being paid to analyse every finding and the result reached nobody.

Two things need to be right: the roll-up has to describe the worst finding rather
than an average of unrelated ones, and no vendor name may reach a client-facing
report.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from dnsguard.consensus import attach, decode, for_engine, pair, strip_vendors, summarise

#: Our tooling. These must never appear in a stored report.
TOOL_VENDORS = ("Groq", "OpenRouter", "Gemini", "model_name", "model_responses")


def entry(severity="HIGH", confidence=90.0, **extra):
    """One analysis, shaped like the engine's real output."""
    base = {
        "consensus_severity": severity,
        "confidence_percent": confidence,
        "successful_models": 13,
        "total_models": 15,
        "severity_distribution": {severity: 13},
        "aggregated_remediation": ["Do the thing."],
        "compliance_impact": {"control_mappings": {"SOC2": ["CC6.1"]}},
        "model_responses": [
            {"provider": "Groq", "model_name": "llama-3.3-70b", "severity": severity},
            {"provider": "OpenRouter", "model_name": "some/model", "severity": severity},
        ],
    }
    base.update(extra)
    return base


def b64(payload) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


# ── vendor names never reach a client report ─────────────────────────────────


def test_model_responses_are_removed():
    """They carry `provider` and `model_name`. A scan report is shown to a
    client, and the fleet rule is that underlying tools are never named on one."""
    stripped = strip_vendors(entry())
    assert "model_responses" not in stripped
    assert "Groq" not in json.dumps(stripped)


def test_no_tool_vendor_survives_into_the_report():
    report = attach({"domain": "acme.example", "findings": []}, [entry("CRITICAL")])
    blob = json.dumps(report)
    for vendor in TOOL_VENDORS:
        assert vendor not in blob, vendor


def test_the_counts_survive_because_they_name_nobody():
    """ "13 of 15 models agreed" is the useful part of the provenance and is not
    a vendor name."""
    summary = summarise([entry()])
    assert (summary["successful_models"], summary["total_models"]) == (13, 15)


def test_a_clients_own_provider_is_not_mistaken_for_ours():
    """A DKIM selector called `google` and an SPF include of `_spf.google.com`
    are the *client's* mail provider, in the client's DNS. Stripping those would
    be removing the finding, not protecting the brand."""
    analysis = entry(
        "MEDIUM",
        verification_steps=["Verify that the DKIM selector 'google' is intended."],
    )
    report = attach({"findings": [{"title": "SPF includes _spf.google.com"}]}, [analysis])
    blob = json.dumps(report)
    assert "_spf.google.com" in blob
    assert "DKIM selector 'google'" in blob
    assert "model_responses" not in blob


# ── the roll-up describes the worst finding ──────────────────────────────────


def test_the_headline_is_the_worst_finding():
    summary = summarise([entry("LOW", 60.0), entry("CRITICAL", 98.6), entry("MEDIUM", 70.0)])
    assert summary["consensus_severity"] == "CRITICAL"
    assert summary["confidence_percent"] == 98.6


def test_confidence_is_not_averaged_across_unrelated_findings():
    """An average of confidences about different problems describes nothing. The
    number shown belongs to the finding it is shown next to."""
    summary = summarise([entry("CRITICAL", 98.6), entry("LOW", 10.0), entry("LOW", 10.0)])
    assert summary["confidence_percent"] == 98.6


def test_the_vote_distribution_belongs_to_the_worst_finding():
    """Summing votes across findings makes one bar chart out of opinions about
    several different problems, which means neither."""
    worst = entry("CRITICAL", severity_distribution={"CRITICAL": 13, "HIGH": 2})
    summary = summarise([worst, entry("LOW", severity_distribution={"LOW": 15})])
    assert summary["severity_distribution"] == {"CRITICAL": 13, "HIGH": 2}


def test_the_number_of_findings_analysed_is_reported():
    assert summarise([entry(), entry("LOW")])["analysed_findings"] == 2


def test_an_unrecognised_severity_does_not_take_the_headline():
    """An engine that starts emitting something new should not be able to seize
    the top slot by accident."""
    summary = summarise([entry("CRITICAL"), entry("SPICY")])
    assert summary["consensus_severity"] == "CRITICAL"


@pytest.mark.parametrize("severity", ["critical", "Critical", "CRITICAL"])
def test_severity_is_read_case_insensitively(severity):
    summary = summarise([entry(severity), entry("LOW")])
    assert summary["consensus_severity"] == severity


# ── field mapping ────────────────────────────────────────────────────────────


def test_the_compliance_mapping_is_lifted_to_where_the_dashboard_reads_it():
    """The engine nests it under `compliance_impact.control_mappings`; the page
    reads `compliance_mapping`. Mapped here so every consumer gets it, not just
    the one page that knew."""
    summary = summarise([entry()])
    assert summary["compliance_mapping"] == {"SOC2": ["CC6.1"]}


def test_a_missing_compliance_mapping_is_an_empty_object_not_absent():
    summary = summarise([entry(compliance_impact={})])
    assert summary["compliance_mapping"] == {}


def test_near_duplicate_remediation_is_collapsed():
    """Several models independently produce the same instruction in slightly
    different words. Six ways to say "delete the alias record" makes the list
    look padded and the advice look uncertain."""
    analysis = entry(
        aggregated_remediation=[
            "Delete the alias record for vpn.example.com.",
            "delete the alias record for vpn.example.com",
            "Delete the alias record for vpn.example.com!",
            "Re-claim the destination.",
        ]
    )
    steps = summarise([analysis])["aggregated_remediation"]
    assert len(steps) == 2
    assert steps[0] == "Delete the alias record for vpn.example.com.", "original wording kept"


def test_empty_remediation_entries_are_dropped():
    assert summarise([entry(aggregated_remediation=["", "  ", "Do it."])])[
        "aggregated_remediation"
    ] == ["Do it."]


# ── a failed analysis must not cost the scan ─────────────────────────────────


def test_an_empty_consensus_leaves_the_report_untouched():
    """The engine's contract says the output is empty when analysis failed. A
    scan whose enrichment did not run still has findings worth storing."""
    report = {"domain": "acme.example", "findings": [{"title": "x"}]}
    assert attach(report, []) == report


def test_no_empty_ai_section_is_written():
    """The dashboard hides the panel when the key is absent, which is correct.
    Writing an empty object would make it render a panel with nothing in it."""
    assert "ai_consensus" not in attach({"findings": []}, [])


def test_entries_without_a_severity_are_ignored():
    assert summarise([{"confidence_percent": 90}]) is None


@pytest.mark.parametrize("raw", ["", "   ", "not base64!!", b64({"nope": True}), b64("a string")])
def test_malformed_enrichment_does_not_cost_the_scan(raw):
    """Whatever arrives, the report survives. Enrichment is optional; the scan
    is not."""
    assert decode(raw) in ([], [{"nope": True}])


def test_a_single_object_is_accepted_as_well_as_a_list():
    assert decode(b64(entry("HIGH")))[0]["consensus_severity"] == "HIGH"


def test_a_list_is_decoded_whole():
    assert len(decode(b64([entry(), entry("LOW")]))) == 2


def test_non_dict_entries_in_the_list_are_skipped():
    assert len(decode(b64([entry(), "junk", 42, None]))) == 1


# ── what the report ends up carrying ─────────────────────────────────────────


def test_the_dashboard_fields_are_all_present():
    report = attach({"findings": []}, [entry("CRITICAL", 98.6)])
    assert report["ai_consensus_severity"] == "CRITICAL"
    assert report["ai_confidence_percent"] == 98.6
    for field in (
        "consensus_severity",
        "confidence_percent",
        "successful_models",
        "total_models",
        "severity_distribution",
        "aggregated_remediation",
        "compliance_mapping",
    ):
        assert field in report["ai_consensus"], field


def test_the_per_finding_detail_is_kept_alongside_the_headline():
    report = attach({"findings": []}, [entry("CRITICAL"), entry("LOW")])
    assert len(report["ai_consensus_findings"]) == 2
    assert all("model_responses" not in e for e in report["ai_consensus_findings"])


def test_the_original_report_is_not_mutated():
    report = {"findings": [], "domain": "acme.example"}
    attach(report, [entry()])
    assert "ai_consensus" not in report


# ── the transport, which is where this actually broke ────────────────────────
#
# The first version passed the engine's `consensus_b64` output through an
# environment variable. It worked against every fixture and every local run, and
# died in production with:
#
#   An error occurred trying to start process '/usr/bin/bash' ...
#   Argument list too long
#
# The analysis for one scan is 207KB of JSON — 276KB as base64 — and an
# environment block has a size limit. The tool was right and the transport was
# untested, which is its own lesson: verifying a component against real data is
# not the same as verifying how the data gets there.


ROOT = Path(__file__).resolve().parent.parent
ENRICH = ROOT / "tools" / "enrich.py"


def run_enrich(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ENRICH), *args], capture_output=True, text=True, cwd=str(ROOT)
    )


def write(path: Path, data) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_the_analysis_is_read_from_a_file_not_an_environment_variable(tmp_path):
    """A file has no size limit worth worrying about. An environment block does,
    and one scan's analysis exceeds it."""
    report = write(tmp_path / "r.json", {"domain": "acme.example", "findings": []})
    analysis = write(tmp_path / "c.json", [entry("CRITICAL", 98.6)])
    out = tmp_path / "payload.json"

    result = run_enrich("--report", str(report), "--consensus-file", str(analysis), "-o", str(out))
    assert result.returncode == 0, result.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["ai_consensus_severity"] == "CRITICAL"


def test_a_large_analysis_is_handled(tmp_path):
    """Sized like the real thing, which is what the environment variable could
    not carry."""
    big = [entry("CRITICAL", 98.6, verification_steps=["step " * 200] * 40) for _ in range(8)]
    analysis = write(tmp_path / "c.json", big)
    assert analysis.stat().st_size > 100_000, "the fixture must actually be large"

    report = write(tmp_path / "r.json", {"findings": []})
    out = tmp_path / "payload.json"
    result = run_enrich("--report", str(report), "--consensus-file", str(analysis), "-o", str(out))
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["ai_consensus_severity"] == "CRITICAL"


@pytest.mark.parametrize("missing", ["/nonexistent/analysis.json"])
def test_a_missing_analysis_writes_the_report_through_unchanged(tmp_path, missing):
    """The download step is `continue-on-error`; a scan without enrichment is
    still a scan worth storing."""
    report = write(tmp_path / "r.json", {"domain": "acme.example", "findings": [{"t": 1}]})
    out = tmp_path / "payload.json"
    result = run_enrich("--report", str(report), "--consensus-file", missing, "-o", str(out))
    assert result.returncode == 0
    assert "no consensus to merge" in result.stdout
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "ai_consensus" not in payload
    assert payload["findings"] == [{"t": 1}]


def test_no_analysis_argument_at_all_is_fine(tmp_path):
    """What the workflow passes when the engine produced nothing."""
    report = write(tmp_path / "r.json", {"findings": []})
    out = tmp_path / "payload.json"
    assert run_enrich("--report", str(report), "-o", str(out)).returncode == 0


def test_a_corrupt_analysis_does_not_cost_the_scan(tmp_path):
    report = write(tmp_path / "r.json", {"findings": [{"t": 1}]})
    (tmp_path / "c.json").write_text("{not json", encoding="utf-8")
    out = tmp_path / "payload.json"
    result = run_enrich(
        "--report", str(report), "--consensus-file", str(tmp_path / "c.json"), "-o", str(out)
    )
    assert result.returncode == 0
    assert "ai_consensus" not in json.loads(out.read_text(encoding="utf-8"))


def test_a_missing_report_is_a_usage_error(tmp_path):
    """The report is the thing being stored. Its absence is not degradation."""
    assert run_enrich("--report", "/nope.json", "-o", str(tmp_path / "o.json")).returncode == 2


# ── pairing an analysis to the finding it is about ───────────────────────────
#
# The engine returns analyses in the order it received the findings and puts no
# identifier on them, so the only pairing available is positional. Verified
# against a real run — the DNSSEC analysis lands on the DNSSEC finding — but an
# unchecked assumption fails silently here in a particularly nasty way: a
# reordered entry would put a CRITICAL analysis beside an INFO finding, and that
# is exactly what a *correct* pairing looks like when the engine rates something
# higher than we did.


def a_finding(title="Missing SPF Record", severity="high", fingerprint="fp-1"):
    return {
        "title": title,
        "severity": severity,
        "fingerprint": fingerprint,
        "asset": "acme.example",
    }


def test_each_analysis_names_the_finding_it_is_about():
    findings = [a_finding("Takeover", "critical", "fp-a"), a_finding("DNSSEC", "low", "fp-b")]
    paired = pair(findings, [entry("CRITICAL"), entry("MEDIUM")])
    assert [p["finding_fingerprint"] for p in paired] == ["fp-a", "fp-b"]
    assert [p["finding_title"] for p in paired] == ["Takeover", "DNSSEC"]


def test_our_severity_is_carried_next_to_the_engine_s():
    """The disagreement is the useful part. Our modules rated DNSSEC low and the
    engine rated it medium; a reader can only see that if both are present."""
    paired = pair([a_finding("DNSSEC", "low")], [entry("MEDIUM")])
    assert (paired[0]["finding_severity"], paired[0]["consensus_severity"]) == ("low", "MEDIUM")


def test_a_mismatched_count_pairs_nothing():
    """An unlabelled analysis is better than a confidently mislabelled one."""
    paired = pair([a_finding()], [entry("CRITICAL"), entry("LOW")])
    assert all("finding_fingerprint" not in p for p in paired)
    assert all("unpaired_reason" in p for p in paired)


def test_the_reason_names_both_counts():
    paired = pair([a_finding(), a_finding()], [entry()])
    assert "1 analyses for 2 findings" in paired[0]["unpaired_reason"]


def test_pairing_still_strips_vendor_names():
    paired = pair([a_finding()], [entry("CRITICAL")])
    assert "model_responses" not in paired[0]
    assert "Groq" not in json.dumps(paired)


def test_a_report_with_no_findings_pairs_nothing_and_does_not_raise():
    paired = pair([], [entry()])
    assert "unpaired_reason" in paired[0]


def test_attach_pairs_against_the_reports_own_findings():
    report = {"findings": [a_finding("Takeover", "critical", "fp-a")]}
    enriched = attach(report, [entry("CRITICAL")])
    assert enriched["ai_consensus_findings"][0]["finding_fingerprint"] == "fp-a"


def test_a_finding_without_a_fingerprint_still_gets_its_title():
    """Older stored reports predate the fingerprint reaching the client row."""
    paired = pair([{"title": "Old finding", "severity": "high"}], [entry()])
    assert paired[0]["finding_title"] == "Old finding"
    assert paired[0]["finding_fingerprint"] == ""


# ── what the engine is asked about ───────────────────────────────────────────
#
# Every finding used to go. On the 2026-09-14 production run, six of the eight
# were good news — DMARC at p=reject, DKIM keys published, SPF ending in -all,
# two inventory summaries — and the engine, which rates whatever it is handed as
# a risk to remediate, advised the client to "consider reducing the enforcement
# level" of DMARC, to make DKIM public keys "not publicly accessible", and to
# "implement SPF". The takeover masked it on our domain; on a clean domain that
# is the headline of the AI panel.


def good_news(title="Mail authentication policy is enforcing"):
    return {"title": title, "severity": "info", "remediation": "", "confidence": "confirmed"}


def test_informational_findings_with_nothing_to_do_are_not_sent():
    assert for_engine([good_news()]) == []


def test_anything_above_informational_is_sent():
    finding = a_finding("Domain answers are not signed", "low")
    assert for_engine([finding]) == [finding]


def test_an_informational_finding_with_a_remediation_is_still_a_gap():
    """TLS-RPT absent is informational and still something to do."""
    gap = {
        "title": "Mail transport failures are not reported",
        "severity": "info",
        "remediation": "Publish a _smtp._tls TXT record.",
        "confidence": "confirmed",
    }
    assert for_engine([gap]) == [gap]


def test_a_whitespace_remediation_is_no_remediation():
    assert for_engine([{"severity": "info", "remediation": "   "}]) == []


def test_inconclusive_findings_are_not_sent_at_any_severity():
    """Their remediation is addressed to us, and an analysis of one rates a
    risk the scanner has no evidence of."""
    ours = {
        "title": "Path measurement unavailable",
        "severity": "medium",
        "remediation": "Install traceroute on the scan runner.",
        "confidence": "inconclusive",
    }
    assert for_engine([ours]) == []


def test_the_real_report_sends_two_of_eight():
    """The shape of the 2026-09-14 production report."""
    report = [
        a_finding("An alias points at a name somebody else can claim", "critical", "fp-t"),
        good_news("Alias destinations checked"),
        good_news("Mail signing keys are published"),
        good_news("Mail authentication policy is enforcing"),
        good_news("Zone inventory collected"),
        {
            **a_finding("Domain answers are not signed", "low", "fp-d"),
            "remediation": "Enable DNSSEC at your DNS provider.",
        },
        good_news("Sender authorisation policy is enforcing"),
        good_news("Public host inventory collected"),
    ]
    assert [f["fingerprint"] for f in for_engine(report)] == ["fp-t", "fp-d"]


def test_report_order_is_preserved():
    """The pairing is positional, so the order sent is the order matched."""
    first, second = a_finding("A", "high", "fp-1"), a_finding("B", "low", "fp-2")
    assert for_engine([first, good_news(), second]) == [first, second]


def test_severity_and_confidence_are_read_case_insensitively():
    assert for_engine([{"severity": "INFO", "remediation": ""}]) == []
    assert for_engine([{"severity": "high", "confidence": "Inconclusive"}]) == []


def test_attach_pairs_against_what_the_engine_was_sent():
    """Two analyses for a report of eight findings is a correct count once the
    six good-news rows are withheld — and each lands on the finding it is about."""
    report = {
        "findings": [
            good_news("Zone inventory collected"),
            a_finding("Takeover", "critical", "fp-t"),
            good_news("Sender authorisation policy is enforcing"),
            {**a_finding("DNSSEC", "low", "fp-d"), "remediation": "Enable DNSSEC."},
        ]
    }
    enriched = attach(report, [entry("CRITICAL"), entry("MEDIUM")])
    paired = enriched["ai_consensus_findings"]
    assert [p["finding_fingerprint"] for p in paired] == ["fp-t", "fp-d"]
    assert all("unpaired_reason" not in p for p in paired)


def test_attach_does_not_pair_against_the_whole_report():
    """The old behaviour — eight analyses for eight findings — is now a count
    mismatch, and says so rather than mislabelling."""
    report = {"findings": [good_news(), a_finding("Takeover", "critical", "fp-t")]}
    enriched = attach(report, [entry("INFO"), entry("CRITICAL")])
    assert all("unpaired_reason" in p for p in enriched["ai_consensus_findings"])


# ── the tool the workflow runs ───────────────────────────────────────────────

ENGINE_INPUT = ROOT / "tools" / "engine-input.py"


def run_engine_input(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ENGINE_INPUT), *args], capture_output=True, text=True, cwd=str(ROOT)
    )


def test_the_tool_writes_the_selected_findings_as_a_json_list(tmp_path):
    report = write(
        tmp_path / "r.json", {"findings": [good_news(), a_finding("Takeover", "critical", "fp-t")]}
    )
    out = tmp_path / "engine.json"
    result = run_engine_input("--report", str(report), "-o", str(out))
    assert result.returncode == 0, result.stderr
    text = out.read_text(encoding="utf-8")
    assert text.startswith("[") and text.endswith("]\n")
    assert [f["fingerprint"] for f in json.loads(text)] == ["fp-t"]


def test_the_tool_says_what_it_withheld_and_why(tmp_path):
    report = write(
        tmp_path / "r.json",
        {
            "findings": [
                good_news("Zone inventory collected"),
                {
                    "title": "Path measurement unavailable",
                    "severity": "info",
                    "remediation": "Install traceroute.",
                    "confidence": "inconclusive",
                },
                a_finding("Takeover", "critical"),
            ]
        },
    )
    result = run_engine_input("--report", str(report), "-o", str(tmp_path / "e.json"))
    assert "1 of 3 finding(s) sent to the engine" in result.stdout
    assert "Zone inventory collected  (informational, nothing to do)" in result.stdout
    assert "Path measurement unavailable  (inconclusive)" in result.stdout


def test_a_clean_domain_gives_the_engine_nothing(tmp_path):
    """Written as an empty list, which the workflow reads as has_findings=false
    and skips the engine altogether."""
    report = write(tmp_path / "r.json", {"findings": [good_news(), good_news("SPF ok")]})
    out = tmp_path / "engine.json"
    assert run_engine_input("--report", str(report), "-o", str(out)).returncode == 0
    assert json.loads(out.read_text(encoding="utf-8")) == []


def test_a_report_without_findings_is_an_empty_list_not_an_error(tmp_path):
    report = write(tmp_path / "r.json", {"domain": "acme.example"})
    out = tmp_path / "engine.json"
    assert run_engine_input("--report", str(report), "-o", str(out)).returncode == 0
    assert json.loads(out.read_text(encoding="utf-8")) == []


def test_a_missing_report_is_a_usage_error_for_the_tool(tmp_path):
    result = run_engine_input("--report", str(tmp_path / "nope.json"), "-o", str(tmp_path / "e"))
    assert result.returncode == 2
    assert "no such report" in result.stderr


def test_the_tool_and_the_store_step_agree(tmp_path):
    """The whole point: what the tool sends is what `attach` pairs against, so
    the engine's answers land on the right findings end to end."""
    findings = [
        good_news("Zone inventory collected"),
        a_finding("Takeover", "critical", "fp-t"),
        good_news("Sender authorisation policy is enforcing"),
        {**a_finding("DNSSEC", "low", "fp-d"), "remediation": "Enable DNSSEC."},
    ]
    report = write(tmp_path / "r.json", {"findings": findings})
    out = tmp_path / "engine.json"
    run_engine_input("--report", str(report), "-o", str(out))
    sent = json.loads(out.read_text(encoding="utf-8"))
    # The engine answers one analysis per finding it was sent, in order.
    answers = [entry("CRITICAL"), entry("MEDIUM")]
    assert len(answers) == len(sent)
    paired = attach({"findings": findings}, answers)["ai_consensus_findings"]
    assert [p["finding_fingerprint"] for p in paired] == [f["fingerprint"] for f in sent]
