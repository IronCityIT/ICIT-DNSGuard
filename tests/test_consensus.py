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

from dnsguard.consensus import attach, decode, strip_vendors, summarise

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
