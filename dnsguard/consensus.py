"""Making the AI consensus reach the client, and stripping what must not.

## The defect this closes

The scan pipeline calls the shared consensus engine on every run. The engine
answers — for the ironcityit.com run it returned eight analyses, the worst of
them CRITICAL at 98.6% confidence with 13 of 15 models agreeing, a compliance
mapping across ten frameworks, and concrete remediation steps.

The `store` job then wrote `consensus: {status: "success"}` and threw the rest
away. Meanwhile the dashboard has a whole AI panel that looks for
`data.ai_consensus`, finds nothing, and hides itself. So the product has been
paying four providers to analyse every finding, on every scan, and showing the
result to nobody.

## The shape the dashboard reads

A single object, not the engine's per-finding list:
`consensus_severity`, `confidence_percent`, `successful_models`/`total_models`,
`severity_distribution`, `aggregated_remediation`, `compliance_mapping`.

So the list is rolled up to **the worst finding's** analysis. Not an average:
averaging confidence across findings of different severities produces a number
that describes nothing, and summing the vote distribution across findings
conflates votes about different problems. The headline is the worst finding, and
the per-finding detail is kept alongside it for anything that wants more.

## White-label — the part that is not cosmetic

The engine's `model_responses` carry `provider` and `model_name`: Google, Groq,
OpenRouter. The fleet rule is that underlying tools are never named on a
client-facing surface, and a scan report shown to a client is exactly that. They
are removed here rather than filtered at the point of display, because there will
be more than one point of display and only one of these.

The counts survive — "13 of 15 models agreed" is the useful part and names
nobody.
"""

from __future__ import annotations

import base64
import binascii
import builtins
import json
from typing import Any

#: Worst first. The engine emits upper case; comparisons here are case-folded so
#: a change of convention at the other end does not silently reorder severities.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Removed before storage. Everything else the engine returns is either a count,
#: a verdict or a remediation, and none of those name a vendor.
VENDOR_FIELDS = ("model_responses", "failed_model_details")


def severity_rank(value: str) -> int:
    try:
        return SEVERITY_ORDER.index(str(value).strip().lower())
    except ValueError:
        # An unrecognised severity sorts last rather than first: an engine that
        # starts emitting something new should not be able to take over the
        # headline by accident.
        return len(SEVERITY_ORDER)


def decode(consensus_b64: str) -> builtins.list[dict[str, Any]]:
    """The engine's output, from the base64 its workflow hands back.

    Empty input is not an error — the contract says the output is empty when the
    analysis failed, and a scan whose AI enrichment did not run is a scan that
    still has findings worth storing.
    """
    text = (consensus_b64 or "").strip()
    if not text:
        return []
    try:
        decoded = base64.b64decode(text, validate=True)
        parsed = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        # Malformed enrichment must not cost us the scan it was enriching.
        return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, builtins.list):
        return [entry for entry in parsed if isinstance(entry, dict)]
    return []


def strip_vendors(entry: dict[str, Any]) -> dict[str, Any]:
    """One analysis with every vendor name removed."""
    return {key: value for key, value in entry.items() if key not in VENDOR_FIELDS}


def summarise(entries: builtins.list[dict[str, Any]]) -> dict[str, Any] | None:
    """The headline object the dashboard renders, or None if there is nothing.

    Built from the worst finding rather than from an aggregate. Averaging
    confidence across findings of different severities describes nothing, and a
    vote distribution summed across findings conflates votes about different
    problems into one bar chart that means neither.
    """
    usable = [e for e in entries if e.get("consensus_severity")]
    if not usable:
        return None

    worst = min(usable, key=lambda e: severity_rank(e.get("consensus_severity", "")))
    compliance = worst.get("compliance_impact") or {}

    summary = strip_vendors(worst)
    # The dashboard reads `compliance_mapping`; the engine emits the same content
    # nested under `compliance_impact.control_mappings`. Mapped here rather than
    # in the page, so any other consumer gets it too.
    summary["compliance_mapping"] = compliance.get("control_mappings") or {}
    summary["aggregated_remediation"] = _dedupe(worst.get("aggregated_remediation") or [])
    summary["analysed_findings"] = len(usable)
    return summary


def _dedupe(steps: builtins.list[Any]) -> builtins.list[str]:
    """Remediation steps, in order, without the near-repeats.

    Several models independently produce the same instruction in slightly
    different words. Showing a client six ways to say "delete the alias record"
    makes the list look padded and the advice look uncertain.
    """
    seen: set[str] = set()
    out: builtins.list[str] = []
    for step in steps:
        text = str(step).strip()
        if not text:
            continue
        # Compared without punctuation or case, so "Delete the record." and
        # "delete the record" collapse; kept in the original wording.
        key = "".join(ch for ch in text.lower() if ch.isalnum() or ch.isspace()).strip()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def pair(
    findings: builtins.list[dict[str, Any]], entries: builtins.list[dict[str, Any]]
) -> builtins.list[dict[str, Any]]:
    """Attach each analysis to the finding it is about.

    The engine returns analyses in the order it received the findings and puts no
    identifier on them, so the only available pairing is positional. That works —
    verified against a real run, where the DNSSEC analysis lands on the DNSSEC
    finding — but it is an assumption, and an unchecked one fails silently: a
    reordered or dropped entry would put a CRITICAL analysis beside an INFO
    finding, which is exactly what a *correct* pairing can also look like when
    the engine rates something higher than we did.

    So the count is checked. If it does not match, nothing is paired and every
    entry says why, because an unlabelled analysis is better than a confidently
    mislabelled one.
    """
    aligned = len(findings) == len(entries)
    out: builtins.list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        detail = strip_vendors(entry)
        if aligned:
            finding = findings[index]
            detail["finding_fingerprint"] = finding.get("fingerprint", "")
            detail["finding_title"] = finding.get("title", "")
            detail["finding_asset"] = finding.get("asset", "") or finding.get("target", "")
            detail["finding_severity"] = finding.get("severity", "")
        else:
            detail["unpaired_reason"] = (
                f"the engine returned {len(entries)} analyses for {len(findings)} findings, "
                "so which analysis belongs to which finding cannot be established"
            )
        out.append(detail)
    return out


def attach(report: dict[str, Any], entries: builtins.list[dict[str, Any]]) -> dict[str, Any]:
    """Add the consensus to a report, or leave it exactly as it was.

    A scan whose enrichment failed must be stored unchanged rather than stored
    with an empty AI section: the dashboard hides the panel when the key is
    absent, which is the correct thing for it to do, and writing an empty object
    would make it render a panel with nothing in it.
    """
    summary = summarise(entries)
    if summary is None:
        return report

    enriched = dict(report)
    enriched["ai_consensus"] = summary
    enriched["ai_consensus_severity"] = summary.get("consensus_severity", "")
    enriched["ai_confidence_percent"] = summary.get("confidence_percent", 0)
    # The per-finding detail, vendor names removed and each analysis labelled
    # with the finding it is about, for anything that wants more than the
    # headline.
    enriched["ai_consensus_findings"] = pair(report.get("findings") or [], entries)
    return enriched
