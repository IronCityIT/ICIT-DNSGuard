"""Assemble a client-facing report from module findings.

This is the compatibility seam between the new module framework and everything
already consuming DNS Guard output: the deployed dashboard, the store payload
filter in the scan workflow, and the shared consensus engine. Those read
specific keys — `findings[]`, `email_security.grade`, `dnssec.implemented`,
`subdomains[]` — and the dashboard is live, so the report keeps producing them
exactly rather than making the UI chase a schema change.

Everything new is additive: `modules_run`, `posture`, and the per-finding
`module`/`evidence` fields ride alongside the old shape. A consumer that only
knows the old keys keeps working; one that knows the new keys gets more.

Nothing here names an underlying tool. `tools_used`, which the previous report
carried into a client-readable Firestore document, is gone.
"""

from __future__ import annotations

import builtins
import hashlib
import time
from typing import Any

from .analytics import Posture, score
from .clock import Clock, iso

SCHEMA = "icit.dnsguard.report.v2"

# Client-facing grouping for the findings table. Keyed by module so a new module
# has to declare where it belongs rather than defaulting into "General".
CATEGORY = {
    "spf_audit": "Email Security",
    "dkim_audit": "Email Security",
    "dmarc_audit": "Email Security",
    "transport_security_audit": "Email Security",
    "dnssec_audit": "DNS Configuration",
    "dns_records": "DNS Configuration",
    "subdomain_discovery": "Attack Surface",
    "alias_takeover": "Attack Surface",
    "reputation_lookup": "Threat Intelligence",
    "resolver_performance": "Availability",
    "network_path": "Availability",
}


def slug(value: str) -> str:
    """A client name reduced to a tenant id.

    Must match the client_id the scan workflow derives with tr/sed, or the same
    client lands in two Firestore partitions depending on which path wrote it.
    """
    out = []
    for char in value.lower():
        out.append(char if char.isascii() and char.isalnum() else "-")
    return "-".join(part for part in "".join(out).split("-") if part)


def make_scan_id(domain: str, now: float | None = None) -> str:
    seed = f"{domain}{now if now is not None else time.time()}".encode()
    return f"dnsguard-{hashlib.sha256(seed).hexdigest()[:16]}"


def build(
    findings: builtins.list[Any],
    domain: str,
    client_name: str = "Unknown",
    client_id: str = "",
    scan_id: str = "",
    modules_run: builtins.list[str] | None = None,
    duration_seconds: float = 0.0,
    errors: builtins.list[str] | None = None,
    clock: Clock | None = None,
) -> dict[str, Any]:
    clock = clock or Clock()
    posture = score(findings, domain)

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "scan_id": scan_id or make_scan_id(domain),
        "domain": domain,
        "target": domain,
        "client_name": client_name,
        "client_id": client_id or slug(client_name),
        "scan_timestamp": iso(clock.now()),
        "scan_duration_seconds": round(duration_seconds, 3),
        # ── the keys the deployed dashboard reads ──────────────────────────
        "findings": [_client_finding(f) for f in findings],
        "email_security": _email_security(findings, posture),
        "dnssec": _dnssec(findings),
        "subdomains": _subdomains(findings),
        "records": _records(findings),
        "threat_indicators": _threat_indicators(findings),
        "overall_risk_score": posture.risk_score,
        "risk_level": posture.risk_level,
        "executive_summary": posture.executive_summary,
        "quick_wins": posture.quick_wins,
        # ── additive ───────────────────────────────────────────────────────
        "modules_run": modules_run or posture.modules_run,
        "posture": posture.to_dict(),
        "errors": errors or [],
    }
    return report


# ── the old shape, derived from findings ─────────────────────────────────────


def _client_finding(finding: Any) -> dict[str, Any]:
    evidence = dict(getattr(finding, "evidence", None) or {})
    # `Finding.remediation` is the contract base.py documents — "every
    # non-informational finding states what to do about it, in the finding
    # itself". Older modules put it in evidence instead, so that is still read as
    # a fallback; without the field itself being read first, any module using the
    # documented way rendered a blank remediation to the client.
    remediation = getattr(finding, "remediation", "") or evidence.pop("remediation", "")
    evidence.pop("remediation", None)
    return {
        "severity": finding.severity,
        "category": CATEGORY.get(finding.module, "General"),
        "title": finding.title,
        "finding": getattr(finding, "detail", ""),
        "remediation": remediation,
        "business_impact": getattr(finding, "detail", ""),
        "module": finding.module,
        "target": getattr(finding, "target", ""),
        # The specific thing this is about, when it is narrower than the scan
        # target. Three findings on three hosts all reading "ironcityit.com" is
        # not a report somebody can act from.
        "asset": getattr(finding, "asset", "") or getattr(finding, "target", ""),
        # How firmly this is known. Dropping it rendered "we could not check
        # this" identically to "we proved this", which is the one distinction a
        # client most needs from a security report.
        "confidence": getattr(finding, "confidence", "confirmed"),
        "fingerprint": finding.fingerprint() if hasattr(finding, "fingerprint") else "",
        "evidence": evidence,
    }


def _by_module(findings: builtins.list[Any], module: str) -> builtins.list[Any]:
    return [f for f in findings if f.module == module]


def _email_security(findings: builtins.list[Any], posture: Posture) -> dict[str, Any]:
    """Reconstruct the email_security block the dashboard renders.

    Each flag is read from the evidence the module actually attached, not
    inferred from severity — a module can report a medium finding on a record
    that exists, and "does SPF exist" and "is SPF any good" are different
    questions the UI shows differently.
    """
    spf = _first_evidence(findings, "spf_audit")
    dkim = _first_evidence(findings, "dkim_audit")
    dmarc = _first_evidence(findings, "dmarc_audit")
    transport = _by_module(findings, "transport_security_audit")

    return {
        "spf_record": spf.get("record", ""),
        "spf_valid": bool(spf.get("record")),
        "spf_mechanism": f"{spf.get('qualifier', '')} ({spf.get('strength', '')})".strip(),
        "spf_lookup_count": int(spf.get("lookup_count", 0) or 0),
        "spf_includes": spf.get("includes", []),
        "spf_issues": _titles(findings, "spf_audit"),
        "dkim_configured": bool(dkim.get("selectors")),
        "dkim_selectors": dkim.get("selectors", []),
        "dkim_issues": _titles(findings, "dkim_audit"),
        "dmarc_record": dmarc.get("record", ""),
        "dmarc_valid": bool(dmarc.get("record")),
        "dmarc_policy": dmarc.get("policy", "none"),
        "dmarc_rua": dmarc.get("rua", []),
        "dmarc_issues": _titles(findings, "dmarc_audit"),
        "mta_sts": any(f.evidence.get("mta_sts") for f in transport),
        "tls_rpt": any(f.evidence.get("tls_rpt") for f in transport),
        "overall_score": posture.email_score,
        "grade": posture.email_grade,
    }


def _dnssec(findings: builtins.list[Any]) -> dict[str, Any]:
    evidence = _first_evidence(findings, "dnssec_audit")
    signed = int(evidence.get("dnskey_count", 0) or 0) > 0
    trusted = int(evidence.get("ds_count", 0) or 0) > 0
    return {
        # "implemented" keeps its old meaning for the dashboard's tick, but a
        # zone signed with no delegation is not validated, so it does not count.
        "implemented": signed and trusted,
        "signed": signed,
        "delegation_present": trusted,
        "issues": _titles(findings, "dnssec_audit"),
    }


def _subdomains(findings: builtins.list[Any]) -> builtins.list[dict[str, Any]]:
    for finding in _by_module(findings, "subdomain_discovery"):
        hosts = (finding.evidence or {}).get("hosts")
        if hosts is not None and finding.title == "Public host inventory collected":
            return [
                {
                    "subdomain": h["host"],
                    "ip_addresses": h.get("addresses", []),
                    "cnames": h.get("aliases", []),
                    "source": h.get("source", "unknown"),
                    "is_alive": bool(h.get("addresses") or h.get("aliases")),
                }
                for h in hosts
            ]
    return []


def _records(findings: builtins.list[Any]) -> builtins.list[dict[str, Any]]:
    for finding in _by_module(findings, "dns_records"):
        records = (finding.evidence or {}).get("records")
        if records is not None:
            return [
                {
                    "domain": r.get("name", ""),
                    "record_type": r.get("type", ""),
                    "value": r.get("value", ""),
                    "ttl": r.get("ttl", 0),
                    "purpose": r.get("purpose", ""),
                }
                for r in records
            ]
    return []


def _threat_indicators(findings: builtins.list[Any]) -> int:
    """How many findings are backed by a threat-feed citation."""
    return sum(1 for f in findings if (f.evidence or {}).get("provenance"))


def _first_evidence(findings: builtins.list[Any], module: str) -> dict[str, Any]:
    """The richest evidence any of a module's findings carried.

    A module emits one finding per issue plus an informational one, and the
    detail (the parsed record, the selectors) may hang off either — so take the
    largest rather than assuming an ordering that a future edit would break.
    """
    candidates = [dict(f.evidence or {}) for f in _by_module(findings, module)]
    return max(candidates, key=len) if candidates else {}


def _titles(findings: builtins.list[Any], module: str) -> builtins.list[str]:
    return [f.title for f in _by_module(findings, module) if f.severity != "info"]
