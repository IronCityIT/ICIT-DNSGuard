"""Compliance mapping: which controls this product's findings and its own
control plane speak to.

Two directions, and both are needed for the mapping to be honest.

  Findings -> controls.   A domain with no DMARC is not just a finding; it is a
                          deficiency against a named control in whatever
                          framework the tenant is audited on.
  Product -> controls.    The audit chain, the approval gate, policy versioning
                          and feed provenance are themselves evidence. An
                          auditor asking "how do you control changes to your
                          filtering" is answered by the approval records, not by
                          a paragraph of prose.

The mapping is deliberately conservative. A control is only claimed as SATISFIED
when the product holds evidence that actually demonstrates it; everything else
is NOT_ASSESSED rather than quietly counted as a pass. Inflating coverage is the
one failure mode that makes a compliance feature worse than not having one.
"""

from __future__ import annotations

import builtins
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any

FRAMEWORKS = ("SOC2", "CIS_V8", "HIPAA", "NIST_800_53")

SATISFIED = "satisfied"
DEFICIENT = "deficient"
NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class Control:
    framework: str
    id: str
    title: str

    @property
    def key(self) -> str:
        return f"{self.framework}:{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CONTROLS: dict[str, Control] = {
    c.key: c
    for c in (
        Control("SOC2", "CC6.1", "Logical access controls restrict access to protected assets"),
        Control("SOC2", "CC6.6", "Boundary protection restricts access from outside the system"),
        Control("SOC2", "CC6.7", "Transmission of information is protected"),
        Control("SOC2", "CC6.8", "Controls prevent or detect unauthorised or malicious software"),
        Control("SOC2", "CC7.1", "Configuration is monitored to detect susceptibility to threats"),
        Control(
            "SOC2", "CC7.2", "System components are monitored for anomalies and events are logged"
        ),
        Control(
            "SOC2",
            "CC8.1",
            "Changes are authorised, designed, tested and approved before deployment",
        ),
        Control(
            "SOC2", "A1.2", "Environmental and infrastructure protections support availability"
        ),
        Control("CIS_V8", "1.1", "Establish and maintain a detailed enterprise asset inventory"),
        Control("CIS_V8", "4.1", "Establish and maintain a secure configuration process"),
        Control("CIS_V8", "4.9", "Configure trusted DNS servers on enterprise assets"),
        Control("CIS_V8", "8.2", "Collect audit logs"),
        Control("CIS_V8", "9.2", "Use DNS filtering services"),
        Control("CIS_V8", "9.5", "Implement DMARC"),
        Control("CIS_V8", "13.3", "Deploy a network intrusion detection solution"),
        Control("HIPAA", "164.308(a)(1)(ii)(D)", "Information system activity review"),
        Control("HIPAA", "164.312(b)", "Audit controls record and examine activity"),
        Control(
            "HIPAA",
            "164.312(c)(1)",
            "Integrity controls protect information from improper alteration",
        ),
        Control(
            "HIPAA",
            "164.312(e)(1)",
            "Transmission security guards against unauthorised access in transit",
        ),
        Control("NIST_800_53", "AU-9", "Protection of audit information"),
        Control("NIST_800_53", "CM-3", "Configuration change control"),
        Control("NIST_800_53", "SC-8", "Transmission confidentiality and integrity"),
        Control("NIST_800_53", "SC-20", "Secure name / address resolution (authoritative source)"),
        Control("NIST_800_53", "SC-21", "Secure name / address resolution (recursive resolver)"),
        Control("NIST_800_53", "SI-4", "System monitoring"),
    )
}

# Which scan module speaks to which controls. A module appearing here means its
# result is admissible evidence for those controls — not that it proves them.
MODULE_CONTROLS: dict[str, tuple[str, ...]] = {
    "spf_audit": ("SOC2:CC6.7", "CIS_V8:9.5", "HIPAA:164.312(e)(1)", "NIST_800_53:SC-8"),
    "dkim_audit": ("SOC2:CC6.7", "CIS_V8:9.5", "HIPAA:164.312(e)(1)", "NIST_800_53:SC-8"),
    "dmarc_audit": ("SOC2:CC6.7", "CIS_V8:9.5", "HIPAA:164.312(e)(1)"),
    "transport_security_audit": ("SOC2:CC6.7", "HIPAA:164.312(e)(1)", "NIST_800_53:SC-8"),
    "dnssec_audit": ("SOC2:CC6.6", "HIPAA:164.312(c)(1)", "NIST_800_53:SC-20"),
    "dns_records": ("SOC2:CC7.1", "CIS_V8:4.1"),
    "subdomain_discovery": ("SOC2:CC6.1", "CIS_V8:1.1"),
    "resolver_performance": ("SOC2:A1.2", "CIS_V8:4.9", "NIST_800_53:SC-21"),
    "network_path": ("SOC2:A1.2",),
}

# The control plane's own capabilities, and the evidence key that proves each.
# Nothing here is claimed unless the corresponding evidence is actually present.
CAPABILITY_CONTROLS: dict[str, tuple[str, ...]] = {
    "audit_chain": (
        "SOC2:CC7.2",
        "CIS_V8:8.2",
        "HIPAA:164.312(b)",
        "HIPAA:164.308(a)(1)(ii)(D)",
        "NIST_800_53:AU-9",
    ),
    "approval_gate": ("SOC2:CC8.1", "NIST_800_53:CM-3"),
    "policy_versioning": ("SOC2:CC8.1", "NIST_800_53:CM-3"),
    "feed_provenance": ("SOC2:CC7.1", "NIST_800_53:SI-4"),
    "dns_filtering": ("SOC2:CC6.8", "CIS_V8:9.2", "SOC2:CC6.6"),
    "monitoring": ("SOC2:CC7.2", "CIS_V8:13.3", "NIST_800_53:SI-4"),
    "exception_expiry": ("SOC2:CC6.1",),
}

# A finding at or above this severity makes its controls deficient rather than
# satisfied. info and low are observations, not control failures.
DEFICIENT_AT = ("medium", "high", "critical")


@dataclass
class ControlStatus:
    control: Control
    status: str
    evidence: builtins.list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {"control": self.control.to_dict(), "status": self.status, "evidence": self.evidence}


def assess(
    findings: builtins.list[Any] | None = None,
    capabilities: dict[str, dict[str, Any]] | None = None,
    frameworks: tuple[str, ...] = FRAMEWORKS,
) -> builtins.list[ControlStatus]:
    """Status of every control in the requested frameworks.

    `capabilities` maps a capability name to the evidence proving it is in use,
    e.g. {"audit_chain": {"records": 412, "verified": True}}. A capability with
    no evidence, or with evidence that reports failure, does not satisfy anything.
    """
    findings = findings or []
    capabilities = capabilities or {}
    evidence: dict[str, builtins.list[dict[str, Any]]] = defaultdict(list)
    deficient: set[str] = set()

    for finding in findings:
        for key in MODULE_CONTROLS.get(getattr(finding, "module", ""), ()):
            if key not in CONTROLS:
                continue
            entry = {
                "kind": "finding",
                "module": finding.module,
                "target": getattr(finding, "target", ""),
                "severity": finding.severity,
                "title": finding.title,
            }
            evidence[key].append(entry)
            if finding.severity in DEFICIENT_AT:
                deficient.add(key)

    for capability, proof in capabilities.items():
        if not _capability_holds(proof):
            continue
        for key in CAPABILITY_CONTROLS.get(capability, ()):
            if key in CONTROLS:
                evidence[key].append({"kind": "capability", "capability": capability, **proof})

    out = []
    for key, control in sorted(CONTROLS.items()):
        if control.framework not in frameworks:
            continue
        items = evidence.get(key, [])
        if key in deficient:
            status = DEFICIENT
        elif items:
            status = SATISFIED
        else:
            status = NOT_ASSESSED
        out.append(ControlStatus(control=control, status=status, evidence=items))
    return out


def _capability_holds(proof: dict[str, Any]) -> bool:
    """A capability counts only when its evidence says it is actually working.

    An audit chain that fails verification is not evidence of audit controls; it
    is evidence against them.
    """
    if not proof:
        return False
    if proof.get("verified") is False:
        return False
    return proof.get("enabled") is not False


def coverage(statuses: builtins.list[ControlStatus]) -> dict[str, Any]:
    """Per-framework totals, plus an explicit list of what was not assessed.

    The not-assessed list is not decoration. A coverage number without it invites
    reading 60% satisfied as 40% failing, when most of the remainder is simply
    outside what a DNS product can see.
    """
    by_framework: dict[str, dict[str, Any]] = {}
    for status in statuses:
        row = by_framework.setdefault(
            status.control.framework,
            {
                "satisfied": 0,
                "deficient": 0,
                "not_assessed": 0,
                "total": 0,
                "not_assessed_controls": [],
            },
        )
        row[status.status] += 1
        row["total"] += 1
        if status.status == NOT_ASSESSED:
            row["not_assessed_controls"].append(status.control.id)

    for row in by_framework.values():
        assessed = row["satisfied"] + row["deficient"]
        row["assessed"] = assessed
        row["satisfied_rate"] = round(row["satisfied"] / assessed, 4) if assessed else 0.0

    return {
        "frameworks": by_framework,
        "totals": {
            "satisfied": sum(r["satisfied"] for r in by_framework.values()),
            "deficient": sum(r["deficient"] for r in by_framework.values()),
            "not_assessed": sum(r["not_assessed"] for r in by_framework.values()),
        },
    }


def controls_for_finding(finding: Any) -> builtins.list[Control]:
    """Which controls one finding bears on — used to stamp remediation work."""
    return [
        CONTROLS[k]
        for k in MODULE_CONTROLS.get(getattr(finding, "module", ""), ())
        if k in CONTROLS
    ]
