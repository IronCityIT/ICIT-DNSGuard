"""Evidence packs: everything needed to answer an auditor, in one verifiable file.

The scenario this is built for is narrow and real. Someone asks: *show me that
the block on this domain on this date was authorised, by whom, on what basis,
and prove the record has not been edited since.* Answering that from a dashboard
means screenshots. Answering it from here means a bundle whose every section is
hashed, with a manifest hash over the section hashes, plus the audit chain's own
verification result carried inside.

The bundle is deliberately plain JSON with no compression and no signing key.
Signing belongs to whoever operates the export (their key, their custody chain);
what this module owes them is content that a signature would be worth putting on
— stable serialisation, complete sections, and an honest verification result
including when it fails.
"""

from __future__ import annotations

import builtins
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .approvals import ApprovalGate
from .audit import AuditLog, canonical, digest
from .clock import Clock, iso
from .compliance import assess, coverage
from .errors import ValidationError
from .exceptions_policy import ExceptionService
from .feeds import FeedRegistry
from .policy import PolicyService

SCHEMA = "icit.dnsguard.evidence.v1"


@dataclass
class EvidenceBundle:
    schema: str
    tenant_id: str
    generated_at: str
    generated_by: str
    period: dict[str, str]
    sections: dict[str, Any]
    manifest: dict[str, str]
    manifest_hash: str
    integrity: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "tenant_id": self.tenant_id,
            "generated_at": self.generated_at,
            "generated_by": self.generated_by,
            "period": self.period,
            "integrity": self.integrity,
            "manifest": self.manifest,
            "manifest_hash": self.manifest_hash,
            "sections": self.sections,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str)


@dataclass
class EvidenceExporter:
    audit: AuditLog
    policies: PolicyService
    gate: ApprovalGate
    feeds: FeedRegistry
    exceptions: ExceptionService
    clock: Clock = field(default_factory=Clock)

    def export(
        self,
        tenant_id: str,
        actor: str,
        findings: builtins.list[Any] | None = None,
        frameworks: tuple[str, ...] | None = None,
        note: str = "",
    ) -> EvidenceBundle:
        records = self.audit.records(tenant_id)
        integrity = self.audit.verify(tenant_id)

        sections: dict[str, Any] = {
            "audit": [r.to_dict() for r in records],
            "approvals": [a.to_dict() for a in self.gate.all(tenant_id)],
            "policies": {
                policy_id: self.policies.history(tenant_id, policy_id)
                for policy_id in self.policies.policies(tenant_id)
            },
            "exceptions": [e.to_dict() for e in self.exceptions.all(tenant_id)],
            "feeds": {
                "registered": [f.to_dict() for f in self.feeds.list(tenant_id)],
                "health": self.feeds.health(tenant_id),
                "snapshots": [s.to_dict() for s in self.feeds.snapshots(tenant_id)],
            },
        }

        # The control plane's own capabilities, evidenced rather than asserted.
        # Each entry is only claimed because the section above proves it.
        capabilities = {
            "audit_chain": {"records": len(records), "verified": bool(integrity["valid"])},
            "approval_gate": {"requests": len(sections["approvals"])},
            "policy_versioning": {"policies": len(sections["policies"])},
            "feed_provenance": {"feeds": len(sections["feeds"]["registered"])},
            "exception_expiry": {"exceptions": len(sections["exceptions"])},
        }
        statuses = assess(
            findings or [], capabilities, frameworks or ("SOC2", "CIS_V8", "HIPAA", "NIST_800_53")
        )
        sections["compliance"] = {
            "controls": [s.to_dict() for s in statuses],
            "coverage": coverage(statuses),
        }
        if findings:
            sections["findings"] = [
                f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in findings
            ]

        manifest = {name: digest(section) for name, section in sorted(sections.items())}
        period = {
            "from": records[0].timestamp if records else "",
            "to": records[-1].timestamp if records else "",
        }

        bundle = EvidenceBundle(
            schema=SCHEMA,
            tenant_id=tenant_id,
            generated_at=iso(self.clock.now()),
            generated_by=actor,
            period=period,
            sections=sections,
            manifest=manifest,
            manifest_hash=digest(manifest),
            integrity={
                "audit_chain": integrity,
                "note": note,
                # Stated plainly rather than left for a reader to infer: a broken
                # chain does not stop the export, it travels with it.
                "warning": ""
                if integrity["valid"]
                else f"AUDIT CHAIN IS BROKEN at record {integrity['broken_at']}: {integrity['reason']}",
            },
        )

        self.audit.append(
            tenant_id,
            actor,
            "evidence.export",
            f"evidence/{bundle.manifest_hash[:16]}",
            outcome="executed",
            detail={
                "manifest_hash": bundle.manifest_hash,
                "sections": sorted(sections),
                "chain_valid": integrity["valid"],
            },
        )
        return bundle

    def write(self, bundle: EvidenceBundle, directory: str | Path) -> Path:
        """Write the bundle to disk. Named by manifest hash so two exports of the
        same state are the same file, and a tampered one is a different name."""
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        target = path / f"evidence-{bundle.tenant_id}-{bundle.manifest_hash[:16]}.json"
        target.write_text(bundle.to_json(), encoding="utf-8")
        return target


def verify(bundle: dict[str, Any]) -> dict[str, Any]:
    """Re-derive every hash in a bundle. Independent of the exporter on purpose —
    a recipient runs this without trusting the thing that produced the file."""
    if bundle.get("schema") != SCHEMA:
        raise ValidationError(
            f"unknown evidence schema {bundle.get('schema')!r}; expected {SCHEMA}"
        )

    sections = bundle.get("sections", {})
    manifest = bundle.get("manifest", {})
    problems: builtins.list[str] = []

    for name in sorted(set(manifest) | set(sections)):
        if name not in sections:
            problems.append(f"manifest lists section {name!r} but the bundle does not contain it")
        elif name not in manifest:
            problems.append(f"section {name!r} is present but not covered by the manifest")
        elif digest(sections[name]) != manifest[name]:
            problems.append(f"section {name!r} does not match its manifest hash")

    if digest(manifest) != bundle.get("manifest_hash"):
        problems.append("manifest hash does not match the manifest")

    chain = bundle.get("integrity", {}).get("audit_chain", {})
    if chain and not chain.get("valid", False):
        problems.append(
            f"the audit chain was already broken when this bundle was exported "
            f"(record {chain.get('broken_at')})"
        )

    return {
        "valid": not problems,
        "problems": problems,
        "sections_checked": len(manifest),
        "bytes": len(canonical(bundle)),
    }
