"""DNSSEC: is the zone's answers signed, and is the signature chain complete?"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query


class DnssecAudit(ScanModule):
    name = "dnssec_audit"
    description = (
        "Checks whether the domain's answers are cryptographically signed against tampering."
    )
    target_kinds = ("domain", "hostname", "url")
    groups = ("standard", "deep")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        dnskey = query(res, host, "DNSKEY")
        ds = query(res, host, "DS")

        if not dnskey:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    title="Domain answers are not signed",
                    detail=(
                        "No signing key is published, so a resolver cannot tell a genuine answer "
                        "from a forged one. An attacker who can influence a resolver can point "
                        "visitors and mail at their own servers."
                    ),
                    evidence={
                        "remediation": "Enable DNSSEC at your DNS provider and publish the delegation record at the registrar."
                    },
                )
            ]

        if not ds:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="medium",
                    title="Signing is configured but not trusted",
                    detail=(
                        "The zone publishes a signing key but the registrar publishes no delegation "
                        "record, so the chain of trust is broken and validators ignore the signatures. "
                        "This is the signing-enabled-but-does-nothing state."
                    ),
                    evidence={
                        "dnskey_count": len(dnskey),
                        "remediation": "Publish the DS record at the registrar to complete the chain.",
                    },
                )
            ]

        return [
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Domain answers are signed and trusted",
                detail=f"{len(dnskey)} signing key(s) published with a complete delegation chain.",
                evidence={"dnskey_count": len(dnskey), "ds_count": len(ds)},
            )
        ]
