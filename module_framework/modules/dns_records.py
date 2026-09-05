"""Zone inventory: what the domain publishes, and the structural gaps in it.

Combines the analyzer's collect_records() with the zone audit that used to live
in DNSControlManager.audit() — one module, because the audit is only meaningful
against the records it just collected.
"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query_ttl

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA")

PURPOSE = {
    "A": "Website/server address",
    "AAAA": "IPv6 address",
    "MX": "Mail server",
    "TXT": "Text record",
    "NS": "Name server",
    "SOA": "Zone authority",
    "CNAME": "Alias",
    "CAA": "Certificate issuance authority",
}

# Below this, a cached record cannot be re-pointed quickly during an incident.
LOW_TTL_SECONDS = 60
HIGH_TTL_SECONDS = 86400


def classify_txt(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("v=spf1"):
        return "Sender authorisation (SPF)"
    if lowered.startswith("v=dmarc1"):
        return "Mail authentication policy (DMARC)"
    if lowered.startswith("v=dkim1"):
        return "Mail signing key (DKIM)"
    if lowered.startswith("v=stsv1"):
        return "Mail transport policy (MTA-STS)"
    return PURPOSE["TXT"]


class DnsRecords(ScanModule):
    name = "dns_records"
    description = "Inventories what the domain publishes and flags structural gaps in the zone."
    target_kinds = ("domain", "hostname", "url")
    groups = ("quick", "standard", "deep")

    def collect(self, host: str, ctx: dict[str, Any]) -> list[dict[str, Any]]:
        res = make_resolver(ctx.get("nameservers"))
        records: list[dict[str, Any]] = []
        for rtype in RECORD_TYPES:
            values, ttl = query_ttl(res, host, rtype)
            for value in values:
                purpose = classify_txt(value) if rtype == "TXT" else PURPOSE.get(rtype, rtype)
                records.append(
                    {"name": host, "type": rtype, "value": value, "ttl": ttl, "purpose": purpose}
                )
        return records

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        records = self.collect(host, ctx)
        findings = audit_zone(self.name, host, records)
        findings.append(
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Zone inventory collected",
                detail=f"{len(records)} record(s) published across {len({r['type'] for r in records})} type(s).",
                evidence={"records": records},
            )
        )
        return findings


def audit_zone(module: str, host: str, records: list[dict[str, Any]]) -> list[Finding]:
    """Structural checks over a collected zone. Pure — no network access."""
    findings: list[Finding] = []
    types = [r["type"] for r in records]
    ns_count = types.count("NS")

    if not records:
        return [
            Finding(
                module=module,
                target=host,
                severity="high",
                title="Domain publishes no DNS records",
                detail="No records of any type resolved. The domain may be unregistered, expired or misdelegated.",
                evidence={
                    "remediation": "Confirm the domain is registered and delegated to working name servers."
                },
            )
        ]

    if "A" not in types and "AAAA" not in types and "CNAME" not in types:
        findings.append(
            Finding(
                module=module,
                target=host,
                severity="medium",
                title="Domain does not resolve to an address",
                detail="No A, AAAA or CNAME record is published, so the bare domain does not reach a server.",
                evidence={
                    "remediation": "Publish an address record, or a redirect at the hosting layer."
                },
            )
        )

    if 0 < ns_count < 2:
        findings.append(
            Finding(
                module=module,
                target=host,
                severity="medium",
                title="Single point of failure in name service",
                detail=f"Only {ns_count} name server is published. If it goes down, the domain disappears entirely — mail included.",
                evidence={
                    "ns_count": ns_count,
                    "remediation": "Publish at least two name servers on separate infrastructure.",
                },
            )
        )

    if "CAA" not in types:
        findings.append(
            Finding(
                module=module,
                target=host,
                severity="low",
                title="Any certificate authority may issue certificates for this domain",
                detail="No CAA record is published, so nothing restricts which authority can issue a certificate for the domain.",
                evidence={
                    "remediation": "Publish a CAA record naming only the authorities you actually use."
                },
            )
        )

    for record in records:
        if record["type"] in ("A", "AAAA", "MX") and 0 < record["ttl"] < LOW_TTL_SECONDS:
            findings.append(
                Finding(
                    module=module,
                    target=host,
                    severity="info",
                    title="Very short record lifetime",
                    detail=f"{record['type']} record has a {record['ttl']}s TTL, which multiplies lookup volume and cost.",
                    evidence={"record": record},
                )
            )
        elif record["type"] in ("A", "AAAA", "MX") and record["ttl"] >= HIGH_TTL_SECONDS:
            findings.append(
                Finding(
                    module=module,
                    target=host,
                    severity="low",
                    title="Record cannot be re-pointed quickly",
                    detail=(
                        f"{record['type']} record has a {record['ttl']}s TTL. During an outage or "
                        "compromise, resolvers keep the old answer for up to that long."
                    ),
                    evidence={
                        "record": record,
                        "remediation": "Lower the TTL to 300-3600s before any planned change.",
                    },
                )
            )
    return findings
