"""Zone inventory: what the domain publishes, and the structural gaps in it.

Combines the analyzer's collect_records() with the zone audit that used to live
in DNSControlManager.audit() — one module, because the audit is only meaningful
against the records it just collected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query_ttl, resolution

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

# `<flags> <tag> <value>`. Only the flags and the tag decide whether ordinary
# issuance is restricted, so the value — whose quoting the lookup helpers may have
# half-stripped — is never parsed.
CAA_VALUE = re.compile(r"\s*(\d{1,3})\s+([a-z0-9]+)(?:\s|$)", re.ASCII | re.IGNORECASE)
CAA_CRITICAL = 128
# The registered properties. An authority that meets any other tag marked critical
# must refuse to issue.
CAA_KNOWN_TAGS = frozenset(
    {"issue", "issuewild", "iodef", "contactemail", "contactphone", "issuemail", "issuevmc"}
)


@dataclass(frozen=True)
class EffectiveCaa:
    """The CAA record set a certificate authority would obey for a name.

    No values and no `failed_at` means the climb completed and found nothing.
    """

    owner: str = ""
    values: tuple[str, ...] = ()
    #: The name whose lookup failed. A closer set may exist there, so the climb
    #: does not continue past it and nothing is known about the effective set.
    failed_at: str = ""


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

    def effective_caa(
        self, host: str, records: list[dict[str, Any]], ctx: dict[str, Any]
    ) -> EffectiveCaa | None:
        """The closest CAA set at or above `host` (RFC 8659 section 3)."""
        if not records:
            return None  # An empty zone is one finding; issuance is not the problem.
        own = tuple(r["value"] for r in records if r["type"] == "CAA")
        if own:
            return EffectiveCaa(host, own)

        res = make_resolver(ctx.get("nameservers"))
        labels = host.rstrip(".").split(".")
        for cut in range(len(labels)):
            name = ".".join(labels[cut:])
            # Asked again at the host itself: collection cannot tell a failed
            # lookup from a missing record.
            status, values = resolution(res, name, "CAA")
            if status == "error":
                return EffectiveCaa(failed_at=name)
            if values:
                return EffectiveCaa(name, tuple(values))
        return EffectiveCaa()

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        records = self.collect(host, ctx)
        findings = audit_zone(self.name, host, records, self.effective_caa(host, records, ctx))
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


def restricts_issuance(values: tuple[str, ...]) -> bool:
    """Whether a CAA set limits who may issue an ordinary certificate.

    `issue` does, including the empty form that forbids all issuance. `issuewild`
    governs wildcards only and `iodef` is a reporting address, so neither does on
    its own. Values that do not parse are no evidence of protection.
    """
    for value in values:
        match = CAA_VALUE.match(value)
        if not match or int(match[1]) > 255:
            continue
        flags, tag = int(match[1]), match[2].lower()
        if tag == "issue" or (flags & CAA_CRITICAL and tag not in CAA_KNOWN_TAGS):
            return True
    return False


def audit_caa(module: str, host: str, caa: EffectiveCaa) -> list[Finding]:
    """What the effective CAA set means for who may issue certificates."""
    if caa.failed_at:
        return [
            Finding(
                module=module,
                target=host,
                severity="info",
                confidence="inconclusive",
                title="Certificate issuance restrictions (CAA) could not be checked",
                detail=(
                    f"The CAA lookup for {caa.failed_at} did not complete, so it is not known "
                    "whether certificate issuance is restricted. This is neither a pass nor a "
                    "missing record."
                ),
                evidence={
                    "caa_lookup_failed_at": caa.failed_at,
                    "remediation": "Re-run the scan. If this persists, check that the name servers answer CAA queries.",
                },
            )
        ]
    if restricts_issuance(caa.values):
        return []

    detail = "No CAA record is published, so nothing restricts which authority can issue a certificate for the domain."
    evidence: dict[str, Any] = {
        "remediation": "Publish a CAA record naming only the authorities you actually use."
    }
    if caa.values:
        detail = (
            f"A CAA record exists at {caa.owner} but contains no issue restriction, so nothing "
            "restricts which authority can issue an ordinary certificate for the domain."
        )
        # Not "records": the report reads the client's inventory from that key.
        evidence = {
            "caa_owner": caa.owner,
            "caa_records": list(caa.values),
            "remediation": "Add an issue property to the CAA record set naming only the authorities you actually use.",
        }
    return [
        Finding(
            module=module,
            target=host,
            severity="low",
            title="Any certificate authority may issue certificates for this domain",
            detail=detail,
            evidence=evidence,
        )
    ]


def audit_zone(
    module: str, host: str, records: list[dict[str, Any]], caa: EffectiveCaa | None = None
) -> list[Finding]:
    """Structural checks over a collected zone. Pure — no network access.

    Without `caa`, only the presence of a CAA record in `records` is judged.
    """
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

    if caa is not None:
        findings.extend(audit_caa(module, host, caa))
    elif "CAA" not in types:
        findings.extend(audit_caa(module, host, EffectiveCaa()))

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
