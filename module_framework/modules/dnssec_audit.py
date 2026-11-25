"""DNSSEC: is the zone's answers signed, and is the signature chain complete?"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query, resolution


def _zone_of(res: Any, host: str) -> str:
    """The apex of the zone that serves `host`, or `host` itself when unknown.

    Not `_dns.zone_apex`: that keeps climbing past errors and NXDOMAIN, which
    here would credit the client with a parent's signatures (co.uk's, say).
    This climbs only past a name known not to be an apex, and any lookup that
    does not settle the question falls back to the scanned host.
    """
    labels = host.rstrip(".").split(".")
    # Stops before the TLD, which is never the client's zone.
    for cut in range(len(labels) - 1):
        name = ".".join(labels[cut:])
        # An alias cannot sit at an apex, and an SOA lookup would follow it into
        # whatever zone the destination belongs to, so this is asked first.
        alias, _ = resolution(res, name, "CNAME")
        if alias == "ok":
            continue
        if alias != "nodata":
            return host
        soa, _ = resolution(res, name, "SOA")
        if soa == "ok":
            return name if cut else host
        if soa != "nodata":
            return host
    return host


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
        zone = _zone_of(res, host)
        dnskey = query(res, zone, "DNSKEY")
        ds = query(res, zone, "DS")

        # Findings stay on the scanned host so stored fingerprints do not move;
        # when the answer came from an enclosing zone, they say which one.
        served_by = ""
        zone_evidence: dict[str, Any] = {}
        if zone != host:
            served_by = f"{host} is served by the {zone} zone. "
            zone_evidence = {"zone": zone}

        if not dnskey:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    title="Domain answers are not signed",
                    detail=served_by
                    + (
                        "No signing key is published, so a resolver cannot tell a genuine answer "
                        "from a forged one. An attacker who can influence a resolver can point "
                        "visitors and mail at their own servers."
                    ),
                    evidence={
                        "remediation": "Enable DNSSEC at your DNS provider and publish the delegation record at the registrar.",
                        **zone_evidence,
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
                    detail=served_by
                    + (
                        "The zone publishes a signing key but the registrar publishes no delegation "
                        "record, so the chain of trust is broken and validators ignore the signatures. "
                        "This is the signing-enabled-but-does-nothing state."
                    ),
                    evidence={
                        "dnskey_count": len(dnskey),
                        "remediation": "Publish the DS record at the registrar to complete the chain.",
                        **zone_evidence,
                    },
                )
            ]

        return [
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Domain answers are signed and trusted",
                detail=served_by
                + f"{len(dnskey)} signing key(s) published with a complete delegation chain.",
                evidence={"dnskey_count": len(dnskey), "ds_count": len(ds), **zone_evidence},
            )
        ]
