"""DMARC posture: published, enforcing, and reporting somewhere a human reads."""

from __future__ import annotations

import re
from typing import Any

from base import Finding, ScanModule

from ._dns import find_txt, host_of, make_resolver

POLICIES = ("none", "quarantine", "reject")


def parse_dmarc(record: str) -> dict[str, Any]:
    """Pure parse of a DMARC record into its tags."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()
    policy = tags.get("p", "none").lower()
    return {
        "record": record,
        "policy": policy if policy in POLICIES else "none",
        "subdomain_policy": tags.get("sp", "").lower(),
        "rua": [a.strip() for a in tags.get("rua", "").split(",") if a.strip()],
        "ruf": [a.strip() for a in tags.get("ruf", "").split(",") if a.strip()],
        "pct": int(m.group(1)) if (m := re.match(r"^(\d{1,3})$", tags.get("pct", "100"))) else 100,
    }


class DmarcAudit(ScanModule):
    name = "dmarc_audit"
    description = "Checks whether the domain tells receivers what to do with unauthenticated mail, and whether it is enforced."
    target_kinds = ("domain", "hostname", "url")
    groups = ("quick", "standard", "deep", "email")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        record = find_txt(res, f"_dmarc.{host}", "v=dmarc1")

        if not record:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="No mail authentication policy published",
                    detail=(
                        "No DMARC record was found. Nothing tells receiving mail servers what to do "
                        "with mail that fails authentication, and no one receives reports about "
                        "who is sending mail as this domain."
                    ),
                    evidence={
                        "record": "",
                        "remediation": "Publish a DMARC record at _dmarc with p=none and a rua address, then tighten once reports look clean.",
                    },
                )
            ]

        parsed = parse_dmarc(record)
        findings: list[Finding] = []

        if parsed["policy"] == "none":
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="medium",
                    title="Mail authentication policy is monitor-only",
                    detail="The policy is p=none, so mail that fails authentication is still delivered. Spoofed mail reaches recipients.",
                    evidence={
                        **parsed,
                        "remediation": "Move to p=quarantine, then p=reject, once reports confirm your legitimate senders pass.",
                    },
                )
            )
        elif parsed["pct"] < 100:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    title="Mail authentication policy is only partially applied",
                    detail=f"The policy is enforced on {parsed['pct']}% of failing mail; the remainder is delivered.",
                    evidence={
                        **parsed,
                        "remediation": "Raise pct to 100 once the partial rollout looks clean.",
                    },
                )
            )

        if not parsed["rua"]:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    title="Mail authentication reports go nowhere",
                    detail="The policy has no rua address, so aggregate reports about spoofing attempts are never delivered.",
                    evidence={
                        **parsed,
                        "remediation": "Add rua=mailto: pointing at a monitored mailbox or reporting service.",
                    },
                )
            )

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    title="Mail authentication policy is enforcing",
                    detail=f"DMARC is published with p={parsed['policy']} at {parsed['pct']}% and reports to {len(parsed['rua'])} address(es).",
                    evidence=parsed,
                )
            )
        return findings
