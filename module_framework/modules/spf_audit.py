"""SPF posture: is the domain's sender policy present, strict, and within the
RFC 7208 lookup budget? Ported from the analyzer's analyze_email_security()."""

from __future__ import annotations

import re
from typing import Any

from base import Finding, ScanModule

from ._dns import find_txt, host_of, make_resolver

# Mechanisms that cost a DNS lookup against the RFC 7208 limit of 10. Note that
# "a" and "mx" cost a lookup in their bare form too — counting only "a:"/"mx:"
# (as the previous implementation did) under-reports records that are already
# over budget, which is the failure mode this check exists to catch.
_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})
_QUALIFIERS = "+-~?"


def count_lookups(record: str) -> int:
    """DNS lookups an SPF record costs the receiver, per RFC 7208 section 4.6.4."""
    total = 0
    for token in record.split():
        bare = token.lstrip(_QUALIFIERS).lower()
        if bare.startswith("redirect="):
            total += 1
            continue
        mechanism = bare.split(":", 1)[0].split("=", 1)[0]
        if mechanism in _LOOKUP_MECHANISMS:
            total += 1
    return total


def parse_spf(record: str) -> dict[str, Any]:
    """Pure parse of an SPF record. No network access — unit-testable on its own."""
    lowered = record.lower()
    if "-all" in lowered:
        qualifier = "-all"
        strength = "hard fail"
    elif "~all" in lowered:
        qualifier = "~all"
        strength = "soft fail"
    elif "?all" in lowered:
        qualifier = "?all"
        strength = "neutral"
    elif "+all" in lowered:
        qualifier = "+all"
        strength = "pass all"
    else:
        qualifier = ""
        strength = "unspecified"

    return {
        "record": record,
        "qualifier": qualifier,
        "strength": strength,
        "lookup_count": count_lookups(record),
        "includes": re.findall(r"include:([^\s]+)", record, flags=re.IGNORECASE),
    }


class SpfAudit(ScanModule):
    name = "spf_audit"
    description = "Checks the domain's sender authorisation policy for presence, strictness and lookup budget."
    target_kinds = ("domain", "hostname", "url")
    groups = ("quick", "standard", "deep", "email")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        record = find_txt(res, host, "v=spf1")

        if not record:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="No sender authorisation policy published",
                    detail=(
                        "No SPF record was found. Any mail server on the internet can "
                        "send mail claiming to be this domain, and legitimate mail is "
                        "more likely to be filtered as spam."
                    ),
                    evidence={
                        "record": "",
                        "remediation": "Publish an SPF TXT record naming every service that sends mail for you, ending in -all.",
                    },
                )
            ]

        parsed = parse_spf(record)
        findings: list[Finding] = []
        issues: list[str] = []

        if parsed["qualifier"] == "+all":
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="critical",
                    title="Sender policy authorises every server on the internet",
                    detail="The SPF record ends in +all, which explicitly permits any host to send mail as this domain.",
                    evidence={
                        **parsed,
                        "remediation": "Replace +all with -all and enumerate your real senders.",
                    },
                )
            )
        elif parsed["qualifier"] in ("~all", "?all", ""):
            issues.append(
                f"policy ends in {parsed['qualifier'] or 'no all-mechanism'} ({parsed['strength']})"
            )

        if parsed["lookup_count"] > 10:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="Sender policy exceeds its DNS lookup budget",
                    detail=(
                        f"The policy needs {parsed['lookup_count']} DNS lookups; the protocol limit is 10. "
                        "Receivers stop evaluating at the limit and treat the result as a permanent error, "
                        "so authentication fails for mail that should pass."
                    ),
                    evidence={
                        **parsed,
                        "remediation": "Flatten or remove includes until the record needs 10 lookups or fewer.",
                    },
                )
            )
        elif parsed["lookup_count"] > 7:
            issues.append(f"approaching the DNS lookup limit ({parsed['lookup_count']}/10)")

        if issues:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="medium",
                    title="Sender policy is permissive",
                    detail="; ".join(issues),
                    evidence={
                        **parsed,
                        "remediation": "Tighten the policy to -all once you have confirmed every legitimate sender is listed.",
                    },
                )
            )

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    title="Sender authorisation policy is enforcing",
                    detail=f"SPF is published and ends in {parsed['qualifier']} with {parsed['lookup_count']} lookups.",
                    evidence=parsed,
                )
            )
        return findings
