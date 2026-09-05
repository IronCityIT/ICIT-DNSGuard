"""MTA-STS and TLS-RPT: is mail to this domain protected in transit, and is
failure to protect it reported?"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._dns import find_txt, host_of, make_resolver


class TransportSecurityAudit(ScanModule):
    name = "transport_security_audit"
    description = "Checks whether inbound mail is required to use encrypted transport and whether failures are reported."
    target_kinds = ("domain", "hostname", "url")
    groups = ("deep", "email")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        mta_sts = find_txt(res, f"_mta-sts.{host}", "v=STSv1")
        tls_rpt = find_txt(res, f"_smtp._tls.{host}", "v=TLSRPTv1")

        findings: list[Finding] = []
        if not mta_sts:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    title="Encrypted mail transport is not enforced",
                    detail=(
                        "No MTA-STS policy is published, so a network attacker can strip encryption "
                        "from mail sent to this domain and read it in transit."
                    ),
                    evidence={
                        "remediation": "Publish an MTA-STS policy and the _mta-sts TXT record, starting in testing mode."
                    },
                )
            )
        if not tls_rpt:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    title="Mail transport failures are not reported",
                    detail="No TLS-RPT record is published, so failures to negotiate encrypted transport go unnoticed.",
                    evidence={
                        "remediation": "Publish a _smtp._tls TXT record pointing at a monitored mailbox."
                    },
                )
            )
        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    title="Encrypted mail transport is enforced and reported",
                    detail="Both an MTA-STS policy and a TLS reporting address are published.",
                    evidence={"mta_sts": mta_sts, "tls_rpt": tls_rpt},
                )
            )
        return findings
