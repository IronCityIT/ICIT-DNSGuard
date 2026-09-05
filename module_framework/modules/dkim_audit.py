"""DKIM posture: does the domain publish signing keys under any known selector?"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from base import Finding, ScanModule

from ._dns import DKIM_SELECTORS, find_txt, host_of, make_resolver


class DkimAudit(ScanModule):
    name = "dkim_audit"
    description = (
        "Looks for published mail-signing keys under the selectors the common mail providers use."
    )
    target_kinds = ("domain", "hostname", "url")
    groups = ("standard", "deep", "email")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        selectors = tuple(ctx.get("dkim_selectors") or DKIM_SELECTORS)

        def probe(selector: str) -> str | None:
            record = find_txt(res, f"{selector}._domainkey.{host}", "v=dkim1")
            return selector if record else None

        with ThreadPoolExecutor(max_workers=10) as pool:
            found = [s for s in pool.map(probe, selectors) if s]

        if not found:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="No mail signing keys found",
                    detail=(
                        "No DKIM key was published under any of the selectors used by the common "
                        "mail providers. Receivers cannot cryptographically verify that mail from "
                        "this domain is genuine, and forwarded mail loses authentication entirely."
                    ),
                    evidence={
                        "selectors_probed": len(selectors),
                        "remediation": "Enable DKIM signing with your mail provider and publish the selector record it gives you.",
                    },
                )
            ]

        return [
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Mail signing keys are published",
                detail=f"Signing keys found under {len(found)} selector(s).",
                evidence={"selectors": sorted(found), "selectors_probed": len(selectors)},
            )
        ]
