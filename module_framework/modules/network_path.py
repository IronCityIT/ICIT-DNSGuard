"""Network path to the domain's servers. Ported from HopsAnalyzer.

Off by default (not in the standard groups) because it needs traceroute on the
host and produces noisy results from inside containers.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # noqa: S404 - traceroute is invoked with a fixed argv, never a shell
from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query

_HOP_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MS = re.compile(r"([\d.]+)\s*ms")

LONG_PATH_HOPS = 20


def trace(target: str, max_hops: int = 20, timeout: int = 60) -> dict[str, Any]:
    """Run traceroute against one target. argv form only — the target never
    reaches a shell, so a hostile hostname cannot become a command."""
    binary = shutil.which("traceroute") or shutil.which("tracert")
    result: dict[str, Any] = {
        "target": target,
        "hops": [],
        "reachable": False,
        "available": bool(binary),
    }
    if not binary:
        return result

    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            [binary, "-m", str(max_hops), "-w", "1", "-q", "1", target],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return result

    for line in proc.stdout.splitlines()[1:]:
        match = _HOP_LINE.match(line)
        if not match:
            continue
        rest = match.group(2)
        ip = _IP.search(rest)
        ms = _MS.search(rest)
        result["hops"].append(
            {
                "hop": int(match.group(1)),
                "address": ip.group(1) if ip else None,
                "rtt_ms": float(ms.group(1)) if ms else None,
            }
        )
    result["reachable"] = any(h["address"] for h in result["hops"])
    return result


class NetworkPath(ScanModule):
    name = "network_path"
    description = "Maps the network path between the scanner and the domain's servers."
    target_kinds = ("domain", "hostname", "url", "ip")
    groups = ("performance",)

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        kind = getattr(target, "kind", "domain")
        if kind == "ip":
            destination = str(getattr(target, "value", target))
        else:
            host = host_of(target)
            addresses = query(make_resolver(ctx.get("nameservers")), host, "A")
            if not addresses:
                return [
                    Finding(
                        module=self.name,
                        target=host,
                        severity="info",
                        title="No address to trace",
                        detail="The domain publishes no address record, so there is no path to map.",
                        evidence={},
                    )
                ]
            destination = addresses[0]

        result = trace(destination, int(ctx.get("max_hops", 20)))
        if not result["available"]:
            return [
                Finding(
                    module=self.name,
                    target=destination,
                    severity="info",
                    title="Path measurement unavailable",
                    detail="No traceroute utility is present on the scanner host, so the network path was not measured.",
                    evidence={
                        "remediation": "Install traceroute on the scan runner to enable this check."
                    },
                )
            ]

        findings: list[Finding] = []
        if not result["reachable"]:
            findings.append(
                Finding(
                    module=self.name,
                    target=destination,
                    severity="medium",
                    title="Server is not reachable from the scanner",
                    detail="No hop along the path responded. The server may be firewalled, down, or filtering probes.",
                    evidence=result,
                )
            )
        elif len(result["hops"]) >= LONG_PATH_HOPS:
            findings.append(
                Finding(
                    module=self.name,
                    target=destination,
                    severity="info",
                    title="Long network path",
                    detail=f"{len(result['hops'])} hops to reach the server, which adds latency for every visitor.",
                    evidence=result,
                )
            )

        findings.append(
            Finding(
                module=self.name,
                target=destination,
                severity="info",
                title="Network path measured",
                detail=f"{len(result['hops'])} hop(s) recorded.",
                evidence=result,
            )
        )
        return findings
