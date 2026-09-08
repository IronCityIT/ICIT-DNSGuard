"""Network path to the domain's servers. Ported from HopsAnalyzer.

Off by default (not in the standard groups) because it needs traceroute on the
host and produces noisy results from inside containers.

## Two things this used to get wrong

**`reachable` did not mean reachable.** It was true when *any* hop along the way
answered — which is almost always, because the first router is usually the
scanner's own gateway. So a trace that died three hops out at somebody's ISP was
recorded as having reached the server, and the "not reachable" finding fired
essentially never. Reaching the destination now means the last responding hop
*is* the destination.

**A server that ignores traceroute was called a problem.** Not answering ICMP or
UDP probes is ordinary, frequently deliberate, and often the better
configuration — so reporting it at `medium` told a client their correctly
hardened server was broken. It is now an `info` finding at `inconclusive`
confidence that says what was and was not established, because the honest
statement is about *our* vantage point rather than about their posture.

The traceroute call is injectable so the parsing and the conclusions can be
tested without sending packets anywhere.
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
    # Every key is set here, not on the success path. There are two early
    # returns below — no traceroute binary, and a timeout — and a caller reading
    # `reached` after either of them would raise rather than report.
    result: dict[str, Any] = {
        "target": target,
        "hops": [],
        "responding_hops": 0,
        "reached": False,
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
    responded = [h for h in result["hops"] if h["address"]]
    result["responding_hops"] = len(responded)
    # Reached, not merely "something answered". The last responding hop has to be
    # the destination itself; anything else means the trace stopped short, which
    # is a different fact about a different machine.
    result["reached"] = bool(responded) and responded[-1]["address"] == target
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
                        category="operational",
                        detail=(
                            "The domain publishes no address record, so there is no path to map."
                        ),
                        evidence={},
                    )
                ]
            destination = addresses[0]

        # Injected so the parsing and the conclusions can be tested without
        # sending packets at anybody.
        run_trace = ctx.get("trace") or trace
        result = run_trace(destination, int(ctx.get("max_hops", 20)))
        if not result["available"]:
            return [
                Finding(
                    module=self.name,
                    target=destination,
                    severity="info",
                    title="Path measurement unavailable",
                    confidence="inconclusive",
                    category="operational",
                    detail=(
                        "No traceroute utility is present on the scanner host, so the network "
                        "path was not measured. Nothing is claimed about it either way."
                    ),
                    remediation="Install traceroute on the scan runner to enable this check.",
                )
            ]

        findings: list[Finding] = []
        if not result["reached"]:
            findings.append(
                Finding(
                    module=self.name,
                    target=destination,
                    severity="info",
                    confidence="inconclusive",
                    category="operational",
                    title="The path to the server could not be traced all the way",
                    detail=(
                        f"{result['responding_hops']} hop(s) answered, but the trace did not "
                        f"reach {destination}. This is not a fault: hosts and networks routinely "
                        "drop the probes traceroute depends on, and doing so is often deliberate. "
                        "It says where our measurement stopped, not that the server is down — "
                        "reachability from a browser is a different question and is not answered "
                        "here."
                    ),
                    remediation=(
                        "None required unless the server is genuinely unreachable, which this "
                        "check cannot establish. Confirm with a request to the service itself."
                    ),
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
                    category="operational",
                    detail=(
                        f"{len(result['hops'])} hops to reach the server, which adds latency for "
                        "every visitor."
                    ),
                    evidence=result,
                )
            )

        findings.append(
            Finding(
                module=self.name,
                target=destination,
                severity="info",
                title="Network path measured",
                category="operational",
                detail=(
                    f"{len(result['hops'])} hop(s) recorded, "
                    f"{result['responding_hops']} of which responded."
                ),
                evidence=result,
            )
        )
        return findings
