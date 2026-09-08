"""Resolver performance: how fast and how reliably does each public resolver
answer for this domain? Ported from DNSPerformanceTester.

Kept dependency-free (no numpy) so the module runs anywhere the scanner runs.

## The instrument is checked before the measurement is believed

This module used to report, at **high** severity, "Domain does not answer from any
major resolver — to most of the internet this domain is down" whenever every
lookup failed. Every lookup failing is exactly what happens when the *scanner*
cannot reach 1.1.1.1 and friends, which is ordinary inside containers, on
networks that force their own resolver, and in CI. A completely healthy domain
was therefore one egress rule away from being reported as down, in the most
absolute language the product uses.

So before concluding anything about a domain, each resolver is asked for a name
that certainly exists. If it cannot answer *that*, the failure is ours and the
result is reported as unmeasured rather than as the client being unreachable.

It is the same control the takeover module uses on negative DNS answers, for the
same reason: a measurement is only worth as much as the confidence that the
instrument was working when it was taken.
"""

from __future__ import annotations

import statistics
import time
from typing import Any

import dns.resolver
from base import Finding, ScanModule

from ._dns import host_of, make_resolver

# Public resolvers, addressed by IP so the benchmark does not itself depend on DNS.
RESOLVERS: dict[str, tuple[str, str]] = {
    "cloudflare": ("1.1.1.1", "Cloudflare"),
    "google": ("8.8.8.8", "Google"),
    "quad9": ("9.9.9.9", "Quad9"),
    "opendns": ("208.67.222.222", "OpenDNS"),
}

SLOW_MS = 250.0
LOSSY_PERCENT = 10.0

#: The control question. A name in the DNS hierarchy itself, so the check does
#: not depend on any particular third party staying up — every working resolver
#: answers for a TLD, and one that cannot is not answering us at all.
CONTROL_NAME = "com"
CONTROL_TYPE = "SOA"


def benchmark(host: str, address: str, label: str, queries: int = 15) -> dict[str, Any]:
    res = make_resolver([address], timeout=3.0, lifetime=5.0)
    latencies: list[float] = []
    failures = 0
    for _ in range(queries):
        start = time.perf_counter()
        try:
            res.resolve(host, "A")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # An authoritative "no such record" is a successful round trip.
            latencies.append((time.perf_counter() - start) * 1000)
        except Exception:
            failures += 1
        else:
            latencies.append((time.perf_counter() - start) * 1000)

    if not latencies:
        return {
            "resolver": label,
            "address": address,
            "queries": queries,
            "latency_avg_ms": None,
            "latency_min_ms": None,
            "latency_max_ms": None,
            "loss_percent": 100.0,
        }
    return {
        "resolver": label,
        "address": address,
        "queries": queries,
        "latency_avg_ms": round(statistics.fmean(latencies), 2),
        "latency_min_ms": round(min(latencies), 2),
        "latency_max_ms": round(max(latencies), 2),
        "loss_percent": round(failures / queries * 100, 2),
    }


def resolver_answers(address: str) -> bool:
    """Can this resolver answer us at all?

    Asked only when every lookup for the target failed, and the answer decides
    whether that means the domain is unreachable or that we are.
    """
    res = make_resolver([address], timeout=3.0, lifetime=5.0)
    try:
        res.resolve(CONTROL_NAME, CONTROL_TYPE)
    except Exception:
        return False
    return True


class ResolverPerformance(ScanModule):
    name = "resolver_performance"
    description = (
        "Measures how quickly and reliably the major public resolvers answer for this domain."
    )
    target_kinds = ("domain", "hostname", "url")
    groups = ("deep", "performance")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        queries = int(ctx.get("perf_queries", 15))
        # Injected so the conclusions can be tested without sending a single
        # query at a public resolver.
        measure = ctx.get("benchmark") or benchmark
        control = ctx.get("resolver_answers") or resolver_answers

        results = [measure(host, addr, label, queries) for addr, label in RESOLVERS.values()]

        # A resolver that answered nothing is only evidence about the domain if
        # it can answer at all. Checked once per resolver, and only for the ones
        # that failed completely — a resolver that answered is its own proof.
        for result in results:
            result["usable"] = (
                True if result["loss_percent"] < 100.0 else bool(control(result["address"]))
            )

        findings: list[Finding] = []
        unusable = [r for r in results if not r["usable"]]
        if len(unusable) == len(results):
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    confidence="inconclusive",
                    category="operational",
                    title="Resolver performance could not be measured",
                    detail=(
                        "None of the public resolvers answered this scanner, including for a "
                        "name that certainly exists. That is a fact about where this scan ran "
                        "from — outbound DNS is commonly blocked in containers and on networks "
                        "that force their own resolver — and says nothing about whether the "
                        "domain resolves for anybody else."
                    ),
                    remediation=(
                        "Re-run from a host with outbound DNS to the public resolvers, or "
                        "exclude this check where that is not available."
                    ),
                    evidence={"results": results},
                )
            ]

        measured = [r for r in results if r["usable"]]
        unreachable = [r for r in measured if r["loss_percent"] >= 100.0]
        lossy = [
            r
            for r in measured
            if 0 < r["loss_percent"] < 100.0 and r["loss_percent"] >= LOSSY_PERCENT
        ]
        slow = [r for r in measured if r["latency_avg_ms"] and r["latency_avg_ms"] > SLOW_MS]

        if unreachable and len(unreachable) == len(measured):
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="Domain does not answer from any major resolver",
                    detail=(
                        f"All {len(measured)} public resolver(s) that could be reached from this "
                        "scanner answered for a name that certainly exists, and none of them "
                        "answered for this domain. To most of the internet this domain is down."
                    ),
                    evidence={"results": results},
                )
            )
        elif unreachable:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="medium",
                    title="Domain is unreachable through some major resolvers",
                    detail=(
                        f"{len(unreachable)} of {len(measured)} reachable public resolvers could "
                        "not answer for this domain, while answering for a name that certainly "
                        "exists. Visitors using them cannot reach you."
                    ),
                    evidence={"results": results},
                )
            )

        if lossy:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    title="Intermittent lookup failures",
                    detail=f"{len(lossy)} resolver(s) dropped at least {LOSSY_PERCENT}% of lookups.",
                    evidence={"results": lossy},
                )
            )
        if slow:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    title="Slow lookup responses",
                    detail=f"{len(slow)} resolver(s) averaged over {SLOW_MS:.0f}ms, which users feel as a slow first page load.",
                    evidence={"results": slow},
                )
            )

        findings.append(
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Resolver performance measured",
                category="operational",
                detail=(
                    f"{queries} lookups against each of {len(measured)} reachable public "
                    f"resolver(s)"
                    + (
                        f"; {len(unusable)} did not answer this scanner and were excluded."
                        if unusable
                        else "."
                    )
                ),
                evidence={"results": results},
            )
        )
        return findings
