"""Resolver performance: how fast and how reliably does each public resolver
answer for this domain? Ported from DNSPerformanceTester.

Kept dependency-free (no numpy) so the module runs anywhere the scanner runs.
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
        results = [benchmark(host, addr, label, queries) for addr, label in RESOLVERS.values()]

        findings: list[Finding] = []
        unreachable = [r for r in results if r["loss_percent"] >= 100.0]
        lossy = [
            r
            for r in results
            if 0 < r["loss_percent"] < 100.0 and r["loss_percent"] >= LOSSY_PERCENT
        ]
        slow = [r for r in results if r["latency_avg_ms"] and r["latency_avg_ms"] > SLOW_MS]

        if len(unreachable) == len(results):
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="Domain does not answer from any major resolver",
                    detail="Every public resolver tested failed to get an answer. To most of the internet this domain is down.",
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
                    detail=f"{len(unreachable)} of {len(results)} public resolvers could not answer. Visitors using them cannot reach you.",
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
                detail=f"{queries} lookups against each of {len(results)} public resolvers.",
                evidence={"results": results},
            )
        )
        return findings
