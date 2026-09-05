"""Reputation of the addresses and the domain itself, from external providers.

Ported from the old api_clients.py. Two things changed in the port and both
matter:

  * Every answer carries provenance — which provider said it, when, and what the
    raw counts were. A reputation verdict with no attribution is not usable as a
    reason to block anything, and this product's whole position is that a block
    has to be defensible.
  * A provider that is missing a key, rate-limiting, or down is reported as
    "not consulted", never as "clean". Silently downgrading absence of evidence
    to evidence of absence is how a reputation check becomes decoration.

Keys come from the environment by name only (VIRUSTOTAL_API_KEY,
ABUSEIPDB_API_KEY, IPSTACK_API_KEY); nothing is hardcoded and no key is ever
written into a finding.
"""

from __future__ import annotations

import os
from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query

# Above this share of engines flagging it, treat an address as bad rather than noisy.
VT_MALICIOUS_ENGINES = 3
ABUSE_CONFIDENCE = 50
MAX_ADDRESSES = 5


class ReputationLookup(ScanModule):
    name = "reputation_lookup"
    description = (
        "Checks the domain and the addresses it points at against external reputation providers."
    )
    target_kinds = ("domain", "hostname", "url", "ip")
    groups = ("deep", "reputation")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        session = ctx.get("http") or _session()
        providers = _configured(ctx)

        if not providers:
            return [
                Finding(
                    module=self.name,
                    target=host_of(target) or str(getattr(target, "value", target)),
                    severity="info",
                    title="Reputation providers were not consulted",
                    detail=(
                        "No reputation provider is configured, so nothing external was "
                        "checked. This is not a clean result — it is an unchecked one."
                    ),
                    evidence={"providers_configured": [], "consulted": False},
                )
            ]

        kind = getattr(target, "kind", "domain")
        if kind == "ip":
            host = str(getattr(target, "value", target))
            addresses = [host]
        else:
            host = host_of(target)
            addresses = query(make_resolver(ctx.get("nameservers")), host, "A")[:MAX_ADDRESSES]

        findings: list[Finding] = []
        verdicts: list[dict[str, Any]] = []
        unavailable: list[str] = []

        if kind != "ip" and "virustotal" in providers:
            verdict = _virustotal_domain(session, providers["virustotal"], host)
            if verdict.get("consulted"):
                verdicts.append(verdict)
            else:
                unavailable.append("virustotal")

        for address in addresses:
            for provider, key in providers.items():
                if provider == "ipstack":
                    continue
                lookup = _VERDICT[provider]
                verdict = lookup(session, key, address)
                if verdict.get("consulted"):
                    verdicts.append(verdict)
                elif provider not in unavailable:
                    unavailable.append(provider)

        flagged = [v for v in verdicts if v.get("malicious")]
        if flagged:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="high" if len(flagged) > 1 else "medium",
                    title="Infrastructure has a negative reputation",
                    detail=(
                        f"{len(flagged)} reputation verdict(s) flag this domain or the addresses "
                        "it points at. Mail and web traffic from flagged addresses is widely "
                        "filtered, and a shared host that is flagged affects every site on it."
                    ),
                    evidence={
                        "verdicts": flagged,
                        "remediation": "Confirm the address is yours and not shared with abusive tenants, then request delisting with each provider.",
                    },
                )
            )

        if unavailable:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    title="Some reputation providers could not be consulted",
                    detail=(
                        f"{len(unavailable)} provider(s) did not answer, so this assessment is "
                        "partial. Absence of a verdict is not a clean verdict."
                    ),
                    evidence={"unavailable": sorted(unavailable), "consulted": len(verdicts)},
                )
            )

        findings.append(
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Reputation checked",
                detail=f"{len(verdicts)} verdict(s) collected across {len(addresses)} address(es).",
                evidence={
                    "verdicts": verdicts,
                    "addresses": addresses,
                    "providers_configured": sorted(providers),
                },
            )
        )
        return findings


# ── providers ────────────────────────────────────────────────────────────────


def _configured(ctx: dict[str, Any]) -> dict[str, str]:
    """Providers with a key present. By name from the environment, never inline."""
    if ctx.get("reputation_keys") is not None:
        return dict(ctx["reputation_keys"])
    keys = {
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY", ""),
        "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
        "ipstack": os.environ.get("IPSTACK_API_KEY", ""),
    }
    return {name: key for name, key in keys.items() if key}


def _session() -> Any:
    import requests

    session = requests.Session()
    session.headers.update({"User-Agent": "IronCity-DNSGuard/1.0"})
    return session


def _get(session: Any, url: str, **kwargs: Any) -> Any:
    kwargs.setdefault("timeout", 10)
    return session.get(url, **kwargs)


def _virustotal(session: Any, key: str, address: str) -> dict[str, Any]:
    try:
        response = _get(
            session,
            f"https://www.virustotal.com/api/v3/ip_addresses/{address}",
            headers={"x-apikey": key},
        )
        if response.status_code != 200:
            return {
                "provider": "virustotal",
                "target": address,
                "consulted": False,
                "reason": f"HTTP {response.status_code}",
            }
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception as exc:  # noqa: BLE001 - any failure is "not consulted"
        return {"provider": "virustotal", "target": address, "consulted": False, "reason": str(exc)}

    malicious = int(stats.get("malicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    return {
        "provider": "virustotal",
        "target": address,
        "consulted": True,
        "malicious": malicious > VT_MALICIOUS_ENGINES,
        "engines_flagging": malicious,
        "engines_total": total,
    }


def _virustotal_domain(session: Any, key: str, domain: str) -> dict[str, Any]:
    try:
        response = _get(
            session,
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
        )
        if response.status_code != 200:
            return {
                "provider": "virustotal",
                "target": domain,
                "consulted": False,
                "reason": f"HTTP {response.status_code}",
            }
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception as exc:  # noqa: BLE001
        return {"provider": "virustotal", "target": domain, "consulted": False, "reason": str(exc)}

    malicious = int(stats.get("malicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    return {
        "provider": "virustotal",
        "target": domain,
        "consulted": True,
        "malicious": malicious > VT_MALICIOUS_ENGINES,
        "engines_flagging": malicious,
        "engines_total": total,
    }


def _abuseipdb(session: Any, key: str, address: str) -> dict[str, Any]:
    try:
        response = _get(
            session,
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": address, "maxAgeInDays": 90},
        )
        if response.status_code != 200:
            return {
                "provider": "abuseipdb",
                "target": address,
                "consulted": False,
                "reason": f"HTTP {response.status_code}",
            }
        data = response.json()["data"]
    except Exception as exc:  # noqa: BLE001
        return {"provider": "abuseipdb", "target": address, "consulted": False, "reason": str(exc)}

    confidence = int(data.get("abuseConfidenceScore", 0))
    return {
        "provider": "abuseipdb",
        "target": address,
        "consulted": True,
        "malicious": confidence > ABUSE_CONFIDENCE,
        "abuse_confidence": confidence,
        "reports": int(data.get("totalReports", 0)),
    }


_VERDICT = {"virustotal": _virustotal, "abuseipdb": _abuseipdb}
