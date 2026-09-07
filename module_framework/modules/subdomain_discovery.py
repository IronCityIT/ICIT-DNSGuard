"""Attack-surface discovery: which names under this domain are publicly visible?

Two independent sources, as before: certificate transparency logs (everything the
domain has ever been issued a certificate for) and a probe list of the names that
are conventionally present. Findings call out the classes of exposure that matter
rather than listing every host as a problem.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query

PROBE_NAMES = (
    "www",
    "mail",
    "webmail",
    "remote",
    "ftp",
    "smtp",
    "pop",
    "imap",
    "blog",
    "shop",
    "store",
    "api",
    "dev",
    "staging",
    "test",
    "beta",
    "uat",
    "admin",
    "portal",
    "vpn",
    "secure",
    "login",
    "sso",
    "app",
    "apps",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "files",
    "ns1",
    "ns2",
    "dns",
    "mx",
    "mx1",
    "mx2",
    "autodiscover",
    "lyncdiscover",
    "owa",
    "exchange",
    "cpanel",
    "whm",
    "plesk",
    "support",
    "help",
    "docs",
    "git",
    "jenkins",
    "ci",
    "jira",
    "confluence",
    "db",
    "backup",
    "old",
)

# Names that should not be reachable from the public internet.
SENSITIVE_NAMES = frozenset(
    {
        "admin",
        "dev",
        "staging",
        "test",
        "beta",
        "uat",
        "db",
        "backup",
        "old",
        "jenkins",
        "ci",
        "git",
        "jira",
        "confluence",
        "cpanel",
        "whm",
        "plesk",
    }
)

LARGE_SURFACE = 50


def coverage_is_full(coverage: dict[str, Any]) -> bool:
    """Did discovery see everything it was asked to see?

    Certificate transparency is the half that finds names nobody would guess. If
    it was requested and did not answer, the sweep covered conventional names
    only — a materially smaller surface, and the caller is entitled to know
    before treating a clean result as a clean domain.
    """
    return coverage.get("certificate_transparency") in ("ok", "not requested")


def coverage_note(coverage: dict[str, Any]) -> str:
    """One clause a person can read, describing what was actually examined."""
    probes = coverage.get("probe_names", 0)
    status = coverage.get("certificate_transparency")
    if status == "ok":
        found = coverage.get("certificate_transparency_names", 0)
        return f"({probes} conventional, {found} from certificate transparency)."
    if status == "not requested":
        return f"({probes} conventional names; certificate transparency was not requested)."
    return (
        f"({probes} conventional names only — certificate transparency was unavailable, so "
        "names that would not be guessed were not examined)."
    )


def _crtsh_names(session: Any, domain: str, timeout: float = 15.0) -> tuple[set[str], str]:
    """Names this domain has been issued certificates for, and whether the
    lookup actually worked.

    Still best-effort — a third party being slow must not fail a scan — but the
    *status* is returned rather than swallowed. Silently degrading to the probe
    list halves the discovered surface and reports the same clean result, which
    is the shape of a check that passes without having checked.
    """
    try:
        resp = session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout)
        if resp.status_code != 200:
            return set(), "unavailable"
        entries = resp.json()
    except Exception:
        return set(), "unavailable"

    names: set[str] = set()
    for entry in entries:
        for line in str(entry.get("name_value", "")).split("\n"):
            name = line.strip().lower().rstrip(".")
            if name and name.endswith(domain) and "*" not in name:
                names.add(name)
    return names, "ok"


class SubdomainDiscovery(ScanModule):
    name = "subdomain_discovery"
    description = (
        "Discovers the hosts published under a domain and flags the ones that should not be public."
    )
    target_kinds = ("domain", "hostname", "url")
    groups = ("standard", "deep", "surface")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        session = ctx.get("http") or _default_session()

        # Cached on ctx so that alias_takeover, which needs the same candidate
        # set, does not repeat the certificate-transparency call and the probe
        # sweep when both modules run in the same scan. Whichever runs first
        # pays for it.
        cached = ctx.get("alias_candidates")
        if isinstance(cached, dict) and cached.get("root") == host:
            candidates = set(cached["names"])
            coverage = cached["coverage"]
        else:
            candidates = {f"{name}.{host}" for name in PROBE_NAMES}
            coverage = {
                "probe_names": len(PROBE_NAMES),
                "certificate_transparency": "not requested",
            }
            if ctx.get("use_certificate_transparency", True):
                found, status = _crtsh_names(session, host)
                candidates |= found
                coverage["certificate_transparency"] = status
                coverage["certificate_transparency_names"] = len(found)
            ctx["alias_candidates"] = {
                "root": host,
                "names": sorted(candidates),
                "coverage": coverage,
            }

        def resolve(fqdn: str) -> dict[str, Any] | None:
            addresses = query(res, fqdn, "A")
            aliases = [c.rstrip(".") for c in query(res, fqdn, "CNAME")]
            if not addresses and not aliases:
                return None
            label = fqdn[: -(len(host) + 1)].split(".")[0]
            return {
                "host": fqdn,
                "addresses": addresses,
                "aliases": aliases,
                "source": "certificate-transparency"
                if fqdn not in {f"{n}.{host}" for n in PROBE_NAMES}
                else "probe",
                "label": label,
            }

        with ThreadPoolExecutor(max_workers=int(ctx.get("workers", 10))) as pool:
            live = [r for r in pool.map(resolve, sorted(candidates)) if r]

        findings: list[Finding] = []
        sensitive = [h for h in live if h["label"] in SENSITIVE_NAMES]
        if sensitive:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="medium",
                    title="Internal-sounding hosts are reachable from the internet",
                    detail=(
                        f"{len(sensitive)} host(s) whose names indicate non-production or "
                        "administrative use resolve publicly. These are routinely the least "
                        "patched and least monitored systems an organisation runs."
                    ),
                    evidence={
                        "hosts": sensitive,
                        "remediation": "Put these behind the VPN or remove the public records.",
                    },
                )
            )

        dangling = [h for h in live if h["aliases"] and not h["addresses"]]
        if dangling:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="Aliases point at destinations that do not resolve",
                    detail=(
                        f"{len(dangling)} host(s) alias a destination that returns no address. "
                        "If the destination is a de-provisioned hosting account, whoever registers "
                        "that name next can serve content on your domain."
                    ),
                    evidence={
                        "hosts": dangling,
                        "remediation": "Remove the alias, or re-claim the destination.",
                    },
                )
            )

        if len(live) > LARGE_SURFACE:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    title="Large public footprint",
                    detail=f"{len(live)} hosts resolve under this domain. Every one is a way in.",
                    evidence={"host_count": len(live)},
                )
            )

        findings.append(
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Public host inventory collected",
                detail=(
                    f"{len(live)} host(s) resolve under {host}, from {len(candidates)} name(s) "
                    + coverage_note(coverage)
                ),
                evidence={"hosts": live, "coverage": coverage},
                confidence="confirmed" if coverage_is_full(coverage) else "possible",
            )
        )
        return findings


def _default_session() -> Any:
    import requests

    session = requests.Session()
    session.headers.update({"User-Agent": "IronCity-DNSGuard/1.0"})
    return session
