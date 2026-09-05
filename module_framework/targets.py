"""
targets.py — normalize and validate scan targets.

Accepts single values, comma lists, or files. Classifies each into a kind
(ip, url, domain, hostname), expands CIDR to individual IPs, dedupes, and
validates. This is what fixes "enter in ips urls etc" — one parser, every tool.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Target:
    raw: str  # what the user typed
    kind: str  # one of: ip, url, domain, hostname
    value: str  # normalized value (ip string, url, or host)


def _classify(token: str) -> list[Target]:
    token = token.strip()
    if not token:
        return []

    # URL (has a scheme)
    if "://" in token:
        parsed = urlparse(token)
        if not parsed.hostname:
            raise ValueError(f"unparseable URL: {token!r}")
        return [Target(raw=token, kind="url", value=token)]

    # CIDR -> expand to host IPs
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        return [Target(raw=token, kind="ip", value=str(ip)) for ip in net.hosts()]

    # Bare IP
    try:
        ip = ipaddress.ip_address(token)
        return [Target(raw=token, kind="ip", value=str(ip))]
    except ValueError:
        pass

    # Domain vs hostname: a dotted name with a TLD-ish last label = domain
    if "." in token and not token.endswith("."):
        return [Target(raw=token, kind="domain", value=token.lower())]

    return [Target(raw=token, kind="hostname", value=token.lower())]


def parse_targets(values: list[str] | None = None, files: list[str] | None = None) -> list[Target]:
    """Parse from inline values and/or files. Returns deduped, validated Targets."""
    tokens: list[str] = []
    for v in values or []:
        tokens.extend(part for part in v.split(",") if part.strip())
    for path in files or []:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()  # strip comments
                if line:
                    tokens.append(line)

    out: list[Target] = []
    seen: set[tuple[str, str]] = set()
    for tok in tokens:
        for t in _classify(tok):
            key = (t.kind, t.value)
            if key not in seen:
                seen.add(key)
                out.append(t)
    return out
