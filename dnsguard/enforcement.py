"""Compiling a published policy into the artifacts a resolver actually enforces.

The old code had two loose generators — an RPZ zone writer and an Unbound
blocklist writer — hanging off a class that also did zone auditing. They are
re-housed here because they are the same operation from three angles: take the
rules that are live for a site and render them for whichever resolver is in
front of that site.

Compilation is pure and deterministic: the same effective policy produces
byte-identical output, and the output carries a hash of the ruleset it came
from. That is what makes "which policy version is this resolver actually
running" answerable — you compare the stamp in the file to the version you
believe is published, rather than reading the zone.

Pushing an artifact to a live resolver is `enforcement.push`, which is already
classified disruptive. Compiling one is not, so an operator can review exactly
what would ship before anyone signs it off.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass
from typing import Any

from .audit import digest
from .clock import Clock, iso
from .errors import ValidationError
from .policy import PolicyVersion

FORMATS = ("rpz", "unbound", "hosts", "dnsmasq")

# RPZ answers a blocked name with NXDOMAIN by CNAMEing it to the zone root.
RPZ_SINK = "CNAME ."


@dataclass
class Artifact:
    fmt: str
    content: str
    rule_count: int
    policy_hash: str
    generated_at: str

    @property
    def content_hash(self) -> str:
        return digest(self.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.fmt,
            "content": self.content,
            "rule_count": self.rule_count,
            "policy_hash": self.policy_hash,
            "content_hash": self.content_hash,
            "generated_at": self.generated_at,
        }


def blocked_names(version: PolicyVersion) -> builtins.list[str]:
    """Names a resolver should refuse, in a stable order.

    Only domain and wildcard rules compile: category and feed rules are resolved
    against the indicator index at decision time, and flattening them into a
    static file would freeze a snapshot of a feed into a resolver config with no
    way to tell how old it is. That is exactly the un-provenanced blocklist this
    product exists to replace.
    """
    names = {
        rule.match_value.removeprefix("*.")
        for rule in version.rules
        if rule.enabled and rule.action == "block" and rule.match_kind in ("domain", "wildcard")
    }
    return sorted(names)


def compile_policy(
    version: PolicyVersion, fmt: str = "rpz", clock: Clock | None = None
) -> Artifact:
    if fmt not in FORMATS:
        raise ValidationError(f"unknown enforcement format {fmt!r}; expected {FORMATS}")

    clock = clock or Clock()
    names = blocked_names(version)
    policy_hash = version.content_hash()
    stamp = iso(clock.now())
    header = _header(fmt, version, policy_hash, stamp, len(names))
    body = _RENDER[fmt](names)

    return Artifact(
        fmt=fmt,
        content=header + body,
        rule_count=len(names),
        policy_hash=policy_hash,
        generated_at=stamp,
    )


def _header(fmt: str, version: PolicyVersion, policy_hash: str, stamp: str, count: int) -> str:
    """Every artifact says which policy version produced it and when.

    A resolver config with no provenance is unauditable — the stamp is what lets
    an operator confirm the box is running what they think it is.
    """
    comment = ";" if fmt == "rpz" else "#"
    lines = [
        f"{comment} Iron City DNS Guard enforcement artifact",
        f"{comment} policy: {version.policy_id} version {version.version}",
        f"{comment} policy_hash: {policy_hash}",
        f"{comment} generated: {stamp}",
        f"{comment} entries: {count}",
        "",
    ]
    return "\n".join(lines)


def _render_rpz(names: builtins.list[str]) -> str:
    lines = [
        "$TTL 300",
        "@ IN SOA localhost. root.localhost. 1 3600 900 86400 300",
        "  IN NS localhost.",
        "",
    ]
    for name in names:
        lines.append(f"{name} {RPZ_SINK}")
        lines.append(f"*.{name} {RPZ_SINK}")
    return "\n".join(lines) + "\n"


def _render_unbound(names: builtins.list[str]) -> str:
    lines = ["server:"]
    lines.extend(f'    local-zone: "{name}" always_nxdomain' for name in names)
    return "\n".join(lines) + "\n"


def _render_hosts(names: builtins.list[str]) -> str:
    return "\n".join(f"0.0.0.0 {name}" for name in names) + ("\n" if names else "")


def _render_dnsmasq(names: builtins.list[str]) -> str:
    return "\n".join(f"address=/{name}/" for name in names) + ("\n" if names else "")


_RENDER = {
    "rpz": _render_rpz,
    "unbound": _render_unbound,
    "hosts": _render_hosts,
    "dnsmasq": _render_dnsmasq,
}
