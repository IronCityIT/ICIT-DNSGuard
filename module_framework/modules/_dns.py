"""
_dns.py — shared DNS plumbing for the scan modules.

One resolver factory and one set of lookup helpers so every module times out the
same way and swallows the same "this record simply does not exist" conditions.
Ported from the monolithic analyzer's inline try/except blocks; the behaviour is
unchanged, it just lives in one place now.
"""

from __future__ import annotations

from typing import Any

import dns.rdatatype
import dns.resolver

DEFAULT_TIMEOUT = 5.0
DEFAULT_LIFETIME = 10.0

# Selectors published by the mail providers SMBs actually use. Kept verbatim from
# the previous analyzer so DKIM discovery does not regress.
DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "dkim",
    "mail",
    "email",
    "mandrill",
    "mailchimp",
    "sendgrid",
    "amazonses",
    "ses",
    "zendesk",
    "freshdesk",
    "mailgun",
    "sparkpost",
    "mimecast",
    "proofpoint",
    "smtp",
    "s1",
    "s2",
    "mx",
    "cm",
    "pm",
)


def make_resolver(
    nameservers: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    lifetime: float = DEFAULT_LIFETIME,
) -> dns.resolver.Resolver:
    res = dns.resolver.Resolver()
    if nameservers:
        res.nameservers = nameservers
    res.timeout = timeout
    res.lifetime = lifetime
    return res


def host_of(target: Any) -> str:
    """The DNS name a Target refers to, whatever shape the user typed.

    A url target carries a full URL; domain/hostname targets carry the name
    directly. Modules only ever want the name, so they all come through here.
    """
    kind = getattr(target, "kind", "domain")
    value = str(getattr(target, "value", target))
    if kind == "url":
        from urllib.parse import urlparse

        return (urlparse(value).hostname or "").lower()
    return value.lower().rstrip(".")


def query(res: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    """Return record values as strings, or [] when the record does not exist.

    NXDOMAIN / NoAnswer / timeouts are *absence*, not failure: a domain with no
    CAA record is a normal domain. Anything unexpected also returns [] rather
    than aborting a whole scan over one record type.
    """
    try:
        answers = res.resolve(name, rtype)
    except Exception:
        return []
    return [str(r).strip('"') for r in answers]


def query_ttl(res: dns.resolver.Resolver, name: str, rtype: str) -> tuple[list[str], int]:
    try:
        answers = res.resolve(name, rtype)
    except Exception:
        return [], 0
    ttl = int(getattr(answers.rrset, "ttl", 0) or 0)
    return [str(r).strip('"') for r in answers], ttl


def txt_records(res: dns.resolver.Resolver, name: str) -> list[str]:
    return query(res, name, "TXT")


def find_txt(res: dns.resolver.Resolver, name: str, prefix: str) -> str:
    """First TXT record at `name` whose value starts with `prefix` (case-insensitive)."""
    for txt in txt_records(res, name):
        if txt.lower().startswith(prefix.lower()):
            return txt
    return ""


#: Why a lookup produced no usable answer. The distinction matters for takeover
#: analysis and is lost by `query`, which collapses all of these to [].
#:   ok        records were returned
#:   nxdomain  the name does not exist anywhere in the DNS
#:   nodata    the name exists but carries no record of this type
#:   error     the question could not be answered (timeout, SERVFAIL, no resolver)
RESOLUTIONS = ("ok", "nxdomain", "nodata", "error")


def resolution(res: dns.resolver.Resolver, name: str, rtype: str = "A") -> tuple[str, list[str]]:
    """Resolve `name`, reporting *why* when nothing came back.

    `query` treats NXDOMAIN, NODATA and a timeout identically, which is right for
    "does this domain publish a CAA record" and wrong for anything reasoning
    about whether a name is claimable. NXDOMAIN means the name does not exist and
    something could be put there; NODATA means it exists and is merely missing an
    address; an error means we do not know, and must not be reported as either.
    """
    try:
        answers = res.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        return "nodata", []
    except Exception:
        # SERVFAIL, timeouts, a lame delegation: unknown, and deliberately not
        # folded into nxdomain. Guessing here invents takeovers that do not exist.
        return "error", []
    return "ok", [str(r).strip('"') for r in answers]


def zone_apex(res: dns.resolver.Resolver, name: str) -> str:
    """The closest enclosing zone apex for `name` — the zone that serves it.

    Walks *down* from the name itself, label by label, asking for SOA, and stops
    at the first answer. That is the nearest zone cut, which is what answers
    "who would somebody have to go to in order to create this name": for
    `icit.mynetgear.com` it is `mynetgear.com`, and for a provider that serves
    each region separately it is that regional zone rather than the brand apex.

    The TLD is never a candidate. A bare TLD always has an SOA, and "you would
    have to claim .com" is not an answer anybody can act on.

    Returns "" when nothing between the name and the TLD answers, which is
    itself the interesting case: the registrable domain is not registered at all.
    """
    labels = name.rstrip(".").split(".")
    # Stop before the TLD: a bare TLD always has an SOA and answering "com" is
    # never the useful answer.
    for cut in range(len(labels) - 1):
        candidate = ".".join(labels[cut:])
        status, _ = resolution(res, candidate, "SOA")
        if status == "ok":
            return candidate
    return ""
