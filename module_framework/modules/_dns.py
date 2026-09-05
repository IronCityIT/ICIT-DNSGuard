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
