"""DKIM posture: does the domain publish signing keys under any known selector?"""

from __future__ import annotations

import base64
import binascii
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from base import Finding, ScanModule

from ._dns import DKIM_SELECTORS, host_of, make_resolver, txt_records

USABLE = "usable"
REVOKED = "revoked"
NOT_A_KEY = ""

# The boundary between two strings of one TXT record, or a stray quote. A long
# key is published as several strings; they concatenate with nothing in between.
_STRING_BOUNDARY = re.compile(r'"\s*"|"')

# The smallest public key in use is Ed25519, at 32 bytes. The floor is what tells
# a key from short words that are also valid base64, like a policy of "none".
_MIN_KEY_BYTES = 32


def classify_record(txt: str) -> str:
    """Whether one TXT value is a USABLE key, a REVOKED key, or NOT_A_KEY.

    RFC 6376 section 3.6.1: v= is optional but must be DKIM1 when given, p= is
    required, and an empty p= means the key has been revoked.
    """
    tags: dict[str, str] = {}
    for part in _STRING_BOUNDARY.sub("", txt).split(";"):
        name, separator, value = part.partition("=")
        if not separator:
            continue
        name = name.strip().lower()
        if name in tags:
            return NOT_A_KEY  # section 3.2: a repeated tag invalidates the list
        tags[name] = value.strip()

    if "p" not in tags:
        return NOT_A_KEY
    key = "".join(tags["p"].split())

    if "v" in tags:
        if tags["v"].lower() != "dkim1":
            return NOT_A_KEY
        return USABLE if key else REVOKED
    # Nothing declares this record to be a DKIM key, so the key itself has to.
    return USABLE if _is_plausible_key(key) else NOT_A_KEY


def _is_plausible_key(key: str) -> bool:
    unpadded = key.rstrip("=")
    try:
        decoded = base64.b64decode(unpadded + "=" * (-len(unpadded) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) >= _MIN_KEY_BYTES


class DkimAudit(ScanModule):
    name = "dkim_audit"
    description = (
        "Looks for published mail-signing keys under the selectors the common mail providers use."
    )
    target_kinds = ("domain", "hostname", "url")
    groups = ("standard", "deep", "email")

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        selectors = tuple(ctx.get("dkim_selectors") or DKIM_SELECTORS)

        def probe(selector: str) -> str:
            records = txt_records(res, f"{selector}._domainkey.{host}")
            states = {classify_record(txt) for txt in records}
            if USABLE in states:
                return USABLE
            return REVOKED if REVOKED in states else NOT_A_KEY

        with ThreadPoolExecutor(max_workers=10) as pool:
            states = dict(zip(selectors, pool.map(probe, selectors), strict=True))
        usable = sorted(s for s, state in states.items() if state == USABLE)
        revoked = sorted(s for s, state in states.items() if state == REVOKED)

        if not usable and revoked:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="Every mail signing key found has been revoked",
                    detail=(
                        f"Signing key records were found under {len(revoked)} selector(s), but each "
                        "one is published with an empty key, which tells receivers the key has "
                        "been revoked. Receivers cannot cryptographically verify that mail from "
                        "this domain is genuine."
                    ),
                    # No "selectors" key: the report reads it as DKIM being configured.
                    evidence={
                        "revoked_selectors": revoked,
                        "selectors_probed": len(selectors),
                        "remediation": (
                            "If this domain sends mail, enable DKIM signing with your mail provider "
                            "and publish the current selector record it gives you. If it does not "
                            "send mail, keep the revoked keys and make sure SPF and DMARC reject "
                            "all mail from it."
                        ),
                    },
                )
            ]

        if not usable:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="high",
                    title="No mail signing keys found",
                    detail=(
                        "No DKIM key was published under any of the selectors used by the common "
                        "mail providers. Receivers cannot cryptographically verify that mail from "
                        "this domain is genuine, and forwarded mail loses authentication entirely."
                    ),
                    evidence={
                        "selectors_probed": len(selectors),
                        "remediation": "Enable DKIM signing with your mail provider and publish the selector record it gives you.",
                    },
                )
            ]

        evidence: dict[str, Any] = {"selectors": usable, "selectors_probed": len(selectors)}
        if revoked:
            evidence["revoked_selectors"] = revoked
        return [
            Finding(
                module=self.name,
                target=host,
                severity="info",
                title="Mail signing keys are published",
                detail=f"Signing keys found under {len(usable)} selector(s).",
                evidence=evidence,
            )
        ]
