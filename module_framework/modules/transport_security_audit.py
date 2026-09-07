"""MTA-STS and TLS-RPT: is mail to this domain protected in transit, and is
failure to protect it reported?

## Why this module fetches something

MTA-STS (RFC 8461) has two halves, and the DNS half is only a pointer. The TXT
record at `_mta-sts.<domain>` carries a version and an id — nothing else. The
policy that actually decides anything lives at

    https://mta-sts.<domain>/.well-known/mta-sts.txt

and it is that file which says `mode: enforce`, `mode: testing` or `mode: none`.

This module previously reported "Encrypted mail transport is enforced and
reported" on the strength of the TXT record alone. That is wrong in three
separate ways, all of them in the reassuring direction:

  * **A domain in `mode: testing` was reported as enforced.** Testing is the
    rollout stage where a sender reports failures and delivers anyway — the
    domain is not protected, which is the entire point of the mode.
  * **A domain in `mode: none` was reported as enforced.** That mode exists to
    switch MTA-STS off; the record is advertising an opt-out.
  * **A domain publishing the record with no policy file was reported as
    enforced.** A sender fetches the policy, fails, and falls back to
    opportunistic TLS — so the record does nothing at all.

It is the same mistake the DNSSEC module made and had corrected: reporting a
mechanism as working because one visible half of it is present. Here, unusually,
the half that is easy to see is the half that decides nothing.

The fetch is injected (`ctx["http"]`), so no test touches the network.
"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._dns import find_txt, host_of, make_resolver

POLICY_PATH = "/.well-known/mta-sts.txt"

#: RFC 8461 §3.2. `enforce` is the only one that protects anything.
MODES = ("enforce", "testing", "none")

#: A policy shorter-lived than a day means a sender that cannot reach the policy
#: host for a day stops enforcing. RFC 8461 recommends weeks.
SHORT_MAX_AGE = 86400

#: Bounded because this is a fetch from a host named by the scanned domain. A
#: policy file is a few hundred bytes; anything larger is not one.
MAX_POLICY_BYTES = 64 * 1024
FETCH_TIMEOUT = 10.0


def parse_policy(text: str) -> dict[str, Any]:
    """Parse an MTA-STS policy file into its fields.

    Line-oriented `key: value`, with `mx` repeated. Unknown keys are kept rather
    than dropped: a policy carrying something this parser has not been taught
    about is still evidence, and silently discarding it would make the report
    look more certain than the data.
    """
    policy: dict[str, Any] = {"mx": []}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            policy["mx"].append(value)
        else:
            policy[key] = value
    return policy


def fetch_policy(session: Any, host: str) -> tuple[str, str]:
    """Retrieve the policy. Returns (status, body).

    status is `ok`, `missing` (the server answered, but not with a policy) or
    `error` (we could not find out). The third is deliberately distinct: a
    timeout is not evidence that a domain is unprotected, and reporting it as
    one would manufacture findings out of our own connectivity.
    """
    url = f"https://mta-sts.{host}{POLICY_PATH}"
    try:
        response = session.get(url, timeout=FETCH_TIMEOUT)
    except Exception:
        return "error", ""
    status = int(getattr(response, "status_code", 0))
    if status != 200:
        return "missing", ""
    body = getattr(response, "text", "") or ""
    return "ok", body[:MAX_POLICY_BYTES]


def _default_session() -> Any:
    import requests

    session = requests.Session()
    session.headers.update({"User-Agent": "IronCity-DNSGuard/1.0"})
    return session


class TransportSecurityAudit(ScanModule):
    name = "transport_security_audit"
    description = (
        "Checks whether inbound mail is required to use encrypted transport, "
        "whether that requirement is actually in force, and whether failures are reported."
    )
    target_kinds = ("domain", "hostname", "url")
    groups = ("deep", "email")
    category = "email"

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        host = host_of(target)
        if not host:
            return []
        res = make_resolver(ctx.get("nameservers"))
        mta_sts = find_txt(res, f"_mta-sts.{host}", "v=STSv1")
        tls_rpt = find_txt(res, f"_smtp._tls.{host}", "v=TLSRPTv1")

        findings: list[Finding] = []
        findings.extend(self._mta_sts(host, mta_sts, ctx))
        if not tls_rpt:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    category="email",
                    title="Mail transport failures are not reported",
                    detail=(
                        "No TLS-RPT record is published, so failures to negotiate encrypted "
                        "transport go unnoticed."
                    ),
                    remediation="Publish a _smtp._tls TXT record pointing at a monitored mailbox.",
                )
            )
        return findings

    def _mta_sts(self, host: str, record: str, ctx: dict[str, Any]) -> list[Finding]:
        if not record:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    category="email",
                    title="Encrypted mail transport is not enforced",
                    detail=(
                        "No MTA-STS policy is published, so a network attacker can strip "
                        "encryption from mail sent to this domain and read it in transit."
                    ),
                    remediation=(
                        "Publish an MTA-STS policy and the _mta-sts TXT record, starting in "
                        "testing mode."
                    ),
                )
            ]

        session = ctx.get("http") or _default_session()
        status, body = fetch_policy(session, host)
        evidence: dict[str, Any] = {"record": record, "policy_status": status}

        if status == "error":
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="info",
                    category="email",
                    confidence="inconclusive",
                    title="Whether encrypted mail transport is enforced could not be established",
                    detail=(
                        f"An MTA-STS record is published, but the policy at "
                        f"https://mta-sts.{host}{POLICY_PATH} could not be retrieved. The record "
                        "alone does not enforce anything — the policy is what carries the mode — "
                        "so this is unassessed rather than clean."
                    ),
                    remediation=(
                        f"Re-run this check from a host that can reach mta-sts.{host}, and "
                        "confirm the policy is served over valid HTTPS."
                    ),
                    evidence=evidence,
                )
            ]

        if status == "missing":
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="medium",
                    category="email",
                    title="An MTA-STS policy is advertised but not published",
                    detail=(
                        f"The _mta-sts record tells senders a policy exists, but nothing is "
                        f"served at https://mta-sts.{host}{POLICY_PATH}. A sender fetches the "
                        "policy, fails, and falls back to unprotected delivery — so the record "
                        "provides no protection while appearing to."
                    ),
                    remediation=(
                        f"Serve the policy file at https://mta-sts.{host}{POLICY_PATH} over "
                        "valid HTTPS, or remove the _mta-sts record so senders stop trying."
                    ),
                    evidence=evidence,
                )
            ]

        policy = parse_policy(body)
        mode = str(policy.get("mode", "")).lower()
        evidence["mode"] = mode
        evidence["mx"] = policy.get("mx", [])
        evidence["max_age"] = policy.get("max_age", "")

        if mode not in MODES:
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="medium",
                    category="email",
                    title="The MTA-STS policy does not state a usable mode",
                    detail=(
                        f"The policy was retrieved but its mode is {mode or 'absent'!r}, which is "
                        "not one of enforce, testing or none. A sender that cannot parse the "
                        "policy applies none of it."
                    ),
                    remediation="Correct the policy file to declare mode: enforce.",
                    evidence=evidence,
                )
            ]

        if mode == "none":
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    category="email",
                    title="Encrypted mail transport is explicitly switched off",
                    detail=(
                        "The MTA-STS policy is published with mode: none, which tells senders "
                        "not to apply it. Mail to this domain is delivered with opportunistic "
                        "TLS, which an attacker on the network path can strip."
                    ),
                    remediation="Move the policy to mode: testing, then to mode: enforce.",
                    evidence=evidence,
                )
            ]

        if mode == "testing":
            return [
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    category="email",
                    title="Encrypted mail transport is published but not yet enforced",
                    detail=(
                        "The MTA-STS policy is in mode: testing. Senders report failures and "
                        "deliver anyway, so mail can still be downgraded and read in transit. "
                        "This is the correct rollout stage — it is not the finished state, and "
                        "a domain can sit in it for years without anyone noticing."
                    ),
                    remediation=(
                        "Review the TLS-RPT reports, then move the policy to mode: enforce."
                    ),
                    evidence=evidence,
                )
            ]

        findings = [
            Finding(
                module=self.name,
                target=host,
                severity="info",
                category="email",
                title="Encrypted mail transport is enforced",
                detail=(
                    "An MTA-STS policy is published in mode: enforce, so a sender that cannot "
                    "negotiate authenticated TLS to a listed host will not deliver at all."
                ),
                evidence=evidence,
            )
        ]

        max_age = str(policy.get("max_age", "")).strip()
        if max_age.isdigit() and int(max_age) < SHORT_MAX_AGE:
            findings.append(
                Finding(
                    module=self.name,
                    target=host,
                    severity="low",
                    category="email",
                    title="The MTA-STS policy expires quickly",
                    detail=(
                        f"max_age is {max_age} seconds. A sender caches the policy for that long, "
                        "so an attacker who can keep the policy host unreachable for slightly "
                        "longer returns the domain to unprotected delivery."
                    ),
                    remediation="Raise max_age to at least a few weeks once the policy is stable.",
                    evidence=evidence,
                )
            )
        return findings
