"""Subdomain takeover: not "this alias dangles" but "here is who could claim it".

`subdomain_discovery` already reports aliases whose destination returns no
address, and hedges: *if* the destination is a de-provisioned hosting account,
whoever registers that name next can serve content on your domain. That "if" is
the whole finding. It is the difference between a typo in a CNAME — which is
untidy and harmless — and a live path for somebody else to publish on the
client's domain, get a certificate for it, and receive anything sent to it.

This module answers the "if", using only DNS.

Three questions, in order, because each one narrows the next:

1. **Why does the destination not resolve?** NXDOMAIN means the name does not
   exist anywhere and something can be put there. NODATA means it exists and is
   merely missing an address record — untidy, not claimable. A timeout means we
   do not know. `_dns.query` collapses all three to an empty list, which is
   correct for "does this domain publish CAA" and actively misleading here, so
   this module uses `resolution` instead.

2. **Can this resolver's negative answers be believed at all?** Every verdict
   below rests on telling NXDOMAIN from NODATA, and plenty of resolvers do not
   report that faithfully. The one in the sandbox this module was written in
   answers NODATA for names that do not exist, and a zone that wildcards never
   produces NXDOMAIN for anything. Either would quietly turn the finding that
   matters most into "a broken record, not a risk". So before any conclusion is
   drawn about a destination, a random name under the same parent is looked up:
   it cannot exist, so a resolver worth believing must call it NXDOMAIN. When it
   does not, the answer is inconclusive and says why.

3. **What would somebody actually have to claim?** Walk down from the
   destination to the closest enclosing zone that answers SOA. For
   `icit.mynetgear.com` the answer is `mynetgear.com` — the child is what is
   missing, the parent is what serves it.

4. **Is that zone one where names are handed out on request?** A platform that
   gives any signed-up user a name under its domain is a confirmed takeover
   path: the attacker claims the label and inherits the client's subdomain. A
   zone that is nobody's self-service platform is a dangling record whose
   claimability we cannot prove from DNS, and it is reported as exactly that.

And the strongest case of all, which falls out of step 3: when *no* ancestor is
registered, the destination domain itself is available. Whoever registers it
controls the client's subdomain outright.

WHAT THIS MODULE WILL NOT DO. It never attempts to claim, register or reserve
anything. Confirming a takeover by performing one means taking a name on a third
party's service, and that is an action against somebody else's system that needs
a person to decide. Every conclusion here is drawn from read-only lookups, and
the confidence field says plainly where proof stops.
"""

from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from base import Finding, ScanModule

from ._dns import host_of, make_resolver, query, resolution, zone_apex
from .subdomain_discovery import (
    PROBE_NAMES,
    _crtsh_names,
    _default_session,
    coverage_is_full,
    coverage_note,
)

#: Zones that hand a name under them to anyone who asks for it.
#:
#: Each entry is the zone apex a destination would sit under, mapped to what
#: claiming it involves. `open` marks the services where a name is taken by
#: signing up and typing it — no proof of ownership, no payment, no wait — which
#: is what separates a takeover somebody can do this afternoon from one that
#: needs an account with the same provider the client already uses.
#:
#: This list is a floor, not a ceiling. An unlisted zone still produces a
#: dangling finding; it is reported at a lower confidence because the claim
#: mechanism has not been established, not because it is safe.
CLAIMABLE_ZONES: dict[str, dict[str, Any]] = {
    # Dynamic DNS. Free, instant, and the reason this module exists: a name that
    # is NXDOMAIN on one of these is unregistered, and registering it is the
    # entire attack.
    "no-ip.com": {"kind": "dynamic DNS", "open": True},
    "ddns.net": {"kind": "dynamic DNS", "open": True},
    "hopto.org": {"kind": "dynamic DNS", "open": True},
    "zapto.org": {"kind": "dynamic DNS", "open": True},
    "sytes.net": {"kind": "dynamic DNS", "open": True},
    "myftp.org": {"kind": "dynamic DNS", "open": True},
    "myftp.biz": {"kind": "dynamic DNS", "open": True},
    "serveftp.com": {"kind": "dynamic DNS", "open": True},
    "servebeer.com": {"kind": "dynamic DNS", "open": True},
    "serveblog.net": {"kind": "dynamic DNS", "open": True},
    "servegame.com": {"kind": "dynamic DNS", "open": True},
    "redirectme.net": {"kind": "dynamic DNS", "open": True},
    "mynetgear.com": {"kind": "dynamic DNS", "open": True},
    "duckdns.org": {"kind": "dynamic DNS", "open": True},
    "dynu.com": {"kind": "dynamic DNS", "open": True},
    "afraid.org": {"kind": "dynamic DNS", "open": True},
    "chickenkiller.com": {"kind": "dynamic DNS", "open": True},
    "mooo.com": {"kind": "dynamic DNS", "open": True},
    # Static site and app hosting. The name is claimed by creating a project,
    # site or app with that identifier.
    "github.io": {"kind": "static site hosting", "open": True},
    "gitlab.io": {"kind": "static site hosting", "open": True},
    "bitbucket.io": {"kind": "static site hosting", "open": True},
    "netlify.app": {"kind": "static site hosting", "open": True},
    "netlify.com": {"kind": "static site hosting", "open": True},
    "surge.sh": {"kind": "static site hosting", "open": True},
    "pantheonsite.io": {"kind": "managed site hosting", "open": True},
    "webflow.io": {"kind": "site builder", "open": True},
    "readthedocs.io": {"kind": "documentation hosting", "open": True},
    "herokuapp.com": {"kind": "application hosting", "open": True},
    "herokudns.com": {"kind": "application hosting", "open": True},
    "azurewebsites.net": {"kind": "application hosting", "open": True},
    "cloudapp.azure.com": {"kind": "cloud hosting", "open": True},
    "trafficmanager.net": {"kind": "traffic routing", "open": True},
    "blob.core.windows.net": {"kind": "object storage", "open": True},
    "amazonaws.com": {"kind": "object storage", "open": True},
    # Business platforms. Claiming needs an account with that provider, which is
    # a real but larger step than signing up for free dynamic DNS.
    "myshopify.com": {"kind": "commerce platform", "open": False},
    "bigcartel.com": {"kind": "commerce platform", "open": False},
    "statuspage.io": {"kind": "status pages", "open": False},
    "zendesk.com": {"kind": "support desk", "open": False},
    "freshdesk.com": {"kind": "support desk", "open": False},
    "helpjuice.com": {"kind": "knowledge base", "open": False},
    "helpscoutdocs.com": {"kind": "knowledge base", "open": False},
    "uservoice.com": {"kind": "feedback portal", "open": False},
    "createsend.com": {"kind": "email marketing", "open": False},
    "unbouncepages.com": {"kind": "landing pages", "open": False},
    "launchrock.com": {"kind": "landing pages", "open": False},
    "wpengine.com": {"kind": "managed site hosting", "open": False},
    "ghost.io": {"kind": "publishing platform", "open": False},
    "tumblr.com": {"kind": "publishing platform", "open": False},
    "wordpress.com": {"kind": "publishing platform", "open": False},
    "thinkific.com": {"kind": "course platform", "open": False},
    "intercom.help": {"kind": "support content", "open": False},
    "canny.io": {"kind": "feedback portal", "open": False},
    "tilda.ws": {"kind": "site builder", "open": False},
}

#: Labels a person is expected to trust with something. A takeover of `blog` is
#: an embarrassment; a takeover of `vpn`, `sso` or `login` is a credential
#: harvester on a hostname the client's own staff were taught to use, served over
#: a certificate that will validate. That difference is worth a severity step.
TRUSTED_LABELS = frozenset(
    {
        "vpn",
        "sso",
        "login",
        "signin",
        "auth",
        "adfs",
        "okta",
        "admin",
        "secure",
        "portal",
        "remote",
        "mail",
        "webmail",
        "owa",
        "exchange",
        "autodiscover",
        "api",
        "pay",
        "payment",
        "billing",
        "account",
        "accounts",
        "id",
        "vault",
        "citrix",
        "rdp",
        "gateway",
    }
)


def _label_of(fqdn: str, root: str) -> str:
    """The leftmost label of `fqdn` within `root`."""
    if fqdn.endswith("." + root):
        return fqdn[: -(len(root) + 1)].split(".")[0]
    return fqdn.split(".")[0]


def _zone_entry(apex: str) -> dict[str, Any] | None:
    """The claimable-zone entry covering `apex`, if any.

    Matched on the apex *and* its ancestors, because a provider may serve each
    customer region from its own zone (`s3.eu-west-1.amazonaws.com`) while the
    claim mechanism belongs to the parent.
    """
    labels = apex.split(".")
    for cut in range(len(labels)):
        candidate = ".".join(labels[cut:])
        if candidate in CLAIMABLE_ZONES:
            return {"zone": candidate, **CLAIMABLE_ZONES[candidate]}
    return None


class AliasTakeover(ScanModule):
    name = "alias_takeover"
    description = (
        "Checks whether an alias that points nowhere could be claimed by somebody else, "
        "and names what they would have to claim."
    )
    target_kinds = ("domain", "hostname", "url")
    groups = ("standard", "deep", "surface")
    # Recursive resolvers only. No packet reaches the scanned host, and nothing
    # is claimed, registered or reserved anywhere.
    contact = "dns"
    category = "dns"

    def run(self, target: Any, ctx: dict[str, Any]) -> list[Finding]:
        root = host_of(target)
        if not root:
            return []
        res = make_resolver(ctx.get("nameservers"))

        aliases, coverage = self._aliases(root, ctx, res)
        if not aliases:
            return []

        # One control probe per destination zone, shared across the aliases.
        cache: dict[str, bool] = {}
        verdicts = [
            self._verdict(res, fqdn, destination, root, cache) for fqdn, destination in aliases
        ]
        findings = [f for f in (self._finding(v, root) for v in verdicts) if f]

        exposed = [v for v in verdicts if v["verdict"] != "resolves"]
        findings.append(
            Finding(
                module=self.name,
                target=root,
                severity="info",
                category="inventory",
                title="Alias destinations checked",
                detail=(
                    f"{len(aliases)} alias(es) under {root} were followed to their destination; "
                    f"{len(exposed)} did not resolve to an address. Discovery examined "
                    f"{len(ctx['alias_candidates']['names'])} name(s) " + coverage_note(coverage)
                ),
                evidence={"checked": verdicts, "coverage": coverage},
                # A clean result over a reduced surface is not the same claim as
                # a clean result over the full one, and must not read as one.
                confidence="confirmed" if coverage_is_full(coverage) else "possible",
                key="alias destinations checked",
            )
        )
        return findings

    # ── discovery ───────────────────────────────────────────────────────────

    def _aliases(
        self, root: str, ctx: dict[str, Any], res: Any
    ) -> tuple[list[tuple[str, str]], dict[str, Any]]:
        """Every (name, destination) alias pair under the scope root.

        Reuses whatever `subdomain_discovery` already resolved when both modules
        run together — the host list is cached on ctx by whichever runs first, so
        a group scan pays for certificate-transparency and the probe sweep once
        rather than twice. Run bare, this module still does its own discovery: a
        module that only works when another one ran first is not a module.
        """
        cached = ctx.get("alias_candidates")
        if isinstance(cached, dict) and cached.get("root") == root:
            names = cached["names"]
            coverage = cached["coverage"]
        else:
            session = ctx.get("http") or _default_session()
            found_names = {f"{label}.{root}" for label in PROBE_NAMES}
            coverage = {
                "probe_names": len(PROBE_NAMES),
                "certificate_transparency": "not requested",
            }
            if ctx.get("use_certificate_transparency", True):
                found, status = _crtsh_names(session, root)
                found_names |= found
                coverage["certificate_transparency"] = status
                coverage["certificate_transparency_names"] = len(found)
            names = sorted(found_names)
            ctx["alias_candidates"] = {"root": root, "names": names, "coverage": coverage}

        def alias_of(fqdn: str) -> tuple[str, str] | None:
            targets = query(res, fqdn, "CNAME")
            if not targets:
                return None
            return fqdn, targets[0].rstrip(".").lower()

        with ThreadPoolExecutor(max_workers=int(ctx.get("workers", 10))) as pool:
            return [pair for pair in pool.map(alias_of, names) if pair], coverage

    # ── the three questions ─────────────────────────────────────────────────

    def _negatives_are_faithful(self, res: Any, parent: str, cache: dict[str, bool]) -> bool:
        """Does a name that cannot exist under `parent` come back as NXDOMAIN?

        This is the control for the measurement. A random label under the same
        parent is guaranteed absent, so a resolver and zone that report negatives
        honestly must answer NXDOMAIN for it. Anything else means one of two
        things, and both destroy the verdict:

          * the resolver rewrites negative answers (NODATA, a redirect page, an
            address for everything), so NXDOMAIN never arrives and a real
            takeover reads as a merely broken record;
          * the zone wildcards, so every name under it "exists" and the absence
            of the destination cannot be established from DNS at all.

        Cached per parent: one extra lookup per distinct destination zone, not
        one per alias.
        """
        if parent in cache:
            return cache[parent]
        nonce = f"dnsguard-control-{secrets.token_hex(6)}"
        status, _ = resolution(res, f"{nonce}.{parent}", "A")
        cache[parent] = status == "nxdomain"
        return cache[parent]

    def _verdict(
        self, res: Any, fqdn: str, destination: str, root: str, cache: dict[str, bool]
    ) -> dict[str, Any]:
        status, addresses = resolution(res, destination, "A")
        if status == "ok" and addresses:
            return self._row(fqdn, destination, "resolves", addresses=addresses)

        if status == "error":
            # We do not know, and saying so is the only honest option. Reported
            # as inconclusive rather than folded into either a pass or a finding.
            return self._row(fqdn, destination, "unresolved", reason="lookup did not complete")

        parent = destination.split(".", 1)[1] if "." in destination else destination
        trustworthy = self._negatives_are_faithful(res, parent, cache)

        if not trustworthy:
            # The instrument is not reporting absence faithfully, so neither
            # answer below can be earned. This is the case that would otherwise
            # produce a false negative on the most serious finding the module
            # makes, which is why it is checked rather than assumed.
            return self._row(
                fqdn,
                destination,
                "unresolved",
                reason=(
                    f"a name that cannot exist under {parent} was not reported as NXDOMAIN, so "
                    "this resolver's negative answers cannot be told apart"
                ),
            )

        if status == "nodata":
            # The destination exists. Somebody owns it; it just publishes no
            # address. Calling this a takeover would be a false alarm — and the
            # control above is what earns the right to say so.
            return self._row(fqdn, destination, "no_address")

        # NXDOMAIN, from a resolver that has just demonstrated it means it. The
        # destination name is free. What would it cost to take it?
        apex = zone_apex(res, destination)
        if not apex:
            return self._row(fqdn, destination, "unregistered_domain", apex="")

        entry = _zone_entry(apex)
        if entry:
            return self._row(fqdn, destination, "claimable_service", apex=apex, service=entry)
        return self._row(fqdn, destination, "dangling", apex=apex)

    def _row(self, fqdn: str, destination: str, verdict: str, **extra: Any) -> dict[str, Any]:
        return {"host": fqdn, "destination": destination, "verdict": verdict, **extra}

    # ── reporting ───────────────────────────────────────────────────────────

    def _finding(self, v: dict[str, Any], root: str) -> Finding | None:
        verdict = v["verdict"]
        if verdict == "resolves":
            return None

        host, destination = v["host"], v["destination"]
        label = _label_of(host, root)
        trusted = label in TRUSTED_LABELS

        if verdict == "unregistered_domain":
            return self._make(
                v,
                root,
                "critical",
                "confirmed",
                title="An alias points at a domain nobody has registered",
                detail=(
                    f"{host} is an alias for {destination}, and no part of that destination is "
                    "registered. Anyone can register the domain and immediately control what "
                    f"{host} answers — including obtaining a valid certificate for it, because "
                    "certificate authorities will issue to whoever controls the name."
                ),
                remediation=(
                    f"Delete the alias record for {host}. If the destination is still wanted, "
                    "register it before republishing the record."
                ),
            )

        if verdict == "claimable_service":
            service = v["service"]
            open_signup = service["open"]
            return self._make(
                v,
                root,
                "critical" if (open_signup and trusted) else "high",
                "confirmed",
                title="An alias points at a name somebody else can claim",
                detail=(
                    f"{host} is an alias for {destination}, which does not exist. Its parent "
                    f"{service['zone']} is a {service['kind']} service, where names under it are "
                    + (
                        "handed out to whoever asks for them first. Claiming this one takes an "
                        "account and a few minutes"
                    )
                    + (
                        f". {host} is a name staff and clients are taught to trust, so content "
                        "served there would be believed, and a certificate for it would validate."
                        if trusted
                        else ", so an outsider can publish on this hostname."
                    )
                ),
                remediation=(
                    f"Delete the alias record for {host}, or re-claim {destination} on "
                    f"{service['zone']} before somebody else does. Deleting is the safer order."
                ),
            )

        if verdict == "dangling":
            return self._make(
                v,
                root,
                "high" if trusted else "medium",
                "possible",
                title="An alias points at a destination that does not exist",
                detail=(
                    f"{host} is an alias for {destination}, which returns NXDOMAIN. Its parent "
                    f"zone {v['apex']} is registered and is not a service known to hand out names "
                    "on request, so whether an outsider could claim this destination has not been "
                    "established — only that the record leads nowhere and something could be put "
                    "there by whoever controls that zone."
                ),
                remediation=(
                    f"Delete the alias record for {host} unless the destination is about to be "
                    f"recreated. Confirm with the owner of {v['apex']} who can create names there."
                ),
            )

        if verdict == "no_address":
            return self._make(
                v,
                root,
                "low",
                "confirmed",
                title="An alias points at a name with no address",
                detail=(
                    f"{host} is an alias for {destination}, which exists but publishes no address "
                    "record. Requests to this hostname fail. The destination is registered, so "
                    "this is a broken record rather than a takeover risk."
                ),
                remediation=f"Publish an address for {destination}, or remove the alias for {host}.",
            )

        return self._make(
            v,
            root,
            "info",
            "inconclusive",
            title="An alias destination could not be checked",
            detail=(
                f"{host} is an alias for {destination}, and it could not be established whether "
                f"that destination exists: {v.get('reason', 'the lookup did not complete')}. This "
                "is not a pass. The destination may well be claimable by somebody else, and this "
                "check should be repeated from a resolver that reports NXDOMAIN faithfully."
            ),
            remediation=(
                f"Re-run this check against {destination} using a resolver that returns "
                "NXDOMAIN for names that do not exist — pass --nameservers to the scanner. "
                "Until then this alias is unassessed, not clean."
            ),
        )

    def _make(
        self,
        v: dict[str, Any],
        root: str,
        severity: str,
        confidence: str,
        *,
        title: str,
        detail: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            module=self.name,
            target=root,
            asset=v["host"],
            severity=severity,
            confidence=confidence,
            category="dns",
            title=title,
            detail=detail,
            remediation=remediation,
            evidence=v,
            # Keyed on the verdict rather than the title so that a destination
            # moving from "dangling" to "claimable" is the same finding getting
            # worse, while the host staying dangling week after week stays one
            # finding rather than a new one each scan.
            key=f"{v['verdict']}:{v['host']}",
        )
