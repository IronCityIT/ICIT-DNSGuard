"""Hold the line on our own DNS: compare observed aliases to what was recorded.

`exposure.py` does this for what the Firebase projects expose to an
unauthenticated caller. This is the same idea for the other live boundary this
product knows how to measure — the aliases published under domains we own, and
whether any of them could be claimed by somebody else.

The reason it exists is specific. This repository found a claimable takeover on
`vpn.ironcityit.com`, wrote it down, and then had no way to notice if a second
one appeared, or if that one got worse. A finding recorded in a document decays
into folklore; a finding recorded in a file that CI compares against reality does
not.

Same policy as the Firestore baseline, for the same reason: **the known and
recorded state does not fail the build.** A gate that is permanently red for a
condition the author of an unrelated pull request cannot fix is a gate people
learn to click past. Only a posture *worse* than the record fails. An improvement
is reported, loudly, with a prompt to tighten the file so the gain is held.

One thing does not follow that rule. When the verdict is `unresolved` — the
takeover module could not establish whether the destination exists, because the
resolver's negative answers could not be trusted — nothing has been verified, and
reporting a pass would be a lie of exactly the kind this file exists to prevent.
That is its own outcome, and its own exit code.
"""

from __future__ import annotations

from typing import Any

#: Alias postures, best to worst. `unresolved` is deliberately absent: it is not
#: a rung on this ladder but the absence of a measurement, and comparing it
#: against a recorded rung would either invent a regression or hide one.
POSTURES = (
    "resolves",
    "no_address",
    "dangling",
    "claimable_service",
    "unregistered_domain",
)

UNVERIFIED = "unresolved"

#: What each posture means, for the report a person reads.
MEANINGS = {
    "resolves": "the destination resolves to an address",
    "no_address": "the destination exists but publishes no address",
    "dangling": "the destination does not exist; claimability unproven",
    "claimable_service": "the destination does not exist and its parent hands out names",
    "unregistered_domain": "the destination's domain is not registered at all",
}


def rank(posture: str) -> int:
    """Position on the ladder. An unknown posture sorts worst, so a verdict this
    file has not been taught about fails loudly rather than passing quietly."""
    try:
        return POSTURES.index(posture)
    except ValueError:
        return len(POSTURES)


def compare(
    observed: list[dict[str, Any]],
    baseline: dict[str, Any],
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare one domain's observed aliases against its recorded ones.

    `observed` is the `checked` evidence the takeover module emits: one row per
    alias, each with `host`, `destination` and `verdict`.

    `coverage` is what discovery actually examined. It is carried through
    untouched rather than folded into the verdict: a reduced sweep does not make
    any alias worse, but it does mean the gate looked at less than it appears to,
    and whoever reads a green build is entitled to see that.

    Returns regressions, improvements, unverified rows and the unchanged ones,
    each with enough detail to act on without re-running anything.
    """
    recorded = {row["host"]: row for row in baseline.get("aliases", [])}
    seen = {row["host"]: row for row in observed}

    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for host, row in sorted(seen.items()):
        verdict = row["verdict"]
        was = recorded.get(host, {}).get("verdict", "resolves")

        if verdict == UNVERIFIED:
            # Not a rung on the ladder. Nothing was measured, so nothing is
            # concluded — including "fine".
            unverified.append(
                {
                    "host": host,
                    "destination": row.get("destination", ""),
                    "recorded": was,
                    "reason": row.get("reason", "the destination could not be resolved"),
                }
            )
            continue

        entry = {
            "host": host,
            "destination": row.get("destination", ""),
            "recorded": was,
            "observed": verdict,
            "meaning": MEANINGS.get(verdict, verdict),
            "known": host in recorded,
        }
        if rank(verdict) > rank(was):
            regressions.append(entry)
        elif rank(verdict) < rank(was):
            improvements.append(entry)
        else:
            unchanged.append(entry)

    # An alias that was recorded and is now gone entirely is the record having
    # been acted on — the outcome this file is trying to produce.
    for host, row in sorted(recorded.items()):
        if host in seen:
            continue
        if rank(row.get("verdict", "resolves")) > 0:
            improvements.append(
                {
                    "host": host,
                    "destination": row.get("destination", ""),
                    "recorded": row.get("verdict", ""),
                    "observed": "absent",
                    "meaning": "the record is no longer published",
                    "known": True,
                }
            )

    return {
        "domain": baseline.get("domain", ""),
        "coverage": coverage or {},
        "regressions": regressions,
        "improvements": improvements,
        "unverified": unverified,
        "unchanged": unchanged,
        "ok": not regressions and not unverified,
    }


def reduced_coverage(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Domains where discovery saw less than it was asked to.

    Certificate transparency is the half that finds names nobody would guess.
    When it does not answer, the sweep covered conventional names only — so a
    dangling alias on an unconventional name would not have been discovered, and
    a green build over that surface is a smaller claim than it looks.
    """
    return [
        {"domain": result["domain"], "coverage": result["coverage"]}
        for result in results
        if result.get("coverage", {}).get("certificate_transparency") == "unavailable"
    ]


def summarise(results: list[dict[str, Any]], strict_coverage: bool = False) -> dict[str, Any]:
    """Roll several domains' comparisons into one verdict and exit code.

    Exit codes are distinct on purpose. "Something got worse" and "nothing could
    be checked" need different responses from whoever sees the red build, and
    collapsing them would send them looking in the wrong place.

    Reduced coverage is reported always and fails only under `strict_coverage`.
    Failing by default would put a third party's uptime in the path of every
    pull request, and a gate that goes red for reasons unrelated to the change is
    a gate people learn to click past — the failure mode this whole file is
    written against.
    """
    regressions = [r for result in results for r in result["regressions"]]
    unverified = [u for result in results for u in result["unverified"]]
    improvements = [i for result in results for i in result["improvements"]]
    reduced = reduced_coverage(results)

    if regressions:
        code, verdict = 1, "regressed"
    elif unverified:
        code, verdict = 2, "unverified"
    elif reduced and strict_coverage:
        code, verdict = 2, "reduced_coverage"
    else:
        code, verdict = 0, "held"

    return {
        "verdict": verdict,
        "exit_code": code,
        "regressions": regressions,
        "unverified": unverified,
        "improvements": improvements,
        "reduced_coverage": reduced,
        "domains": results,
    }
