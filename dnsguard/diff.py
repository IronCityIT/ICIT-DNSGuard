"""What changed between two scans.

Storing scans is an archive. Comparing them is the product: "your posture got
worse this week" is the sentence a client acts on, and "these three are fixed" is
the one that shows the work was worth paying for. Neither is available from a
list of reports.

## Why this is fingerprint-keyed, and not title-keyed

`Finding.fingerprint()` already exists and is deliberately built from
`(module, target, asset, key or title)` — **excluding severity, detail and
evidence**. That exclusion is the whole mechanism here. A certificate that slips
from "expires in 30 days" (medium) to "expires in 5 days" (high) is *the same
finding getting worse*, and comparing on the whole row would report it as one
problem resolved and a different one appearing. The client would see churn where
there is a deterioration.

So findings are matched on fingerprint, and severity movement within a match is a
first-class outcome rather than a new finding.

## Five outcomes, because "changed" is not actionable

  new         absent before, present now
  resolved    present before, absent now
  worsened    same finding, higher severity
  improved    same finding, lower severity
  unchanged   same finding, same severity

A first scan is reported as a **baseline** rather than as a page of new problems.
Every finding on a first scan is technically new, and saying so turns "here is
where you stand" into "twenty-three things just broke", which is both alarming
and false.

## Confidence is carried, not compared

A finding that moves from `possible` to `confirmed` has not changed — what we
know about it has. Treating that as a deterioration would report the scanner
getting better as the client getting worse. Both values are carried on the row so
a reader can see it, and neither drives the outcome.
"""

from __future__ import annotations

import builtins
import hashlib
from dataclasses import dataclass, field
from typing import Any

#: Worst last, matching module_framework.base.SEVERITIES. Duplicated rather than
#: imported: the control plane does not import the scan framework, and a report
#: that arrived from an older scanner still has to be comparable.
SEVERITIES = ("info", "low", "medium", "high", "critical")

OUTCOMES = ("new", "resolved", "worsened", "improved", "unchanged")


def severity_rank(severity: str) -> int:
    try:
        return SEVERITIES.index(str(severity).lower())
    except ValueError:
        return 0


def fingerprint_of(row: dict[str, Any]) -> str:
    """The row's fingerprint, or one derived the same way if it has none.

    Reports stored before the fingerprint reached the client row still have to be
    comparable, so the fallback rebuilds it from the same fields rather than
    refusing to compare — an older report should produce a slightly weaker diff,
    not no diff at all.
    """
    existing = str(row.get("fingerprint", "") or "")
    if existing:
        return existing
    identity = " ".join(
        str(row.get(field, "")).strip().lower() for field in ("module", "target", "asset", "title")
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


@dataclass
class Change:
    """One finding's movement between two scans."""

    outcome: str
    fingerprint: str
    title: str
    asset: str
    severity: str
    previous_severity: str = ""
    category: str = ""
    confidence: str = ""
    previous_confidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "asset": self.asset,
            "severity": self.severity,
            "previous_severity": self.previous_severity,
            "category": self.category,
            "confidence": self.confidence,
            "previous_confidence": self.previous_confidence,
            "remediation": self.remediation,
        }


@dataclass
class Comparison:
    """Two scans, and what moved between them."""

    changes: builtins.list[Change] = field(default_factory=list)
    baseline: bool = False
    previous_scan_id: str = ""
    current_scan_id: str = ""

    def of(self, outcome: str) -> builtins.list[Change]:
        return [c for c in self.changes if c.outcome == outcome]

    @property
    def regressed(self) -> bool:
        """Did anything get worse? The one question a scheduled comparison is
        actually asking."""
        return bool(self.of("new") or self.of("worsened"))

    def summary(self) -> dict[str, int]:
        return {outcome: len(self.of(outcome)) for outcome in OUTCOMES}

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "previous_scan_id": self.previous_scan_id,
            "current_scan_id": self.current_scan_id,
            "regressed": self.regressed,
            "summary": self.summary(),
            "changes": [c.to_dict() for c in self.changes],
        }


def _change(outcome: str, row: dict[str, Any], previous: dict[str, Any] | None = None) -> Change:
    return Change(
        outcome=outcome,
        fingerprint=fingerprint_of(row),
        title=str(row.get("title", "")),
        asset=str(row.get("asset", "") or row.get("target", "")),
        severity=str(row.get("severity", "info")),
        previous_severity=str(previous.get("severity", "")) if previous else "",
        category=str(row.get("category", "")),
        confidence=str(row.get("confidence", "")),
        previous_confidence=str(previous.get("confidence", "")) if previous else "",
        remediation=str(row.get("remediation", "")),
    )


def compare(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> Comparison:
    """Compare two stored scan documents.

    `previous` may be None, which is the first scan for a target. That is
    reported as a baseline rather than as a page of new problems.
    """
    current_rows = {fingerprint_of(r): r for r in current.get("findings") or []}
    current_id = str(current.get("scan_id", ""))

    if previous is None:
        return Comparison(
            changes=[_change("new", row) for row in current_rows.values()],
            baseline=True,
            current_scan_id=current_id,
        )

    previous_rows = {fingerprint_of(r): r for r in previous.get("findings") or []}
    changes: builtins.list[Change] = []

    for key, row in current_rows.items():
        was = previous_rows.get(key)
        if was is None:
            changes.append(_change("new", row))
            continue
        now_rank, was_rank = (
            severity_rank(row.get("severity", "")),
            severity_rank(was.get("severity", "")),
        )
        if now_rank > was_rank:
            changes.append(_change("worsened", row, was))
        elif now_rank < was_rank:
            changes.append(_change("improved", row, was))
        else:
            changes.append(_change("unchanged", row, was))

    for key, row in previous_rows.items():
        if key not in current_rows:
            changes.append(_change("resolved", row, row))

    # Worst first, then by outcome, so the thing to act on is at the top rather
    # than wherever the scan happened to emit it.
    order = {
        name: index
        for index, name in enumerate(("worsened", "new", "resolved", "improved", "unchanged"))
    }
    changes.sort(key=lambda c: (order.get(c.outcome, 99), -severity_rank(c.severity), c.title))

    return Comparison(
        changes=changes,
        baseline=False,
        previous_scan_id=str(previous.get("scan_id", "")),
        current_scan_id=current_id,
    )
