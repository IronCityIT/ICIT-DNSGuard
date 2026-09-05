"""Analytics over what the product actually did, and over what it found.

Two distinct things get measured and they answer different questions:

  Query analytics  — the resolver decision stream. "What did we block last week,
                     which site, which feed drove it, and is that going up?"
  Posture scoring  — the scan findings. "How exposed is this domain, and what
                     are the three things worth fixing first?"

Both are pure functions over data. Nothing here reads a store or a clock of its
own, so the same code serves the API, the dashboard, a scheduled report and a
test, and every number is reproducible from the events that produced it.

Posture scoring is the analyzer's grade / risk score / executive summary /
quick-wins output, re-housed. The weights are unchanged; what changed is that it
now derives from findings rather than from a monolith's internal state, so it
works over any subset of modules the operator chose to run.
"""

from __future__ import annotations

import builtins
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from .clock import parse_iso

# ── the decision stream ──────────────────────────────────────────────────────


@dataclass
class QueryEvent:
    """One resolution decision. The unit of everything on the analytics page."""

    timestamp: str
    tenant_id: str
    site_id: str
    name: str
    action: str
    qtype: str = "A"
    rule_id: str = ""
    matched_on: str = ""
    feed_id: str = ""
    category: str = ""
    degraded_from: str = ""
    # Never the client IP itself: an identifier the tenant can correlate and we
    # cannot reverse. Analytics does not need to know who asked.
    client_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def event_from_decision(
    decision: Any,
    tenant_id: str,
    site_id: str,
    timestamp: str,
    qtype: str = "A",
    client_key: str = "",
) -> QueryEvent:
    """Turn a policy Decision into an analytics event, keeping the feed and
    category that drove it so the stream can be sliced by provenance later."""
    citation = decision.provenance[0] if decision.provenance else {}
    return QueryEvent(
        timestamp=timestamp,
        tenant_id=tenant_id,
        site_id=site_id,
        name=decision.name,
        action=decision.action,
        qtype=qtype,
        rule_id=decision.rule_id,
        matched_on=decision.matched_on,
        feed_id=str(citation.get("feed_id", "")),
        category=str(citation.get("category", "")),
        degraded_from=decision.degraded_from,
        client_key=client_key,
    )


def summarise(events: builtins.list[QueryEvent], top: int = 10) -> dict[str, Any]:
    """Everything the analytics page needs, in one pass over the stream."""
    total = len(events)
    by_action: Counter[str] = Counter(e.action for e in events)
    blocked = [e for e in events if e.action == "block"]
    monitored = [e for e in events if e.action == "monitor"]

    return {
        "total_queries": total,
        "by_action": dict(by_action),
        "blocked": len(blocked),
        "monitored": len(monitored),
        "block_rate": round(len(blocked) / total, 4) if total else 0.0,
        # What monitor mode and staleness are suppressing. An operator needs to
        # see this number before they turn enforcement on.
        "would_block": sum(1 for e in events if e.degraded_from in ("block", "redirect")),
        "unique_names": len({e.name for e in events}),
        "unique_blocked_names": len({e.name for e in blocked}),
        "top_blocked_names": _top(blocked, lambda e: e.name, top),
        "top_categories": _top(blocked, lambda e: e.category or "uncategorised", top),
        "top_feeds": _top([e for e in blocked if e.feed_id], lambda e: e.feed_id, top),
        "by_site": _top(events, lambda e: e.site_id, top),
        "blocked_by_site": _top(blocked, lambda e: e.site_id, top),
    }


def timeseries(
    events: builtins.list[QueryEvent],
    bucket_seconds: int = 3600,
    actions: tuple[str, ...] = ("block",),
) -> builtins.list[dict[str, Any]]:
    """Counts per fixed-width bucket, ordered, with empty buckets included.

    Empty buckets matter: a gap that is silently skipped reads on a chart as a
    quiet period rather than as an outage in the collector.
    """
    if not events or bucket_seconds <= 0:
        return []

    stamps = sorted(parse_iso(e.timestamp).timestamp() for e in events)
    first = int(stamps[0] // bucket_seconds * bucket_seconds)
    last = int(stamps[-1] // bucket_seconds * bucket_seconds)

    counts: dict[int, Counter[str]] = defaultdict(Counter)
    for event in events:
        bucket = int(parse_iso(event.timestamp).timestamp() // bucket_seconds * bucket_seconds)
        counts[bucket][event.action] += 1
        counts[bucket]["total"] += 1

    out = []
    bucket = first
    while bucket <= last:
        row: dict[str, Any] = {"bucket_start": bucket, "total": counts[bucket]["total"]}
        for action in actions:
            row[action] = counts[bucket][action]
        out.append(row)
        bucket += bucket_seconds
    return out


def _top(events: builtins.list[QueryEvent], key: Any, limit: int) -> builtins.list[dict[str, Any]]:
    counter: Counter[str] = Counter(key(e) for e in events)
    return [{"key": k, "count": c} for k, c in counter.most_common(limit)]


# ── posture scoring ──────────────────────────────────────────────────────────

# Severity -> how much risk it adds. Unchanged from the previous analyzer.
SEVERITY_RISK = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}

# What a clean result in each area is worth. Also unchanged: SPF 40 (30 + 10 for
# a hard fail), DKIM 30, DMARC 30 (20 + up to 10 for enforcement).
EMAIL_WEIGHTS = {"spf_audit": 40, "dkim_audit": 30, "dmarc_audit": 30}

GRADES = ((90, "A+"), (80, "A"), (70, "B"), (60, "C"), (40, "D"), (0, "F"))
RISK_LEVELS = ((80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "minimal"))


@dataclass
class Posture:
    email_score: int
    email_grade: str
    risk_score: int
    risk_level: str
    findings_by_severity: dict[str, int]
    executive_summary: str
    quick_wins: builtins.list[str] = field(default_factory=list)
    modules_run: builtins.list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score(findings: builtins.list[Any], domain: str = "") -> Posture:
    """Grade the email posture and the overall risk from a set of findings.

    Only modules that actually ran are scored. Running just the DMARC check and
    getting an F because SPF was never looked at would be a lie, so the email
    score is normalised over the weights of the modules present.
    """
    by_severity: Counter[str] = Counter(f.severity for f in findings)
    modules = sorted({f.module for f in findings})

    available = {m: w for m, w in EMAIL_WEIGHTS.items() if m in modules}
    if available:
        earned = 0.0
        for module, weight in available.items():
            worst = _worst_severity([f for f in findings if f.module == module])
            earned += weight * _credit(worst)
        email_score = round(earned / sum(available.values()) * 100)
    else:
        email_score = 0

    risk = 0 if not available else 100 - email_score
    for severity, count in by_severity.items():
        risk += SEVERITY_RISK.get(severity, 0) * count
    risk = max(0, min(100, risk))

    grade = next(g for threshold, g in GRADES if email_score >= threshold)
    level = next(lv for threshold, lv in RISK_LEVELS if risk >= threshold)

    return Posture(
        email_score=email_score,
        email_grade=grade,
        risk_score=risk,
        risk_level=level,
        findings_by_severity={
            s: by_severity.get(s, 0) for s in ("critical", "high", "medium", "low", "info")
        },
        executive_summary=_summary(domain, grade, risk, level, by_severity, bool(available)),
        quick_wins=_quick_wins(findings),
        modules_run=modules,
    )


def _worst_severity(findings: builtins.list[Any]) -> str:
    order = ("info", "low", "medium", "high", "critical")
    worst = "info"
    for finding in findings:
        if order.index(finding.severity) > order.index(worst):
            worst = finding.severity
    return worst


def _credit(worst: str) -> float:
    """How much of a module's weight survives its worst finding."""
    return {"info": 1.0, "low": 0.75, "medium": 0.5, "high": 0.0, "critical": 0.0}[worst]


def _summary(
    domain: str, grade: str, risk: int, level: str, by_severity: Counter[str], scored_email: bool
) -> str:
    subject = domain or "this domain"
    urgent = by_severity.get("critical", 0) + by_severity.get("high", 0)

    if not scored_email:
        return (
            f"{urgent} issue(s) needing attention were found for {subject}. "
            f"Overall risk is {level} ({risk}/100). Email authentication was not "
            "assessed in this scan."
        )
    if grade in ("A+", "A"):
        return (
            f"Email security for {subject} is strong ({grade}). Mail should reach "
            f"recipients reliably and the domain is well defended against impersonation. "
            f"Overall risk is {level} ({risk}/100)."
        )
    if grade == "B":
        return (
            f"Email security for {subject} is good ({grade}) with room to improve. "
            f"{urgent} issue(s) are worth addressing. Overall risk is {level} ({risk}/100)."
        )
    if grade == "C":
        return (
            f"Email security for {subject} needs attention ({grade}). Some mail is "
            f"likely being filtered as spam and the domain can be impersonated. "
            f"Overall risk is {level} ({risk}/100)."
        )
    return (
        f"Email security for {subject} needs immediate attention ({grade}). Mail is "
        f"likely being filtered and anyone can send mail claiming to be this domain. "
        f"{urgent} issue(s) are urgent. Overall risk is {level} ({risk}/100)."
    )


def _quick_wins(findings: builtins.list[Any], limit: int = 3) -> builtins.list[str]:
    """The highest-severity findings that come with a concrete remediation."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(findings, key=lambda f: order.get(f.severity, 9))
    wins = []
    for finding in ranked:
        remediation = (finding.evidence or {}).get("remediation")
        if remediation and remediation not in wins:
            wins.append(remediation)
        if len(wins) == limit:
            break
    return wins
