"""Policy: what this tenant blocks, allows and watches — and how a change to it
gets from someone's idea to production.

Two halves.

**The lifecycle.** A policy is a sequence of immutable versions. You edit a
draft; you submit it; someone else approves it; it publishes. A version that has
left draft is frozen — its content hash is sealed, and "just tweak it" means a
new draft, because otherwise an approval signs off on something that no longer
exists. Publishing and rolling back are disruptive by definition (they change
what resolves for real users) and go through dnsguard.approvals; a rollback is
recorded as a new version that copies an old one, never as a deletion, so the
history stays append-only and an auditor can see every state the tenant was in.

**The decision engine.** Given a name, the effective ruleset and the indicator
index, decide: allow, block, monitor or redirect — and say why, with the feed
citation attached when a feed is what drove it.

One rule about staleness is enforced here rather than left to the operator: a
match from a stale feed snapshot is degraded from block to monitor. If we have
not been able to refresh a list for days, we do not know it still says what it
said, and that is not a good enough basis for taking a name off the internet for
a client. The decision records that it was degraded, so it shows up rather than
silently weakening protection.
"""

from __future__ import annotations

import builtins
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from .approvals import ApprovalGate
from .audit import AuditLog, digest
from .clock import Clock, iso
from .errors import ConflictError, NotFoundError, ValidationError
from .feeds import IndicatorIndex, normalise
from .store import DocumentStore

POLICY_COLLECTION = "policies"
VERSION_COLLECTION = "policyversions"

ACTIONS = ("block", "allow", "monitor", "redirect")
MATCH_KINDS = ("domain", "wildcard", "category", "feed")

# draft            being edited; mutable
# in_review        submitted, awaiting a decision; frozen
# published        live for anything bound to this policy
# superseded       was published, replaced by a later version
# rolled_back      was published, withdrawn by a rollback
# rejected         reviewed and refused
STATES = ("draft", "in_review", "published", "superseded", "rolled_back", "rejected")
FROZEN_STATES = ("in_review", "published", "superseded", "rolled_back", "rejected")


@dataclass
class Rule:
    """One decision, and the reason it exists.

    `justification` is required for anything that blocks. A blocklist entry with
    no stated reason is unreviewable, and reviewing them is the entire point of
    the approval step.
    """

    action: str
    match_kind: str
    match_value: str
    justification: str = ""
    id: str = ""
    precedence: int = 100
    enabled: bool = True
    redirect_to: str = ""
    source: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValidationError(f"unknown action {self.action!r}; expected {ACTIONS}")
        if self.match_kind not in MATCH_KINDS:
            raise ValidationError(f"unknown match kind {self.match_kind!r}; expected {MATCH_KINDS}")
        if not self.match_value:
            raise ValidationError("a rule must have something to match on")
        if self.action == "block" and not self.justification:
            raise ValidationError(f"a block rule must carry a justification ({self.match_value})")
        if self.action == "redirect" and not self.redirect_to:
            raise ValidationError("a redirect rule must say where it redirects to")
        if self.match_kind in ("domain", "wildcard"):
            self.match_value = normalise(self.match_value)
        if not self.id:
            self.id = f"rule-{uuid.uuid4().hex[:12]}"

    def matches(self, name: str, categories: set[str], feed_ids: set[str]) -> bool:
        if not self.enabled:
            return False
        if self.match_kind == "domain":
            return name == self.match_value
        if self.match_kind == "wildcard":
            bare = self.match_value.removeprefix("*.")
            return name == bare or name.endswith("." + bare)
        if self.match_kind == "category":
            return self.match_value in categories
        return self.match_value in feed_ids

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyVersion:
    tenant_id: str
    policy_id: str
    version: int
    rules: builtins.list[Rule]
    state: str = "draft"
    default_action: str = "allow"
    created_by: str = ""
    created_at: str = ""
    published_at: str = ""
    published_by: str = ""
    approval_id: str = ""
    rollback_of: int = 0
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.policy_id}@{self.version}"

    @property
    def subject(self) -> str:
        """How this version is named in approvals and on the audit chain."""
        return f"policy/{self.key}"

    def content_hash(self) -> str:
        """Covers exactly what a reviewer is signing off: the rules and the
        default. Not the state, not the timestamps."""
        return digest(
            {
                "policy_id": self.policy_id,
                "default_action": self.default_action,
                "rules": [r.to_dict() for r in self.rules],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["rules"] = [r.to_dict() for r in self.rules]
        payload["content_hash"] = self.content_hash()
        return payload

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> PolicyVersion:
        data = dict(document)
        data.pop("content_hash", None)
        data["rules"] = [Rule(**r) for r in data.get("rules", [])]
        return cls(**data)


@dataclass
class Decision:
    """What happened to one name, and why."""

    name: str
    action: str
    reason: str
    rule_id: str = ""
    matched_on: str = ""
    policy_version: int = 0
    provenance: builtins.list[dict[str, Any]] = field(default_factory=list)
    degraded_from: str = ""  # set when staleness weakened the action
    redirect_to: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── the store-backed lifecycle ───────────────────────────────────────────────


@dataclass
class PolicyService:
    store: DocumentStore
    audit: AuditLog
    gate: ApprovalGate
    clock: Clock = field(default_factory=Clock)

    # ── drafting ────────────────────────────────────────────────────────────

    def draft(
        self,
        tenant_id: str,
        policy_id: str,
        actor: str,
        rules: builtins.list[Rule],
        default_action: str = "allow",
        note: str = "",
    ) -> PolicyVersion:
        """Open a new draft, numbered one above the highest version that exists.

        A tenant has at most one open draft per policy: a second call replaces
        the draft's contents rather than stacking drafts nobody can tell apart.
        """
        if default_action not in ("allow", "block", "monitor"):
            raise ValidationError(f"invalid default action {default_action!r}")

        existing = self.versions(tenant_id, policy_id)
        open_draft = next((v for v in existing if v.state == "draft"), None)
        version_number = (
            open_draft.version if open_draft else (existing[-1].version + 1 if existing else 1)
        )

        version = PolicyVersion(
            tenant_id=tenant_id,
            policy_id=policy_id,
            version=version_number,
            rules=list(rules),
            state="draft",
            default_action=default_action,
            created_by=actor,
            created_at=iso(self.clock.now()),
            note=note,
        )
        self.gate.authorise(
            tenant_id, actor, "policy.draft", version.subject, {"hash": version.content_hash()}
        )
        self._save(version)
        return version

    def submit(self, tenant_id: str, policy_id: str, version: int, actor: str) -> PolicyVersion:
        """Freeze a draft for review. After this the content cannot change."""
        record = self.version(tenant_id, policy_id, version)
        if record.state != "draft":
            raise ConflictError(f"{record.key} is {record.state}; only a draft can be submitted")
        if not record.rules:
            raise ValidationError(f"{record.key} has no rules; there is nothing to review")
        record.state = "in_review"
        self.gate.authorise(
            tenant_id, actor, "policy.submit", record.subject, {"hash": record.content_hash()}
        )
        self._save(record)
        return record

    def reject(
        self, tenant_id: str, policy_id: str, version: int, actor: str, reason: str
    ) -> PolicyVersion:
        record = self.version(tenant_id, policy_id, version)
        if record.state != "in_review":
            raise ConflictError(
                f"{record.key} is {record.state}; only a submitted version can be rejected"
            )
        record.state = "rejected"
        record.note = reason
        self.gate.authorise(tenant_id, actor, "policy.reject", record.subject, {"reason": reason})
        self._save(record)
        return record

    # ── the disruptive half ─────────────────────────────────────────────────

    def publish(
        self, tenant_id: str, policy_id: str, version: int, actor: str, approval_id: str = ""
    ) -> PolicyVersion:
        """Make a version live. Disruptive: gated on an approval bound to this
        version's content hash, so a version edited after sign-off cannot ship."""
        record = self.version(tenant_id, policy_id, version)
        if record.state not in ("draft", "in_review"):
            raise ConflictError(f"{record.key} is {record.state} and cannot be published")

        if record.state == "draft":
            record.state = "in_review"
            self._save(record)

        # Raises ApprovalRequiredError when unapproved. Nothing below runs then.
        approval = self.gate.authorise(
            tenant_id,
            actor,
            "policy.publish",
            record.subject,
            {"content_hash": record.content_hash(), "rules": len(record.rules)},
            approval_id=approval_id,
            summary=f"publish {record.key}: {len(record.rules)} rule(s), default {record.default_action}",
        )

        for other in self.versions(tenant_id, policy_id):
            if other.state == "published" and other.version != version:
                other.state = "superseded"
                self._save(other)

        record.state = "published"
        record.published_at = iso(self.clock.now())
        record.published_by = actor
        record.approval_id = approval.id if approval else ""
        self._save(record)
        return record

    def rollback(
        self, tenant_id: str, policy_id: str, to_version: int, actor: str, approval_id: str = ""
    ) -> PolicyVersion:
        """Return to an earlier version by copying it forward as a new one.

        Not by re-publishing the old record: history stays append-only, so the
        chain still shows that the tenant was on the bad version for the window
        it was on it. That is the fact an incident review needs.
        """
        source = self.version(tenant_id, policy_id, to_version)
        if source.state not in ("published", "superseded", "rolled_back"):
            raise ConflictError(
                f"{source.key} was never published; there is nothing to roll back to"
            )

        current = self.published(tenant_id, policy_id)
        existing = self.versions(tenant_id, policy_id)
        new_version = PolicyVersion(
            tenant_id=tenant_id,
            policy_id=policy_id,
            version=existing[-1].version + 1,
            rules=[Rule(**r.to_dict()) for r in source.rules],
            state="in_review",
            default_action=source.default_action,
            created_by=actor,
            created_at=iso(self.clock.now()),
            rollback_of=to_version,
            note=f"rollback to version {to_version}",
        )

        approval = self.gate.authorise(
            tenant_id,
            actor,
            "policy.rollback",
            new_version.subject,
            {"content_hash": new_version.content_hash(), "rollback_of": to_version},
            approval_id=approval_id,
            summary=f"roll {policy_id} back to version {to_version}",
        )

        if current is not None:
            current.state = "rolled_back"
            self._save(current)

        new_version.state = "published"
        new_version.published_at = iso(self.clock.now())
        new_version.published_by = actor
        new_version.approval_id = approval.id if approval else ""
        self._save(new_version)
        return new_version

    # ── queries ─────────────────────────────────────────────────────────────

    def versions(self, tenant_id: str, policy_id: str) -> builtins.list[PolicyVersion]:
        found = [
            PolicyVersion.from_dict(d)
            for d in self.store.list(tenant_id, VERSION_COLLECTION)
            if d.get("policy_id") == policy_id
        ]
        return sorted(found, key=lambda v: v.version)

    def version(self, tenant_id: str, policy_id: str, version: int) -> PolicyVersion:
        document = self.store.get(tenant_id, VERSION_COLLECTION, f"{policy_id}.{version}")
        if document is None:
            raise NotFoundError(f"policy {policy_id} has no version {version}")
        return PolicyVersion.from_dict(document)

    def published(self, tenant_id: str, policy_id: str) -> PolicyVersion | None:
        return next(
            (v for v in self.versions(tenant_id, policy_id) if v.state == "published"), None
        )

    def policies(self, tenant_id: str) -> builtins.list[str]:
        return sorted({d["policy_id"] for d in self.store.list(tenant_id, VERSION_COLLECTION)})

    def history(self, tenant_id: str, policy_id: str) -> builtins.list[dict[str, Any]]:
        """The lifecycle, flattened for the dashboard's timeline."""
        return [
            {
                "version": v.version,
                "state": v.state,
                "rules": len(v.rules),
                "content_hash": v.content_hash(),
                "created_by": v.created_by,
                "created_at": v.created_at,
                "published_by": v.published_by,
                "published_at": v.published_at,
                "approval_id": v.approval_id,
                "rollback_of": v.rollback_of,
                "note": v.note,
            }
            for v in self.versions(tenant_id, policy_id)
        ]

    def _save(self, version: PolicyVersion) -> None:
        if version.state in FROZEN_STATES:
            stored = self.store.get(
                version.tenant_id, VERSION_COLLECTION, f"{version.policy_id}.{version.version}"
            )
            # State transitions are allowed on a frozen version; content is not.
            if (
                stored is not None
                and stored.get("state") in FROZEN_STATES
                and stored.get("content_hash") != version.content_hash()
            ):
                raise ConflictError(
                    f"{version.key} is {stored['state']} and its content cannot be changed; "
                    "open a new draft instead"
                )
        self.store.put(
            version.tenant_id,
            VERSION_COLLECTION,
            f"{version.policy_id}.{version.version}",
            version.to_dict(),
        )


# ── the decision engine ──────────────────────────────────────────────────────


def evaluate(
    name: str,
    version: PolicyVersion,
    index: IndicatorIndex | None = None,
    allow_stale_blocks: bool = False,
) -> Decision:
    """Decide what happens to one name under one policy version.

    Rules are evaluated in precedence order, lowest number first; ties keep the
    order they were written in. First match wins, which is the only ordering
    semantics an operator can reason about without a truth table.
    """
    query = normalise(name)
    matches = index.lookup(query) if index is not None else []
    categories = {m.indicator.category for m in matches}
    feed_ids = {m.indicator.feed_id for m in matches}
    citations = [m.provenance() for m in matches]

    for rule in sorted(version.rules, key=lambda r: r.precedence):
        if not rule.matches(query, categories, feed_ids):
            continue

        relevant = [
            m
            for m in matches
            if (rule.match_kind == "category" and m.indicator.category == rule.match_value)
            or (rule.match_kind == "feed" and m.indicator.feed_id == rule.match_value)
        ]
        provenance = [m.provenance() for m in relevant] if relevant else []

        action = rule.action
        degraded_from = ""
        # Staleness only degrades decisions that a feed actually drove. An
        # explicit "block payroll-phish.example" written by a human is not
        # weakened because some unrelated feed went stale.
        if (
            action == "block"
            and rule.match_kind in ("category", "feed")
            and relevant
            and all(m.stale for m in relevant)
            and not allow_stale_blocks
        ):
            action = "monitor"
            degraded_from = "block"

        reason = _reason(rule, action, degraded_from)
        return Decision(
            name=query,
            action=action,
            reason=reason,
            rule_id=rule.id,
            matched_on=f"{rule.match_kind}:{rule.match_value}",
            policy_version=version.version,
            provenance=provenance,
            degraded_from=degraded_from,
            redirect_to=rule.redirect_to if action == "redirect" else "",
        )

    return Decision(
        name=query,
        action=version.default_action,
        reason=f"no rule matched; policy default is {version.default_action}",
        policy_version=version.version,
        provenance=citations if version.default_action != "allow" else [],
    )


def _reason(rule: Rule, action: str, degraded_from: str) -> str:
    if degraded_from:
        return (
            f"matched {rule.match_kind} {rule.match_value}, but every supporting feed "
            "snapshot is stale — recorded for review instead of blocked"
        )
    detail = rule.justification or f"matched {rule.match_kind} {rule.match_value}"
    return f"{action}: {detail}"
