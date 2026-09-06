"""The periodic loop the control plane needs to stay correct.

Everything else in this package reacts to a request. Three things do not, and
without something running them the product decays quietly rather than loudly:

  * **Feeds go stale.** A snapshot that is not refreshed stops being able to
    justify a block. That is the designed behaviour, but only if something is
    actually attempting the refresh — otherwise every feed drifts into staleness
    and protection weakens with no event marking it.
  * **Exceptions lapse.** `active()` already applies expiry on read, so a lapsed
    exception stops working immediately. The sweep is what writes that down, so
    the audit chain shows *when* the hole closed rather than leaving a record
    that says "active" forever.
  * **Alerts only exist when something evaluates them.** A rule that nothing runs
    is a rule that never fires.

Deliberately not disruptive. Every action here either refreshes data, records an
expiry the tenant already agreed to, or raises an alert — none of which changes
what resolves, so none needs approval. Anything that *would* change resolution
stays behind the gate where an operator has to ask for it.

One failing tenant does not stop the others, and one failing feed does not stop
the tenant: this runs unattended, and a loop that aborts on the first error
leaves the rest of the fleet unmaintained without saying so.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass, field
from typing import Any

from .alerts import AlertService, compute_metrics
from .analytics import QueryEvent
from .approvals import ApprovalGate
from .audit import AuditLog
from .clock import Clock
from .exceptions_policy import ExceptionService
from .feeds import FeedFetcher, FeedRegistry


@dataclass
class MaintenanceRunner:
    registry: FeedRegistry
    fetcher: FeedFetcher | None
    exceptions: ExceptionService
    alerts: AlertService
    gate: ApprovalGate
    audit: AuditLog
    clock: Clock = field(default_factory=Clock)
    expiry_horizon_days: int = 30

    def run(
        self, tenant_id: str, events: builtins.list[QueryEvent] | None = None
    ) -> dict[str, Any]:
        """One maintenance pass for one tenant. Never raises for a tenant-level
        problem — the report says what failed."""
        report: dict[str, Any] = {"tenant_id": tenant_id, "errors": []}

        report["feeds"] = self._refresh_feeds(tenant_id, report)
        report["expired_exceptions"] = self._sweep(tenant_id, report)
        report["alerts"] = self._evaluate(tenant_id, events or [], report)
        report["audit_chain"] = self.audit.verify(tenant_id)

        # A broken chain is the one condition worth shouting about from a
        # background job: it means the record of everything above cannot be
        # trusted, and no amount of successful refreshing makes up for that.
        if not report["audit_chain"]["valid"]:
            report["errors"].append(
                f"audit chain broken at record {report['audit_chain']['broken_at']}: "
                f"{report['audit_chain']['reason']}"
            )

        report["ok"] = not report["errors"]
        return report

    def run_all(
        self, tenant_ids: builtins.list[str] | None = None
    ) -> builtins.list[dict[str, Any]]:
        """Every tenant. One tenant's failure does not abort the pass."""
        targets = tenant_ids if tenant_ids is not None else self.registry.store.tenants()
        out = []
        for tenant_id in targets:
            try:
                out.append(self.run(tenant_id))
            except Exception as exc:  # noqa: BLE001 - unattended; keep going
                out.append({"tenant_id": tenant_id, "ok": False, "errors": [str(exc)]})
        return out

    # ── steps ───────────────────────────────────────────────────────────────

    def _refresh_feeds(self, tenant_id: str, report: dict[str, Any]) -> dict[str, Any]:
        if self.fetcher is None:
            # An explicit, visible skip. A maintenance report that silently
            # omitted feeds would read as "feeds are fine".
            return {"attempted": False, "reason": "no fetcher configured"}

        try:
            result = self.fetcher.refresh_all(tenant_id)
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(f"feed refresh failed: {exc}")
            return {"attempted": True, "error": str(exc)}

        for feed_id in result["degraded"]:
            report["errors"].append(f"feed {feed_id} could not be refreshed")

        stale = [row for row in self.registry.health(tenant_id) if row["stale"]]
        return {
            "attempted": True,
            "refreshed": result["refreshed"],
            "unchanged": result["unchanged"],
            "degraded": result["degraded"],
            "indicator_count": result["indicator_count"],
            "stale_after_refresh": [row["feed_id"] for row in stale],
        }

    def _sweep(self, tenant_id: str, report: dict[str, Any]) -> builtins.list[str]:
        try:
            return [record.id for record in self.exceptions.sweep(tenant_id)]
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(f"exception sweep failed: {exc}")
            return []

    def _evaluate(
        self, tenant_id: str, events: builtins.list[QueryEvent], report: dict[str, Any]
    ) -> builtins.list[dict[str, Any]]:
        try:
            metrics = compute_metrics(
                events,
                feed_health=self.registry.health(tenant_id),
                expiring_exceptions=len(
                    self.exceptions.expiring_within(tenant_id, self.expiry_horizon_days)
                ),
                pending_approvals=len(self.gate.pending(tenant_id)),
            )
            raised = self.alerts.evaluate(tenant_id, metrics, evidence={"source": "maintenance"})
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(f"alert evaluation failed: {exc}")
            return []
        return [alert.to_dict() for alert in raised]
