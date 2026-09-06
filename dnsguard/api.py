"""The DNS Guard control-plane API.

Design decisions worth stating, because they are the difference between an API
that degrades and one that falls over:

**Tenancy is in the path and checked against the caller.** Every route lives
under /api/v1/tenants/{tenant_id}/..., and a principal whose tenant does not
match gets 403 before any handler runs. Multi-tenancy is not a filter a handler
might forget to apply.

**Errors are typed at the source.** dnsguard.errors carries the status code, so
a NotFoundError raised four layers down becomes a 404 without every layer
re-wrapping it. ApprovalRequiredError becomes 202 with the request id — that is
not an error condition, it is the gate working, and the client's next move is to
route it for sign-off.

**Optional data degrades; required data does not.** Feed health comes from a
dependency that can be down. Those panels return a `degraded` marker and a
reason rather than 500-ing a page that is mostly fine. A policy read has no such
fallback and fails honestly.

**Readiness is not liveness.** /healthz says the process is up. /readyz says
whether dependencies are answering, including which circuit breakers are open.
A load balancer that cannot tell those apart will either route to a broken
instance or restart a healthy one.
"""

from __future__ import annotations

import builtins
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .alerts import AlertRule, AlertService, compute_metrics, default_rules
from .analytics import QueryEvent, summarise, timeseries
from .approvals import ACTION_RISK, ApprovalGate, classify
from .audit import AuditLog
from .clock import Clock
from .compliance import assess, coverage
from .errors import ApprovalRequiredError, DnsGuardError, TenantIsolationError, ValidationError
from .evidence import EvidenceExporter
from .exceptions_policy import ExceptionService
from .feeds import FeedFetcher, FeedRegistry
from .fetcher import HttpFetcher
from .maintenance import MaintenanceRunner
from .policy import PolicyService, Rule
from .resilience import BreakerRegistry, try_call
from .store import DocumentStore, JsonFileStore, MemoryStore
from .tenancy import Site, Tenant, TenantDirectory

API_PREFIX = "/api/v1"

VIEWER, OPERATOR, APPROVER = "viewer", "operator", "approver"


@dataclass
class Principal:
    """Who is calling, which tenant they belong to, and what they may do."""

    actor: str
    tenant_id: str
    roles: builtins.list[str] = field(default_factory=lambda: [VIEWER])

    def may(self, role: str) -> bool:
        return role in self.roles


# ── request models ───────────────────────────────────────────────────────────


class RuleIn(BaseModel):
    action: str
    match_kind: str
    match_value: str
    justification: str = ""
    precedence: int = 100
    redirect_to: str = ""
    enabled: bool = True


class DraftIn(BaseModel):
    rules: builtins.list[RuleIn]
    default_action: str = "allow"
    note: str = ""


class DecisionIn(BaseModel):
    approve: bool
    reason: str = ""


class SiteIn(BaseModel):
    id: str
    name: str
    kind: str = "office"
    timezone: str = "UTC"
    tags: builtins.list[str] = Field(default_factory=list)
    notes: str = ""


class TenantIn(BaseModel):
    id: str
    name: str
    auth0_org_id: str = ""
    contact_email: str = ""


class ExceptionIn(BaseModel):
    match_value: str
    reason: str
    match_kind: str = "domain"
    scope: str = "tenant"
    ttl_days: int | None = None
    ticket_ref: str = ""


class AlertRuleIn(BaseModel):
    name: str
    metric: str
    threshold: float
    comparator: str = "gt"
    severity: str = "medium"
    window_minutes: int = 60
    scope: str = "tenant"
    cooldown_minutes: int = 60
    description: str = ""


class ResolutionIn(BaseModel):
    resolution: str


class EnforcementIn(BaseModel):
    enforcing: bool


class AssignmentIn(BaseModel):
    policy_id: str


class EventsIn(BaseModel):
    events: builtins.list[dict[str, Any]]


# ── services container ───────────────────────────────────────────────────────


@dataclass
class Services:
    store: DocumentStore
    clock: Clock
    audit: AuditLog
    gate: ApprovalGate
    policies: PolicyService
    feeds: FeedRegistry
    exceptions: ExceptionService
    alerts: AlertService
    directory: TenantDirectory
    evidence: EvidenceExporter
    breakers: BreakerRegistry
    maintenance: MaintenanceRunner

    @classmethod
    def build(cls, store: DocumentStore | None = None, clock: Clock | None = None) -> Services:
        store = store or _default_store()
        clock = clock or Clock()
        audit = AuditLog(store, clock)
        gate = ApprovalGate(store=store, audit=audit, clock=clock)
        policies = PolicyService(store=store, audit=audit, gate=gate, clock=clock)
        feeds = FeedRegistry(store, clock)
        exceptions = ExceptionService(store=store, audit=audit, gate=gate, clock=clock)
        alerts = AlertService(store=store, audit=audit, clock=clock)
        directory = TenantDirectory(
            store=store,
            audit=audit,
            gate=gate,
            policies=policies,
            exceptions=exceptions,
            clock=clock,
        )
        evidence = EvidenceExporter(
            audit=audit,
            policies=policies,
            gate=gate,
            feeds=feeds,
            exceptions=exceptions,
            clock=clock,
        )
        breakers = BreakerRegistry(clock=clock)
        # A fetcher is wired in only when outbound fetching is wanted. Left off,
        # maintenance reports feeds as "not attempted" rather than implying they
        # are healthy — see MaintenanceRunner._refresh_feeds.
        fetcher = (
            FeedFetcher(registry=feeds, fetch=HttpFetcher(), clock=clock, breakers=breakers)
            if os.environ.get("DNSGUARD_FETCH_FEEDS", "").lower() in ("1", "true", "yes")
            else None
        )
        maintenance = MaintenanceRunner(
            registry=feeds,
            fetcher=fetcher,
            exceptions=exceptions,
            alerts=alerts,
            gate=gate,
            audit=audit,
            clock=clock,
        )
        return cls(
            store=store,
            clock=clock,
            audit=audit,
            gate=gate,
            policies=policies,
            feeds=feeds,
            exceptions=exceptions,
            alerts=alerts,
            directory=directory,
            evidence=evidence,
            breakers=breakers,
            maintenance=maintenance,
        )


def _default_store() -> DocumentStore:
    root = os.environ.get("DNSGUARD_DATA_DIR")
    return JsonFileStore(root) if root else MemoryStore()


# ── the app ──────────────────────────────────────────────────────────────────


def create_app(
    services: Services | None = None,
    authenticate: Callable[[str | None, str | None, str | None], Principal] | None = None,
    allow_anonymous: bool = False,
    cors_origins: builtins.list[str] | None = None,
) -> FastAPI:
    """Build the API.

    `allow_anonymous` exists for tests and local development only. In any other
    mode a bearer token is required, and the app refuses to start without one
    configured rather than coming up silently unauthenticated — which is exactly
    how this product's Firestore ended up world-readable.
    """
    services = services or Services.build()
    token = os.environ.get("DNSGUARD_API_TOKEN", "")

    if authenticate is None:
        if not allow_anonymous and not token:
            raise RuntimeError(
                "DNSGUARD_API_TOKEN is not set. Set it, or pass allow_anonymous=True "
                "for local development. The API will not start unauthenticated."
            )
        authenticate = _header_auth(token, allow_anonymous)

    app = FastAPI(
        title="Iron City DNS Guard control plane",
        version="1.0.0",
        description="Policy, threat-feed provenance, analytics and evidence for protective DNS.",
    )
    app.state.services = services
    # Default closed: an explicit origin list, never "*". The endpoints below
    # return tenant data, unlike the public free-scan trigger.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or [],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["Authorization", "Content-Type", "X-Client-Id", "X-Actor"],
    )

    @app.middleware("http")
    async def request_id(request: Request, call_next: Any) -> Any:
        """One id per request, echoed back, so a client report of "it failed"
        can be found in the logs without guessing at timestamps."""
        rid = request.headers.get("X-Request-Id") or f"req-{uuid.uuid4().hex[:16]}"
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response

    @app.exception_handler(DnsGuardError)
    async def domain_error(_request: Request, exc: DnsGuardError) -> JSONResponse:
        body: dict[str, Any] = {"error": type(exc).__name__, "detail": str(exc)}
        if isinstance(exc, ApprovalRequiredError):
            # 202: the gate did its job. The client's next move is sign-off.
            body["approval_request_id"] = exc.request_id
            body["action"] = exc.action
        return JSONResponse(status_code=exc.status_code, content=body)

    def principal(
        authorization: str | None = Header(default=None),
        x_client_id: str | None = Header(default=None),
        x_actor: str | None = Header(default=None),
    ) -> Principal:
        return authenticate(authorization, x_client_id, x_actor)  # type: ignore[misc]

    def scoped(
        tenant_id: str = Path(...), caller: Principal = Depends(principal)
    ) -> tuple[str, Principal]:
        """Bind the path tenant to the caller's tenant. Nothing gets past this
        with a mismatch, so no handler has to remember the check."""
        if caller.tenant_id != tenant_id:
            raise TenantIsolationError(
                f"caller belongs to {caller.tenant_id} and cannot act on {tenant_id}"
            )
        return tenant_id, caller

    def require(caller: Principal, role: str) -> None:
        if not caller.may(role):
            raise HTTPException(status_code=403, detail=f"this action requires the {role} role")

    _register_routes(app, services, scoped, principal, require)
    return app


def _header_auth(token: str, allow_anonymous: bool) -> Callable[..., Principal]:
    def authenticate(
        authorization: str | None, client_id: str | None, actor: str | None
    ) -> Principal:
        if not allow_anonymous:
            presented = (authorization or "").removeprefix("Bearer ").strip()
            if not presented or presented != token:
                raise HTTPException(status_code=401, detail="a valid bearer token is required")
        if not client_id:
            raise HTTPException(
                status_code=401, detail="X-Client-Id identifies the tenant and is required"
            )
        return Principal(
            actor=actor or "unknown",
            tenant_id=client_id,
            roles=[VIEWER, OPERATOR, APPROVER],
        )

    return authenticate


def _register_routes(  # noqa: C901 - a route table; splitting it hides the surface
    app: FastAPI,
    services: Services,
    scoped: Any,
    principal: Any,
    require: Any,
) -> None:
    svc = services

    # ── health ──────────────────────────────────────────────────────────────

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        """Liveness only. Deliberately touches nothing external."""
        return {"status": "ok", "service": "dnsguard-control-plane", "version": app.version}

    @app.get("/readyz")
    def readyz() -> dict[str, Any]:
        """Readiness. Reports which dependencies are shedding load, and answers
        even when they all are — a readiness probe that cannot respond during an
        outage tells you nothing about the outage."""
        no_tenants: builtins.list[str] = []
        probe = try_call(svc.store.tenants, fallback=no_tenants, clock=svc.clock)
        breakers = svc.breakers.snapshot()
        open_circuits = [b["name"] for b in breakers if b["state"] == "open"]
        return {
            "status": "ready" if probe.ok and not open_circuits else "degraded",
            "store": {"reachable": probe.ok, "tenants": len(probe.value or [])},
            "circuits": breakers,
            "open_circuits": open_circuits,
        }

    @app.get(f"{API_PREFIX}/catalog")
    def catalog() -> dict[str, Any]:
        """Scan modules and groups, for the dashboard's module picker.

        Read from the same registry the CLI runs from, so selection in the UI and
        selection on the command line cannot drift apart. If the framework is not
        importable the endpoint degrades to an empty catalogue rather than taking
        the whole dashboard down.
        """
        result = try_call(_load_catalog, fallback={"modules": [], "groups": []}, clock=svc.clock)
        payload = dict(result.value or {})
        payload["degraded"] = result.degraded
        if result.degraded:
            payload["reason"] = result.error
        return payload

    @app.get(f"{API_PREFIX}/actions")
    def actions() -> dict[str, Any]:
        """Which actions are disruptive. Published so the UI can warn before the
        API refuses, rather than surprising the operator with a 202."""
        return {
            "actions": [
                {
                    "action": action,
                    "disruption": classify(action).value,
                    "approval_required": classify(action).value == "high",
                }
                for action in sorted(ACTION_RISK)
            ]
        }

    # ── tenants and sites ───────────────────────────────────────────────────

    @app.post(f"{API_PREFIX}/tenants", status_code=201)
    def create_tenant(body: TenantIn, caller: Principal = Depends(principal)) -> dict[str, Any]:
        require(caller, OPERATOR)
        if caller.tenant_id != body.id:
            raise TenantIsolationError(
                f"caller belongs to {caller.tenant_id} and cannot create {body.id}"
            )
        tenant = svc.directory.create_tenant(
            Tenant(
                id=body.id,
                name=body.name,
                auth0_org_id=body.auth0_org_id,
                contact_email=body.contact_email,
            ),
            caller.actor,
        )
        for rule in default_rules(tenant.id):
            svc.alerts.create_rule(rule, caller.actor)
        return tenant.to_dict()

    @app.get(API_PREFIX + "/tenants/{tenant_id}")
    def get_tenant(scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        return svc.directory.tenant(tenant_id).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/sites", status_code=201)
    def create_site(body: SiteIn, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        site = svc.directory.create_site(
            Site(
                id=body.id,
                tenant_id=tenant_id,
                name=body.name,
                kind=body.kind,
                timezone=body.timezone,
                tags=body.tags,
                notes=body.notes,
            ),
            caller.actor,
        )
        return site.to_dict()

    @app.get(API_PREFIX + "/tenants/{tenant_id}/sites")
    def list_sites(scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        return {"sites": [s.to_dict() for s in svc.directory.sites(tenant_id)]}

    @app.put(API_PREFIX + "/tenants/{tenant_id}/sites/{site_id}/policy")
    def bind_site_policy(
        site_id: str, body: AssignmentIn, approval_id: str = "", scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.directory.assign_site_policy(
            tenant_id, site_id, body.policy_id, caller.actor, approval_id
        ).to_dict()

    @app.put(API_PREFIX + "/tenants/{tenant_id}/sites/{site_id}/enforcement")
    def set_enforcement(
        site_id: str, body: EnforcementIn, approval_id: str = "", scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.directory.set_enforcing(
            tenant_id, site_id, body.enforcing, caller.actor, approval_id
        ).to_dict()

    @app.get(API_PREFIX + "/tenants/{tenant_id}/sites/{site_id}/effective-policy")
    def effective_policy(site_id: str, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        effective = svc.directory.effective_policy(tenant_id, site_id)
        return {
            **effective.explain(),
            "rules": [r.to_dict() for r in effective.version.rules],
        }

    @app.get(API_PREFIX + "/tenants/{tenant_id}/sites/{site_id}/decide")
    def decide(site_id: str, name: str, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        """What would happen to this name at this site, and why. Read-only — it
        is the "explain this block" endpoint, not an enforcement path.

        The indicator index is loaded from what was persisted, so category and
        feed rules resolve against the entries this tenant's feeds actually
        carry. Without it those rules match nothing, and the endpoint reports a
        clean allow for a name sitting on three blocklists.
        """
        tenant_id, _ = scope
        index = svc.feeds.load_index(tenant_id)
        return svc.directory.decide(tenant_id, site_id, name, index).to_dict()

    @app.put(API_PREFIX + "/tenants/{tenant_id}/policy")
    def bind_tenant_policy(
        body: AssignmentIn, approval_id: str = "", scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.directory.assign_tenant_policy(
            tenant_id, body.policy_id, caller.actor, approval_id
        ).to_dict()

    # ── policy lifecycle ────────────────────────────────────────────────────

    @app.get(API_PREFIX + "/tenants/{tenant_id}/policies")
    def list_policies(scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        return {
            "policies": [
                {"policy_id": pid, "history": svc.policies.history(tenant_id, pid)}
                for pid in svc.policies.policies(tenant_id)
            ]
        }

    @app.post(API_PREFIX + "/tenants/{tenant_id}/policies/{policy_id}/draft", status_code=201)
    def draft(policy_id: str, body: DraftIn, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        rules = [Rule(**r.model_dump()) for r in body.rules]
        return svc.policies.draft(
            tenant_id, policy_id, caller.actor, rules, body.default_action, body.note
        ).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/policies/{policy_id}/versions/{version}/submit")
    def submit(policy_id: str, version: int, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.policies.submit(tenant_id, policy_id, version, caller.actor).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/policies/{policy_id}/versions/{version}/publish")
    def publish(
        policy_id: str, version: int, approval_id: str = "", scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.policies.publish(
            tenant_id, policy_id, version, caller.actor, approval_id
        ).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/policies/{policy_id}/rollback/{to_version}")
    def rollback(
        policy_id: str, to_version: int, approval_id: str = "", scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.policies.rollback(
            tenant_id, policy_id, to_version, caller.actor, approval_id
        ).to_dict()

    # ── approvals ───────────────────────────────────────────────────────────

    @app.get(API_PREFIX + "/tenants/{tenant_id}/approvals")
    def approvals(state: str = "pending", scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        records = svc.gate.pending(tenant_id) if state == "pending" else svc.gate.all(tenant_id)
        return {"approvals": [a.to_dict() for a in records]}

    @app.post(API_PREFIX + "/tenants/{tenant_id}/approvals/{approval_id}/decision")
    def decide_approval(
        approval_id: str, body: DecisionIn, scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, APPROVER)
        return svc.gate.decide(
            tenant_id, approval_id, caller.actor, body.approve, body.reason
        ).to_dict()

    # ── exceptions ──────────────────────────────────────────────────────────

    @app.get(API_PREFIX + "/tenants/{tenant_id}/exceptions")
    def list_exceptions(
        active_only: bool = False, expiring_days: int = 0, scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, _ = scope
        if expiring_days:
            records = svc.exceptions.expiring_within(tenant_id, expiring_days)
        elif active_only:
            records = svc.exceptions.active(tenant_id)
        else:
            records = svc.exceptions.all(tenant_id)
        return {"exceptions": [e.to_dict() for e in records]}

    @app.post(API_PREFIX + "/tenants/{tenant_id}/exceptions", status_code=201)
    def request_exception(body: ExceptionIn, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.exceptions.request(
            tenant_id,
            caller.actor,
            body.match_value,
            body.reason,
            body.match_kind,
            body.scope,
            body.ttl_days,
            body.ticket_ref,
        ).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/exceptions/{exception_id}/grant")
    def grant_exception(
        exception_id: str, approval_id: str = "", scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.exceptions.grant(tenant_id, exception_id, caller.actor, approval_id).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/exceptions/{exception_id}/revoke")
    def revoke_exception(
        exception_id: str, reason: str = "", approval_id: str = "", scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.exceptions.revoke(
            tenant_id, exception_id, caller.actor, reason, approval_id
        ).to_dict()

    # ── feeds ───────────────────────────────────────────────────────────────

    @app.get(API_PREFIX + "/tenants/{tenant_id}/feeds")
    def feeds(scope: tuple = Depends(scoped)) -> dict[str, Any]:
        """Feed inventory and freshness. Degrades rather than failing the page:
        a feed panel that cannot load must not take the dashboard with it."""
        tenant_id, _ = scope
        no_feeds: builtins.list[dict[str, Any]] = []
        result = try_call(lambda: svc.feeds.health(tenant_id), fallback=no_feeds, clock=svc.clock)
        return {
            "feeds": result.value or [],
            "degraded": result.degraded,
            "reason": result.error if result.degraded else "",
        }

    @app.post(API_PREFIX + "/tenants/{tenant_id}/maintenance")
    def maintenance(scope: tuple = Depends(scoped)) -> dict[str, Any]:
        """Run one maintenance pass: refresh feeds, record lapsed exceptions,
        evaluate alert rules, verify the audit chain.

        Exposed so an external scheduler can drive the loop without shell access
        to the host. Non-disruptive by construction — every step either refreshes
        data or records an expiry the tenant already agreed to — so it needs the
        operator role but no approval.
        """
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.maintenance.run(tenant_id)

    @app.get(API_PREFIX + "/tenants/{tenant_id}/feeds/{feed_id}/snapshots")
    def snapshots(feed_id: str, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        return {"snapshots": [s.to_dict() for s in svc.feeds.snapshots(tenant_id, feed_id)]}

    # ── analytics ───────────────────────────────────────────────────────────

    @app.post(API_PREFIX + "/tenants/{tenant_id}/analytics/summary")
    def analytics_summary(
        body: EventsIn, bucket_seconds: int = 3600, scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        """Summarise a decision stream. The events are supplied by the caller
        (the resolver exporter or a log ingest) rather than stored here, so the
        control plane never becomes a query-log warehouse it cannot defend."""
        tenant_id, _ = scope
        try:
            events = [QueryEvent(**e) for e in body.events]
        except TypeError as exc:
            raise ValidationError(f"malformed query event: {exc}") from exc
        foreign = {e.tenant_id for e in events} - {tenant_id, ""}
        if foreign:
            raise TenantIsolationError(f"events reference other tenants: {sorted(foreign)}")
        return {
            "summary": summarise(events),
            "timeseries": timeseries(events, bucket_seconds),
        }

    @app.get(API_PREFIX + "/tenants/{tenant_id}/compliance")
    def compliance(scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        records = svc.audit.records(tenant_id)
        integrity = svc.audit.verify(tenant_id)
        statuses = assess(
            [],
            {
                "audit_chain": {"records": len(records), "verified": integrity["valid"]},
                "approval_gate": {"requests": len(svc.gate.all(tenant_id))},
                "policy_versioning": {"policies": len(svc.policies.policies(tenant_id))},
                "feed_provenance": {"feeds": len(svc.feeds.list(tenant_id))},
                "exception_expiry": {"exceptions": len(svc.exceptions.all(tenant_id))},
            },
        )
        return {
            "controls": [s.to_dict() for s in statuses],
            "coverage": coverage(statuses),
            "audit_chain": integrity,
        }

    # ── alerts ──────────────────────────────────────────────────────────────

    @app.get(API_PREFIX + "/tenants/{tenant_id}/alerts")
    def list_alerts(state: str = "", scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        return {"alerts": [a.to_dict() for a in svc.alerts.alerts(tenant_id, state)]}

    @app.get(API_PREFIX + "/tenants/{tenant_id}/alert-rules")
    def list_alert_rules(scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        return {"rules": [r.to_dict() for r in svc.alerts.rules(tenant_id, enabled_only=False)]}

    @app.post(API_PREFIX + "/tenants/{tenant_id}/alert-rules", status_code=201)
    def create_alert_rule(body: AlertRuleIn, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.alerts.create_rule(
            AlertRule(tenant_id=tenant_id, **body.model_dump()), caller.actor
        ).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/alerts/evaluate")
    def evaluate_alerts(body: EventsIn, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        events = [QueryEvent(**e) for e in body.events]
        metrics = compute_metrics(
            events,
            feed_health=svc.feeds.health(tenant_id),
            expiring_exceptions=len(svc.exceptions.expiring_within(tenant_id, 30)),
            pending_approvals=len(svc.gate.pending(tenant_id)),
        )
        raised = svc.alerts.evaluate(tenant_id, metrics, evidence={"summary": summarise(events)})
        return {"metrics": metrics, "raised": [a.to_dict() for a in raised]}

    @app.post(API_PREFIX + "/tenants/{tenant_id}/alerts/{alert_id}/acknowledge")
    def acknowledge(alert_id: str, scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.alerts.acknowledge(tenant_id, alert_id, caller.actor).to_dict()

    @app.post(API_PREFIX + "/tenants/{tenant_id}/alerts/{alert_id}/resolve")
    def resolve(
        alert_id: str, body: ResolutionIn, scope: tuple = Depends(scoped)
    ) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.alerts.resolve(tenant_id, alert_id, caller.actor, body.resolution).to_dict()

    # ── audit and evidence ──────────────────────────────────────────────────

    @app.get(API_PREFIX + "/tenants/{tenant_id}/audit")
    def audit(since: int = 0, subject: str = "", scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, _ = scope
        if subject:
            records = svc.audit.for_subject(tenant_id, subject)
        else:
            records = svc.audit.since(tenant_id, since)
        return {"records": [r.to_dict() for r in records], "integrity": svc.audit.verify(tenant_id)}

    @app.post(API_PREFIX + "/tenants/{tenant_id}/evidence")
    def evidence(note: str = "", scope: tuple = Depends(scoped)) -> dict[str, Any]:
        tenant_id, caller = scope
        require(caller, OPERATOR)
        return svc.evidence.export(tenant_id, caller.actor, note=note).to_dict()


def _load_catalog() -> dict[str, Any]:
    """Import the scan framework lazily.

    The control plane must start and serve policy even on a host where the
    scanner's dependencies are not installed — an API that will not boot because
    a DNS library is missing is a worse outage than a missing module picker.
    """
    import pathlib
    import sys

    framework = pathlib.Path(__file__).resolve().parent.parent / "module_framework"
    if str(framework) not in sys.path:
        sys.path.insert(0, str(framework))

    import registry  # noqa: PLC0415

    found = registry.discover("modules")
    return {"modules": registry.catalog(found), "groups": sorted(registry.all_groups(found))}
