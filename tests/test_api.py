"""API behaviour, driven through a real ASGI client.

Tenant isolation, the approval gate's 202, degraded responses and the auth
requirement are all tested at the HTTP boundary, because that is where they
either hold or do not.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from dnsguard.api import Principal, Services, create_app
from dnsguard.clock import FrozenClock
from dnsguard.store import MemoryStore


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def services(clock):
    return Services.build(store=MemoryStore(), clock=clock)


def client_for(services, actor="bill", tenant="acme", roles=None):
    app = create_app(
        services,
        authenticate=lambda *_: Principal(
            actor=actor, tenant_id=tenant, roles=roles or ["viewer", "operator", "approver"]
        ),
    )
    return TestClient(app)


@pytest.fixture
def client(services):
    return client_for(services)


@pytest.fixture
def approver(services):
    return client_for(services, actor="ann")


def bootstrap(client) -> None:
    client.post("/api/v1/tenants", json={"id": "acme", "name": "Acme Ltd"}).raise_for_status()
    client.post(
        "/api/v1/tenants/acme/sites", json={"id": "hq", "name": "Head office"}
    ).raise_for_status()


def draft_and_submit(client, policy="default", rules=None):
    body = {
        "rules": rules
        or [
            {
                "action": "block",
                "match_kind": "domain",
                "match_value": "evil.example",
                "justification": "malware host",
            }
        ],
        "default_action": "allow",
    }
    created = client.post(f"/api/v1/tenants/acme/policies/{policy}/draft", json=body)
    created.raise_for_status()
    version = created.json()["version"]
    client.post(
        f"/api/v1/tenants/acme/policies/{policy}/versions/{version}/submit"
    ).raise_for_status()
    return version


def approve(client, approver, request_id):
    response = approver.post(
        f"/api/v1/tenants/acme/approvals/{request_id}/decision",
        json={"approve": True, "reason": "reviewed"},
    )
    response.raise_for_status()
    return response.json()


# ── health and metadata ──────────────────────────────────────────────────────


def test_healthz_is_liveness_only(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"


def test_readyz_reports_dependency_state(client):
    body = client.get("/readyz").json()
    assert body["status"] in ("ready", "degraded")
    assert body["store"]["reachable"] is True
    assert body["open_circuits"] == []


def test_the_catalog_comes_from_the_same_registry_the_cli_uses(client):
    body = client.get("/api/v1/catalog").json()
    assert body["degraded"] is False
    names = {m["name"] for m in body["modules"]}
    assert {"spf_audit", "dmarc_audit", "dns_records"} <= names
    assert "standard" in body["groups"]


def test_disruptive_actions_are_published_so_the_ui_can_warn_first(client):
    actions = {a["action"]: a for a in client.get("/api/v1/actions").json()["actions"]}
    assert actions["policy.publish"]["approval_required"] is True
    assert actions["policy.draft"]["approval_required"] is False


# ── authentication and tenancy ───────────────────────────────────────────────


def test_the_app_refuses_to_start_unauthenticated_by_default(services, monkeypatch):
    monkeypatch.delenv("DNSGUARD_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="will not start unauthenticated"):
        create_app(services)


def test_a_bearer_token_is_required_when_one_is_configured(services, monkeypatch):
    monkeypatch.setenv("DNSGUARD_API_TOKEN", "s3cret")
    app = create_app(services)
    with TestClient(app) as raw:
        assert raw.get("/api/v1/tenants/acme", headers={"X-Client-Id": "acme"}).status_code == 401
        assert (
            raw.get(
                "/api/v1/tenants/acme",
                headers={"Authorization": "Bearer wrong", "X-Client-Id": "acme"},
            ).status_code
            == 401
        )


def test_a_valid_token_still_needs_a_tenant(services, monkeypatch):
    monkeypatch.setenv("DNSGUARD_API_TOKEN", "s3cret")
    with TestClient(create_app(services)) as raw:
        response = raw.get("/api/v1/tenants/acme", headers={"Authorization": "Bearer s3cret"})
        assert response.status_code == 401
        assert "X-Client-Id" in response.json()["detail"]


def test_a_caller_cannot_reach_another_tenants_data(services):
    bootstrap(client_for(services))
    intruder = client_for(services, actor="mallory", tenant="globex")
    response = intruder.get("/api/v1/tenants/acme/sites")
    assert response.status_code == 403
    assert response.json()["error"] == "TenantIsolationError"


def test_a_caller_cannot_create_a_tenant_they_do_not_belong_to(services):
    response = client_for(services, tenant="acme").post(
        "/api/v1/tenants", json={"id": "globex", "name": "Globex"}
    )
    assert response.status_code == 403


def test_a_viewer_cannot_change_anything(services):
    bootstrap(client_for(services))
    viewer = client_for(services, roles=["viewer"])
    assert viewer.get("/api/v1/tenants/acme/sites").status_code == 200
    response = viewer.post("/api/v1/tenants/acme/sites", json={"id": "branch", "name": "Branch"})
    assert response.status_code == 403
    assert "operator" in response.json()["detail"]


def test_approving_requires_the_approver_role(services, client):
    bootstrap(client)
    version = draft_and_submit(client)
    pending = client.post(f"/api/v1/tenants/acme/policies/default/versions/{version}/publish")
    request_id = pending.json()["approval_request_id"]

    operator = client_for(services, actor="ann", roles=["viewer", "operator"])
    response = operator.post(
        f"/api/v1/tenants/acme/approvals/{request_id}/decision", json={"approve": True}
    )
    assert response.status_code == 403


# ── the approval gate over HTTP ──────────────────────────────────────────────


def test_publishing_returns_202_with_the_approval_request(client):
    bootstrap(client)
    version = draft_and_submit(client)
    response = client.post(f"/api/v1/tenants/acme/policies/default/versions/{version}/publish")

    assert response.status_code == 202
    body = response.json()
    assert body["error"] == "ApprovalRequiredError"
    assert body["action"] == "policy.publish"
    assert body["approval_request_id"].startswith("apr-")


def test_the_pending_queue_shows_what_is_waiting(client):
    bootstrap(client)
    version = draft_and_submit(client)
    client.post(f"/api/v1/tenants/acme/policies/default/versions/{version}/publish")
    pending = client.get("/api/v1/tenants/acme/approvals").json()["approvals"]
    assert len(pending) == 1
    assert pending[0]["action"] == "policy.publish"
    assert "publish default@1" in pending[0]["summary"]


def test_the_requester_cannot_approve_their_own_change_over_http(client):
    bootstrap(client)
    version = draft_and_submit(client)
    request_id = client.post(
        f"/api/v1/tenants/acme/policies/default/versions/{version}/publish"
    ).json()["approval_request_id"]

    response = client.post(
        f"/api/v1/tenants/acme/approvals/{request_id}/decision", json={"approve": True}
    )
    assert response.status_code == 400
    assert "separation of duties" in response.json()["detail"]


def test_an_approved_publish_goes_live(client, approver):
    bootstrap(client)
    version = draft_and_submit(client)
    request_id = client.post(
        f"/api/v1/tenants/acme/policies/default/versions/{version}/publish"
    ).json()["approval_request_id"]
    approve(client, approver, request_id)

    response = client.post(
        f"/api/v1/tenants/acme/policies/default/versions/{version}/publish",
        params={"approval_id": request_id},
    )
    assert response.status_code == 200
    assert response.json()["state"] == "published"


# ── the decision path end to end ─────────────────────────────────────────────


def live_policy(client, approver):
    bootstrap(client)
    version = draft_and_submit(client)
    request_id = client.post(
        f"/api/v1/tenants/acme/policies/default/versions/{version}/publish"
    ).json()["approval_request_id"]
    approve(client, approver, request_id)
    client.post(
        f"/api/v1/tenants/acme/policies/default/versions/{version}/publish",
        params={"approval_id": request_id},
    ).raise_for_status()

    bind = client.put("/api/v1/tenants/acme/policy", json={"policy_id": "default"})
    approve(client, approver, bind.json()["approval_request_id"])
    client.put(
        "/api/v1/tenants/acme/policy",
        json={"policy_id": "default"},
        params={"approval_id": bind.json()["approval_request_id"]},
    ).raise_for_status()


def test_a_new_site_is_in_monitor_mode_and_says_what_it_would_have_done(client, approver):
    live_policy(client, approver)
    decision = client.get(
        "/api/v1/tenants/acme/sites/hq/decide", params={"name": "evil.example"}
    ).json()
    assert decision["action"] == "monitor"
    assert decision["degraded_from"] == "block"


def test_turning_on_enforcement_needs_approval_then_blocks(client, approver):
    live_policy(client, approver)
    pending = client.put("/api/v1/tenants/acme/sites/hq/enforcement", json={"enforcing": True})
    assert pending.status_code == 202
    request_id = pending.json()["approval_request_id"]
    approve(client, approver, request_id)
    client.put(
        "/api/v1/tenants/acme/sites/hq/enforcement",
        json={"enforcing": True},
        params={"approval_id": request_id},
    ).raise_for_status()

    decision = client.get(
        "/api/v1/tenants/acme/sites/hq/decide", params={"name": "evil.example"}
    ).json()
    assert decision["action"] == "block"
    assert "malware host" in decision["reason"]


def test_the_effective_policy_explains_where_each_rule_came_from(client, approver):
    live_policy(client, approver)
    body = client.get("/api/v1/tenants/acme/sites/hq/effective-policy").json()
    assert body["tenant_policy"] == "default@1"
    assert body["site_policy"] is None
    assert body["enforcing"] is False
    assert body["rules"][0]["source"]["layer"] == "tenant"


def test_a_site_with_no_policy_is_a_409_not_a_500(client):
    bootstrap(client)
    response = client.get("/api/v1/tenants/acme/sites/hq/effective-policy")
    assert response.status_code == 409
    assert "no published policy" in response.json()["detail"]


def test_an_unknown_site_is_a_404(client):
    bootstrap(client)
    assert client.get("/api/v1/tenants/acme/sites/nope/effective-policy").status_code == 404


# ── analytics ────────────────────────────────────────────────────────────────


def sample_events(tenant="acme"):
    return [
        {
            "timestamp": "2026-01-01T00:10:00Z",
            "tenant_id": tenant,
            "site_id": "hq",
            "name": "evil.example",
            "action": "block",
        },
        {
            "timestamp": "2026-01-01T00:20:00Z",
            "tenant_id": tenant,
            "site_id": "hq",
            "name": "ok.example",
            "action": "allow",
        },
    ]


def test_analytics_summarises_a_supplied_stream(client):
    bootstrap(client)
    body = client.post(
        "/api/v1/tenants/acme/analytics/summary", json={"events": sample_events()}
    ).json()
    assert body["summary"]["blocked"] == 1
    assert body["summary"]["block_rate"] == 0.5
    assert body["timeseries"][0]["block"] == 1


def test_analytics_refuses_events_belonging_to_another_tenant(client):
    bootstrap(client)
    response = client.post(
        "/api/v1/tenants/acme/analytics/summary", json={"events": sample_events("globex")}
    )
    assert response.status_code == 403


def test_malformed_events_are_a_400_not_a_500(client):
    bootstrap(client)
    response = client.post(
        "/api/v1/tenants/acme/analytics/summary", json={"events": [{"nonsense": True}]}
    )
    assert response.status_code == 400


# ── exceptions, alerts, feeds ────────────────────────────────────────────────


def test_an_exception_is_requested_then_granted_under_approval(client, approver):
    live_policy(client, approver)
    created = client.post(
        "/api/v1/tenants/acme/exceptions",
        json={"match_value": "supplier.example", "reason": "false positive", "ttl_days": 30},
    )
    created.raise_for_status()
    exception_id = created.json()["id"]

    pending = client.post(f"/api/v1/tenants/acme/exceptions/{exception_id}/grant")
    assert pending.status_code == 202
    approve(client, approver, pending.json()["approval_request_id"])
    granted = client.post(
        f"/api/v1/tenants/acme/exceptions/{exception_id}/grant",
        params={"approval_id": pending.json()["approval_request_id"]},
    )
    assert granted.json()["state"] == "active"


def test_an_exception_longer_than_the_ceiling_is_rejected(client):
    bootstrap(client)
    response = client.post(
        "/api/v1/tenants/acme/exceptions",
        json={"match_value": "x.example", "reason": "forever please", "ttl_days": 3650},
    )
    assert response.status_code == 400


def test_a_new_tenant_starts_with_the_default_alert_rules(client):
    bootstrap(client)
    rules = client.get("/api/v1/tenants/acme/alert-rules").json()["rules"]
    assert len(rules) >= 3
    assert all(r["description"] for r in rules)


def test_evaluating_alerts_returns_the_metrics_it_judged_on(client):
    bootstrap(client)
    body = client.post(
        "/api/v1/tenants/acme/alerts/evaluate", json={"events": sample_events()}
    ).json()
    assert "blocked_count" in body["metrics"]
    assert isinstance(body["raised"], list)


def test_the_feeds_panel_reports_degradation_rather_than_failing(services, monkeypatch):
    bootstrap(client_for(services))

    def broken(_tenant_id):
        raise ConnectionError("feed store unavailable")

    monkeypatch.setattr(services.feeds, "health", broken)
    body = client_for(services).get("/api/v1/tenants/acme/feeds").json()
    assert body["degraded"] is True
    assert body["feeds"] == []
    assert "unavailable" in body["reason"]


# ── audit and evidence ───────────────────────────────────────────────────────


def test_the_audit_endpoint_returns_the_chain_and_its_verification(client, approver):
    live_policy(client, approver)
    body = client.get("/api/v1/tenants/acme/audit").json()
    assert body["integrity"]["valid"] is True
    actions = [r["action"] for r in body["records"]]
    assert actions[0] == "tenant.create"
    assert {"site.create", "policy.draft", "policy.publish", "approval.decide"} <= set(actions)
    assert [r["seq"] for r in body["records"]] == list(range(1, len(actions) + 1))


def test_evidence_export_is_verifiable_over_http(client, approver):
    from dnsguard.evidence import verify

    live_policy(client, approver)
    bundle = client.post("/api/v1/tenants/acme/evidence", params={"note": "quarterly"}).json()
    assert verify(bundle)["valid"] is True
    assert bundle["integrity"]["note"] == "quarterly"


def test_compliance_reports_coverage_and_chain_state(client, approver):
    live_policy(client, approver)
    body = client.get("/api/v1/tenants/acme/compliance").json()
    assert body["audit_chain"]["valid"] is True
    satisfied = {c["control"]["id"] for c in body["controls"] if c["status"] == "satisfied"}
    assert "CC8.1" in satisfied  # the approval gate is the evidence
    assert body["coverage"]["totals"]["satisfied"] > 0


# ── plumbing ─────────────────────────────────────────────────────────────────


def test_every_response_carries_a_request_id(client):
    response = client.get("/healthz")
    assert response.headers["X-Request-Id"].startswith("req-")


def test_a_supplied_request_id_is_echoed_back(client):
    response = client.get("/healthz", headers={"X-Request-Id": "trace-123"})
    assert response.headers["X-Request-Id"] == "trace-123"


def test_cors_is_closed_by_default(services):
    app = create_app(services, authenticate=lambda *_: Principal("bill", "acme"))
    cors = [m for m in app.user_middleware if "CORS" in str(m)]
    assert cors, "CORS middleware should be installed"
    assert cors[0].kwargs["allow_origins"] == []


# ── feed-driven decisions and maintenance ────────────────────────────────────


def register_feed_with_entries(services, clock):
    """A tenant whose feed has actually been fetched and persisted."""
    from dnsguard.feeds import FeedFetcher, FeedSource, FetchResponse
    from dnsguard.resilience import BreakerRegistry, RetryPolicy

    services.feeds.register(
        "acme",
        FeedSource(
            id="icit-malware",
            name="Curated list",
            publisher="Iron City IT",
            url="https://feeds.example/m.txt",
            category="malware",
            trust_tier="vetted",
            fmt="hosts",
        ),
    )
    FeedFetcher(
        registry=services.feeds,
        fetch=lambda url, etag="": FetchResponse("0.0.0.0 listed.example\n"),
        clock=clock,
        breakers=BreakerRegistry(clock=clock),
        policy=RetryPolicy(attempts=1, jitter=False),
    ).refresh("acme", "icit-malware")


def test_a_category_rule_resolves_against_persisted_feed_entries(services, clock, approver):
    """The decision endpoint used to pass no indicator index at all, so a
    category rule matched nothing and a listed domain came back as a clean
    allow."""
    client = client_for(services)
    register_feed_with_entries(services, clock)
    bootstrap(client)
    version = draft_and_submit(
        client,
        rules=[
            {
                "action": "block",
                "match_kind": "category",
                "match_value": "malware",
                "justification": "tenant blocks malware categorically",
            }
        ],
    )
    request_id = client.post(
        f"/api/v1/tenants/acme/policies/default/versions/{version}/publish"
    ).json()["approval_request_id"]
    approve(client, approver, request_id)
    client.post(
        f"/api/v1/tenants/acme/policies/default/versions/{version}/publish",
        params={"approval_id": request_id},
    ).raise_for_status()
    bind = client.put("/api/v1/tenants/acme/policy", json={"policy_id": "default"})
    approve(client, approver, bind.json()["approval_request_id"])
    client.put(
        "/api/v1/tenants/acme/policy",
        json={"policy_id": "default"},
        params={"approval_id": bind.json()["approval_request_id"]},
    ).raise_for_status()

    decision = client.get(
        "/api/v1/tenants/acme/sites/hq/decide", params={"name": "listed.example"}
    ).json()

    assert decision["degraded_from"] == "block"  # monitor mode, but it matched
    assert decision["provenance"], "the decision must cite the feed that drove it"
    assert decision["provenance"][0]["feed_id"] == "icit-malware"
    assert decision["provenance"][0]["line_no"] == 1


def test_maintenance_runs_over_http_and_reports_what_it_did(client):
    bootstrap(client)
    report = client.post("/api/v1/tenants/acme/maintenance").json()
    assert report["ok"] is True
    assert report["audit_chain"]["valid"] is True
    assert report["feeds"]["attempted"] is False  # no fetcher configured in tests


def test_maintenance_needs_the_operator_role(services):
    bootstrap(client_for(services))
    viewer = client_for(services, roles=["viewer"])
    assert viewer.post("/api/v1/tenants/acme/maintenance").status_code == 403


def test_maintenance_cannot_be_run_against_another_tenant(services):
    bootstrap(client_for(services))
    intruder = client_for(services, actor="mallory", tenant="globex")
    assert intruder.post("/api/v1/tenants/acme/maintenance").status_code == 403
