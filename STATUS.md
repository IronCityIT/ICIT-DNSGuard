# DNS Guard — STATUS

**Run:** 2026-09-04 · **Branch:** `productize/dnsguard-policy-platform` · **Base:** `main`
**Tier:** IN SCOPE (full autonomy: branch → PR → merge → deploy to `icit-dnsguard`).
**Scope of this run:** productize DNS Guard from a single-domain assessment script
into a protective-DNS control plane — policy lifecycle, threat-feed provenance,
analytics, tenant/site policy, alerts and exceptions, audit and evidence,
resilient API and UI, FleetFix and compliance contracts, with every disruptive
action approval-gated. Jenkins gates, STATUS, commits.

Deeper design rationale lives in the commit messages; open items and blockers in
`PRODUCTIZE_NOTES.md`.

---

## PROVEN — verified locally this run

| Area | What was verified | Result |
|---|---|---|
| **Gates** | All eleven `tools/gates.sh` gates: ruff lint, ruff format, mypy, pytest, JSON contract, workflow YAML (actionlint + shellcheck), `node --check` on the cloud function, `node --check` on both dashboard pages, secret hygiene, shellcheck on the gate script itself, build | ✅ green |
| **Tests** | 378 tests, 88% line coverage over `dnsguard/` + `module_framework/`. No test touches the network — DNS lookups, HTTP fetches and the clock are all injected | ✅ 378/378 |
| **Typecheck** | `mypy dnsguard module_framework tools` — 36 source files | ✅ clean |
| **Real scan** | `tools/scan.py --domain ironcityit.com --group standard` against the live domain: grade A+, risk 12/100, 7 findings, 25 records, 20 hosts, RC=0 | ✅ |
| **Report contract** | Every key the deployed dashboard reads asserted by name; report passes the same JSON gate the workflow applies (`head -c 1` = `{`, `json.tool` parses) | ✅ |
| **White-label** | No underlying tool name in any module description, report, or client-facing page. `tools_used` removed from the report entirely | ✅ enforced by test |
| **Approval gate** | Publish, rollback, policy binding, enforcement changes, exception grant/revoke and FleetFix dispatch all refuse to execute unapproved — proven at the function level and again over HTTP | ✅ |
| **Audit chain** | Tamper detection proven adversarially: edited record, removed record, and a record re-signed with a recomputed hash — all three located by `verify()` | ✅ |
| **Tenant isolation** | Store-level (no API returns a document without a tenant id) and HTTP-level (a caller from another tenant gets 403 before any handler runs) | ✅ |
| **Evidence pack** | Exports, verifies against its own manifest, and fails verification when a section is edited — including when the manifest is repaired to match | ✅ |
| **Dashboard** | Both pages parse under `node --check`; console has zero inline script/style/handlers, so its strict CSP is honest | ✅ |
| **Workflow YAML** | All three workflows parse under PyYAML `safe_load` | ✅ |

---

## DEFECTS found and fixed this run

| # | Severity | Defect | Status |
|---|---|---|---|
| D1 | **High** | Stored XSS on the live free-scan page. Findings, AI remediation text, compliance tags and the error message were interpolated into `innerHTML` from a Firestore document that is currently world-writable. `?scan=<id>` is a link anyone can be sent, so a forged document meant script execution in a visitor's browser | **Fixed** — all DOM-constructed via `textContent` |
| D2 | **High** | Firestore rules absent from the repo; live project still on open test-mode rules (world-readable **and** world-writable) | **Partially fixed** — `firestore.rules` added and wired into `firebase.json`: no client writes, no `list`. Residual read-by-id needs auth (see blockers) |
| D3 | **Medium** | SPF lookup counting matched only `a:`/`mx:`, so bare `a`, `mx` and `redirect=` were not counted. A record already over the RFC 7208 budget could be reported as compliant | **Fixed** — record is tokenised |
| D4 | **Medium** | DNSSEC reported "implemented" on a DNSKEY alone. A zone signed with no DS at the registrar is unvalidated; signatures are ignored | **Fixed** — now its own finding, and the dashboard tick no longer lights up for it |
| D5 | **Medium** | Dangling CNAMEs were collected and never examined | **Fixed** — now a high finding. It immediately found a real one, see below |
| D6 | **Medium** | `src/api/api.py` imported four names that do not exist and called two methods that do not exist. The FastAPI backend has never once loaded | **Fixed** — replaced by `dnsguard/api.py` |
| D7 | **Medium** | `IndicatorIndex` cached feed freshness at construction, so a long-lived index reported stale snapshots as current indefinitely | **Fixed** — staleness computed per lookup |
| D8 | **Low** | The free-scan page loaded its logo from `raw.githubusercontent.com`, putting a third party in the load path of a client-facing page and handing them every visitor's IP. The file was in the same directory | **Fixed** |
| D9 | **Low** | Dashboard read Firestore with a collection query, which requires `list` over every scan ever run. `scan_id` is the document id | **Fixed** — direct `get` |
| D10 | **Low** | No hosting security headers. The product flags exactly these on clients | **Fixed** — HSTS, CSP, nosniff, frame-options, referrer and permissions policy |

### Real finding on our own infrastructure

`vpn.ironcityit.com` is a CNAME to `icit.mynetgear.com`, which does not resolve.
Found by the new `subdomain_discovery` module during verification. If that
destination is a de-provisioned account, whoever claims the name next serves
content on our domain. **This is production, not a fixture — worth checking today.**

---

## BLOCKED — cannot be completed in this environment

| Item | Why | What would unblock it |
|---|---|---|
| **Deploy anything** | `FIREBASE_SERVICE_ACCOUNT` does not exist in this repo or at org level. `deploy-functions.yml` has never succeeded once across the fleet, which is *why* production still carries open test-mode rules | Mint the service account and set the secret per repo |
| **`firestore.rules` taking effect** | Same blocker. The file is committed and wired into `firebase.json`, but a rules file that is never deployed changes nothing | As above |
| **Hosting deploy** | `firebase-deploy.yml` fails on every push to `main` with `Input required and not supplied: firebaseServiceAccount`. Every dashboard fix on this branch is committed but not published | As above |
| **Tenant-partitioned reads** | The free-scan page has no identity to filter on. Tenant rules would return zero rows and break the live funnel | Auth0 → Firebase custom token with a `client_id` claim (step 2 of the remediation order) |
| **`ai-consensus` job** | `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `IRONCITY_API_KEY` are not present. All four are on the approved list; they are simply not provisioned | Provision the four secrets |
| **Live `workflow_dispatch` dry-run** | Would write to the live production Firestore, and `ai-consensus` cannot pass without the secrets above | Run once the secrets land; the store step can then be validated in one pass |
| **Docker image build** | No Docker in this sandbox | `docker build .` on a Docker host. The gate SKIPs loudly rather than passing |
| ~~`actionlint`~~ | Was skipping locally. Now installed with shellcheck and pinned in both `ci.yml` and this environment | **Resolved** — the yaml gate runs actionlint + shellcheck everywhere |

---

## What was built

| Module | What it is |
|---|---|
| `module_framework/` + 10 modules | The fleet-standard scan framework. Every capability of the old 664-line analyzer, plus `dns_tools.py` and `api_clients.py`, re-housed as individually selectable modules |
| `dnsguard/store.py` | Tenant-partitioned document storage. No call returns a document without a tenant id |
| `dnsguard/resilience.py` | Bounded retry with full jitter, circuit breaker per dependency, and a non-raising variant that reports `degraded` |
| `dnsguard/audit.py` | Append-only hash chain per tenant; `verify()` names the record where it breaks |
| `dnsguard/approvals.py` | The gate. Unregistered actions fail closed; approvals are bound to action + subject + payload hash and are single-use |
| `dnsguard/feeds.py` | Threat-feed provenance. No indicator exists apart from its feed, snapshot checksum and line number |
| `dnsguard/policy.py` | Versioned lifecycle, immutable once submitted, approval-gated publish and rollback, explainable decisions |
| `dnsguard/tenancy.py` | Tenant baseline + per-site override, layered so a site rule always wins. Sites start in monitor mode |
| `dnsguard/exceptions_policy.py` | Exceptions that must expire, are approval-gated, and can only ever loosen a decision |
| `dnsguard/analytics.py` | Decision-stream aggregation + posture scoring (the old grade/risk/summary/quick-wins, normalised over modules that ran) |
| `dnsguard/alerts.py` | Rules over a named metric set, with evidence and cooldown |
| `dnsguard/compliance.py` | SOC 2 / CIS v8 / HIPAA / NIST 800-53 mapping, in both directions |
| `dnsguard/fleetfix.py` | `icit.fleetfix.workorder.v1` — the remediation handoff, with `disruptive` and `approval` as first-class fields |
| `dnsguard/evidence.py` | Hashed, independently verifiable evidence packs |
| `dnsguard/enforcement.py` | Compiles a published policy to RPZ / Unbound / hosts / dnsmasq, stamped with the policy hash |
| `dnsguard/api.py` | The control-plane API. Refuses to start unauthenticated |
| `dashboard/public/console.*` | Operator console. Degrades per panel, never builds markup from data, treats 202 as pending approval |
| `Jenkinsfile` + `tools/gates.sh` + `ci.yml` | One gate definition, three callers. Eleven gates, including shellcheck on the gate script itself |

---

## How to reproduce

```sh
python3 -m pip install -r requirements-dev.txt
sh tools/gates.sh all              # all eleven gates, same as Jenkins and CI
python3 tools/scan.py --list-modules
python3 tools/scan.py --domain ironcityit.com --group standard -o ./reports
DNSGUARD_API_TOKEN=dev python3 -c "import uvicorn;from dnsguard.api import create_app;uvicorn.run(create_app())"
```

---

## Definition of done — where this run stands

- [x] Branch `productize/dnsguard-policy-platform` pushed
- [x] Workflow, Cloud Function, Firestore schema and dashboard scaffolding committed
- [x] Quality gates run locally and reported — all eleven green, nothing hidden
- [x] PR opened against `main` — [#6](https://github.com/IronCityIT/ICIT-DNSGuard/pull/6)
- [x] **CI gates green on the PR** — run `33942080820`, all eleven steps green.
      Two earlier runs failed and both were real: PyYAML was an undeclared gate
      dependency, and actionlint found an SC2129 that no local run could have caught
      because shellcheck was installed in neither place. Both fixed at the cause, and
      the gate script is now shellchecked by a gate of its own.
- [x] **Merged to `main`** — this repo is IN SCOPE and the gates are green, which is
      the condition the guardrails set. Merging is low-risk for hosting specifically,
      because that deploy is broken; it does change what the public free-scan runs,
      since `triggerDNSScan` dispatches `dns-analysis.yml` against `main`. That path is
      covered by the report-contract tests and by a verified real scan.
- [ ] **Deploy — blocked, not skipped.** `FIREBASE_SERVICE_ACCOUNT` does not exist.
      Until it does, `firestore.rules`, the stored-XSS fix and every other dashboard
      change on this branch sit in `main` unpublished, and the live site keeps serving
      the last hand-deployed build. See the blockers table, and notes I–J in
      `PRODUCTIZE_NOTES.md` for the interim mitigation worth doing by hand.

## What to do next, in order

1. **Check `vpn.ironcityit.com`.** Dangling CNAME to a name that does not resolve, on
   our own production domain. Minutes to confirm, and it is a domain-takeover primitive
   if that destination is claimable.
2. **Set the Firestore rules by hand in the console** if `FIREBASE_SERVICE_ACCOUNT` is
   going to slip. `firestore.rules` in this repo is the file to paste. That alone removes
   the write primitive the stored-XSS chain depends on, without waiting for anything.
3. **Mint `FIREBASE_SERVICE_ACCOUNT`.** It unblocks rules, functions and hosting deploys
   across the whole fleet, not just this product, and it is why production has been open.
4. **Provision the four consensus keys** so `ai-consensus` can run and the pipeline can be
   validated end to end in one pass.
5. **Auth0 → Firebase custom token** with a `client_id` claim — step 2 of the remediation
   order, after which the `get` rule becomes a tenant comparison and the last
   unauthenticated read path closes.
