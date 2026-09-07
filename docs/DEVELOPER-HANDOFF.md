# DNS Guard — Developer Handoff

**Written:** 2026-09-07 · **Repo:** `IronCityIT/ICIT-DNSGuard` · **Branch of record:** `main`

This is the portable handoff. It is written so that somebody with no history on
this product can pick it up, understand what is actually true today, and act
without re-deriving anything.

## How to read the labels

Every claim in this document carries one:

| Label | Meaning |
|---|---|
| **VERIFIED** | Observed directly, in this repo or against a live system, with the command or file named. Reproducible. |
| **TARGET** | The intended end state. Not built yet, or not fully built. Never describes present behaviour. |
| **UNKNOWN** | Not established. Deliberately left unanswered rather than guessed. |

Where an earlier document in this repo asserted something that turned out to be
false, the correction is recorded rather than the assertion quietly edited. This
codebase has been wrong in the reassuring direction before — see
`STATUS.md`, "Correction — the live rules are deployed, and they are not the ones
in this repo".

---

## 1. Purpose

DNS Guard assesses and controls DNS posture for small and mid-sized clients. It
does two distinct jobs, and they are easy to confuse:

1. **Assessment** — a scanner that examines a domain's public DNS surface (mail
   authentication, DNSSEC, published hosts, dangling aliases and subdomain
   takeover, reputation, resolver behaviour) and produces a client-facing report.
   **VERIFIED** — 11 modules, runs from CI and locally.
2. **Protective-DNS control plane** — policy lifecycle, threat-feed provenance,
   tenant/site policy layering, exceptions, approvals, audit, evidence,
   compliance mapping and enforcement-config generation. **VERIFIED** as code and
   tests; **UNKNOWN / not deployed anywhere** — see §10.

There is also a public marketing funnel (free scan) that is the only part
currently serving real users. **VERIFIED**.

---

## 2. Current verified implementation

### 2.1 What exists and is tested

| Component | Path | State |
|---|---|---|
| Scan framework | `module_framework/` | **VERIFIED** — `base.py` (Finding/Asset/ScanModule contracts), `registry.py` (discovery, groups), `targets.py` (ip/cidr/url/domain/hostname/file), `cli.py` |
| Scan modules (11) | `module_framework/modules/` | **VERIFIED** — see §2.2 |
| Control plane | `dnsguard/` | **VERIFIED** as code+tests, **not deployed** |
| SQL document store | `dnsguard/sqlstore.py` | Contract **VERIFIED** on SQLite; MariaDB dialect **NOT VERIFIED** — never executed |
| Scanner entry point | `tools/scan.py` | **VERIFIED** — run live against `ironcityit.com` |
| Maintenance loop | `tools/maintain.py`, `dnsguard/maintenance.py` | **VERIFIED** — live feed fetch, 304 handling, audit verify |
| Exposure ratchets | `tools/check-exposure.py`, `tools/check-dns-exposure.py` | **VERIFIED** — both run in CI on every PR |
| Quality gates | `tools/gates.sh` (11 gates), `.github/workflows/ci.yml`, `Jenkinsfile` | **VERIFIED** green |
| Free-scan funnel | `cloud-function/`, `dashboard/public/index.html`, `.github/workflows/dns-analysis.yml` | **VERIFIED** live in production |
| Operator console | `dashboard/public/console.{html,css,js}` | **VERIFIED** as files; **UNKNOWN** whether ever deployed — it has no live API to talk to |

**Test suite: 532 passing, 89% line coverage** over `dnsguard/` + `module_framework/`.
**VERIFIED** — `sh tools/gates.sh all`, 2026-09-07. No test performs network I/O;
DNS, HTTP and the clock are injected everywhere.

### 2.2 Scan modules

**VERIFIED** via `python3 tools/scan.py --list-modules` (returns 11).

| Module | What it does | Contact class |
|---|---|---|
| `dns_records` | Zone inventory and structural audit | dns |
| `spf_audit` | Sender authorisation: presence, strictness, RFC 7208 lookup budget | dns |
| `dkim_audit` | Published signing keys across common provider selectors | dns |
| `dmarc_audit` | Policy, enforcement level, reporting | dns |
| `transport_security_audit` | MTA-STS and TLS-RPT | dns |
| `dnssec_audit` | Signing **and** the DS delegation that makes it count | dns |
| `subdomain_discovery` | Public host inventory; exposed internal-sounding hosts | dns |
| `alias_takeover` | Whether a dangling alias is claimable, and by whom | dns |
| `reputation_lookup` | External reputation, with attribution | passive |
| `resolver_performance` | Latency/loss across major public resolvers | dns |
| `network_path` | Network path to the domain's servers | direct |

Groups: `quick`, `standard`, `deep`, `email`, `surface`, `performance`,
`reputation`. The registry is the single source of truth for CLI, workflow input
and the console picker.

### 2.3 Control-plane modules

All **VERIFIED** as code and tests; none deployed.

`store.py` (tenant-partitioned document storage) · `policy.py` (versioned
lifecycle, approval-gated publish/rollback, explainable decisions) ·
`feeds.py` + `fetcher.py` (threat-feed provenance; guarded HTTP transport) ·
`tenancy.py` (tenant baseline + per-site override) · `exceptions_policy.py`
(expiring, approval-gated, loosen-only) · `approvals.py` (fail-closed gate) ·
`audit.py` (append-only hash chain) · `evidence.py` (verifiable evidence packs) ·
`analytics.py` · `alerts.py` · `compliance.py` (SOC 2 / CIS v8 / HIPAA / NIST
800-53) · `fleetfix.py` (remediation work-order contract) · `enforcement.py`
(compiles published policy to RPZ / Unbound / hosts / dnsmasq) ·
`resilience.py` (retry + circuit breaker) · `maintenance.py` · `api.py` (FastAPI
control plane) · `exposure.py` + `dns_exposure.py` (self-measurement) ·
`report.py` · `clock.py` · `errors.py`.

---

## 3. Target architecture

**TARGET.** Firebase, Firestore, Firebase Hosting and GCP-managed product storage
are **RETIRED** from the target architecture. They must not be extended, and
nothing new may be built on them.

```
                      GitHub Actions  (execution / orchestration layer)
                              │
      scheduled + dispatched  │  runs tools/scan.py, gates, exposure ratchets
                              ▼
                   ┌──────────────────────┐
                   │  ICIT NAS-backed     │
                   │  self-hosted runtime │
                   ├──────────────────────┤
                   │ MariaDB              │  relational state:
                   │                      │   tenants, scans, findings,
                   │                      │   policy, feeds, approvals,
                   │                      │   audit chain, exceptions
                   ├──────────────────────┤
                   │ NAS volume           │  object/artifact files:
                   │                      │   raw reports, evidence packs,
                   │                      │   feed snapshots
                   ├──────────────────────┤
                   │ Control-plane API    │  dnsguard/api.py (container)
                   │ Ingest API           │  replaces storeScanResults
                   │ Dashboard/console    │  static, self-hosted
                   └──────────────────────┘
```

**Retained from today (already matches target):**
- **GitHub Actions is the execution layer.** **VERIFIED** — already true.
- The `DocumentStore` abstraction in `dnsguard/store.py`. **VERIFIED** — the
  Python control plane has **no Firestore dependency at all**; it is already
  storage-agnostic. This is the seam the migration goes through.

**UNKNOWN — must be supplied by whoever owns the infrastructure:**
- NAS hostname/path, MariaDB host/port/instance, backup schedule and retention,
  network reachability from GitHub-hosted runners (or whether self-hosted runners
  are used instead), TLS termination and certificate source.
- None of these are guessed anywhere in this repo.

---

## 4. Data model

### 4.1 Control plane — present shape (VERIFIED)

`DocumentStore` addresses everything as
`clients/{tenant_id}/{collection}/{doc_id} -> dict`. Every read and write takes a
tenant id, and the store refuses to build a path without one. There is no API in
`dnsguard/store.py` that can return another tenant's document.

Implementations: `MemoryStore` (tests, dev), `JsonFileStore` (atomic temp-file +
rename writes, one JSON file per document), and `SqlDocumentStore`
(`dnsguard/sqlstore.py`, one row per document keyed on the
`(tenant_id, collection, doc_id)` triple as real indexed columns). All three run
the same contract suite. **VERIFIED** — `tests/test_store.py` is parametrised
across them.

The SQL store keeps the body as JSON deliberately: changing the storage engine
and the schema shape in one step removes the ability to tell which change broke
something. The relational tables in §4.3 come after the engine is proven.

Collections in use (**VERIFIED** from the modules that write them):
`feeds`, `feedsnapshots`, `feedindicators`, `policies`, `tenants`, `sites`,
`exceptions`, `approvals`, `audit`, `alerts`, `alertrules`, `evidence`.

### 4.2 Free-scan store — present shape (VERIFIED)

Firestore collection `scans`, document id = `scan_id`. Flat, **not**
tenant-partitioned. Fields written by `cloud-function/index.js`:
`scan_id`, `domain`, `target`, `email`, `status`, `created_at`, `timestamp`,
`source`, `client_name`, `client_id`, plus the whole scan report merged in by
`storeScanResults`, plus `completed_at`, `consensus`, `error`.

**34 documents as of 2026-09-06** (**VERIFIED** by counting a list response;
no stored value was read — see `STATUS.md`).

### 4.3 Target relational model (TARGET)

Relational where relational fits; NAS volume for blobs. Sketch — **not yet
implemented, column types not yet fixed**:

- `tenant(id, name, created_at)`
- `scan(id, tenant_id, target, status, started_at, completed_at, source, report_path)`
- `finding(id, scan_id, tenant_id, module, severity, confidence, category, asset, title, detail, remediation, fingerprint)`
- `feed(id, tenant_id, …)`, `feed_snapshot(id, feed_id, sha256, entry_count, status, fetched_at)`, `feed_indicator(feed_id, line_no, value)`
- `policy(id, tenant_id, version, state, …)`, `policy_rule(policy_id, …)`
- `approval(id, tenant_id, action, subject, payload_hash, state, …)`
- `audit(id, tenant_id, seq, prev_hash, hash, actor, action, payload)`
- `exception(id, tenant_id, site_id, expires_at, state, …)`

**Constraint that must survive the migration:** the audit chain is append-only
and hash-linked. A relational table must enforce that with an ordered `seq` per
tenant and a `prev_hash`/`hash` pair, and `verify()` must keep naming the exact
record where the chain breaks. **VERIFIED** that this works today over documents;
**TARGET** to preserve it over MariaDB.

**PII note (VERIFIED):** the free-scan record contains a submitter `email`. Any
migration carries personal data. It must land in a column that can be
selectively purged, and it must not be copied into artifact files on the NAS
volume.

---

## 5. Execution flow

### 5.1 Free scan — present, live (VERIFIED)

```
dashboard/public/index.html  (Firebase Hosting)
  │ POST { email, domain }
  ▼
triggerDNSScan (GCP Cloud Function, us-east5, public, CORS *)
  │ validates email + strict hostname; mints scan_id;
  │ writes scans/{scan_id} status=queued; creates HubSpot contact;
  │ dispatches dns-analysis.yml with scan_id
  ▼
GitHub Actions: dns-analysis.yml
  │ analyze  → tools/scan.py → report JSON (artifact, 90d)
  │ ai-consensus → IronCityIT/consensus-engine (workflow_call)
  │ store → POST storeScanResults
  │ report-failure → POST storeScanResults status=failed
  ▼
storeScanResults (Cloud Function) → Firestore scans/{scan_id}
  ▼
dashboard polls scans/{scan_id} by document id (get, not list)
```

**Status is monotonic** — a failure report never overwrites a completed scan.
**VERIFIED** in `cloud-function/index.js`.

### 5.2 Free scan — target (TARGET)

Identical up to GitHub Actions. Then:
`store` job POSTs to a **self-hosted ingest API** on NAS-backed infrastructure,
authenticated, which writes MariaDB and stores the raw report on a NAS volume.
The dashboard reads through an authenticated read API rather than talking to a
database directly from the browser.

### 5.3 Scheduled posture baseline (VERIFIED)

`dns-analysis.yml` runs `cron: '17 7 * * 1'` against `ironcityit.com`. Scheduled
runs carry no inputs, so the workflow's `|| default` fallbacks supply them.

### 5.4 Exposure ratchets (VERIFIED)

Run on every PR in `ci.yml`, job `Live exposure has not regressed`:
- `check-exposure.py` — unauthenticated GETs against the fleet's Firestore REST
  endpoints, comparing to `exposure-baseline.json`.
- `check-dns-exposure.py` — runs `alias_takeover` against our own domains,
  comparing to `dns-baseline.json`.

Both fail only on regression. Exit 2 means *nothing could be verified*, which is
deliberately not a pass.

---

## 6. Configuration

**VERIFIED** — environment variables read by the code:

| Name | Read by | Effect |
|---|---|---|
| `DNSGUARD_API_TOKEN` | `dnsguard/api.py` | Bearer token. **The API refuses to start without it** unless `allow_anonymous=True` (tests/dev only). |
| `DNSGUARD_DATA_DIR` | `dnsguard/api.py`, Dockerfile | Root for `JsonFileStore`. Unset → in-memory store. |
| `DNSGUARD_FETCH_FEEDS` | `dnsguard/api.py` | `1/true/yes` wires the HTTP feed fetcher. Off → maintenance reports feeds as "not attempted" rather than healthy. |

CLI flags of note: `tools/scan.py --nameservers` (resolvers that report NXDOMAIN
faithfully), `--modules`/`--group`, `--dry-run`;
`tools/maintain.py --fetch` (network off by default), `--dry-run`;
`tools/check-dns-exposure.py --require-certificate-transparency`.

---

## 7. Access, auth and RBAC

### 7.1 Control-plane API — present (VERIFIED, and weak)

- Transport auth: a **single shared bearer token** (`DNSGUARD_API_TOKEN`).
- Tenant: taken from the **`X-Client-Id` request header**.
- Actor: taken from the **`X-Actor` request header**.
- Roles: `VIEWER`, `OPERATOR`, `APPROVER` exist and every route declares what it
  needs.

**DEFECT D23 — VERIFIED, high.** `_header_auth` in `dnsguard/api.py` returns
`Principal(tenant_id=client_id, roles=[VIEWER, OPERATOR, APPROVER])`
unconditionally. So any holder of the one shared token can **claim any tenant**
and **holds every role, including approver**. Tenant isolation is enforced
between the claimed tenant and the path (`scoped()`), and that part works — but
the claim itself is not authenticated beyond the shared secret, and the approval
gate's separation of duties is not enforced by identity.

Mitigating fact (**VERIFIED**): the API is **not deployed anywhere**, so this is
not currently exposed. It is a blocker for deploying it, not a live incident.

**TARGET:** per-principal identity (Auth0 organisation → signed token carrying
`client_id` and roles), roles from the token, approver distinct from operator.

### 7.2 Free-scan surfaces (VERIFIED)

- `triggerDNSScan` — public, unauthenticated, `CORS *`. Rate limiting: **UNKNOWN**.
- `getScanStatus` — public, unauthenticated. Strips `email` from the response.
- `storeScanResults` — **UNKNOWN whether authenticated**. `deploy.sh` deploys it
  `--no-allow-unauthenticated` but then instructs the operator to make all three
  public by hand in the console. Whether that was done for this one is not
  established from the repo. **This must be checked before it is trusted.**
- Dashboard → Firestore: unauthenticated document `get`.

---

## 8. Security boundaries

**VERIFIED and working:**
- Scan input is validated twice (Cloud Function regex + workflow hostname
  allow-list) before ever reaching a command line. No `eval`; arguments are built
  as an argv array from env.
- The feed fetcher refuses non-public addresses (cloud metadata, loopback,
  private, link-local), refuses plain HTTP by default, follows redirects by hand
  so every hop is re-checked, and caps response size.
- The takeover module verifies its resolver with a control probe before trusting
  a negative answer.
- Approval gate fails closed; unregistered actions are refused.
- Audit chain detects edit, deletion, and re-signing with a recomputed hash.
- Dashboard builds all DOM from `textContent`; the console has zero inline
  script/style and a strict CSP with no `unsafe-inline`.

**VERIFIED and open:**
- Firestore `list` is permitted on the live `icit-dnsguard` project, returning
  all stored scans with `email`, `client_name`, `domain`, `client_id`. The
  committed `firestore.rules` would close it; **those are not the deployed rules**.
- `vpn.ironcityit.com` is a claimable subdomain takeover (see §12).
- D23 above.
- D24 below.

**DEFECT D24 — VERIFIED, high. Committed credential.**
`deploy.sh` assigned a **live-format HubSpot private-app token as a shell default
value**. Present since commit `a0d0759` (2026-01-30) and therefore in the public
git history of this repository, not only at HEAD.

The `secrets` gate reported "no committed credentials found" throughout, because
its pattern list covered AWS, PEM private keys, GitHub and Slack tokens only, and
its literal-assignment check was scoped to `.github/workflows/` — so a literal in
a shell script at repo root was invisible to it (`tools/gates.sh`, `gate_secrets`).

Both are addressed in the same change that introduces this document:
`deploy.sh` is removed (it deploys retired Firebase/GCP infrastructure and has no
place in target state), and the gate is broadened.

**DEFECT D25 — VERIFIED, high. The secrets gate's private-key rule had never
run.** Found while writing a test for the broadened gate, not by review.

`gate_secrets` iterated its rules with `for pattern in $patterns`, which
word-splits on `IFS`. The PEM rule — `-----BEGIN [A-Z ]*PRIVATE KEY-----` —
contains spaces, so it was never applied as written. It became four fragments:
`-----BEGIN`, `[A-Z`, `]*PRIVATE`, `KEY-----`.

Worse, each fragment was passed to `grep` as a **positional argument**, and a
pattern beginning with `-` is parsed as options:

```
$ grep -rIEn '-----BEGIN' file
grep: unrecognized option '-----BEGIN'      # exit 2
```

The gate wrapped that in `if grep …; then hits=…`, and `if` reads grep's *error*
exit exactly as it reads "no match". So the rule failed, silently, on every run
since it was written. **A committed PEM private key would have passed this gate.**

Fixed three ways, because the third is what stops it recurring:
1. `IFS` pinned to newline for the loop, so a rule containing spaces stays one rule.
2. `-e "$pattern"` everywhere, so a rule may begin with `-`.
3. **Every rule is compile-checked before use**, and a rule that does not compile
   fails the gate loudly instead of contributing nothing. This check caught the
   PEM rule on its very first run.

`tests/test_gates.py` now plants nine credential shapes and requires the gate to
fail on each, plants a Firebase Web API key and requires it to pass, and asserts
the shipped tree is clean. Its own fixtures are assembled at runtime so the file
carries no matching literal — with a test enforcing that, because the tempting
alternative is to exclude `tests/` from the scan, which would hand a real secret
somewhere to hide.

> **ROTATION IS STILL REQUIRED AND IS NOT DONE.** Deleting the file does not
> remove the value from git history. The token must be revoked and reissued in
> HubSpot by a person with access. **BLOCKED** — no HubSpot credential or admin
> access exists in this environment. The value is deliberately not reproduced in
> this document; read it from `git show a0d0759:deploy.sh` if needed for
> revocation.

---

## 9. Secrets — by name only

Never write a value into a file. All of these are referenced by name.

**In use / expected (VERIFIED as names in workflows and code):**
`GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `IRONCITY_API_KEY`,
`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `STORE_SCAN_RESULTS_URL`,
`DNSGUARD_CLOUD_FUNCTION_URL`, `FIREBASE_SERVICE_ACCOUNT`, `GITHUB_TOKEN`.

**Present on the repository (VERIFIED via `gh secret list`, 2026-09-06):**
`GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `IRONCITY_API_KEY`,
`STORE_SCAN_RESULTS_URL`, `DNSGUARD_CLOUD_FUNCTION_URL`.

**Absent (VERIFIED):** `FIREBASE_SERVICE_ACCOUNT`.

**Referenced by the deployed Cloud Function, set outside this repo (VERIFIED as
names in `cloud-function/index.js`):** `HUBSPOT_API_KEY`, `GITHUB_PAT`,
`STORE_RESULTS_URL`.

**TARGET, not yet created:** MariaDB credentials, NAS volume credentials, ingest
API token. Names to be agreed with whoever provisions them; not invented here.

---

## 10. Network and deployment

**VERIFIED:**
- **Nothing in this repository can be deployed from the current environment.**
  No `gcloud`, no `firebase` CLI, no application-default credentials, and
  `FIREBASE_SERVICE_ACCOUNT` is not on the repository. Re-checked 2026-09-06.
- `firebase-deploy.yml` has failed on **every** push to `main` with
  `Input required and not supplied: firebaseServiceAccount`.
- Consequence: every dashboard change since the stored-XSS fix is committed to
  `main` and **unpublished**. The live site serves the last hand-deployed build.
- `Jenkinsfile` deploys nothing by design; it runs the same `tools/gates.sh`.
- A `Dockerfile` exists for the control plane (non-root uid 10001, `/data`
  volume, refuses to start without `DNSGUARD_API_TOKEN`). **UNKNOWN** whether it
  has ever been built — no Docker in this environment, and the build gate SKIPs
  loudly rather than passing.

**TARGET:** control-plane API and ingest API run as containers on NAS-backed
infrastructure; the dashboard is served as static files from the same
infrastructure; GitHub Actions reaches the ingest API over an authenticated
channel. Reachability from GitHub-hosted runners to the NAS is **UNKNOWN** and
is the first infrastructure question to answer — it decides whether self-hosted
runners are required.

---

## 11. Migration away from Firebase

Every Firebase/Firestore/GCP reference in the repository, classified.
**VERIFIED** by `grep -rniE "firebase|firestore|gcp|cloudfunctions|web\.app"`.

| Path | What it is | Disposition |
|---|---|---|
| `deploy.sh` | Manual Cloud Shell script: deploys 3 Cloud Functions + Firebase Hosting. Also held D24. | **REMOVE** — done in this change |
| `.github/workflows/firebase-deploy.yml` | Hosting deploy; has never succeeded | **REMOVE** in Phase 4 |
| `firebase.json` | Hosting config, CSP + security headers, rewrites | **MIGRATE** — the header/CSP policy is worth keeping; it must be re-expressed for the self-hosted web server |
| `firestore.rules` | Firestore security rules | **REMOVE** in Phase 4; replaced by API-side authorisation |
| `cloud-function/index.js` + `package.json` | `triggerDNSScan`, `storeScanResults`, `getScanStatus` | **MIGRATE** — reimplement as the self-hosted ingest/trigger/read API. Contains the only HubSpot integration. |
| `.github/workflows/dns-analysis.yml` | `store` and `report-failure` jobs POST to `storeScanResults` | **MIGRATE** — repoint to the ingest API in Phase 3 |
| `dashboard/public/index.html` | Loads Firebase JS SDK; reads Firestore directly | **MIGRATE** — read through the API instead |
| `dashboard/public/console.html`, `console.js` | Talks to `*.run.app` / `*.cloudfunctions.net` | **MIGRATE** — repoint to the control-plane API |
| `dnsguard/store.py` | Docstring references the Firestore layout | **KEEP** — code has **no** Firestore dependency; comment to be reworded |
| `dnsguard/api.py`, `report.py` | Comments referencing Firestore | **KEEP** — comments only |
| `dnsguard/exposure.py`, `tools/check-exposure.py`, `exposure-baseline.json`, `tests/test_exposure.py` | **Measure** what the live Firestore projects expose | **KEEP while Firestore exists.** This is not a dependency — it is the instrument that proves the exposure is closing. Retire only when the projects are decommissioned. |
| `index.html` (repo root), `dashboard/public/index.html.{backup,old}` | Stale duplicates carrying an old Firebase config | **REMOVED** in this change. **VERIFIED unserved**: Firebase Hosting serves only `dashboard/public`, and `.backup`/`.old` are in its ignore list |
| `README.md`, `STATUS.md`, `PRODUCTIZE_NOTES.md`, `docs/UI-WIRING.md` | Describe the Firebase architecture as current | **UPDATE** — this document supersedes the architecture sections |

### Phased plan (TARGET)

**No phase performs a destructive migration. Data is copied and verified before
anything is switched, and nothing is deleted until the replacement is proven.**

- **Phase 0 — document and stop the bleeding.** This document; remove `deploy.sh`;
  broaden the secrets gate. *(This change.)*
- **Phase 1 — MariaDB-backed `DocumentStore`.** Additive: a new implementation
  behind the existing abstraction. Nothing switches to it. Contract tests run
  against all implementations. **DONE, with one caveat** — `dnsguard/sqlstore.py`.
  The full `DocumentStore` contract is **VERIFIED** against a real engine
  (SQLite) through this class. Execution against a live **MariaDB is NOT
  VERIFIED**: no server, no client library and no container runtime exists in
  the environment it was written in, so the MariaDB dialect's DDL and upsert are
  asserted as statements and have never been run. **The first connection to a
  real MariaDB is the test that has not happened yet.** The dialect is four
  strings, separated deliberately so that test is cheap.
- **Phase 2 — self-hosted ingest + read API** on NAS infrastructure, replacing
  `storeScanResults` and `getScanStatus`, writing MariaDB and NAS volumes.
  Authenticated; tenant-partitioned from the first row.
- **Phase 3 — cut over.** `dns-analysis.yml` writes to both stores, then to the
  new one only. Dashboard reads through the API. Existing 34 scan documents are
  **exported and imported, then reconciled by count and checksum** before the
  Firestore path is switched off.
- **Phase 4 — retire.** Delete `firebase-deploy.yml`, `firestore.rules`,
  `cloud-function/`, `firebase.json`. Decommission the GCP projects. Retire the
  exposure ratchet last, once there is nothing left to measure.

**Blocking unknowns for Phases 2–4:** NAS/MariaDB connection details, runner
reachability, TLS, backup/restore procedure, who owns rotation of the new
secrets. None are guessed here.

---

## 12. Known defects and blockers

| # | Sev | Defect | State |
|---|---|---|---|
| **D24** | High | Live-format HubSpot token committed in `deploy.sh` since `a0d0759`; secrets gate blind to it | File removed and gate broadened in this change. **ROTATION BLOCKED — needs a person with HubSpot access.** |
| **D25** | High | Secrets gate's PEM private-key rule never ran — word-split, then rejected by grep as an option, then silently skipped | **Fixed** in this change: IFS pinned, `-e` used, and every rule compile-checked so a dead rule fails loudly |
| **D23** | High | Shared API token grants *any* tenant and *all* roles, approver included | Open. Not exposed (API undeployed). Blocks deployment. |
| — | High | Live Firestore permits unauthenticated `list` of all 34 scans incl. submitter emails | Open. **BLOCKED** on deploy credential or a console action. ShadowScan proves the console route needs no service account. |
| — | Critical | `vpn.ironcityit.com` → `icit.mynetgear.com` (NXDOMAIN) on a self-service dynamic-DNS zone: claimable subdomain takeover on a trusted hostname | Open, monitored by `check-dns-exposure.py`. **One DNS change: delete or re-claim.** Needs DNS access this environment does not have. |
| — | High | `iron-city-it-threatinspector` carries original test-mode rules; `ironcity-attacksimpro` permits enumeration | Flagged, **not this repo's to change** |
| — | Med | Nothing can be deployed: no `gcloud`/`firebase`/ADC, `FIREBASE_SERVICE_ACCOUNT` absent | Open, environmental |
| — | Med | Certificate transparency does not answer from GitHub runners, so the DNS ratchet sweeps 56 conventional names only | Reported by the gate; fatal only with `--require-certificate-transparency` |
| — | Low | Docker image never built — no Docker available; gate SKIPs loudly | Open, environmental |
| — | Low | Three stale duplicate dashboard files | **Fixed** — removed, after verifying none is served |

---

## 13. Tests and gates

`sh tools/gates.sh all` — eleven gates, one definition of green, three callers
(local, `ci.yml`, `Jenkinsfile`):

lint (ruff) · format (ruff) · typecheck (mypy) · test (pytest+coverage) ·
JSON contract · workflow YAML (PyYAML + actionlint + shellcheck) ·
cloud function (`node --check`) · dashboard (`node --check` on extracted inline
JS) · secret hygiene · shellcheck on the gate script itself · build.

Plus the CI-only `exposure` job (§5.4). **VERIFIED green**, 532 tests.

Reproduce:
```sh
python3 -m pip install -r requirements-dev.txt
sh tools/gates.sh all
python3 tools/scan.py --domain ironcityit.com --group standard -o ./reports
python3 tools/check-dns-exposure.py --baseline dns-baseline.json --nameservers 1.1.1.1,8.8.8.8
```

---

## 14. Operational runbooks

**Run a scan by hand.**
`python3 tools/scan.py -d <domain> -c <client> --group standard -o ./reports`.
Add `--nameservers 1.1.1.1,8.8.8.8` if the local resolver may not report NXDOMAIN
faithfully — the takeover check will otherwise report `inconclusive` rather than
guess, which is correct but unhelpful.

**Maintenance pass.**
`python3 tools/maintain.py --data-dir <dir> --all` (network off);
add `--fetch` to refresh feeds. Exit 1 only when a tenant reported a problem, so
cron mail means something is wrong.

**A free scan is stuck.** Check the `dns-analysis.yml` run for that `scan_id`.
`report-failure` should have written a terminal state; if it did not, the
dashboard will spin. Confirm `storeScanResults` returned 2xx in the run log.

**Exposure gate went red.** Exit 1 = a posture got worse; the output names the
host and both postures. Exit 2 = nothing was verified (untrustworthy resolver, or
strict coverage requested and certificate transparency did not answer) — this is
*not* a pass; re-run with `--nameservers`.

**Suspected credential exposure.** Do not print the value. Identify the commit
with `git log -S`, revoke at the provider first, then remove from HEAD, then
broaden `gate_secrets` so the pattern cannot recur.

---

## 15. Rollback and DR

**VERIFIED today:**
- Code: every change lands through a PR onto `main`; `git revert` is the rollback.
- Scan reports: GitHub Actions artifacts, 90-day retention. This is currently the
  only durable copy of a report outside Firestore.
- `JsonFileStore` writes atomically (temp file + `os.replace`), so a crash cannot
  leave a half-written policy or audit record.

**UNKNOWN — no evidence exists either way:**
- Whether Firestore has ever been backed up, and whether point-in-time recovery
  is enabled on `icit-dnsguard`.
- Whether any restore has ever been tested.

**TARGET:** MariaDB logical backups on a defined schedule to a separate NAS
volume, with restore rehearsed and evidenced; artifact volume snapshotted;
documented RPO/RTO. **None of these figures are set — do not invent them.**

---

## 16. Enhancements and backlog

Ordered by value, nonblocked first.

1. **Run `dnsguard/sqlstore.py` against a real MariaDB.** Everything else in
   Phase 2 rests on it, and it is currently the only unexecuted code path in the
   storage layer. Needs a server; nothing else.
2. **Decide the connection driver and add it to `requirements.txt`.** The store
   takes any DB-API 2.0 factory, so this is a deployment choice rather than a
   code one, and it is deliberately not made here.
3. **Fix D23** — real per-principal identity and roles; approver ≠ operator.
4. **Phase 2 ingest API**, tenant-partitioned from the first row.
5. **Re-express `firebase.json`'s CSP and security headers** for the self-hosted
   server, so the hardening survives the move rather than being rediscovered.
6. **Change detection** — `Finding.fingerprint()` exists and is stable across
   scans, but nothing yet diffs two scans into new/resolved/still-open.
7. **`AssetSink` is dead code** — `module_framework/base.py` defines a
   deduplicating inventory sink, `tools/scan.py` never creates one and no module
   uses it. Either wire it up or remove it.
8. **Coverage gaps**: `module_framework/cli.py` 0%, `network_path` 33%,
   `resolver_performance` 33%, `transport_security_audit` 42%.
9. **Rate limiting** on the public trigger endpoint — currently **UNKNOWN**.

---

## 17. Evidence and provenance

Everything asserted as VERIFIED above traces to one of these.

| Claim | How it was established | When |
|---|---|---|
| 532 tests, 89% coverage, 11 gates green | `sh tools/gates.sh all` | 2026-09-07 |
| 11 scan modules registered | `python3 tools/scan.py --list-modules` | 2026-09-07 |
| `vpn.ironcityit.com` claimable takeover | `tools/scan.py --modules alias_takeover --nameservers 1.1.1.1,8.8.8.8` → CRITICAL, `claimable_service`, apex `mynetgear.com` | 2026-09-06 |
| Public resolvers return NXDOMAIN for `icit.mynetgear.com`; sandbox resolver returns SERVFAIL | Direct `dns.resolver` queries against 1.1.1.1, 8.8.8.8, 9.9.9.9 and the host resolver | 2026-09-06 |
| Sandbox resolver reports NODATA for non-existent names | Same | 2026-09-06 |
| Firestore `list` open on `icit-dnsguard`, 34 documents | `tools/check-exposure.py`; read-only status codes, no stored value read | 2026-09-06 |
| Fleet postures (ShadowScan closed; ThreatInspector test-mode) | Same tool, `--all` | 2026-09-06 |
| Repo secrets present/absent | `gh secret list` | 2026-09-06 |
| No deploy credential in environment | `which gcloud firebase`, `ls ~/.config/gcloud`, env scan | 2026-09-06 |
| Hosting deploy has never succeeded | `gh run list` — `Deploy to Firebase Hosting` failure on every `main` push | 2026-09-06 |
| Live feed fetch: 376 indicators, then 304 unchanged | `tools/maintain.py --fetch` twice against a live publisher | 2026-09-06 |
| SSRF guard refuses metadata/loopback/private over https | Direct `HttpFetcher.check()` calls | 2026-09-06 |
| CI runner sweeps 56 names (certificate transparency unavailable) | `gh run view --log`, DNS comparison step | 2026-09-06 |
| D24 committed since `a0d0759` (2026-01-30) | `git log -S` on `deploy.sh` | 2026-09-07 |
| D23 grants all roles and any tenant | Read of `_header_auth` in `dnsguard/api.py` | 2026-09-07 |
| D25 — PEM rule word-split into four fragments | `for p in $patterns` echoed in `sh`, showing the split tokens | 2026-09-07 |
| D25 — grep rejects a `-`-leading pattern as an option (exit 2, read as "no match") | `grep -rIEn '-----BEGIN' file` → `grep: unrecognized option` | 2026-09-07 |
| Gate now fires on 9 planted shapes and passes a Firebase Web key | `pytest tests/test_gates.py` — 15 passed | 2026-09-07 |
| `deploy.sh`, `index.html`, `index.html.backup`, `index.html.old` unserved | `firebase.json` hosting public dir is `dashboard/public`; `.backup`/`.old` in its ignore list | 2026-09-07 |
| No MariaDB/driver/Docker in environment | `which`, import probes for `pymysql`, `MySQLdb`, `sqlalchemy` | 2026-09-07 |
| SQL store passes the whole `DocumentStore` contract on a real engine | `pytest tests/test_store.py` parametrised over memory/file/sql (SQLite) | 2026-09-07 |
| SQL store reconnects once after a dead socket, and does not loop | `pytest tests/test_sqlstore.py` — 24 passed | 2026-09-07 |
| MariaDB dialect **never executed** | No server, driver or container runtime available — stated, not worked around | 2026-09-07 |

**Anything not in this table, and not labelled TARGET, should be treated as
UNKNOWN until somebody establishes it.**
