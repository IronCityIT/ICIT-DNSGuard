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

---

# Verification run — 2026-09-06

**Branch:** `productize/dnsguard-exposure-verification` · **Base:** `main`
**Read-only.** Three unauthenticated GETs per project against the Firestore REST
API, plus DNS lookups. No write was attempted anywhere, nothing was deployed,
and no client's scan document was read — the document probes use an id this
product does not mint, and where a page of results was returned only the
document count and the *field names* were taken from it. No stored value was
read, printed or written down.

This run went and checked the two items the previous run left at the top of
"what to do next". Both were still open. One of them is not what this document
said it was.

## Correction — the live rules are deployed, and they are not the ones in this repo

The blockers table above records the live project as carrying "open test-mode
rules (world-readable **and** world-writable)", and records `firestore.rules` as
inert until `FIREBASE_SERVICE_ACCOUNT` lands. Neither is accurate today.

| Probe | Result | What it means |
|---|---|---|
| `get` a scan id that does not exist | `404` | Single-document reads are permitted |
| `list` the scans collection | **`200`** | **Enumeration is permitted** |
| `get` a collection this product never writes | `403` | **A rules file is deployed** — test-mode would answer `404` |

A rules file *is* in force: the catch-all deny works. But it is not the file in
this repository, because the committed rules set `allow list: if false` and
listing plainly succeeds. Something narrower than test-mode was deployed at some
point, and it still permits the harvesting the committed file was written to
close.

**One unauthenticated request returns all 34 stored scans**, and those documents
carry `email`, `client_name`, `domain` and `client_id` — every person who used
the free scan, their address, their domain, and the findings against it.

The write posture is **unverified and stated as such**: proving a write path is
open means writing to a live client-facing system, which this run would not do.
The earlier "world-writable" claim was inferred from test-mode rules that are
demonstrably no longer the whole story, so it should not be repeated until it is
either tested deliberately or the rules are read from the console.

## Fleet state — the same probe against every product project

| Project | Rules deployed | Single-doc read | **Enumeration** | Stored docs | Identifying fields exposed |
|---|---|---|---|---|---|
| `icit-shadowscan` | yes | closed | **closed** | — | none reachable |
| `icit-dnsguard` | yes | open | **OPEN** | 34 | `email`, `client_name`, `domain`, `client_id` |
| `ironcity-attacksimpro` | yes | open | **OPEN** | 23 | none in the returned page |
| `iron-city-it-threatinspector` | **NO — test-mode** | open | **OPEN** | 25 | `client_id`, `target` |

Two things follow, and the second is the more useful one.

**Threat Inspector is in the worst position**, not this product: an unknown
collection answers `404` there, which is how a project behaves when it still
carries the rules it was created with. Anything a rules file would deny is
allowed there today.

**ShadowScan is closed, on the same fleet, with the same missing service
account.** Whatever was done there did not need `FIREBASE_SERVICE_ACCOUNT`, so
"we cannot close this until the secret is minted" is not true as a general
claim. Its rules are the pattern to copy, and copying them is a console action
measured in minutes.

## Correction — the consensus secrets are no longer missing

The blockers table lists `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`
and `IRONCITY_API_KEY` as absent. All four are present on this repository, set
`2026-08-25`, along with `STORE_SCAN_RESULTS_URL` and
`DNSGUARD_CLOUD_FUNCTION_URL`. The `ai-consensus` blocker is stale.

`FIREBASE_SERVICE_ACCOUNT` is still genuinely absent, and no Firebase or gcloud
credential exists in this environment, so deploying remains impossible from
here. That one is real.

## `vpn.ironcityit.com` — confirmed, with the mechanism named

Item 1 of the previous run's next-steps list. Still live, and worse than
"does not resolve":

```
vpn.ironcityit.com.   CNAME   icit.mynetgear.com.     <- record still published
icit.mynetgear.com.   A       NXDOMAIN                <- destination is gone
mynetgear.com.        SOA     ns2.no-ip.com.          <- self-service dynamic DNS
```

The destination sits on a **self-service dynamic-DNS service**, where hostnames
are claimed by whoever registers them. An `NXDOMAIN` there means the name is
unregistered. Whoever claims `icit` on that service controls what
`vpn.ironcityit.com` answers — on a hostname called *vpn*, which is exactly the
name a staff member or a client would trust with credentials.

Confirmed by this product's own `subdomain_discovery` module against
`ironcityit.com`: 20 hosts resolve, and this is the only dangling alias among
them. No attempt was made to claim the destination — that is an action against a
third party's service and needs a person.

**Remediation is one DNS change: delete the record, or re-claim the name.**

## What this run added

| File | What it is |
|---|---|
| `dnsguard/exposure.py` | Turns three unauthenticated probes into a verdict. Injected transport, so the tests never touch the network |
| `tools/check-exposure.py` | `python3 tools/check-exposure.py --project icit-dnsguard`. Exits non-zero on a high finding, so CI can gate on it once the rules are correct |
| `tests/test_exposure.py` | 10 tests, including the two mistakes that matter: reading a `404` as a denial, and reading a failed probe as a pass |

The reason this is a tool and not a paragraph: this document confidently
described the live rules, and was wrong, for a fortnight. A claim about a
production security boundary should be re-checkable in one command by whoever
next doubts it.

## What to do next, in order — revised

1. **Deploy `firestore.rules`, or paste it into the console.** ShadowScan proves
   this does not need the missing service account. It closes enumeration of 34
   scans and every submitter email on this product today.
2. **Do the same for Threat Inspector**, which has no rules at all, and for
   AttackSim Pro. Neither is this repository's to change — flagged, not touched.
3. **Delete or re-claim `vpn.ironcityit.com`.** One record, minutes.
4. **Mint `FIREBASE_SERVICE_ACCOUNT`** — still the thing that unblocks functions
   and hosting deploys fleet-wide, and the stored-XSS fix with them.
5. **Auth0 → Firebase custom token** with a `client_id` claim, after which the
   `get` rule becomes a tenant comparison and the last unauthenticated read path
   closes.

Items 1–3 need no secret and no deploy pipeline.

---

# Feed runtime run — 2026-09-06

**Branch:** `productize/dnsguard-feed-runtime` · **Base:** `main` (at `c843b9c`,
which is PR #7 merged — the exposure verification and its CI ratchet are now on
`main`).

This run closed the gap between a feeds subsystem that passes its tests and one
that can actually run. Two defects behind it were the kind that fail quietly in
the direction of *less* protection, which is the direction that does not get
noticed.

## DEFECTS found and fixed

| # | Severity | Defect | Status |
|---|---|---|---|
| D11 | **High** | Indicators were never persisted. `FeedFetcher.refresh` returned a list and stored nothing, so a control plane that restarted decided against an empty index — and an empty index is indistinguishable from a clean lookup. A name on three blocklists resolved as **allowed**, silently, until the next refresh window | **Fixed** — entries persisted per feed with full provenance; `load_index` rebuilds a tenant's index from disk |
| D12 | **High** | `GET /decide` — the "explain this block" endpoint — passed no indicator index at all, so category and feed rules matched nothing. It reported a clean allow for a name on a live blocklist, which is exactly the answer an operator would repeat to a client | **Fixed** — loads the tenant's persisted index |
| D13 | **Medium** | Nothing in the repository could fetch a feed. The transport is an injection, which is what makes it testable, and no implementation of it existed. Every test supplied a lambda; in production the parameter had nothing to bind to | **Fixed** — `dnsguard/fetcher.py` |
| D14 | **Medium** | No periodic loop. Feeds aged into staleness, lapsed exceptions were never written down, and alert rules were never evaluated — all silently, with no event marking the decay | **Fixed** — `dnsguard/maintenance.py`, a CLI and an HTTP route |

## PROVEN — verified this run

| Area | What was verified | Result |
|---|---|---|
| **Gates** | All eleven `tools/gates.sh` gates | ✅ green |
| **Tests** | 462 tests, 89% line coverage. Still no test touches the network | ✅ 462/462 |
| **Live feed fetch** | `tools/maintain.py --tenant acme --fetch` against a real publisher over https, through the SSRF guard | ✅ 376 indicators persisted |
| **Conditional refresh** | Second pass on the same feed: publisher answered `304`, snapshot recorded `unchanged`, all 376 entries kept, `degraded` empty, freshness clock restarted | ✅ |
| **Persistence** | Fresh process, `load_index` off disk: 376 indicators back with feed id, snapshot id, sha256, line number, category and trust tier intact. A known entry hits; a clean name does not | ✅ |
| **SSRF guard** | Checked directly over **https**, so the scheme rule is not doing the work alone: `169.254.169.254` (cloud metadata), `127.0.0.1`, `10.0.0.5`, `[::1]` and `localhost` all refused. Metadata still refused with `allow_insecure=True` | ✅ |
| **Approval gate** | A maintenance pass consumes no approval — asserted by test. The gate is only worth having if nothing routes around it, background jobs included | ✅ |
| **Audit chain** | Valid after every live pass; a broken chain is the loudest thing the runner reports | ✅ |

## Two failure modes deliberately covered by tests

Both fail quietly toward less protection, which is why they are asserted rather
than reasoned about:

* **A 304 read as an empty feed.** The body of a 304 is empty by definition.
  Parsing it as the feed's contents would drop every block the feed supported,
  and the pass would report success.
* **A 304 read as degradation.** Counting a correctly-cached feed as failed makes
  a healthy feed look broken, and `latest_snapshot` excluding `unchanged` would
  let a stable feed age into staleness and lose the right to justify a block.

## Stated residual, not hidden

The fetch guard resolves the host and then connects, which are two steps. A name
that resolves differently between them (DNS rebinding) is not defeated by this;
closing it needs connection-level pinning that `requests` does not expose. The
guard stops the careless and the opportunistic and is not a substitute for egress
filtering on the runner. This is in the module docstring as well as here.

## How to run the loop

```sh
python3 tools/maintain.py --data-dir ./data --all --dry-run   # what a pass would touch
python3 tools/maintain.py --data-dir ./data --tenant acme     # pass, no network
python3 tools/maintain.py --data-dir ./data --tenant acme --fetch
```

Fetching is off unless `--fetch` is given: feed URLs are operator-supplied, and a
pass that quietly reached out to every one of them the first time somebody ran it
would be a surprise. Exit 1 only when a tenant reported a problem, so cron mail
arrives when something is wrong and not otherwise.

`POST /api/v1/tenants/{id}/maintenance` is the same pass for a scheduler with no
shell on the host — operator role, tenant-scoped like every other route.

## Unchanged blockers

`FIREBASE_SERVICE_ACCOUNT` is still absent and no Firebase or gcloud credential
exists in this environment, so nothing can be deployed from here. The live
Firestore enumeration recorded in the previous run is still open and still needs
the console action described there — this run did not and could not change it.

---

# Takeover verification run — 2026-09-06

**Branch:** `productize/dnsguard-takeover-verification` · **Base:** `main` (at
`18b4c83`, PR #8 merged).

The previous runs found `vpn.ironcityit.com` dangling and then worked out *by
hand* why it mattered — the destination is NXDOMAIN, its parent is served by a
self-service dynamic-DNS provider, so the name is claimable and the hostname is
one staff are taught to trust. The product could not reach that conclusion
itself. Its dangling-alias finding said "**if** the destination is a
de-provisioned hosting account…", and that "if" was the entire finding.

This run makes the product do the analysis.

## DEFECTS found and fixed

| # | Severity | Defect | Status |
|---|---|---|---|
| D15 | **High** | Dangling aliases were reported without any check of whether the destination was claimable. A CNAME typo and a live takeover produced the same finding at the same severity, so the real one could not be picked out | **Fixed** — `alias_takeover` names the mechanism and who could claim it |
| D16 | **High** | `_dns.query` collapsed NXDOMAIN, NODATA and a timeout to an empty list. Every takeover conclusion depends on telling those apart, and nothing could | **Fixed** — `resolution()` reports which |
| D17 | **High** | Found by running the module against a live domain, not by review: **a resolver that answers NODATA for names that do not exist turns every real takeover into "a broken record, not a risk"** — a false negative on the most serious finding the product makes. The resolver in this sandbox does exactly that | **Fixed** — a control probe verifies the resolver before any verdict is trusted |
| D18 | **Medium** | The report ignored `Finding.remediation` and read only `evidence["remediation"]`. `base.py`'s own contract says the fix travels in the finding — so any module using the documented field rendered a **blank remediation** to the client. `base.py` calls a finding without a fix "a complaint" | **Fixed** — field first, legacy key as fallback |
| D19 | **Medium** | `confidence` and `asset` never reached the report. An inconclusive check rendered identically to a proven one, and every finding showed the scan target rather than the affected host | **Fixed** — both carried, plus the fingerprint |
| D20 | **Low** | `CATEGORY` says a new module "has to declare where it belongs rather than defaulting into General". Nothing enforced it and two modules had already fallen through, so whole capabilities showed as "General" | **Fixed** — and a test now fails when a registered module has no category |

## The control probe, and why it is the most important part

Every verdict rests on distinguishing "this name does not exist" from "this name
exists without an address". Resolvers in the wild do not report that faithfully —
filtering resolvers, captive portals and the Docker resolver in this sandbox all
rewrite negative answers, and a zone that wildcards never produces NXDOMAIN for
anything.

So before drawing any conclusion about a destination, the module looks up a
random name under the same parent. That name cannot exist, so a resolver worth
believing must call it NXDOMAIN. When it does not, the verdict is `unresolved`
and says why, instead of quietly reporting the safe answer.

This is not hypothetical. The first live run of this module produced exactly the
inconclusive verdict, because the sandbox resolver returned SERVFAIL for the
destination and NODATA for names that do not exist. Without the control, the
same run would have reported the live takeover on our own domain as a low
severity broken record.

## PROVEN — verified this run

| Area | What was verified | Result |
|---|---|---|
| **Gates** | All eleven `tools/gates.sh` gates | ✅ green |
| **Tests** | 30 new takeover tests, 8 new report-contract tests, whole suite green | ✅ |
| **Live run, conformant resolver** | `tools/scan.py --domain ironcityit.com --modules alias_takeover --nameservers 1.1.1.1,8.8.8.8` | ✅ **critical**, `claimable_service` |
| **Live run, broken resolver** | Same scan on the sandbox resolver | ✅ **inconclusive**, not a false clean |
| **Mechanism named** | `vpn.ironcityit.com → icit.mynetgear.com`, apex `mynetgear.com`, dynamic DNS, open signup, trusted label | ✅ matches the hand analysis exactly |
| **No third-party action** | Nothing claimed, registered or reserved. Read-only lookups; contact class `dns`, so no packet reaches the scanned host | ✅ asserted by test |

The live finding, verbatim from the report:

> **CRITICAL** — An alias points at a name somebody else can claim.
> `vpn.ironcityit.com` is an alias for `icit.mynetgear.com`, which does not
> exist. Its parent `mynetgear.com` is a dynamic DNS service, where names under
> it are handed out to whoever asks for them first. Claiming this one takes an
> account and a few minutes. `vpn.ironcityit.com` is a name staff and clients are
> taught to trust, so content served there would be believed, and a certificate
> for it would validate.

## Stated limits

The claimable-zone list is a floor, not a ceiling. A destination under an
unlisted zone still produces a dangling finding — at `possible` confidence,
because the claim mechanism has not been established, not because it is safe.
Confirming a takeover by performing one would mean claiming a name on a third
party's service, which is an action against somebody else's system and needs a
person; the module never does it, and the confidence field says where proof
stops.

## Still open, unchanged by this run

`FIREBASE_SERVICE_ACCOUNT` remains absent — independently re-checked this run: no
`gcloud` or `firebase` CLI, no application-default credentials, and the secret is
not on the repository. Nothing was deployed. The live Firestore enumeration
recorded earlier is still open.

**`vpn.ironcityit.com` is still live and still claimable.** The product can now
find it on its own, which does not fix it. One DNS change: delete the record, or
re-claim the destination.

---

# DNS exposure ratchet — 2026-09-06

**Branch:** `productize/dnsguard-finding-fidelity` · **Base:** `main` (at
`0c6ee13`, PR #9 merged).

The previous run gave the product the ability to find a claimable takeover on
its own. Nothing re-checked it. A finding recorded in a document decays into
folklore — this repository has already demonstrated that, by confidently
describing a production security boundary and being wrong about it for a
fortnight. So the alias posture gets the same treatment the Firestore posture
already has: a recorded baseline that CI compares against reality.

## What was added

| File | What it is |
|---|---|
| `dnsguard/dns_exposure.py` | The comparison. Postures ranked best-to-worst; only a posture *worse* than the record fails |
| `tools/check-dns-exposure.py` | `python3 tools/check-dns-exposure.py --baseline dns-baseline.json`. Runs the product's own `alias_takeover` module against our domains |
| `dns-baseline.json` | What each alias was verified to be, and why — including the still-open `vpn.ironcityit.com`, recorded at its true severity |
| CI job step | Runs on every PR, in the existing `Live exposure has not regressed` job |
| `tests/test_dns_exposure.py` | 21 tests |

## Three exit codes, because they need three different responses

| Code | Meaning |
|---|---|
| 0 | Every alias is as recorded, or better |
| 1 | An alias is **worse** than recorded, or a new bad one appeared |
| 2 | **Nothing could be verified** — the resolver's negative answers could not be trusted |

Exit 2 is the one worth arguing for. A check that could not measure anything and
reports a pass is precisely the false reassurance this ratchet exists to prevent,
so "unverified" is its own outcome rather than being folded into either a pass or
a regression. `unresolved` is deliberately not a rung on the posture ladder: it
is the absence of a measurement, and comparing it against a recorded rung would
either invent a regression or hide one.

An unlisted alias is treated as expected-to-resolve, so a **new** dangling alias
fails the gate the first time it appears. That is the point of the file.

## PROVEN — verified this run

| Check | Command | Result |
|---|---|---|
| Regression is detected | `--domain ironcityit.com --nameservers 1.1.1.1,8.8.8.8` with no baseline | ✅ exit **1**, `vpn.ironcityit.com` reported `claimable_service` |
| An untrustworthy resolver does not pass | same, on the sandbox's own resolver | ✅ exit **2**, "This is not a pass" |
| The recorded state holds green | `--baseline dns-baseline.json --nameservers 1.1.1.1,8.8.8.8` | ✅ exit **0**, and still prints `still open: vpn.ironcityit.com` |
| Gates | all eleven | ✅ green |

Green, and still honest — the pass output names the open finding rather than
hiding it behind a zero exit.

## Why the known-bad state does not fail the build

Same policy as `exposure-baseline.json`, for the same reason written there: a
gate that is permanently red for a condition the author of an unrelated pull
request cannot fix is a gate people learn to click past, and then it catches
nothing. The open takeover is recorded at its true severity so the gate is honest
about where it starts and still fires if it worsens or a second one appears. An
improvement is reported with a prompt to tighten the file, so a gain that was
actually made gets held.

## Unchanged

`FIREBASE_SERVICE_ACCOUNT` still absent; nothing deployed. The live Firestore
enumeration is still open. **`vpn.ironcityit.com` is still live and still
claimable** — now continuously monitored, which is not the same as fixed. One DNS
change: delete the record, or re-claim the destination.

---

# Discovery coverage — 2026-09-06

**Branch:** `productize/dnsguard-discovery-coverage` · **Base:** `main` (at
`c85e2a1`, PR #10 merged).

Found by reading the CI output of the previous change rather than by review. The
DNS ratchet passed on the GitHub runner and reported **2 aliases**; the same
command locally reported **7**. Both were green.

## D21 — a security gate that could pass having checked a third of the surface

`_crtsh_names` was best-effort by design, which is right: a third party being
slow must not fail a scan. But it swallowed the failure. When certificate
transparency did not answer, discovery silently fell back to the 56 conventional
probe names, and produced an identical clean result over a much smaller surface.
A dangling alias on a name nobody would guess — which is exactly the kind
certificate transparency exists to find — would not have been discovered, and
nothing in the output said so.

That is the same defect class this repository has been working through all week:
a check that reports a pass without having checked.

**Fixed.** The lookup now returns its status alongside its names, and that status
travels all the way to the client-facing finding:

* `subdomain_discovery` and `alias_takeover` both state what was examined —
  *"56 conventional names only — certificate transparency was unavailable, so
  names that would not be guessed were not examined"*;
* the summary finding's **confidence drops to `possible`** over a reduced sweep,
  because a clean result over a smaller surface is a smaller claim;
* the ratchet reports a `COVERAGE` line, and `--require-certificate-transparency`
  makes it exit 2 for whoever wants the stronger guarantee.

Opting out (`--no-certificate-transparency`) is recorded as `not requested` and
is *not* treated as degradation. Conflating a deliberate setting with a failure
would either nag about a choice or hide a real gap.

## Why it does not fail by default

Failing on it would put a third party's uptime in the path of every pull request.
A gate that goes red for reasons unrelated to the change is a gate people learn
to click past — which is the failure mode the whole baseline design is written
against. So: reported always, fatal only when asked.

## PROVEN — verified this run

| Check | Result |
|---|---|
| Gates | ✅ all eleven green |
| Tests | ✅ 62 in the two affected suites; whole suite green |
| Live, certificate transparency reachable | ✅ 7 aliases, coverage `ok`, confidence `confirmed` |
| Live, transport forced to fail | ✅ 2 aliases, coverage `unavailable`, confidence `possible`, degradation stated in the finding text |
| Live, `--no-certificate-transparency` | ✅ recorded as `not requested`, not as degradation |
| Regression still outranks reduced coverage | ✅ a real regression exits 1, not 2 |

## Unchanged

`FIREBASE_SERVICE_ACCOUNT` still absent; nothing deployed. The live Firestore
enumeration is still open. **`vpn.ironcityit.com` is still live and still
claimable** — one DNS change: delete the record, or re-claim the destination.
