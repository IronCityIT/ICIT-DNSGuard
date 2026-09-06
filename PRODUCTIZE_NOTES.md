# DNS Guard — Productization Notes

# GitHub Actions Audit + UI-Accessibility Enhancement (2026-08-24)

Branch: `enhance/actions-ui-20260824`. Scope: audit the workflows, make the tool
runnable and observable from the UI, add error handling.

The headline: **the public free-scan funnel was broken end to end, and the workflow
contained a remotely-triggerable command injection.** Neither is a subtle bug.

---

## 1. CRITICAL — remote code execution via the public scan form

`dns-analysis.yml` built its command as a string and ran it through `eval`:

```yaml
CMD="python src/cli.py -d '${{ inputs.domain }}' -c '${{ inputs.client_name }}' -o ./reports"
eval $CMD
```

`${{ inputs.domain }}` is interpolated directly into a shell string. A domain
containing a single quote closes the quoting and everything after it executes.

This was reachable **by anyone on the internet.** `triggerDNSScan` is a public,
unauthenticated Cloud Function with `Access-Control-Allow-Origin: *`, wired to the
"Run Free Assessment" button. Its only sanitising was:

```js
domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0]
```

That strips a scheme and a path. It does not remove `'`, `;`, `` ` ``, `$`, or
whitespace. A submitted domain of the form `x';<command>;'` reaches `eval` intact.

The runner has `secrets.IRONCITY_API_KEY` in the environment and passes
`secrets: inherit` to the shared engine, so this is credential-exfiltration territory,
not just arbitrary compute.

**Fixed, in two places (defence in depth):**
- The workflow no longer uses `eval` at all. Arguments are built as a bash array and
  every value arrives through `env:`, so nothing is ever parsed as shell.
- Both the workflow and `triggerDNSScan` now require the domain to match a strict
  hostname allow-list (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.…)+$`, ≤253 chars) and
  reject anything else outright.

**This fix is not live until `cloud-function/` is redeployed and the workflow is on
`main`.** Until then the public endpoint remains exploitable — see §6.

---

## 2. The free scan never worked at all

Five separate defects, each individually fatal to the flow:

| # | Defect | Effect |
|---|---|---|
| 1 | `triggerDNSScan` did not return `scan_id` | Dashboard called `pollForResults(undefined, …)` |
| 2 | `triggerDNSScan` did not pass `scan_id` to the workflow | Workflow minted its own id; nothing correlated |
| 3 | The queued Firestore doc had no `scan_id` **field** (only a doc id) | `where('scan_id','==',id)` never matched |
| 4 | The queued doc had no `timestamp` field | The fallback `orderBy('timestamp')` query excludes docs lacking it |
| 5 | The workflow never called `storeScanResults` — it POSTed to the QNAP API | The polled document was never updated with results |

Net effect: the spinner ran for 20 polls (~60s) and then **stopped silently**, leaving
the page on a loading state forever. There is no code path in the previous build where
a free scan could ever have displayed a result.

All five are fixed. `scan_id` is now minted by the trigger, returned to the caller,
forwarded as a workflow input, written as a document field, and used by the workflow
as the key it stores results under.

---

## 3. Store of record moved to Firestore

The workflow POSTed the full report to `https://api.ironcityit.com/ingest` (QNAP Flask
API) and never wrote to Firestore. That violates the standing rule that product scan
data goes to Firestore via `storeScanResults` only.

The direct QNAP POST is **removed**. Results now go to `storeScanResults`. The endpoint
default is this product's own deployed function —
`https://storescanresults-43248247502.us-east5.run.app`, us-east5 — which was already
committed in `cloud-function/index.js`; no endpoint was guessed and no new secret was
invented. A `STORE_SCAN_RESULTS_URL` secret overrides it if set.

`scan_id` used to come from the QNAP response, so removing that POST would have left
`ai-consensus` without one. It is now minted in the workflow (or supplied by the
trigger), which is where it should have come from.

Note: the shared engine *itself* still POSTs to the QNAP API — that is inside
`consensus-engine`, is fleet-wide, and is flagged for that repo's review rather than
worked around here.

---

## 4. Error handling

- `eval` gone; `set -euo pipefail` throughout.
- `pip install -r requirements.txt || pip install dnspython requests` — the `||`
  fallback let a scan run against a half-installed environment. Now fails hard.
- `ls -t reports/*.json | head -1` was unguarded — an empty result silently produced an
  empty `REPORT` and the failure surfaced later as a confusing jq error. Now checked
  explicitly, and uses `find` rather than parsing `ls`.
- Report JSON is validated (`head -c 1` is `{`, then `python3 -m json.tool`) before
  anything downstream consumes it.
- Scanner stderr captured to `reports/scan-stderr.log` and uploaded as a separate
  `if: always()` diagnostics artifact.
- New `report-failure` job posts a `status:"failed"` record so the dashboard resolves
  instead of hanging. It rebuilds `scan_id`/`client_id` with the same rules when the
  analyze job died before emitting them.
- `storeScanResults` no longer force-writes `status: 'complete'` over whatever the
  workflow reported, and status is now **monotonic** — a completed scan is never
  downgraded to failed by the trailing failure report.
- The dashboard gained a real failure branch and a timeout message; previously it just
  stopped polling and left the spinner up.

---

## 5. White-label

The report contains `tools_used: ["dns-resolver", "checkdmarc-style"]`, which was stored
verbatim in the client-readable Firestore document. The store payload now strips it
(`del(.tools_used)`). The dashboard does not render it, but it was readable by anyone
who could read the document — see §6.

---

## 6. Open — needs Bill's decision, NOT changed here

**A. Deploy ordering matters.** The workflow fix and the `cloud-function/` fix are a
matched pair. The currently-deployed `storeScanResults` force-sets `status: 'complete'`,
so if the workflow lands on `main` before the function is redeployed, failure records
will be stored as complete (with an `error` field attached). Still better than today's
"nothing is stored", but **deploy `cloud-function/` first or together.**

**B. There are no Firestore security rules in this repo.** `firebase.json` declares only
`hosting` — no `firestore` block, no `firestore.rules`. The dashboard reads Firestore
directly from the browser with a public web API key. Whatever rules are live in the
`icit-dnsguard` project are not represented in source, so I could not verify them. If
they are permissive, **every scan document — including the submitter's email address —
is world-readable.** This needs checking against the live project.

**C. `getScanStatus` leaked the submitter's email.** It is public (CORS `*`), takes a
`scan_id`, and returned the raw document. I changed it to strip `email` from the
response, but that is only half the fix while (B) is unresolved, because the dashboard
path reads Firestore directly.

**D. No multi-tenancy.** Data is a flat `scans/{scan_id}` collection with no `client_id`
partitioning, unlike the `clients/{client_id}/scans/{scan_id}` layout the architecture
calls for. I added a `client_id` field so records carry it, but **did not re-shape the
collection** — that would break the live dashboard's queries and the deployed function,
and is a migration, not an enhancement.

**E. `firebase-deploy.yml` does NOT actually deploy — it fails on every push to
`main`.** This note previously read "deploys on every push to `main` ... worth knowing
before merging". That is not what happens. The job dies before it reaches Firebase:

```
Error: Input required and not supplied: firebaseServiceAccount
```

`FIREBASE_SERVICE_ACCOUNT` is not present in this repository's secrets
(`gh secret list` returns `DNSGUARD_CLOUD_FUNCTION_URL`, `GEMINI_API_KEY`,
`GROQ_API_KEY`, `IRONCITY_API_KEY`, `OPENROUTER_API_KEY`, `STORE_SCAN_RESULTS_URL`
— and nothing else), nor at org level. Confirmed on runs `33226159052` (2026-08-29)
and `33554828363` (2026-09-01).

Consequences, and they cut both ways:

- The live `icit-dnsguard.web.app` site is **not** updated by merges. Any dashboard
  change in this repo is committed but not published. The site currently serves
  whatever was last deployed by hand.
- Conversely, merging a PR here carries **no** risk of an unreviewed hosting deploy.
- The red X on `main` after every merge is this, not a regression.

**This is an external blocker and was not worked around.** Provisioning the secret is
an account-level action. The same missing credential blocks the `storeScanResults`
redeploy in `ICIT-AttackSimPro`, so it is a fleet-wide gap rather than a DNS Guard one.

**F. Consensus secrets are missing** (`GROQ_API_KEY`, `OPENROUTER_API_KEY`,
`GEMINI_API_KEY`, `IRONCITY_API_KEY`). Same blocker as Threat Inspector — the
`ai-consensus` job cannot run until they are provisioned. All four are on the approved
list; they are simply not present.

**G. `index.html` at repo root (1043 lines) appears to be a stale copy.**
`firebase.json` serves `dashboard/public`, so the root file is not deployed. Not
touched. There are also `index.html.backup` and `index.html.old` in `dashboard/public`.

---

## 7. Validation run

- `actionlint 1.7.7` + `shellcheck 0.10.0` on both workflow files — **exit 0, clean**.
- PyYAML `safe_load` on both — parse clean.
- `node --check` on `cloud-function/index.js` and on the dashboard's inline script — clean.
- Both `jq` filters executed against a **real generated report** — store filter strips
  `tools_used`, preserves `findings`/`email_security`, applies routing fields; failure
  filter emits the expected shape.
- Local smoke: `python3 src/cli.py -d ironcityit.com -c ironcity` → RC=0, valid report,
  1 finding, all keys the dashboard reads present.
- Live dispatch dry-run: **not run** — `ai-consensus` cannot pass without (F), and the
  store step would write to the live production Firestore. Deferred until the secrets
  land, then it can be validated in one pass.

## 8. UI-accessibility gap check

| | Requirement | State |
|---|---|---|
| (a) | `workflow_dispatch` + typed inputs | **Done** — this PR |
| (b) | Trigger Cloud Function | **Already existed** (`triggerDNSScan`) — now actually returns and forwards `scan_id` |
| (c) | Dashboard wired to it | **Already existed** — now actually works, and renders failures |

Unlike Threat Inspector, all three legs exist here. They were simply not connected to
each other. `docs/UI-WIRING.md` documents the corrected flow.

---

## Note F — CRITICAL: live Firestore is world-readable and world-deletable

Found 2026-09-01 by the orchestrator while verifying another worker's Firestore proof.
Not a code defect in this repo; recorded here because this repo is one of the affected
products and the fix has a prerequisite that this repo owns.

### What was verified

Against `icit-dnsguard` (and, identically, `iron-city-it-threatinspector` and
`ironcity-attacksimpro`), with **no credential of any kind**:

- `GET  https://firestore.googleapis.com/v1/projects/icit-dnsguard/databases/(default)/documents/scans`
  → **HTTP 200**, returns scan documents.
- `DELETE .../documents/scans/<any-nonexistent-id>` → **HTTP 200**, i.e. the rules did
  not deny the write. (Probed against a document that does not exist, so nothing was
  destroyed. A rules-denied write returns 403.)

So any anonymous caller on the internet can read every stored scan and delete or forge
scan records. Across the three projects this exposed 82 documents and, on Threat
Inspector, 5 distinct `client_id` values (`audit-demo`, `fixture-selftest`, `internal`,
`ironcity`, `test`) — i.e. multiple tenants readable by anyone.

### Root cause

`deploy-functions.yml` has **never succeeded once** on any product (0 successes across
16 deploy runs fleet-wide) because `FIREBASE_SERVICE_ACCOUNT` does not exist. The
projects therefore still carry the open test-mode rules assigned at project creation.
The missing credential is not only blocking new deploys — it is why production has been
open this entire time.

### Why this repo cannot simply ship a firestore.rules

Two blockers specific to DNS Guard:

1. `firebase.json` declares **only `hosting`** — no `firestore` section — so a rules
   file would not be deployed even once a credential exists.
2. `dashboard/public/index.html` reads Firestore **directly from the browser with no
   authentication** (`db.collection('scans').where(...)`; there is no `firebase.auth()`
   anywhere in it). The permissive rules are therefore load-bearing for the current
   dashboard: applying tenant-filtered rules today would return zero rows and break it.

Writing a rules file now would either break production or be security theatre, so none
was added. This is deliberate, not an oversight.

### Remediation order (must be done in this sequence)

1. Mint `FIREBASE_SERVICE_ACCOUNT` and set it per-repo.
2. Give this dashboard an Auth0 -> Firebase custom-token login that mints a `client_id`
   claim (tenant partitioning cannot exist before this).
3. Move the writer off the flat `scans/{scanId}` collection onto
   `clients/{client_id}/scans/{scanId}`, matching Threat Inspector.
4. Add `firestore.rules` + a `firestore` block in `firebase.json`, then deploy.
5. Re-run the two probes above and confirm 403 on both.

Until step 5 passes, treat all stored scan data as public.

Related: `cloud-function/index.js:221` exposes a public, unauthenticated `GET` by
`scan_id` with `CORS *`. It already strips `email`, but it remains an unauthenticated
read path over the same data and should be revisited in step 2.

---

# Productization: policy control plane (2026-09-04)

Branch: `productize/dnsguard-policy-platform`. Scope: turn the single-domain
assessment script into a protective-DNS control plane. Full run report, gate
results and defect list: `STATUS.md`. Design rationale: the commit messages.

## Code review of the existing Python (required deliverable)

The tool was three separate things pretending to be one product.

**`src/core/analyzer.py` (664 lines)** — one `analyze()` doing records, SPF, DKIM,
DMARC, MTA-STS, DNSSEC and subdomain enumeration in a single pass. No way to run
one check without running all of them; no way for a dashboard to describe what it
would run. Findings were reasonable and SMB-appropriate. Three real bugs in it:
SPF lookup counting missed bare `a`/`mx`/`redirect=` (so a record already over
the RFC 7208 budget could be reported compliant); DNSSEC treated a DNSKEY alone
as "implemented" when a zone with no DS at the registrar is unvalidated; and
dangling CNAMEs were collected and never examined.

**`src/integrations/dns_tools.py`** — a second, unreachable copy of subdomain
enumeration, plus a resolver benchmark (needing numpy, which was never in
`requirements.txt`), a zone auditor, RPZ/Unbound generators, and a traceroute
wrapper that built its command by parsing a string. Nothing imported it except
`src/api/api.py`, which could not load.

**`src/api/api.py`** — imported `DNSGuardConfig`, `ThreatIntel`, `GeoLocation` and
`PerformanceMetrics` from `core.analyzer`. None exist. It called
`analyzer.analyze_domain()` and `analysis.calculate_risk_score()`. Neither exists.
This module has never once imported successfully. It was dead on arrival, not
merely stale.

**`src/integrations/api_clients.py`** — VirusTotal / AbuseIPDB / IPStack clients
with bare `except: pass` throughout, so a rate-limited provider and a clean
result were indistinguishable to every caller.

Everything above is re-housed. Nothing was dropped; `src/` is removed. The
mapping is in the `scan:` commit.

## Open items — for Bill

**H. `vpn.ironcityit.com` is a dangling delegation.** It is a CNAME to
`icit.mynetgear.com`, which does not resolve. Found by the new
`subdomain_discovery` module against our own domain during verification. If that
destination is a de-provisioned account, whoever registers the name next serves
content on `ironcityit.com`. Not a code issue and not fixed here — it is a DNS
record on our production domain. **Worth checking today.**

**I. Note F's remediation order is now partly executable.** Step 1 (mint
`FIREBASE_SERVICE_ACCOUNT`) is still yours and still blocks everything. But the
reasoning that *no* rules file could be added has been narrowed: a rules file
that denies all client writes and denies `list`, while leaving `get` open, does
not break the unauthenticated dashboard and does close world-writability and bulk
harvesting. That file is now committed and wired into `firebase.json`. It is
inert until step 1 lands.

The residual after it deploys: anyone holding a scan id can still read that
document, submitter email included. Scan ids are unguessable but they are not
secrets and they appear in URLs. Closing that is step 2 (Auth0 → Firebase custom
token with a `client_id` claim), after which the `get` rule becomes a `client_id`
comparison. Steps 3–5 of the original order are unchanged.

**J. The free-scan page had stored XSS and it is live.** Findings, AI remediation
text, compliance tags and the error message were interpolated into `innerHTML`
from a Firestore document that anyone on the internet can currently write. A
forged document plus a `?scan=<id>` link was script execution in a visitor's
browser. Fixed on this branch — but the fix is not live until hosting deploys,
which is blocked by the same missing credential. **Until then the live page is
still vulnerable, and the write path is still open.** If step 1 is going to slip,
the interim mitigation is to set the Firestore rules by hand in the console; that
alone removes the write primitive the attack depends on.

**K. One PR, not nine.** The guardrails ask for one PR per logical change. This
run is one PR containing nine coherent commits, because the pieces are not
independently landable — the approval gate has no meaning without the audit
chain, policy publish has no meaning without the gate, and the scanner cannot be
removed from `src/` until the workflow moves. Splitting them would have produced
a sequence of PRs that individually leave `main` in a state nobody would want to
deploy. Flagging the deviation rather than hiding it; the commits are reviewable
one at a time.

**L. Secrets still missing** (unchanged from Note F): `FIREBASE_SERVICE_ACCOUNT`,
and the four consensus keys `GROQ_API_KEY`, `OPENROUTER_API_KEY`,
`GEMINI_API_KEY`, `IRONCITY_API_KEY`. All are on the approved list.

---

# Exposure verification (2026-09-06)

Read-only run against the live projects. Full evidence and the fleet table are in
`STATUS.md`; this records what it means for the notes above, which are now partly
wrong.

## Note F is superseded in one important respect

Note F recorded the live Firestore as carrying open test-mode rules — world-
readable and world-deletable — and concluded that nothing could change until
`FIREBASE_SERVICE_ACCOUNT` was minted. Probed today:

* A collection this product never writes answers **403**. Test-mode answers 404.
  **A rules file is deployed.** Note F's premise no longer holds.
* The scans collection still answers an unauthenticated **list**, returning all
  34 documents including `email`, `client_name` and `domain`. The committed
  `firestore.rules` denies exactly this. So the deployed rules are neither
  test-mode nor the file in this repository — they are something in between that
  nobody recorded deploying.
* **Writes were not probed.** Note F called the project world-writable; that was
  inferred from test-mode, and test-mode is not what is deployed. The claim
  should be treated as unverified rather than repeated, and it matters, because
  the stored-XSS chain in note J depends on a write primitive that may or may not
  still exist.

The remediation order in note F is otherwise unchanged and still correct.

## The "nothing can be done without the service account" reasoning was too strong

`icit-shadowscan` refuses all three probes — no unauthenticated read, no
enumeration, no unknown collection. Same fleet, same missing secret. Whatever
closed it did not require `FIREBASE_SERVICE_ACCOUNT`, so the same can be done
here and on the two projects below without waiting for anything.

## Two other products are exposed, and one is worse than this one

Flagged, not touched — neither repository is this one's to change, and
AttackSim Pro is live and review-only:

| Project | Rules | Enumeration | Stored docs |
|---|---|---|---|
| `iron-city-it-threatinspector` | **none — test-mode** | open | 25 |
| `ironcity-attacksimpro` | deployed | open | 23 |

Threat Inspector answering 404 on an unknown collection is the signature of a
project still carrying the rules it was created with. It needs the same one
console action, and it needs it more than this product does.

## Stale blocker corrected

The four consensus keys are listed throughout these notes as missing. They exist
on this repository, set 2026-08-25, together with `STORE_SCAN_RESULTS_URL` and
`DNSGUARD_CLOUD_FUNCTION_URL`. Only `FIREBASE_SERVICE_ACCOUNT` is genuinely
absent, and no Firebase or gcloud credential exists in this environment either,
so deploying from here remains impossible — that blocker is real and unchanged.

## Note H (`vpn.ironcityit.com`) confirmed, with the takeover path named

The destination `icit.mynetgear.com` is `NXDOMAIN`, and `mynetgear.com` is served
by `ns2.no-ip.com` — a self-service dynamic-DNS provider where hostnames are
claimed by whoever registers them. An unregistered name on such a service is
claimable, which turns the dangling record into a live takeover of a hostname
called *vpn* on our own domain. This product's `subdomain_discovery` module found
it again today and it is the only dangling alias among the 20 hosts that resolve
under `ironcityit.com`.

No attempt was made to claim the destination. That is an action against a third
party's service and it needs a person to decide.

## What was added, and why a tool rather than a note

`dnsguard/exposure.py`, `tools/check-exposure.py` and ten tests. One command
re-checks the live boundary:

    python3 tools/check-exposure.py --project icit-dnsguard

It exits non-zero on a high finding, so once the rules are correct this can gate
CI and stop the state drifting away from the claim again. The reason it exists
is that this repository confidently documented a production security boundary,
and was wrong about it for two weeks, in the direction that made the exposure
look smaller than it was.
