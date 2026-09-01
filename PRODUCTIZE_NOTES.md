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
