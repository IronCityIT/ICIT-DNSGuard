# DNS Guard — UI Wiring

All three legs of UI accessibility already existed in this repo. They were not
connected to each other, so the public free scan could never display a result.

## The corrected flow

```
dashboard (dashboard/public/index.html, Firebase Hosting)
  │  POST { email, domain }
  ▼
triggerDNSScan  (public, CORS *, us-east5)
  │  1. validate email + STRICT hostname check on domain
  │  2. mint scan_id
  │  3. write scans/{scan_id} { scan_id, timestamp, status:"queued", … }
  │  4. dispatch dns-analysis.yml WITH scan_id
  │  5. return { scan_id, … }            ← was missing; caller polled undefined
  ▼
dns-analysis.yml
  │  analyze ─► ai-consensus (shared engine, workflow_call)
  │           └─► store        ─► POST storeScanResults  status:"completed"
  │           └─► report-failure ─► POST storeScanResults status:"failed"
  ▼
storeScanResults  (us-east5)
  │  writes scans/{scan_id}, status monotonic (never downgrades complete→failed)
  ▼
dashboard polls where('scan_id','==',id) → renders results, failure, or timeout
```

## What each leg needed

| | Requirement | Was | Now |
|---|---|---|---|
| (a) | `workflow_dispatch` + typed inputs | Untyped; `domain` interpolated into `eval` | Typed; strict hostname validation; no `eval` |
| (b) | Trigger Cloud Function | Existed, but returned no `scan_id` and forwarded none | Returns and forwards `scan_id`; writes it as a field |
| (c) | Dashboard button/route | Existed, but polled `undefined` and had no failure branch | Polls a real id; renders failure and timeout |

## Input naming

The workflow input is **`domain`**, not `target`. This is deliberate: the *deployed*
`triggerDNSScan` dispatches with `domain`, and renaming it would break the live
free-scan funnel the moment the workflow merged. The ICIT standard accepts
`target`/`domain`; the other standard inputs (`client_name`, `scan_id`) are present and
typed.

## Deploy ordering — important

The workflow change and the `cloud-function/` change are a matched pair:

- the currently-deployed `storeScanResults` force-writes `status: 'complete'`, so a
  failure record from the new workflow would be stored as complete;
- the currently-deployed `triggerDNSScan` does not forward `scan_id`, so a merged
  workflow would still receive none and fall back to `dnsguard-<run_id>`.

**Deploy `cloud-function/` first, or at the same time as the merge.**

```bash
# Bill — from repo root
gcloud functions deploy triggerDNSScan \
  --gen2 --region us-east5 --runtime nodejs20 \
  --source cloud-function --entry-point triggerDNSScan --trigger-http

gcloud functions deploy storeScanResults \
  --gen2 --region us-east5 --runtime nodejs20 \
  --source cloud-function --entry-point storeScanResults --trigger-http
```

Hosting deploys automatically on push to `main` via `firebase-deploy.yml`.

## Still open before this is genuinely client-safe

- **Firestore rules are not in this repo.** `firebase.json` has no `firestore` block and
  there is no `firestore.rules`. The dashboard reads Firestore directly from the browser,
  so rules are the only access control, and they cannot be reviewed from source. If they
  are permissive, every scan document — including submitter emails — is world-readable.
- **No tenant partitioning.** Records are a flat `scans/{scan_id}` collection rather than
  `clients/{client_id}/scans/{scan_id}`. A `client_id` field is now written, but
  re-shaping the collection is a migration and was not attempted.

Both are recorded in `PRODUCTIZE_NOTES.md` §6.
