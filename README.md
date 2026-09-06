# 🛡️ Iron City DNS Guard

**Protective DNS: assessment, policy and evidence.**

DNS Guard answers three questions for a client:

1. **"Will my emails land in spam?"** — sender authorisation, signing and policy
   (SPF, DKIM, DMARC, MTA-STS, TLS-RPT), graded A+ to F.
2. **"What's publicly exposed?"** — the hosts published under a domain, and which
   of them should not be reachable.
3. **"Why did you block that?"** — every blocking decision cites the feed,
   snapshot checksum and line it came from, who approved it, and when.

The third question is what makes this a product rather than a scanner. Anything
that changes what resolves for real users — publishing a policy, rolling one
back, turning enforcement on at a site, granting an exception, dispatching
remediation — does not execute until a second person approves exactly that
change. Every one of those decisions lands on a hash-chained audit log that can
be exported as an independently verifiable evidence pack.

## 🎯 Target Audience

Small to medium businesses who:
- Don't have dedicated IT security staff
- Want to know if their email setup is correct
- Need plain-English explanations and remediation steps

## ✨ Features

### Email Security Analysis
- **SPF** validation and lookup count checking
- **DKIM** selector discovery across 25+ common providers
- **DMARC** policy analysis with enforcement recommendations
- **MTA-STS** and **TLS-RPT** detection
- Letter grades (A+ to F) for easy understanding

### Subdomain Discovery
- Certificate Transparency (crt.sh) integration
- Common subdomain brute-force
- IP resolution and CNAME detection

### SMB-Friendly Output
- Executive summary in plain English
- "Quick Wins" - Top 3 actions to take
- Business impact explanations for each finding

## 🏗️ Architecture

```
GitHub Actions (dns-analysis.yml)
    ↓  selects modules from the registry
tools/scan.py  →  module_framework/modules/*   (11 selectable checks)
    ↓  one report, one schema
AI Consensus Engine (IronCityIT/consensus-engine)  [optional]
    ↓
Cloud Function storeScanResults  →  Firestore
    ↓
Free-scan dashboard (Firebase Hosting)

dnsguard/  — the control plane, served by dnsguard/api.py
    policy · feeds · tenancy · exceptions · approvals · audit
    analytics · alerts · compliance · fleetfix · evidence · enforcement
    ↓
Operator console (dashboard/public/console.html)
```

### The modules

Every check is a `ScanModule`, individually selectable, and the same registry
drives the CLI, the workflow input and the console's picker — so what the UI
offers and what CI runs cannot drift apart.

```
dns_records                zone inventory and structural audit
spf_audit                  sender authorisation: presence, strictness, lookup budget
dkim_audit                 published signing keys across the common providers
dmarc_audit                policy, enforcement level and reporting
transport_security_audit   MTA-STS and TLS-RPT
dnssec_audit               signing AND the delegation that makes it count
subdomain_discovery        public host inventory, dangling aliases, exposed internals
alias_takeover             whether a dangling alias could be claimed, and by whom
resolver_performance       latency and loss across the major public resolvers
reputation_lookup          external reputation, with attribution
network_path               network path to the domain's servers
```

Groups: `quick`, `standard`, `deep`, `email`, `surface`, `performance`,
`reputation`.

### Session Isolation

Each scan gets a unique `scan_id`. Users access their results via:
```
https://icit-dnsguard.web.app/?scan=abc123xyz
```

This ensures users only see their own scan data - critical for free marketing campaigns.

## 🚀 Deployment

### 1. Push to GitHub
```bash
git init
git add -A
git commit -m "DNS Guard v4.0 - SMB Email Security"
git remote add origin https://github.com/IronCityIT/ICIT-DNSGuard.git
git push -u origin main --force
```

### 2. Add GitHub Secrets
- `GROQ_API_KEY` - For AI Consensus Engine
- `OPENROUTER_API_KEY` - For AI Consensus Engine
- `GEMINI_API_KEY` - For AI Consensus Engine
- `DNSGUARD_CLOUD_FUNCTION_URL` - Cloud Function endpoint

### 3. Deploy Dashboard
```bash
firebase deploy --only hosting --project icit-dnsguard
```

## 📊 Running a Scan

### Via GitHub Actions
```bash
gh workflow run "DNS Guard - Security Analysis" \
  -R IronCityIT/ICIT-DNSGuard \
  -f domain=example.com \
  -f client_name="Test Client" \
  -f enable_subdomains=true
```

### Via Portal
Trigger from `portal.ironcityit.com/run` → DNS Guard

### Locally
```bash
pip install -r requirements.txt
python3 tools/scan.py --domain example.com --group standard -o ./reports
python3 tools/scan.py --list-modules
python3 tools/scan.py --domain example.com --modules spf_audit,dmarc_audit
python3 tools/scan.py --domain example.com --dry-run   # validate, query nothing
```

### The control plane
```bash
# Refuses to start without a token — it will not come up unauthenticated.
DNSGUARD_API_TOKEN=dev-token DNSGUARD_DATA_DIR=./data \
  python3 -c "import uvicorn; from dnsguard.api import create_app; uvicorn.run(create_app())"
```

### The maintenance pass
Feeds go stale, exceptions lapse and alert rules only fire when something
evaluates them. This is the loop that keeps all three true, meant for cron,
Cloud Scheduler or a Jenkins timer.

```bash
python3 tools/maintain.py --data-dir ./data --all --dry-run    # what a pass would touch
python3 tools/maintain.py --data-dir ./data --tenant acme      # a pass, no network
python3 tools/maintain.py --data-dir ./data --tenant acme --fetch
```

Fetching is **off** unless `--fetch` is given: feed URLs are operator-supplied, so
reaching out to every one of them should be opted into knowingly. Exit 1 only
when a tenant actually reported a problem, so cron mail means something is wrong.

The pass is non-disruptive by construction — it refreshes data, records expiries
the tenant already agreed to, and raises alerts. Nothing it does changes what
resolves, so nothing it does needs an approval, and a test asserts it consumes
none. `POST /api/v1/tenants/{id}/maintenance` is the same pass for a scheduler
with no shell on the host.

### Quality gates
```bash
pip install -r requirements-dev.txt
sh tools/gates.sh all      # the same eleven gates Jenkins and CI run
sh tools/gates.sh lint     # or one at a time
```

## 📁 Project Structure

```
ICIT-DNSGuard/
├── .github/workflows/
│   ├── ci.yml                # quality gates on every PR
│   ├── dns-analysis.yml      # the scan pipeline
│   └── firebase-deploy.yml   # hosting deploy (see STATUS.md — currently blocked)
├── module_framework/         # the shared scan framework
│   ├── base.py registry.py targets.py cli.py
│   └── modules/              # one file per check
├── dnsguard/                 # the control plane
│   ├── policy.py feeds.py tenancy.py exceptions_policy.py
│   ├── approvals.py audit.py evidence.py compliance.py fleetfix.py
│   ├── analytics.py alerts.py enforcement.py resilience.py
│   ├── store.py clock.py errors.py report.py
│   ├── fetcher.py            # guarded HTTP transport for feeds
│   ├── maintenance.py        # the periodic pass
│   ├── exposure.py           # live Firestore exposure probe
│   └── api.py                # the HTTP surface
├── tools/
│   ├── scan.py               # scan entry point
│   ├── maintain.py           # the maintenance pass, for cron
│   ├── check-exposure.py     # re-check the live exposure boundary
│   └── gates.sh              # every quality gate, one script
├── dashboard/public/
│   ├── index.html            # public free-scan page
│   └── console.{html,css,js} # operator console
├── cloud-function/           # triggerDNSScan, storeScanResults, getScanStatus
├── tests/                    # 378 tests, none touching the network
├── firestore.rules           # multi-tenant rules (see STATUS.md for what is live)
├── Jenkinsfile               # calls tools/gates.sh
└── STATUS.md                 # what is proven, what is blocked, what is open
```

## 🔒 Privacy, tenancy and data

- Every stored record carries a `client_id`, and the control-plane store has no
  call that returns a document without one — cross-tenant reads are a shape the
  API does not have, not a filter someone has to remember.
- The API refuses to start unauthenticated and defaults CORS to an empty origin
  list. Every route checks the caller's tenant against the path tenant before any
  handler runs.
- Free-scan results are addressed by an unguessable scan id. `firestore.rules`
  denies all client writes and denies collection listing, so scans cannot be
  enumerated, forged or deleted.
- **Current live state is not yet the state above.** See `STATUS.md` — the rules
  and the dashboard fixes are committed but cannot deploy until
  `FIREBASE_SERVICE_ACCOUNT` exists.

## ✅ Approval-gated actions

These do not execute until someone other than the requester approves that exact
change, bound to a hash of its content:

```
policy.publish   policy.rollback   policy.assign   policy.unassign
exception.grant  exception.revoke  enforcement.push
feed.disable     feed.trust_change fleetfix.dispatch  tenant.delete
```

An action that is not in the registry is treated as disruptive. Forgetting to
register a new destructive verb has to fail closed, not open.

## 📈 Scoring

### Email Security Grade
| Score | Grade |
|-------|-------|
| 90-100 | A+ |
| 80-89 | A |
| 70-79 | B |
| 60-69 | C |
| 40-59 | D |
| 0-39 | F |

### Risk Score (0-100)
Higher = More risk. Based on:
- Email security score (inverted)
- Number and severity of findings
- Missing security controls

---

© 2026 Iron City IT Advisors | Blue-Collar Security
