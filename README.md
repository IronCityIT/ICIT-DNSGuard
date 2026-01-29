# 🛡️ Iron City DNS Guard v4.0

**SMB-Focused Email Security Analysis**

DNS Guard helps small businesses answer two critical questions:
1. **"Will my emails land in spam?"** - Email deliverability analysis (SPF, DKIM, DMARC)
2. **"What's publicly exposed?"** - Subdomain discovery

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
GitHub Actions Workflow (dns-analysis.yml)
    ↓
Python Analyzer (src/core/analyzer.py)
    ↓
AI Consensus Engine (IronCityIT/consensus-engine) [Optional]
    ↓
Cloud Function (stores in Firestore)
    ↓
Dashboard (Firebase Hosting)
```

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
python src/core/analyzer.py example.com -s -o report.json
```

## 📁 Project Structure

```
ICIT-DNSGuard/
├── .github/workflows/
│   └── dns-analysis.yml      # Main workflow with AI integration
├── src/
│   └── core/
│       └── analyzer.py       # DNS analysis engine
├── dashboard/
│   └── public/
│       └── index.html        # Results dashboard
├── firebase.json             # Firebase Hosting config
├── requirements.txt
└── README.md
```

## 🔒 Privacy & Data

- Scan results stored in Firestore with unique scan IDs
- No account required for free scans
- Session isolation prevents users from seeing others' data
- Results accessible only via direct link

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
