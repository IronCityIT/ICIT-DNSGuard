# 🛡️ Iron City DNS Guard v3.0

Advanced DNS Security Analysis Platform

## Features
- ML-powered TTL anomaly detection (IsolationForest)
- Email security scoring (SPF/DKIM/DMARC) with A+ to F grades
- DNSSEC compliance checking
- Threat intelligence (VirusTotal, AbuseIPDB)
- IP geolocation (IPStack + ip-api fallback)
- Subdomain enumeration (brute force + Certificate Transparency)
- DNS performance benchmarking
- Professional HTML/JSON reports

## Quick Start

```bash
# Install
pip install -r requirements.txt
cp .env.example .env  # Add your API keys

# CLI
python src/cli.py -d example.com -c "Client" -s -t -g

# Web Dashboard
uvicorn src.api.api:app --reload
# Open http://localhost:8000
```

## Deploy to Firebase

```bash
firebase login
firebase init hosting
firebase deploy
```

## GitHub Actions

1. Add secrets: `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`
2. Go to Actions > DNS Guard - Security Analysis
3. Run workflow with domain

## API Keys (Free Tiers)
- **VirusTotal**: https://virustotal.com - 4 req/min free
- **AbuseIPDB**: https://abuseipdb.com - 1000 req/day free
- **IPStack**: https://ipstack.com - 100 req/month free
- **SecurityTrails**: https://securitytrails.com - 50 req/month free

© 2025 Iron City IT Advisors
