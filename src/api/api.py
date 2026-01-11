#!/usr/bin/env python3
"""Iron City DNS Guard - FastAPI Backend"""
import os,sys,json,logging
from datetime import datetime
from pathlib import Path
from typing import List,Dict
from contextlib import asynccontextmanager
from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse,HTMLResponse,JSONResponse
from pydantic import BaseModel,Field
sys.path.insert(0,str(Path(__file__).parent.parent))
from core.analyzer import DNSGuardAnalyzer,DNSGuardConfig,ThreatIntel,GeoLocation,SubdomainResult,PerformanceMetrics
from integrations.api_clients import ThreatIntelAggregator
from integrations.dns_tools import SubdomainEnumerator,DNSPerformanceTester,HopsAnalyzer
logging.basicConfig(level=logging.INFO,format='%(asctime)s|%(levelname)s|%(message)s')
logger=logging.getLogger('dnsguard.api')
BASE_DIR=Path(__file__).parent.parent.parent
REPORTS_DIR,MODELS_DIR,STATIC_DIR=BASE_DIR/'reports',BASE_DIR/'models',BASE_DIR/'dashboard'/'public'
REPORTS_DIR.mkdir(exist_ok=True);MODELS_DIR.mkdir(exist_ok=True)

class ScanRequest(BaseModel):
    domains:List[str]=Field(...,min_items=1);client_name:str;scan_type:str="full";options:Dict[str,bool]={}

@asynccontextmanager
async def lifespan(app:FastAPI):
    logger.info("Starting DNS Guard API...")
    app.state.analyzer=DNSGuardAnalyzer(config=DNSGuardConfig(model_path=str(MODELS_DIR/'model.pkl')),logger=logger)
    app.state.threat_intel=ThreatIntelAggregator()
    app.state.subdomain_enum=SubdomainEnumerator(logger=logger)
    app.state.perf_tester=DNSPerformanceTester(logger=logger)
    app.state.hops_analyzer=HopsAnalyzer(logger=logger)
    logger.info("DNS Guard API ready!");yield

app=FastAPI(title="Iron City DNS Guard API",version="3.0.0",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])
if STATIC_DIR.exists():app.mount("/static",StaticFiles(directory=str(STATIC_DIR)),name="static")

@app.get("/",response_class=HTMLResponse)
async def root():
    idx=STATIC_DIR/"index.html"
    return FileResponse(idx) if idx.exists() else HTMLResponse("<h1>DNS Guard API</h1><p><a href='/docs'>API Docs</a></p>")

@app.get("/api/health")
async def health():return{"status":"healthy","version":"3.0.0","timestamp":datetime.utcnow().isoformat(),"apis_available":app.state.threat_intel.available_apis}

@app.post("/api/scan")
async def scan(req:ScanRequest):
    domain=req.domains[0].strip().lower();logger.info(f"Scanning {domain}")
    try:
        analysis=app.state.analyzer.analyze_domain(domain,req.client_name,req.scan_type);opts=req.options
        if opts.get('threat_intel',True):
            ips=[r.value for r in analysis.records if r.record_type=='A' and r.value][:5]
            for ip in ips:
                for t in app.state.threat_intel.check_ip(ip):analysis.threat_intel.append(ThreatIntel(**t))
                if opts.get('geolocation',True):
                    g=app.state.threat_intel.get_geolocation(ip)
                    if g:analysis.geolocations.append(GeoLocation(**g))
            for t in app.state.threat_intel.check_domain(domain):analysis.threat_intel.append(ThreatIntel(**t))
        if opts.get('subdomains',True):
            for s in app.state.subdomain_enum.enumerate(domain)[:100]:analysis.subdomains.append(SubdomainResult(**s))
        if opts.get('performance',False):
            for k,m in app.state.perf_tester.compare_dns_servers(domain).items():analysis.performance.append(PerformanceMetrics(**m))
        analysis.calculate_risk_score()
        (REPORTS_DIR/f"{analysis.scan_id}.json").write_text(json.dumps(analysis.to_dict(),indent=2,default=str))
        return JSONResponse(content=analysis.to_dict())
    except Exception as e:logger.error(f"Error: {e}");raise HTTPException(500,str(e))

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id:str):
    p=REPORTS_DIR/f"{scan_id}.json"
    if not p.exists():raise HTTPException(404,"Not found")
    return JSONResponse(content=json.loads(p.read_text()))

@app.get("/api/scans")
async def list_scans(limit:int=20):
    scans=[]
    for f in sorted(REPORTS_DIR.glob("*.json"),key=lambda x:x.stat().st_mtime,reverse=True)[:limit]:
        try:d=json.loads(f.read_text());scans.append({"scan_id":d.get("scan_id"),"domain":d.get("domain"),"risk_score":d.get("overall_risk_score"),"timestamp":d.get("scan_timestamp")})
        except:pass
    return{"scans":scans,"total":len(scans)}

if __name__=="__main__":
    import uvicorn;uvicorn.run("api:app",host="0.0.0.0",port=int(os.getenv("PORT","8000")),reload=True)
