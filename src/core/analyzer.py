#!/usr/bin/env python3
"""Iron City DNS Guard - Core Engine v3.0"""
import os,sys,json,logging,hashlib,time
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass,field,asdict
from typing import Optional,List,Dict,Any,Tuple
from enum import Enum
import dns.resolver
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class RiskLevel(Enum):
    CRITICAL="critical";HIGH="high";MEDIUM="medium";LOW="low";INFO="info"

class RecordStatus(Enum):
    VALID="valid";INVALID="invalid";MISSING="missing";ANOMALY="anomaly"

@dataclass
class DNSRecord:
    domain:str;record_type:str;value:Optional[str];ttl:Optional[int]
    status:RecordStatus=RecordStatus.VALID;anomaly_score:float=0.0;is_anomaly:bool=False
    purpose:str="";recommendations:List[str]=field(default_factory=list);error:Optional[str]=None
    def to_dict(self)->Dict:return{'domain':self.domain,'record_type':self.record_type,'value':self.value,'ttl':self.ttl,'status':self.status.value,'anomaly_score':round(self.anomaly_score,3),'is_anomaly':self.is_anomaly,'purpose':self.purpose,'recommendations':self.recommendations,'error':self.error}

@dataclass
class SPFValidation:
    record:Optional[str]=None;status:str="missing";mechanism:str="";includes:List[str]=field(default_factory=list);score:int=0;issues:List[str]=field(default_factory=list)
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class DKIMValidation:
    status:str="unknown";selectors_found:List[str]=field(default_factory=list);score:int=0;issues:List[str]=field(default_factory=list)
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class DMARCValidation:
    record:Optional[str]=None;status:str="missing";policy:str="none";rua:List[str]=field(default_factory=list);score:int=0;issues:List[str]=field(default_factory=list)
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class EmailSecurityScore:
    spf:SPFValidation=field(default_factory=SPFValidation)
    dkim:DKIMValidation=field(default_factory=DKIMValidation)
    dmarc:DMARCValidation=field(default_factory=DMARCValidation)
    overall_score:int=0;grade:str="F"
    def calculate_score(self):
        s=0
        if self.spf.status=="valid":s+=20;s+=15 if self.spf.mechanism=="-all" else 10 if self.spf.mechanism=="~all" else 5
        self.spf.score=s
        d=30 if self.dkim.status=="configured" else 15 if self.dkim.status=="partial" else 0
        self.dkim.score=d
        m=0
        if self.dmarc.status=="valid":m=15;m+=20 if self.dmarc.policy=="reject" else 15 if self.dmarc.policy=="quarantine" else 5
        self.dmarc.score=m
        self.overall_score=s+d+m
        self.grade="A+" if self.overall_score>=90 else "A" if self.overall_score>=80 else "B" if self.overall_score>=70 else "C" if self.overall_score>=60 else "D" if self.overall_score>=50 else "F"
    def to_dict(self)->Dict:return{'spf':self.spf.to_dict(),'dkim':self.dkim.to_dict(),'dmarc':self.dmarc.to_dict(),'overall_score':self.overall_score,'grade':self.grade,'spf_status':self.spf.status,'spf_record':self.spf.record,'dkim_status':self.dkim.status,'dkim_selectors':self.dkim.selectors_found,'dmarc_status':self.dmarc.status,'dmarc_record':self.dmarc.record,'dmarc_policy':self.dmarc.policy}

@dataclass
class GeoLocation:
    ip:str;country:str="Unknown";city:str="Unknown";region:str="Unknown";isp:str="Unknown";source:str=""
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class ThreatIntel:
    target:str;source:str;is_malicious:bool=False;confidence_score:float=0.0;abuse_score:int=0;total_reports:int=0;categories:List[str]=field(default_factory=list)
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class DNSSECStatus:
    implemented:bool=False;validated:bool=False;issues:List[str]=field(default_factory=list)
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class SubdomainResult:
    subdomain:str;ip_addresses:List[str]=field(default_factory=list);cnames:List[str]=field(default_factory=list);source:str="enumeration";is_alive:bool=True
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class PerformanceMetrics:
    dns_server:str;server_name:str="";latency_avg:float=0.0;latency_min:float=0.0;latency_max:float=0.0;queries_per_second:float=0.0;packet_loss:float=0.0
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class Finding:
    severity:str;category:str;finding:str;recommendation:str
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class HopsAnalysis:
    target:str;hops:List[Dict]=field(default_factory=list);total_hops:int=0
    def to_dict(self)->Dict:return asdict(self)

@dataclass
class DNSGuardConfig:
    model_path:str="./models/dns_anomaly_model.pkl";timeout:int=10;anomaly_contamination:float=0.05

@dataclass
class DomainAnalysis:
    domain:str;client_name:str;scan_timestamp:datetime=field(default_factory=datetime.utcnow);scan_id:str=""
    records:List[DNSRecord]=field(default_factory=list);raw_records:Dict[str,List[str]]=field(default_factory=dict)
    email_security:EmailSecurityScore=field(default_factory=EmailSecurityScore)
    dnssec:DNSSECStatus=field(default_factory=DNSSECStatus)
    threat_intel:List[ThreatIntel]=field(default_factory=list)
    geolocations:List[GeoLocation]=field(default_factory=list)
    subdomains:List[SubdomainResult]=field(default_factory=list)
    performance:List[PerformanceMetrics]=field(default_factory=list)
    hops_analysis:List[HopsAnalysis]=field(default_factory=list)
    overall_risk_score:int=100;risk_level:RiskLevel=RiskLevel.INFO
    findings:List[Finding]=field(default_factory=list);recommendations:List[str]=field(default_factory=list)
    scan_duration_seconds:float=0.0;errors:List[str]=field(default_factory=list)
    def __post_init__(self):
        if not self.scan_id:self.scan_id=hashlib.sha256(f"{self.domain}-{self.scan_timestamp.isoformat()}".encode()).hexdigest()[:12]
    def add_finding(self,sev,cat,find,rec):self.findings.append(Finding(sev,cat,find,rec))
    def calculate_risk_score(self):
        score=100;self.email_security.calculate_score()
        if self.email_security.overall_score<50:score-=20;self.add_finding('high','Email Security',f'Grade {self.email_security.grade}','Implement SPF/DKIM/DMARC')
        elif self.email_security.overall_score<70:score-=10
        if not self.dnssec.implemented:score-=10;self.add_finding('medium','DNSSEC','Not implemented','Enable DNSSEC')
        mal=sum(1 for t in self.threat_intel if t.is_malicious)
        if mal:score-=min(30,mal*10);self.add_finding('critical','Threat Intel',f'{mal} malicious IP(s)','Investigate immediately')
        anom=sum(1 for r in self.records if r.is_anomaly)
        if anom:score-=min(15,anom*3)
        types={r.record_type for r in self.records if r.value}
        if 'A' not in types and 'AAAA' not in types:score-=15
        self.overall_risk_score=max(0,min(100,score))
        self.risk_level=RiskLevel.LOW if self.overall_risk_score>=90 else RiskLevel.MEDIUM if self.overall_risk_score>=70 else RiskLevel.HIGH if self.overall_risk_score>=50 else RiskLevel.CRITICAL
        self.findings.sort(key=lambda x:{'critical':0,'high':1,'medium':2,'low':3,'info':4}.get(x.severity,4))
        self.recommendations=[f.recommendation for f in self.findings if f.recommendation]
    def to_dict(self)->Dict:
        return{'domain':self.domain,'client_name':self.client_name,'scan_timestamp':self.scan_timestamp.isoformat(),'scan_id':self.scan_id,'records':[r.to_dict() for r in self.records],'raw_records':self.raw_records,'email_security':self.email_security.to_dict(),'dnssec':self.dnssec.to_dict(),'threat_intel':[t.to_dict() for t in self.threat_intel],'geolocations':[g.to_dict() for g in self.geolocations],'subdomains':[s.to_dict() for s in self.subdomains],'performance':[p.to_dict() for p in self.performance],'hops_analysis':[h.to_dict() for h in self.hops_analysis],'overall_risk_score':self.overall_risk_score,'risk_level':self.risk_level.value,'findings':[f.to_dict() for f in self.findings],'recommendations':self.recommendations,'scan_duration_seconds':self.scan_duration_seconds,'errors':self.errors}

class DNSGuardAnalyzer:
    RECORD_TYPES=['A','AAAA','MX','CNAME','TXT','NS','SOA','CAA']
    PURPOSES={'A':'IPv4 Address','AAAA':'IPv6 Address','MX':'Mail Exchange','CNAME':'Alias','TXT':'Text Record','NS':'Name Server','SOA':'Start of Authority','CAA':'CA Authorization'}
    DKIM_SELECTORS=['default','google','selector1','selector2','k1','mail','dkim']
    def __init__(self,config:DNSGuardConfig=None,logger=None):
        self.config=config or DNSGuardConfig();self.logger=logger or logging.getLogger('dnsguard')
        self.resolver=dns.resolver.Resolver();self.resolver.timeout=self.config.timeout
        self.anomaly_model=None;self.scaler=None;self._init_model()
    def _init_model(self):
        mp=Path(self.config.model_path)
        if mp.exists():
            try:d=joblib.load(mp);self.anomaly_model,self.scaler=d['model'],d['scaler'];return
            except:pass
        ttls=[30,60,120,300,600,900,1800,3600,7200,14400,43200,86400]
        np.random.seed(42)
        X=np.array([[max(1,t+np.random.normal(0,t*0.1))] for t in ttls for _ in range(50)]+[[1],[5],[9999999]]*3)
        self.scaler=StandardScaler();self.anomaly_model=IsolationForest(n_estimators=100,contamination=0.05,random_state=42)
        self.anomaly_model.fit(self.scaler.fit_transform(X))
        mp.parent.mkdir(parents=True,exist_ok=True)
        joblib.dump({'model':self.anomaly_model,'scaler':self.scaler},mp)
    def _detect_anomaly(self,ttl)->Tuple[bool,float]:
        if ttl is None:return False,0.0
        try:X=self.scaler.transform([[ttl]]);return self.anomaly_model.predict(X)[0]==-1,float(-self.anomaly_model.score_samples(X)[0])
        except:return False,0.0
    def _purpose(self,rtype,val):
        if rtype=='TXT' and val:
            vl=val.lower()
            if 'v=spf1' in vl:return 'SPF Record'
            if 'v=dmarc1' in vl:return 'DMARC Record'
            if 'v=dkim1' in vl or 'k=rsa' in vl:return 'DKIM Record'
        return self.PURPOSES.get(rtype,'DNS Record')
    def collect_records(self,domain)->Tuple[List[DNSRecord],Dict]:
        records,raw=[],{}
        for rt in self.RECORD_TYPES:
            try:
                ans=self.resolver.resolve(domain,rt);raw[rt]=[str(r) for r in ans]
                for r in ans:
                    v=str(r);ia,sc=self._detect_anomaly(ans.ttl)
                    records.append(DNSRecord(domain=domain,record_type=rt,value=v,ttl=ans.ttl,status=RecordStatus.ANOMALY if ia else RecordStatus.VALID,anomaly_score=sc,is_anomaly=ia,purpose=self._purpose(rt,v)))
            except dns.resolver.NoAnswer:raw[rt]=[]
            except dns.resolver.NXDOMAIN:records.append(DNSRecord(domain=domain,record_type='NXDOMAIN',value=None,ttl=None,status=RecordStatus.INVALID,error="Domain not found"));break
            except:pass
        return records,raw
    def validate_spf(self,domain,records)->SPFValidation:
        spf=SPFValidation();txt=[r for r in records if r.record_type=='TXT' and r.value and 'v=spf1' in r.value.lower()]
        if not txt:spf.issues.append("No SPF record");return spf
        spf.record=txt[0].value.strip('"');spf.status="valid"
        if '-all' in spf.record:spf.mechanism='-all'
        elif '~all' in spf.record:spf.mechanism='~all';spf.issues.append("Uses ~all softfail")
        elif '?all' in spf.record:spf.mechanism='?all';spf.status="partial"
        elif '+all' in spf.record:spf.mechanism='+all';spf.status="invalid";spf.issues.append("CRITICAL: +all allows any sender")
        return spf
    def validate_dkim(self,domain)->DKIMValidation:
        dkim=DKIMValidation()
        for sel in self.DKIM_SELECTORS:
            try:
                self.resolver.resolve(f'{sel}._domainkey.{domain}','TXT')
                dkim.selectors_found.append(sel);dkim.status="configured"
            except:pass
        if not dkim.selectors_found:dkim.issues.append("No DKIM selectors found")
        return dkim
    def validate_dmarc(self,domain)->DMARCValidation:
        dmarc=DMARCValidation()
        try:
            ans=self.resolver.resolve(f'_dmarc.{domain}','TXT')
            for r in ans:
                v=str(r).strip('"')
                if 'v=dmarc1' in v.lower():
                    dmarc.record=v;dmarc.status="valid"
                    if 'p=reject' in v.lower():dmarc.policy="reject"
                    elif 'p=quarantine' in v.lower():dmarc.policy="quarantine"
                    else:dmarc.policy="none";dmarc.issues.append("Policy is none - no enforcement")
                    if 'rua=' in v.lower():dmarc.rua=[v.split('rua=')[1].split(';')[0]]
        except:dmarc.issues.append("No DMARC record")
        return dmarc
    def analyze_email(self,domain,records)->EmailSecurityScore:
        em=EmailSecurityScore();em.spf=self.validate_spf(domain,records);em.dkim=self.validate_dkim(domain);em.dmarc=self.validate_dmarc(domain);em.calculate_score()
        return em
    def check_dnssec(self,domain)->DNSSECStatus:
        ds=DNSSECStatus()
        try:self.resolver.resolve(domain,'DNSKEY');ds.implemented=True
        except:ds.issues.append("No DNSKEY records")
        return ds
    def analyze_domain(self,domain,client_name="Unknown",scan_type="full")->DomainAnalysis:
        start=time.time();self.logger.info(f"Analyzing {domain}")
        analysis=DomainAnalysis(domain=domain,client_name=client_name)
        try:
            analysis.records,analysis.raw_records=self.collect_records(domain)
            analysis.email_security=self.analyze_email(domain,analysis.records)
            analysis.dnssec=self.check_dnssec(domain)
            analysis.calculate_risk_score()
        except Exception as e:analysis.errors.append(str(e))
        analysis.scan_duration_seconds=time.time()-start
        self.logger.info(f"Done: {analysis.overall_risk_score}/100 in {analysis.scan_duration_seconds:.1f}s")
        return analysis
