#!/usr/bin/env python3
"""Iron City DNS Guard - API Clients (IPStack, VirusTotal, AbuseIPDB, SecurityTrails, MXToolbox)"""
import os,time,logging,requests
from typing import Optional,Dict,List

class BaseAPIClient:
    def __init__(self,api_key="",timeout=10):
        self.api_key=api_key;self.timeout=timeout;self.session=requests.Session()
        self.session.headers['User-Agent']='IronCity-DNSGuard/3.0'
    def _req(self,url,**kw)->Optional[Dict]:
        try:time.sleep(0.25);kw.setdefault('timeout',self.timeout);r=self.session.get(url,**kw);return r.json() if r.status_code==200 else None
        except:return None

class IPStackClient(BaseAPIClient):
    def __init__(self):super().__init__(os.getenv('IPSTACK_API_KEY',''))
    def get_location(self,ip)->Optional[Dict]:
        if not self.api_key:return None
        d=self._req(f"http://api.ipstack.com/{ip}?access_key={self.api_key}")
        if d and 'country_name' in d:return{'ip':ip,'country':d.get('country_name','Unknown'),'city':d.get('city','Unknown'),'region':d.get('region_name','Unknown'),'isp':d.get('connection',{}).get('isp','Unknown'),'source':'IPStack'}
        return None

class IPAPIClient(BaseAPIClient):
    def get_location(self,ip)->Optional[Dict]:
        d=self._req(f"http://ip-api.com/json/{ip}")
        if d and d.get('status')=='success':return{'ip':ip,'country':d.get('country','Unknown'),'city':d.get('city','Unknown'),'region':d.get('regionName','Unknown'),'isp':d.get('isp','Unknown'),'source':'ip-api'}
        return None

class VirusTotalClient(BaseAPIClient):
    def __init__(self):
        super().__init__(os.getenv('VIRUSTOTAL_API_KEY',''))
        if self.api_key:self.session.headers['x-apikey']=self.api_key
    def check_ip(self,ip)->Optional[Dict]:
        if not self.api_key:return None
        d=self._req(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}")
        if d and 'data' in d:
            s=d['data'].get('attributes',{}).get('last_analysis_stats',{});m=s.get('malicious',0);t=sum(s.values()) or 1
            return{'target':ip,'source':'VirusTotal','is_malicious':m>3,'confidence_score':m/t,'abuse_score':0,'total_reports':t}
        return None
    def check_domain(self,domain)->Optional[Dict]:
        if not self.api_key:return None
        d=self._req(f"https://www.virustotal.com/api/v3/domains/{domain}")
        if d and 'data' in d:
            s=d['data'].get('attributes',{}).get('last_analysis_stats',{});m=s.get('malicious',0);t=sum(s.values()) or 1
            return{'target':domain,'source':'VirusTotal','is_malicious':m>3,'confidence_score':m/t}
        return None

class AbuseIPDBClient(BaseAPIClient):
    def __init__(self):
        super().__init__(os.getenv('ABUSEIPDB_API_KEY',''))
        if self.api_key:self.session.headers.update({'Key':self.api_key,'Accept':'application/json'})
    def check_ip(self,ip)->Optional[Dict]:
        if not self.api_key:return None
        d=self._req(f"https://api.abuseipdb.com/api/v2/check",params={'ipAddress':ip,'maxAgeInDays':90})
        if d and 'data' in d:
            a=d['data'].get('abuseConfidenceScore',0)
            return{'target':ip,'source':'AbuseIPDB','is_malicious':a>50,'confidence_score':a/100,'abuse_score':a,'total_reports':d['data'].get('totalReports',0)}
        return None

class ThreatIntelAggregator:
    def __init__(self):
        self.vt=VirusTotalClient();self.abuse=AbuseIPDBClient();self.ipstack=IPStackClient();self.ipapi=IPAPIClient()
        self.available_apis={'virustotal':bool(self.vt.api_key),'abuseipdb':bool(self.abuse.api_key),'ipstack':bool(self.ipstack.api_key)}
    def check_ip(self,ip)->List[Dict]:
        results=[]
        for c in[self.vt,self.abuse]:
            try:r=c.check_ip(ip);results.append(r) if r else None
            except:pass
        return results
    def check_domain(self,domain)->List[Dict]:
        results=[]
        try:r=self.vt.check_domain(domain);results.append(r) if r else None
        except:pass
        return results
    def get_geolocation(self,ip)->Optional[Dict]:
        try:
            if self.ipstack.api_key:g=self.ipstack.get_location(ip);return g if g else None
        except:pass
        try:return self.ipapi.get_location(ip)
        except:return None
