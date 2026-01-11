#!/usr/bin/env python3
"""Iron City DNS Guard - DNS Tools (dnsperf, subdomain enum, dnscontrol, unbound)"""
import os,time,logging,shutil,subprocess
from typing import List,Dict,Optional
from concurrent.futures import ThreadPoolExecutor,as_completed
import dns.resolver,requests,numpy as np

class DNSPerformanceTester:
    SERVERS={'cloudflare':('1.1.1.1','Cloudflare'),'google':('8.8.8.8','Google'),'quad9':('9.9.9.9','Quad9'),'opendns':('208.67.222.222','OpenDNS')}
    def __init__(self,logger=None):self.logger=logger or logging.getLogger('dnsguard.perf')
    def benchmark(self,ip,domain,n=20,name="")->Dict:
        res=dns.resolver.Resolver();res.nameservers=[ip];res.timeout=5;lat,fail=[],0
        for _ in range(n):
            try:s=time.perf_counter();res.resolve(domain,'A');lat.append((time.perf_counter()-s)*1000)
            except:fail+=1
        if not lat:return{'dns_server':ip,'server_name':name,'latency_avg':9999,'packet_loss':100}
        return{'dns_server':ip,'server_name':name or ip,'latency_avg':float(np.mean(lat)),'latency_min':float(np.min(lat)),'latency_max':float(np.max(lat)),'queries_per_second':len(lat)/sum(lat)*1000 if sum(lat)>0 else 0,'packet_loss':fail/n*100}
    def compare_dns_servers(self,domain,n=15)->Dict[str,Dict]:
        return{k:self.benchmark(ip,domain,n,name) for k,(ip,name) in self.SERVERS.items()}

class SubdomainEnumerator:
    COMMON=['www','mail','ftp','smtp','webmail','ns1','ns2','api','dev','staging','test','admin','portal','vpn','blog','shop','app','cdn','static','db','git','jenkins','docs','m','mobile','secure','login','sso','dashboard']
    def __init__(self,logger=None,workers=10):self.logger=logger or logging.getLogger('dnsguard.sub');self.workers=workers;self.res=dns.resolver.Resolver();self.res.timeout=3
    def enumerate(self,domain,use_crt_sh=True)->List[Dict]:
        found,results=set(),[]
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futs={ex.submit(self._resolve,f"{s}.{domain}"):s for s in self.COMMON}
            for f in as_completed(futs):
                r=f.result()
                if r and r['subdomain'] not in found:r['source']='brute-force';results.append(r);found.add(r['subdomain'])
        if use_crt_sh:
            for fqdn in self._crtsh(domain):
                if fqdn not in found:
                    r=self._resolve(fqdn)
                    if r:r['source']='certificate-transparency';results.append(r);found.add(fqdn)
        return results
    def _resolve(self,fqdn)->Optional[Dict]:
        r={'subdomain':fqdn,'ip_addresses':[],'cnames':[],'is_alive':False}
        try:ans=self.res.resolve(fqdn,'A');r['ip_addresses']=[str(x) for x in ans];r['is_alive']=True
        except:pass
        try:ans=self.res.resolve(fqdn,'CNAME');r['cnames']=[str(x) for x in ans];r['is_alive']=True
        except:pass
        return r if r['is_alive'] else None
    def _crtsh(self,domain)->List[str]:
        try:
            r=requests.get(f"https://crt.sh/?q=%.{domain}&output=json",timeout=30)
            if r.status_code==200:
                subs=set()
                for e in r.json():
                    for l in e.get('name_value','').split('\n'):
                        l=l.strip().lower()
                        if l.endswith(domain) and '*' not in l:subs.add(l)
                return list(subs)
        except:pass
        return[]

class DNSControlManager:
    def __init__(self,logger=None):self.logger=logger or logging.getLogger('dnsguard.dnscontrol');self.available=shutil.which('dnscontrol') is not None
    def audit(self,domain,records)->Dict:
        issues,recs,score=[],[],100;types=[r.get('record_type') for r in records];txt=[r.get('value','') for r in records if r.get('record_type')=='TXT']
        if 'A' not in types and 'AAAA' not in types:issues.append('No address records');score-=20
        if types.count('NS')<2:recs.append('Add 2+ NS records');score-=5
        if not any('v=spf1' in t.lower() for t in txt):issues.append('No SPF');score-=10
        if 'CAA' not in types:recs.append('Add CAA record')
        return{'domain':domain,'score':max(0,score),'issues':issues,'recommendations':recs}
    def generate_rpz(self,domains)->str:
        rpz=f"; Iron City DNS Guard RPZ - {time.strftime('%Y-%m-%d')}\n$TTL 300\n@ SOA localhost. root.localhost. 1 3600 900 86400 300\n  NS localhost.\n\n"
        for d in domains:d=d.strip().lower();rpz+=f"{d} CNAME .\n*.{d} CNAME .\n" if d and not d.startswith('#') else ""
        return rpz

class UnboundManager:
    def __init__(self,logger=None):self.logger=logger or logging.getLogger('dnsguard.unbound');self.available=shutil.which('unbound-control') is not None
    def generate_blocklist(self,domains)->str:
        cfg=f"# Iron City DNS Guard Blocklist\nserver:\n"
        for d in domains:d=d.strip().lower();cfg+=f'    local-zone: "{d}" always_nxdomain\n' if d and not d.startswith('#') else ""
        return cfg

class HopsAnalyzer:
    def __init__(self,logger=None):self.logger=logger or logging.getLogger('dnsguard.hops');self.tr=shutil.which('traceroute') or shutil.which('tracert')
    def analyze(self,target,max_hops=20)->Dict:
        r={'target':target,'hops':[],'total_hops':0,'reachable':False}
        if not self.tr:return r
        try:
            cmd=[self.tr,'-m',str(max_hops),'-w','1','-q','1',target]
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
            for l in p.stdout.split('\n')[1:]:
                if not l.strip():continue
                parts=l.split()
                if len(parts)>=2:
                    h={'hop':len(r['hops'])+1}
                    for p in parts[1:]:
                        if '.' in p and p.replace('.','').replace(':','').isalnum():h['ip']=p.strip('()')
                        elif 'ms' in p.lower():
                            try:h['time_ms']=float(p.replace('ms',''))
                            except:pass
                    if h.get('ip'):r['hops'].append(h)
            r['total_hops']=len(r['hops']);r['reachable']=r['total_hops']>0
        except:pass
        return r
