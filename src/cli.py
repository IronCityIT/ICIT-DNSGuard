#!/usr/bin/env python3
"""Iron City DNS Guard - CLI"""
import os,sys,json,argparse,logging
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from core.analyzer import DNSGuardAnalyzer,DNSGuardConfig,ThreatIntel,GeoLocation,SubdomainResult,PerformanceMetrics
from integrations.api_clients import ThreatIntelAggregator
from integrations.dns_tools import SubdomainEnumerator,DNSPerformanceTester

def main():
    p=argparse.ArgumentParser(description='Iron City DNS Guard')
    p.add_argument('-d','--domain',help='Domain');p.add_argument('-D','--domains',help='File with domains')
    p.add_argument('-c','--client',default='CLI',help='Client');p.add_argument('-o','--output',default='./reports')
    p.add_argument('-s','--subdomains',action='store_true');p.add_argument('-t','--threat-intel',action='store_true')
    p.add_argument('-g','--geolocation',action='store_true');p.add_argument('-p','--performance',action='store_true')
    p.add_argument('-v','--verbose',action='store_true');p.add_argument('-q','--quiet',action='store_true')
    args=p.parse_args()
    if not args.quiet:print("\n🛡️  IRON CITY DNS GUARD v3.0\n"+"="*50)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO)
    domains=[args.domain] if args.domain else Path(args.domains).read_text().strip().split('\n') if args.domains else []
    if not domains:print("No domains");return 1
    analyzer=DNSGuardAnalyzer(config=DNSGuardConfig(),logger=logging.getLogger('dnsguard'))
    ti=ThreatIntelAggregator() if args.threat_intel or args.geolocation else None
    se=SubdomainEnumerator() if args.subdomains else None
    pt=DNSPerformanceTester() if args.performance else None
    Path(args.output).mkdir(parents=True,exist_ok=True)
    for domain in domains:
        domain=domain.strip().lower()
        if not domain:continue
        print(f"\n🔍 Analyzing: {domain}")
        a=analyzer.analyze_domain(domain,args.client)
        if ti:
            ips=[r.value for r in a.records if r.record_type=='A'][:5]
            for ip in ips:
                for t in ti.check_ip(ip):a.threat_intel.append(ThreatIntel(**t))
                if args.geolocation:g=ti.get_geolocation(ip);a.geolocations.append(GeoLocation(**g)) if g else None
        if se:
            for s in se.enumerate(domain)[:50]:a.subdomains.append(SubdomainResult(**s))
        if pt:
            for k,m in pt.compare_dns_servers(domain).items():a.performance.append(PerformanceMetrics(**m))
        a.calculate_risk_score()
        icon="🟢" if a.overall_risk_score>=80 else "🟡" if a.overall_risk_score>=60 else "🔴"
        print(f"{icon} Score: {a.overall_risk_score}/100 ({a.risk_level.value})")
        print(f"   Email: {a.email_security.grade} | DNSSEC: {'✅' if a.dnssec.implemented else '❌'} | Records: {len(a.records)}")
        if a.threat_intel:mal=sum(1 for t in a.threat_intel if t.is_malicious);print(f"   Threats: {'🚨 '+str(mal)+' malicious!' if mal else '✅ Clean'}")
        if a.subdomains:print(f"   Subdomains: {len(a.subdomains)} found")
        out=Path(args.output)/f"{a.scan_id}.json"
        out.write_text(json.dumps(a.to_dict(),indent=2,default=str))
        print(f"   📄 Report: {out}")
    print("\n✅ Done!")
    return 0

if __name__=='__main__':sys.exit(main())
