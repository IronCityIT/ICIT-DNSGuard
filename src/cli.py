#!/usr/bin/env python3
"""Iron City DNS Guard - CLI"""
import os,sys,json,argparse,logging
from pathlib import Path
from datetime import datetime

sys.path.insert(0,str(Path(__file__).parent))
from core.analyzer import DNSGuardAnalyzer

def main():
    p=argparse.ArgumentParser(description='Iron City DNS Guard')
    p.add_argument('-d','--domain',required=True,help='Domain')
    p.add_argument('-c','--client',default='CLI',help='Client')
    p.add_argument('-o','--output',default='./reports',help='Output directory')
    p.add_argument('-s','--subdomains',action='store_true')
    p.add_argument('-t','--threat-intel',action='store_true')
    p.add_argument('-g','--geolocation',action='store_true')
    p.add_argument('-v','--verbose',action='store_true')
    args=p.parse_args()
    
    print("\n🛡️  IRON CITY DNS GUARD\n"+"="*50)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    
    analyzer = DNSGuardAnalyzer()
    result = analyzer.analyze(
        domain=args.domain,
        client_name=args.client,
        enable_subdomains=args.subdomains
    )
    
    Path(args.output).mkdir(parents=True, exist_ok=True)
    outfile = Path(args.output) / f"dnsguard-{args.domain}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    
    output = result.to_dict() if hasattr(result, 'to_dict') else result
    with open(outfile, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    
    print(f"Results: {outfile}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
