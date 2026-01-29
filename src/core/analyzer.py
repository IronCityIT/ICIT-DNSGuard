#!/usr/bin/env python3
"""
Iron City DNS Guard v4.0 - SMB-Focused DNS Security Analyzer
Focus: Email deliverability, subdomain discovery, basic DNS health
Target: Small businesses for free marketing week
"""

import os
import sys
import json
import time
import logging
import hashlib
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.rdatatype
import requests

# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DNSRecord:
    domain: str
    record_type: str
    value: str
    ttl: int = 0
    purpose: str = ""

@dataclass
class Finding:
    severity: str  # critical, high, medium, low, info
    category: str  # Email Security, DNS Configuration, Subdomain, etc.
    title: str
    finding: str
    remediation: str
    business_impact: str = ""  # SMB-friendly explanation

@dataclass
class SubdomainResult:
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    source: str = "unknown"
    is_alive: bool = False

@dataclass
class EmailSecurityResult:
    # SPF
    spf_record: str = ""
    spf_valid: bool = False
    spf_mechanism: str = ""
    spf_issues: List[str] = field(default_factory=list)
    spf_includes: List[str] = field(default_factory=list)
    spf_lookup_count: int = 0
    
    # DKIM
    dkim_configured: bool = False
    dkim_selectors: List[str] = field(default_factory=list)
    dkim_issues: List[str] = field(default_factory=list)
    
    # DMARC
    dmarc_record: str = ""
    dmarc_valid: bool = False
    dmarc_policy: str = "none"
    dmarc_rua: List[str] = field(default_factory=list)
    dmarc_issues: List[str] = field(default_factory=list)
    
    # MTA-STS & TLS-RPT
    mta_sts: bool = False
    tls_rpt: bool = False
    
    # Overall
    overall_score: int = 0
    grade: str = "F"

@dataclass
class DNSSECResult:
    implemented: bool = False
    issues: List[str] = field(default_factory=list)

@dataclass
class DomainAnalysis:
    domain: str
    client_name: str = "Unknown"
    scan_id: str = ""
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Core data
    records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[SubdomainResult] = field(default_factory=list)
    email_security: EmailSecurityResult = field(default_factory=EmailSecurityResult)
    dnssec: DNSSECResult = field(default_factory=DNSSECResult)
    
    # Findings
    findings: List[Finding] = field(default_factory=list)
    
    # Scores (0-100, higher = more risk)
    overall_risk_score: int = 0
    risk_level: str = "unknown"
    
    # Executive summary for SMBs
    executive_summary: str = ""
    quick_wins: List[str] = field(default_factory=list)
    
    # Metadata
    scan_duration_seconds: float = 0.0
    tools_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = hashlib.md5(f"{self.domain}{time.time()}".encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        d = asdict(self)
        return d


# Common DKIM selectors to check
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "dkim", "mail", "email", "mandrill", "mailchimp", "sendgrid",
    "amazonses", "ses", "zendesk", "freshdesk", "mailgun", "sparkpost",
    "mimecast", "proofpoint", "smtp", "s1", "s2", "mx", "cm", "pm"
]


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYZER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class DNSGuardAnalyzer:
    """SMB-focused DNS Security Analyzer"""
    
    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger('dnsguard')
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'IronCity-DNSGuard/4.0'})
    
    # ─────────────────────────────────────────────────────────────────────────
    # DNS RECORD COLLECTION
    # ─────────────────────────────────────────────────────────────────────────
    
    def collect_records(self, domain: str) -> List[DNSRecord]:
        """Collect all DNS records for a domain"""
        records = []
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'CAA']
        
        purpose_map = {
            'A': 'Website/Server IP Address',
            'AAAA': 'IPv6 Address',
            'MX': 'Email Server',
            'TXT': 'Text Record',
            'NS': 'Name Server',
            'SOA': 'Zone Authority',
            'CNAME': 'Alias',
            'CAA': 'SSL Certificate Authority'
        }
        
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                for rdata in answers:
                    value = str(rdata).strip('"')
                    purpose = purpose_map.get(rtype, rtype)
                    
                    # Identify special TXT records
                    if rtype == 'TXT':
                        if 'v=spf1' in value.lower():
                            purpose = 'SPF (Email Authentication)'
                        elif 'v=dmarc1' in value.lower():
                            purpose = 'DMARC (Email Policy)'
                        elif 'v=dkim1' in value.lower():
                            purpose = 'DKIM (Email Signing)'
                    
                    records.append(DNSRecord(
                        domain=domain,
                        record_type=rtype,
                        value=value,
                        ttl=answers.rrset.ttl,
                        purpose=purpose
                    ))
            except dns.resolver.NXDOMAIN:
                self.logger.debug(f"NXDOMAIN for {domain} {rtype}")
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {rtype} record for {domain}")
            except Exception as e:
                self.logger.debug(f"Error querying {rtype} for {domain}: {e}")
        
        return records
    
    # ─────────────────────────────────────────────────────────────────────────
    # EMAIL SECURITY ANALYSIS (checkdmarc-style)
    # ─────────────────────────────────────────────────────────────────────────
    
    def analyze_email_security(self, domain: str) -> Tuple[EmailSecurityResult, List[Finding]]:
        """Comprehensive email security analysis - answers 'Will my emails land in spam?'"""
        result = EmailSecurityResult()
        findings = []
        
        # ─── SPF Analysis ───
        try:
            spf_answers = self.resolver.resolve(domain, 'TXT')
            for rdata in spf_answers:
                txt = str(rdata).strip('"')
                if txt.lower().startswith('v=spf1'):
                    result.spf_record = txt
                    result.spf_valid = True
                    
                    # Parse mechanism
                    if '-all' in txt:
                        result.spf_mechanism = '-all (hard fail)'
                    elif '~all' in txt:
                        result.spf_mechanism = '~all (soft fail)'
                        result.spf_issues.append("SPF uses soft fail (~all) - should use hard fail (-all)")
                    elif '?all' in txt:
                        result.spf_mechanism = '?all (neutral)'
                        result.spf_issues.append("SPF uses neutral (?all) - provides no protection")
                    elif '+all' in txt:
                        result.spf_mechanism = '+all (pass all)'
                        result.spf_issues.append("CRITICAL: SPF allows ANY server to send email (+all)")
                    
                    # Count DNS lookups (max 10 per RFC 7208)
                    lookups = len(re.findall(r'include:|a:|mx:|ptr:|exists:', txt.lower()))
                    result.spf_lookup_count = lookups
                    if lookups > 10:
                        result.spf_issues.append(f"SPF exceeds 10 DNS lookup limit ({lookups} found) - emails may fail")
                    elif lookups > 7:
                        result.spf_issues.append(f"SPF approaching lookup limit ({lookups}/10)")
                    
                    # Extract includes
                    result.spf_includes = re.findall(r'include:([^\s]+)', txt)
                    break
        except Exception as e:
            result.spf_issues.append("No SPF record found")
        
        if not result.spf_valid:
            findings.append(Finding(
                severity="high",
                category="Email Security",
                title="Missing SPF Record",
                finding="No SPF record found for this domain",
                remediation="Add an SPF TXT record to specify which servers can send email for your domain. Example: v=spf1 include:_spf.google.com ~all",
                business_impact="Without SPF, spammers can easily send fake emails from your domain. Your legitimate emails are more likely to be marked as spam."
            ))
        elif result.spf_issues:
            findings.append(Finding(
                severity="medium",
                category="Email Security",
                title="SPF Configuration Issues",
                finding="; ".join(result.spf_issues),
                remediation="Update your SPF record to use -all (hard fail) and ensure you stay under 10 DNS lookups",
                business_impact="Weak SPF settings reduce email deliverability and make spoofing easier."
            ))
        
        # ─── DKIM Analysis ───
        for selector in DKIM_SELECTORS:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                self.resolver.resolve(dkim_domain, 'TXT')
                result.dkim_configured = True
                result.dkim_selectors.append(selector)
            except:
                pass
        
        if not result.dkim_configured:
            findings.append(Finding(
                severity="high",
                category="Email Security",
                title="No DKIM Records Found",
                finding="No DKIM selectors found for common email providers",
                remediation="Configure DKIM signing with your email provider. This adds a digital signature to prove emails are really from you.",
                business_impact="Without DKIM, receiving servers can't verify your emails are authentic, increasing spam likelihood."
            ))
        
        # ─── DMARC Analysis ───
        try:
            dmarc_answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in dmarc_answers:
                txt = str(rdata).strip('"')
                if 'v=dmarc1' in txt.lower():
                    result.dmarc_record = txt
                    result.dmarc_valid = True
                    
                    # Parse policy
                    policy_match = re.search(r'p=(\w+)', txt.lower())
                    if policy_match:
                        result.dmarc_policy = policy_match.group(1)
                    
                    if result.dmarc_policy == 'none':
                        result.dmarc_issues.append("DMARC policy is 'none' - no enforcement, monitoring only")
                    elif result.dmarc_policy == 'quarantine':
                        pass  # Acceptable
                    elif result.dmarc_policy == 'reject':
                        pass  # Best
                    
                    # Parse reporting addresses
                    rua_match = re.search(r'rua=([^;\s]+)', txt)
                    if rua_match:
                        result.dmarc_rua = rua_match.group(1).split(',')
                    else:
                        result.dmarc_issues.append("No DMARC reporting address (rua) configured")
                    break
        except:
            result.dmarc_issues.append("No DMARC record found")
        
        if not result.dmarc_valid:
            findings.append(Finding(
                severity="high",
                category="Email Security",
                title="Missing DMARC Record",
                finding="No DMARC record found for this domain",
                remediation="Add a DMARC TXT record at _dmarc.yourdomain.com. Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                business_impact="Without DMARC, you have no visibility into who is sending email as your domain, and no way to stop spoofing."
            ))
        elif result.dmarc_policy == 'none':
            findings.append(Finding(
                severity="medium",
                category="Email Security",
                title="DMARC Policy Not Enforcing",
                finding="DMARC policy is set to 'none' - only monitoring, not blocking spoofed emails",
                remediation="After reviewing DMARC reports, upgrade policy to p=quarantine or p=reject",
                business_impact="Spoofed emails are still being delivered. Move to enforcement to protect your brand."
            ))
        
        # ─── MTA-STS Check ───
        try:
            self.resolver.resolve(f'_mta-sts.{domain}', 'TXT')
            result.mta_sts = True
        except:
            pass
        
        # ─── TLS-RPT Check ───
        try:
            self.resolver.resolve(f'_smtp._tls.{domain}', 'TXT')
            result.tls_rpt = True
        except:
            pass
        
        # ─── Calculate Email Score & Grade ───
        score = 0
        if result.spf_valid:
            score += 30
            if '-all' in result.spf_mechanism:
                score += 10
        if result.dkim_configured:
            score += 30
        if result.dmarc_valid:
            score += 20
            if result.dmarc_policy == 'reject':
                score += 10
            elif result.dmarc_policy == 'quarantine':
                score += 5
        
        result.overall_score = score
        
        if score >= 90:
            result.grade = 'A+'
        elif score >= 80:
            result.grade = 'A'
        elif score >= 70:
            result.grade = 'B'
        elif score >= 60:
            result.grade = 'C'
        elif score >= 40:
            result.grade = 'D'
        else:
            result.grade = 'F'
        
        return result, findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # SUBDOMAIN ENUMERATION
    # ─────────────────────────────────────────────────────────────────────────
    
    def enumerate_subdomains(self, domain: str) -> Tuple[List[SubdomainResult], List[Finding]]:
        """Discover subdomains - answers 'What's publicly exposed?'"""
        subdomains = []
        findings = []
        found_subs = set()
        
        # Method 1: Certificate Transparency (crt.sh)
        try:
            resp = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15
            )
            if resp.status_code == 200:
                certs = resp.json()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(domain) and '*' not in sub:
                            found_subs.add(sub)
        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")
        
        # Method 2: Common subdomain brute force
        common_subs = [
            'www', 'mail', 'webmail', 'remote', 'ftp', 'smtp', 'pop', 'imap',
            'blog', 'shop', 'store', 'api', 'dev', 'staging', 'test', 'beta',
            'admin', 'portal', 'vpn', 'secure', 'login', 'sso', 'app', 'apps',
            'cdn', 'static', 'assets', 'img', 'images', 'media', 'files',
            'ns1', 'ns2', 'dns', 'mx', 'mx1', 'mx2', 'autodiscover', 'lyncdiscover',
            'owa', 'exchange', 'cpanel', 'whm', 'plesk', 'support', 'help', 'docs'
        ]
        
        def check_subdomain(sub):
            fqdn = f"{sub}.{domain}"
            try:
                answers = self.resolver.resolve(fqdn, 'A')
                return SubdomainResult(
                    subdomain=fqdn,
                    ip_addresses=[str(r) for r in answers],
                    source='bruteforce',
                    is_alive=True
                )
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in common_subs}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subs.add(result.subdomain)
        
        # Resolve all found subdomains
        for sub in found_subs:
            try:
                ips = []
                cnames = []
                
                try:
                    a_answers = self.resolver.resolve(sub, 'A')
                    ips = [str(r) for r in a_answers]
                except:
                    pass
                
                try:
                    cname_answers = self.resolver.resolve(sub, 'CNAME')
                    cnames = [str(r).rstrip('.') for r in cname_answers]
                except:
                    pass
                
                subdomains.append(SubdomainResult(
                    subdomain=sub,
                    ip_addresses=ips,
                    cnames=cnames,
                    source='crt.sh' if sub not in common_subs else 'bruteforce',
                    is_alive=bool(ips or cnames)
                ))
            except:
                pass
        
        # Check for potential issues
        if len(subdomains) > 50:
            findings.append(Finding(
                severity="info",
                category="Subdomain Security",
                title="Large Attack Surface",
                finding=f"Found {len(subdomains)} subdomains - this is a large attack surface",
                remediation="Review all subdomains. Remove any that are unused or forgotten.",
                business_impact="Each subdomain is a potential entry point. Forgotten subdomains are a common cause of breaches."
            ))
        
        return subdomains, findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # DNSSEC CHECK
    # ─────────────────────────────────────────────────────────────────────────
    
    def check_dnssec(self, domain: str) -> Tuple[DNSSECResult, List[Finding]]:
        """Check DNSSEC implementation"""
        result = DNSSECResult()
        findings = []
        
        try:
            self.resolver.resolve(domain, 'DNSKEY')
            result.implemented = True
        except:
            result.issues.append("No DNSKEY records found")
            findings.append(Finding(
                severity="low",
                category="DNS Configuration",
                title="DNSSEC Not Implemented",
                finding="DNSSEC is not configured for this domain",
                remediation="Enable DNSSEC through your DNS provider to prevent DNS spoofing attacks",
                business_impact="Without DNSSEC, attackers could redirect your visitors to fake websites. This is relatively rare but serious."
            ))
        
        return result, findings
    
    # ─────────────────────────────────────────────────────────────────────────
    # MAIN ANALYSIS
    # ─────────────────────────────────────────────────────────────────────────
    
    def analyze(self, domain: str, client_name: str = "Unknown", 
                enable_subdomains: bool = True) -> DomainAnalysis:
        """Run complete analysis"""
        start_time = time.time()
        
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('://')[1].split('/')[0]
        
        self.logger.info(f"Analyzing {domain}")
        
        analysis = DomainAnalysis(domain=domain, client_name=client_name)
        all_findings = []
        
        try:
            # 1. Collect DNS records
            analysis.records = self.collect_records(domain)
            analysis.tools_used.append('dns-resolver')
            
            # 2. Email security (the main value for SMBs)
            analysis.email_security, email_findings = self.analyze_email_security(domain)
            all_findings.extend(email_findings)
            analysis.tools_used.append('checkdmarc-style')
            
            # 3. Subdomain enumeration
            if enable_subdomains:
                analysis.subdomains, sub_findings = self.enumerate_subdomains(domain)
                all_findings.extend(sub_findings)
                analysis.tools_used.append('crt.sh')
                analysis.tools_used.append('subdomain-bruteforce')
            
            # 4. DNSSEC check
            analysis.dnssec, dnssec_findings = self.check_dnssec(domain)
            all_findings.extend(dnssec_findings)
            
            # Store findings
            analysis.findings = all_findings
            
            # Calculate risk score (inverted - higher score = more risk)
            risk = 100 - analysis.email_security.overall_score
            
            # Add risk for issues
            critical_count = len([f for f in all_findings if f.severity == 'critical'])
            high_count = len([f for f in all_findings if f.severity == 'high'])
            medium_count = len([f for f in all_findings if f.severity == 'medium'])
            
            risk = min(100, risk + (critical_count * 15) + (high_count * 10) + (medium_count * 5))
            analysis.overall_risk_score = risk
            
            if risk >= 80:
                analysis.risk_level = 'critical'
            elif risk >= 60:
                analysis.risk_level = 'high'
            elif risk >= 40:
                analysis.risk_level = 'medium'
            elif risk >= 20:
                analysis.risk_level = 'low'
            else:
                analysis.risk_level = 'minimal'
            
            # Generate executive summary
            analysis.executive_summary = self._generate_summary(analysis)
            analysis.quick_wins = self._generate_quick_wins(analysis)
            
        except Exception as e:
            analysis.errors.append(str(e))
            self.logger.error(f"Analysis error: {e}")
        
        analysis.scan_duration_seconds = time.time() - start_time
        return analysis
    
    def _generate_summary(self, analysis: DomainAnalysis) -> str:
        """Generate SMB-friendly executive summary"""
        grade = analysis.email_security.grade
        
        if grade in ['A+', 'A']:
            return f"Great news! Your email security for {analysis.domain} is excellent ({grade}). Your emails should have good deliverability and your domain is well-protected against spoofing."
        elif grade == 'B':
            return f"Your email security for {analysis.domain} is good ({grade}), but there's room for improvement. A few configuration changes could boost your deliverability and protection."
        elif grade == 'C':
            return f"Your email security for {analysis.domain} needs attention ({grade}). Some of your emails may be landing in spam folders, and your domain has moderate spoofing risk."
        else:
            return f"Your email security for {analysis.domain} requires immediate attention ({grade}). Your emails are likely being flagged as spam, and your domain is vulnerable to spoofing attacks."
    
    def _generate_quick_wins(self, analysis: DomainAnalysis) -> List[str]:
        """Generate actionable quick wins for SMBs"""
        wins = []
        
        if not analysis.email_security.spf_valid:
            wins.append("Add an SPF record to improve email deliverability")
        
        if not analysis.email_security.dkim_configured:
            wins.append("Enable DKIM signing through your email provider")
        
        if not analysis.email_security.dmarc_valid:
            wins.append("Add a DMARC record to monitor email authentication")
        elif analysis.email_security.dmarc_policy == 'none':
            wins.append("Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")
        
        if not analysis.dnssec.implemented:
            wins.append("Enable DNSSEC for added DNS security")
        
        return wins[:3]  # Top 3 quick wins


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Iron City DNS Guard v4.0')
    parser.add_argument('domain', help='Domain to analyze')
    parser.add_argument('-c', '--client', default='Unknown', help='Client name')
    parser.add_argument('-s', '--subdomains', action='store_true', default=True, help='Enable subdomain enumeration')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    analyzer = DNSGuardAnalyzer()
    result = analyzer.analyze(
        domain=args.domain,
        client_name=args.client,
        enable_subdomains=args.subdomains
    )
    
    output = json.dumps(result.to_dict(), indent=2, default=str)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)
    
    # Print summary
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  Domain: {result.domain}", file=sys.stderr)
    print(f"  Email Grade: {result.email_security.grade}", file=sys.stderr)
    print(f"  Risk Score: {result.overall_risk_score}/100", file=sys.stderr)
    print(f"  Findings: {len(result.findings)}", file=sys.stderr)
    print(f"  Subdomains: {len(result.subdomains)}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)


if __name__ == "__main__":
    main()
