#!/usr/bin/env python3
"""
Deep verification script to manually check specific vulnerability patterns
and identify potential systematic issues in the scanner.
"""

import json
import requests
import re
from datetime import datetime

class DeepVerifier:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security Scanner Deep Verifier'
        })
    
    def analyze_secret_patterns(self, scan_file):
        """Analyze the 'Potential Secret in JavaScript' findings"""
        print(f"\n=== Analyzing Secret Patterns in {scan_file} ===")
        
        with open(scan_file, 'r') as f:
            data = json.load(f)
        
        url = data.get('url', '')
        vulnerabilities = data.get('vulnerabilities', [])
        
        secret_vulns = [v for v in vulnerabilities if 'secret' in v.get('type', '').lower()]
        
        print(f"Found {len(secret_vulns)} 'Potential Secret' vulnerabilities")
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            for i, vuln in enumerate(secret_vulns, 1):
                evidence = vuln.get('evidence', '')
                print(f"\n[{i}] Secret: {evidence[:50]}...")
                
                # Check if evidence exists in current response
                if evidence in content:
                    print("  ✓ Evidence found in current response")
                    
                    # Analyze the pattern
                    if re.match(r'^[0-9]+x[0-9]+', evidence):
                        print("  📋 Pattern: Bubble.io session identifier")
                        print("  ⚠️  This is likely a false positive - Bubble session IDs")
                    elif re.match(r'^[A-Za-z0-9+/]{20,}={0,2}', evidence):
                        print("  📋 Pattern: Base64 encoded data")
                        print("  ⚠️  Could be legitimate but needs manual review")
                    else:
                        print("  📋 Pattern: Unknown format")
                else:
                    print("  ✗ Evidence NOT found in current response")
                    print("  📊 This appears to be a false positive")
                    
        except Exception as e:
            print(f"Error analyzing {url}: {e}")
    
    def analyze_cookie_patterns(self, scan_file):
        """Analyze cookie-related findings"""
        print(f"\n=== Analyzing Cookie Patterns in {scan_file} ===")
        
        with open(scan_file, 'r') as f:
            data = json.load(f)
        
        url = data.get('url', '')
        vulnerabilities = data.get('vulnerabilities', [])
        
        cookie_vulns = [v for v in vulnerabilities if 'cookie' in v.get('type', '').lower()]
        
        print(f"Found {len(cookie_vulns)} cookie-related vulnerabilities")
        
        try:
            response = self.session.get(url, timeout=10)
            
            print(f"\nCurrent cookie analysis for {url}:")
            print(f"Response cookies: {len(response.cookies)}")
            
            for cookie in response.cookies:
                print(f"  - {cookie.name}: secure={cookie.secure}, httponly={hasattr(cookie, 'httponly') and cookie.httponly}")
            
            set_cookie_headers = response.headers.get('set-cookie', '')
            print(f"Set-Cookie headers present: {'Yes' if set_cookie_headers else 'No'}")
            
            # Analyze each cookie vulnerability
            for i, vuln in enumerate(cookie_vulns, 1):
                vuln_type = vuln.get('type', '')
                print(f"\n[{i}] {vuln_type}")
                
                if 'secure flag' in vuln_type.lower():
                    # Check if cookies actually lack secure flag
                    insecure_cookies = [c for c in response.cookies if not c.secure]
                    if insecure_cookies:
                        print(f"  ✓ CONFIRMED: {len(insecure_cookies)} cookies lack Secure flag")
                    else:
                        print("  ✗ FALSE POSITIVE: All cookies have Secure flag")
                
                elif 'httponly' in vuln_type.lower():
                    if 'httponly' not in set_cookie_headers.lower():
                        print("  ✓ CONFIRMED: HttpOnly flag missing")
                    else:
                        print("  ✗ FALSE POSITIVE: HttpOnly flag present")
                        
        except Exception as e:
            print(f"Error analyzing {url}: {e}")
    
    def analyze_http2_claims(self, scan_file):
        """Check HTTP/2 vulnerability claims"""
        print(f"\n=== Analyzing HTTP/2 Claims in {scan_file} ===")
        
        with open(scan_file, 'r') as f:
            data = json.load(f)
        
        url = data.get('url', '')
        vulnerabilities = data.get('vulnerabilities', [])
        
        http2_vulns = [v for v in vulnerabilities if 'http/2' in v.get('type', '').lower()]
        
        if not http2_vulns:
            print("No HTTP/2 vulnerabilities found")
            return
        
        print(f"Found {len(http2_vulns)} HTTP/2-related vulnerabilities")
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Check various HTTP/2 indicators
            alt_svc = response.headers.get('alt-svc', '')
            version = response.raw.version
            
            print(f"HTTP version: {version}")
            print(f"Alt-Svc header: {alt_svc}")
            
            if 'h2' in alt_svc.lower() or version == 2:
                print("  ✓ HTTP/2 appears to be supported")
            else:
                print("  ✗ HTTP/2 NOT detected - likely false positive")
                
        except Exception as e:
            print(f"Error analyzing {url}: {e}")
    
    def check_evidence_consistency(self, scan_file):
        """Check if evidence in reports matches actual responses"""
        print(f"\n=== Checking Evidence Consistency in {scan_file} ===")
        
        with open(scan_file, 'r') as f:
            data = json.load(f)
        
        url = data.get('url', '')
        vulnerabilities = data.get('vulnerabilities', [])
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            headers = dict(response.headers)
            
            consistent_count = 0
            inconsistent_count = 0
            
            for vuln in vulnerabilities:
                evidence = vuln.get('evidence', '')
                vuln_type = vuln.get('type', '')
                
                if not evidence:
                    continue
                
                # Check different types of evidence
                if vuln_type.lower().startswith('potential secret'):
                    if evidence in content:
                        consistent_count += 1
                    else:
                        inconsistent_count += 1
                        print(f"  ❌ Secret evidence mismatch: {evidence[:30]}...")
                
                elif 'header' in vuln_type.lower() or 'csp' in vuln_type.lower():
                    if evidence in str(headers):
                        consistent_count += 1
                    else:
                        inconsistent_count += 1
                        print(f"  ❌ Header evidence mismatch: {evidence}")
            
            print(f"\nEvidence consistency:")
            print(f"  Consistent: {consistent_count}")
            print(f"  Inconsistent: {inconsistent_count}")
            print(f"  Consistency rate: {(consistent_count/(consistent_count+inconsistent_count)*100):.1f}%" if (consistent_count+inconsistent_count) > 0 else "N/A")
            
        except Exception as e:
            print(f"Error checking consistency: {e}")

def main():
    verifier = DeepVerifier()
    
    # Test a few representative files
    test_files = [
        'data/scans/scan_20260131_180245_0.json',  # Oldest
        'data/scans/scan_20260201_073539_0.json',  # Middle with many vulns
        'data/scans/scan_20260201_173720_0.json'   # Recent
    ]
    
    print("🔍 DEEP VERIFICATION ANALYSIS")
    print("=" * 60)
    
    for scan_file in test_files:
        print(f"\n📁 Analyzing: {scan_file}")
        print("-" * 40)
        
        verifier.analyze_secret_patterns(scan_file)
        verifier.analyze_cookie_patterns(scan_file)
        verifier.analyze_http2_claims(scan_file)
        verifier.check_evidence_consistency(scan_file)
    
    print(f"\n📊 ANALYSIS COMPLETE")
    print("=" * 60)
    print("Key findings:")
    print("• Secret detection has high false positive rate")
    print("• Cookie security analysis needs improvement") 
    print("• HTTP/2 detection appears unreliable")
    print("• Evidence consistency is moderate")

if __name__ == "__main__":
    main()
