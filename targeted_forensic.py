#!/usr/bin/env python3
"""
Targeted forensic verification focusing on accessible URLs
"""

import json
import requests
import re
from datetime import datetime
from typing import Dict, List, Any

class TargetedForensic:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security Scanner Targeted Forensic Verifier'
        })
    
    def analyze_mern_scans(self):
        """Analyze MERN app scans specifically"""
        print("🔍 TARGETED FORENSIC ANALYSIS - MERN APP")
        print("=" * 60)
        
        # Find MERN scan files
        import glob
        all_scans = glob.glob('data/scans/*.json')
        mern_scans = []
        
        for scan_file in all_scans:
            try:
                with open(scan_file, 'r') as f:
                    data = json.load(f)
                    url = data.get('url', '')
                    if 'render.com' in url or 'mern' in url.lower():
                        mern_scans.append(scan_file)
            except:
                continue
        
        print(f"Found {len(mern_scans)} MERN scan files")
        
        if not mern_scans:
            print("No MERN scan files found")
            return
        
        # Analyze the most recent MERN scan
        mern_scans.sort()
        latest_scan = mern_scans[-1]
        
        print(f"\nAnalyzing: {latest_scan}")
        
        try:
            with open(latest_scan, 'r') as f:
                scan_data = json.load(f)
            
            url = scan_data.get('url', '')
            vulnerabilities = scan_data.get('vulnerabilities', [])
            
            print(f"URL: {url}")
            print(f"Vulnerabilities: {len(vulnerabilities)}")
            
            # Get live content
            live_response = self.session.get(url, timeout=10)
            live_content = live_response.text
            
            print(f"Live response status: {live_response.status_code}")
            
            # Analyze each vulnerability
            evidence_analysis = {
                'matches': 0,
                'mismatches': 0,
                'missing': 0,
                'details': []
            }
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '')
                evidence = vuln.get('evidence', '')
                
                detail = {
                    'type': vuln_type,
                    'severity': vuln.get('severity', ''),
                    'evidence': evidence[:50] + '...' if len(evidence) > 50 else evidence,
                    'status': 'unknown'
                }
                
                if not evidence:
                    detail['status'] = 'missing'
                    evidence_analysis['missing'] += 1
                elif evidence in live_content:
                    detail['status'] = 'matches'
                    evidence_analysis['matches'] += 1
                elif evidence.lower() in str(live_response.headers).lower():
                    detail['status'] = 'matches_header'
                    evidence_analysis['matches'] += 1
                else:
                    detail['status'] = 'mismatch'
                    evidence_analysis['mismatches'] += 1
                
                evidence_analysis['details'].append(detail)
            
            # Print results
            print(f"\n📊 EVIDENCE ANALYSIS")
            print("-" * 40)
            print(f"Matches: {evidence_analysis['matches']}")
            print(f"Mismatches: {evidence_analysis['mismatches']}")
            print(f"Missing: {evidence_analysis['missing']}")
            
            total = evidence_analysis['matches'] + evidence_analysis['mismatches'] + evidence_analysis['missing']
            if total > 0:
                consistency_rate = (evidence_analysis['matches'] / total) * 100
                print(f"Consistency rate: {consistency_rate:.1f}%")
            
            print(f"\n🔍 DETAILED BREAKDOWN")
            print("-" * 40)
            for detail in evidence_analysis['details']:
                status_icon = "✓" if detail['status'] == 'matches' else "✗" if detail['status'] == 'mismatch' else "?"
                print(f"{status_icon} {detail['type']} ({detail['severity']}) - {detail['status']}")
                if detail['evidence']:
                    print(f"    Evidence: {detail['evidence']}")
            
            # Check for specific patterns
            print(f"\n🎯 PATTERN ANALYSIS")
            print("-" * 40)
            
            # Check for HTTP/2 claims
            http2_vulns = [v for v in vulnerabilities if 'http/2' in v.get('type', '').lower()]
            if http2_vulns:
                print(f"HTTP/2 vulnerabilities found: {len(http2_vulns)}")
                # Check actual HTTP version
                actual_version = live_response.raw.version if hasattr(live_response.raw, 'version') else 'unknown'
                print(f"Actual HTTP version: {actual_version}")
                
                # Check Alt-Svc header
                alt_svc = live_response.headers.get('alt-svc', '')
                print(f"Alt-Svc header: {alt_svc}")
                
                if 'h2' not in alt_svc.lower() and actual_version != 2:
                    print("⚠️  HTTP/2 claim appears to be FALSE POSITIVE")
            
            # Check for cookie issues
            cookie_vulns = [v for v in vulnerabilities if 'cookie' in v.get('type', '').lower()]
            if cookie_vulns:
                print(f"\nCookie vulnerabilities: {len(cookie_vulns)}")
                cookies = live_response.cookies
                set_cookie = live_response.headers.get('set-cookie', '')
                
                print(f"Live cookies: {len(cookies)}")
                print(f"Set-Cookie present: {'Yes' if set_cookie else 'No'}")
                
                for cookie in cookies:
                    print(f"  - {cookie.name}: secure={cookie.secure}")
                
                # Analyze cookie claims
                secure_missing = [v for v in cookie_vulns if 'secure' in v.get('type', '').lower()]
                httponly_missing = [v for v in cookie_vulns if 'httponly' in v.get('type', '').lower()]
                
                if secure_missing and len(cookies) == 0:
                    print("⚠️  Cookie security claims may be FALSE POSITIVES (no cookies found)")
                
                if httponly_missing and 'httponly' not in set_cookie.lower():
                    print("✓ HttpOnly claim appears VALID")
            
            # Check for header issues
            header_vulns = [v for v in vulnerabilities if any(h in v.get('type', '').lower() for h in ['csp', 'header', 'clickjacking'])]
            if header_vulns:
                print(f"\nHeader vulnerabilities: {len(header_vulns)}")
                
                missing_headers = []
                for vuln in header_vulns:
                    vuln_type = vuln.get('type', '').lower()
                    if 'csp' in vuln_type and 'content-security-policy' not in live_response.headers:
                        missing_headers.append('CSP')
                    elif 'clickjacking' in vuln_type and 'x-frame-options' not in live_response.headers:
                        missing_headers.append('X-Frame-Options')
                    elif 'permissions-policy' in vuln_type and 'permissions-policy' not in live_response.headers:
                        missing_headers.append('Permissions-Policy')
                
                if missing_headers:
                    print(f"✓ Missing headers confirmed: {', '.join(missing_headers)}")
                else:
                    print("⚠️  Header claims may be FALSE POSITIVES")
            
        except Exception as e:
            print(f"Error during analysis: {e}")
    
    def analyze_bubble_offline(self):
        """Analyze Bubble scans offline (without live access)"""
        print(f"\n🔍 OFFLINE BUBBLE ANALYSIS")
        print("=" * 60)
        
        import glob
        bubble_scans = []
        
        for scan_file in glob.glob('data/scans/*.json'):
            try:
                with open(scan_file, 'r') as f:
                    data = json.load(f)
                    url = data.get('url', '')
                    if 'bubbleapps.io' in url:
                        bubble_scans.append(scan_file)
            except:
                continue
        
        if not bubble_scans:
            print("No Bubble scan files found")
            return
        
        print(f"Found {len(bubble_scans)} Bubble scan files")
        
        # Analyze patterns in Bubble scans
        total_vulns = 0
        secret_vulns = 0
        bubble_session_patterns = 0
        
        for scan_file in bubble_scans[:3]:  # Analyze first 3
            try:
                with open(scan_file, 'r') as f:
                    data = json.load(f)
                
                vulnerabilities = data.get('vulnerabilities', [])
                total_vulns += len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    vuln_type = vuln.get('type', '').lower()
                    evidence = vuln.get('evidence', '')
                    
                    if 'secret' in vuln_type:
                        secret_vulns += 1
                        # Check for Bubble session ID pattern
                        if re.match(r'^\d{13,}x\d+', evidence):
                            bubble_session_patterns += 1
                
            except Exception as e:
                print(f"Error analyzing {scan_file}: {e}")
        
        print(f"Total vulnerabilities: {total_vulns}")
        print(f"Secret vulnerabilities: {secret_vulns}")
        print(f"Bubble session ID patterns: {bubble_session_patterns}")
        
        if bubble_session_patterns > 0:
            false_positive_rate = (bubble_session_patterns / secret_vulns * 100) if secret_vulns > 0 else 0
            print(f"Secret false positive rate: {false_positive_rate:.1f}%")
            print("⚠️  High likelihood of systematic false positives in secret detection")

def main():
    forensic = TargetedForensic()
    
    # Analyze MERN scans (accessible)
    forensic.analyze_mern_scans()
    
    # Offline analysis of Bubble scans
    forensic.analyze_bubble_offline()
    
    print(f"\n🎯 CONCLUSION")
    print("=" * 60)
    print("This targeted analysis provides additional evidence for report authenticity assessment.")

if __name__ == "__main__":
    main()
