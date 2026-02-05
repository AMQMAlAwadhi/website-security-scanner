#!/usr/bin/env python3
"""
Script to verify if all results in generated security reports are real.
This script validates vulnerabilities by testing actual URLs and checking evidence.
"""

import json
import requests
import re
import time
from datetime import datetime
from urllib.parse import urlparse
import sys

class ReportVerifier:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security Scanner Verifier'
        })
        self.verification_results = {
            'total_vulnerabilities': 0,
            'verified_vulnerabilities': 0,
            'false_positives': 0,
            'verification_errors': 0,
            'detailed_results': []
        }
    
    def load_scan_results(self, scan_file_path):
        """Load scan results from JSON file"""
        try:
            with open(scan_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading scan file {scan_file_path}: {e}")
            return None
    
    def verify_vulnerability(self, vulnerability, url):
        """Verify if a vulnerability is real by testing the URL"""
        vuln_type = vulnerability.get('type', '').lower()
        evidence = vulnerability.get('evidence', '')
        
        verification_result = {
            'type': vulnerability.get('type'),
            'severity': vulnerability.get('severity'),
            'url': url,
            'evidence': evidence,
            'is_real': False,
            'verification_method': '',
            'details': ''
        }
        
        try:
            # Make a request to the URL to get current state
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Verify different types of vulnerabilities
            if 'cookie' in vuln_type:
                verification_result.update(self._verify_cookie_vulnerability(vulnerability, response))
            elif 'header' in vuln_type or 'csp' in vuln_type or 'clickjacking' in vuln_type:
                verification_result.update(self._verify_header_vulnerability(vulnerability, response))
            elif 'secret' in vuln_type:
                verification_result.update(self._verify_secret_vulnerability(vulnerability, response))
            elif 'dom' in vuln_type or 'xss' in vuln_type:
                verification_result.update(self._verify_dom_vulnerability(vulnerability, response))
            elif 'endpoint' in vuln_type:
                verification_result.update(self._verify_endpoint_vulnerability(vulnerability, response))
            elif 'http/2' in vuln_type:
                verification_result.update(self._verify_http2_vulnerability(vulnerability, response))
            else:
                verification_result.update({
                    'is_real': None,
                    'verification_method': 'manual',
                    'details': f'No automated verification available for {vulnerability.get("type")}'
                })
                
        except Exception as e:
            verification_result.update({
                'is_real': None,
                'verification_method': 'error',
                'details': f'Verification failed: {str(e)}'
            })
        
        return verification_result
    
    def _verify_cookie_vulnerability(self, vulnerability, response):
        """Verify cookie-related vulnerabilities"""
        cookies = response.cookies
        set_cookie_headers = response.headers.get('set-cookie', '')
        
        vuln_type = vulnerability.get('type', '').lower()
        evidence = vulnerability.get('evidence', '')
        
        is_real = False
        details = ''
        
        if 'insecure cookie' in vuln_type or 'secure flag' in vuln_type:
            # Check if any cookie lacks Secure flag
            for cookie in cookies:
                if not cookie.secure and 'secure' not in set_cookie_headers.lower():
                    is_real = True
                    details = f'Cookie {cookie.name} lacks Secure flag'
                    break
        
        elif 'httponly' in vuln_type:
            # Check if any cookie lacks HttpOnly flag
            if 'httponly' not in set_cookie_headers.lower():
                is_real = True
                details = 'Cookie lacks HttpOnly flag'
        
        elif 'samesite' in vuln_type:
            # Check if any cookie lacks SameSite attribute
            if 'samesite' not in set_cookie_headers.lower():
                is_real = True
                details = 'Cookie lacks SameSite attribute'
        
        return {
            'is_real': is_real,
            'verification_method': 'header_analysis',
            'details': details
        }
    
    def _verify_header_vulnerability(self, vulnerability, response):
        """Verify header-related vulnerabilities"""
        headers = response.headers
        vuln_type = vulnerability.get('type', '').lower()
        
        is_real = False
        details = ''
        
        if 'content security policy' in vuln_type or 'csp' in vuln_type:
            if 'content-security-policy' not in headers:
                is_real = True
                details = 'CSP header is missing'
        
        elif 'clickjacking' in vuln_type or 'x-frame-options' in vuln_type:
            if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
                is_real = True
                details = 'Clickjacking protection headers are missing'
        
        elif 'permissions-policy' in vuln_type:
            if 'permissions-policy' not in headers:
                is_real = True
                details = 'Permissions-Policy header is missing'
        
        elif 'x-permitted-cross-domain' in vuln_type:
            if 'x-permitted-cross-domain-policies' not in headers:
                is_real = True
                details = 'X-Permitted-Cross-Domain-Policies header is missing'
        
        return {
            'is_real': is_real,
            'verification_method': 'header_analysis',
            'details': details
        }
    
    def _verify_secret_vulnerability(self, vulnerability, response):
        """Verify secret exposure vulnerabilities"""
        evidence = vulnerability.get('evidence', '')
        content = response.text
        
        # Check if the secret is still present in the response
        is_real = evidence in content if evidence else False
        
        return {
            'is_real': is_real,
            'verification_method': 'content_search',
            'details': f'Secret {"found" if is_real else "not found"} in response content'
        }
    
    def _verify_dom_vulnerability(self, vulnerability, response):
        """Verify DOM-based vulnerabilities"""
        content = response.text
        
        # Look for DOM sources and sinks
        dom_sources = ['location.href', 'document.URL', 'window.location', 'document.referrer']
        dom_sinks = ['innerHTML', 'outerHTML', 'document.write', 'eval']
        
        has_sources = any(source in content for source in dom_sources)
        has_sinks = any(sink in content for sink in dom_sinks)
        
        is_real = has_sources and has_sinks
        
        return {
            'is_real': is_real,
            'verification_method': 'content_analysis',
            'details': f'DOM sources: {has_sources}, DOM sinks: {has_sinks}'
        }
    
    def _verify_endpoint_vulnerability(self, vulnerability, response):
        """Verify exposed endpoint vulnerabilities"""
        evidence = vulnerability.get('evidence', '')
        
        # Extract endpoint URL from evidence
        endpoint_match = re.search(r'https?://[^\s"]+', evidence)
        if endpoint_match:
            endpoint_url = endpoint_match.group(0)
            try:
                # Try to access the endpoint
                endpoint_response = self.session.get(endpoint_url, timeout=5)
                is_real = endpoint_response.status_code != 404
                
                return {
                    'is_real': is_real,
                    'verification_method': 'endpoint_test',
                    'details': f'Endpoint returns status {endpoint_response.status_code}'
                }
            except:
                return {
                    'is_real': False,
                    'verification_method': 'endpoint_test',
                    'details': 'Endpoint not accessible'
                }
        
        return {
            'is_real': None,
            'verification_method': 'manual',
            'details': 'Could not extract endpoint URL from evidence'
        }
    
    def _verify_http2_vulnerability(self, vulnerability, response):
        """Verify HTTP/2 related vulnerabilities"""
        # Check if HTTP/2 is actually being used
        is_real = 'h2' in response.headers.get('alt-svc', '').lower()
        
        return {
            'is_real': is_real,
            'verification_method': 'protocol_check',
            'details': f'HTTP/2 {"supported" if is_real else "not detected"}'
        }
    
    def verify_scan_file(self, scan_file_path):
        """Verify all vulnerabilities in a scan file"""
        print(f"\nVerifying scan file: {scan_file_path}")
        
        scan_data = self.load_scan_results(scan_file_path)
        if not scan_data:
            return None
        
        url = scan_data.get('url', '')
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        print(f"URL: {url}")
        print(f"Total vulnerabilities to verify: {len(vulnerabilities)}")
        
        file_results = {
            'scan_file': scan_file_path,
            'url': url,
            'total_vulnerabilities': len(vulnerabilities),
            'verified_results': []
        }
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n[{i}/{len(vulnerabilities)}] Verifying: {vuln.get('type', 'Unknown')}")
            
            verification = self.verify_vulnerability(vuln, url)
            verification['original_severity'] = vuln.get('severity')
            verification['original_confidence'] = vuln.get('confidence')
            
            file_results['verified_results'].append(verification)
            
            # Update global counters
            self.verification_results['total_vulnerabilities'] += 1
            
            if verification['is_real'] is True:
                self.verification_results['verified_vulnerabilities'] += 1
                print(f"  ✓ REAL: {verification['details']}")
            elif verification['is_real'] is False:
                self.verification_results['false_positives'] += 1
                print(f"  ✗ FALSE POSITIVE: {verification['details']}")
            else:
                self.verification_results['verification_errors'] += 1
                print(f"  ? UNCERTAIN: {verification['details']}")
            
            # Rate limiting
            time.sleep(0.5)
        
        return file_results
    
    def generate_verification_report(self, scan_files):
        """Generate a comprehensive verification report"""
        print("\n" + "="*80)
        print("REPORT VERIFICATION SUMMARY")
        print("="*80)
        
        all_file_results = []
        
        for scan_file in scan_files:
            file_result = self.verify_scan_file(scan_file)
            if file_result:
                all_file_results.append(file_result)
        
        # Generate summary
        print(f"\n\nOVERALL VERIFICATION RESULTS:")
        print(f"Total vulnerabilities checked: {self.verification_results['total_vulnerabilities']}")
        print(f"Verified real vulnerabilities: {self.verification_results['verified_vulnerabilities']}")
        print(f"False positives: {self.verification_results['false_positives']}")
        print(f"Uncertain/Errors: {self.verification_results['verification_errors']}")
        
        if self.verification_results['total_vulnerabilities'] > 0:
            accuracy_rate = (self.verification_results['verified_vulnerabilities'] / 
                            self.verification_results['total_vulnerabilities']) * 100
            false_positive_rate = (self.verification_results['false_positives'] / 
                                 self.verification_results['total_vulnerabilities']) * 100
            
            print(f"Accuracy rate: {accuracy_rate:.1f}%")
            print(f"False positive rate: {false_positive_rate:.1f}%")
        
        # Save detailed report
        report_data = {
            'verification_timestamp': datetime.now().isoformat(),
            'summary': self.verification_results,
            'file_results': all_file_results
        }
        
        report_file = f'verification_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"\nDetailed verification report saved to: {report_file}")
        
        return report_data

def main():
    verifier = ReportVerifier()
    
    # Get all scan files
    import glob
    scan_files = glob.glob('data/scans/*.json')
    
    if not scan_files:
        print("No scan files found in data/scans/ directory")
        return
    
    print(f"Found {len(scan_files)} scan files to verify")
    
    # Verify the most recent 5 scan files to avoid too many requests
    scan_files.sort()
    recent_files = scan_files[-5:] if len(scan_files) > 5 else scan_files
    
    print(f"Verifying the most recent {len(recent_files)} scan files...")
    
    # Generate verification report
    report = verifier.generate_verification_report(recent_files)
    
    # Print conclusion
    total = verifier.verification_results['total_vulnerabilities']
    real = verifier.verification_results['verified_vulnerabilities']
    false_positives = verifier.verification_results['false_positives']
    
    if total > 0:
        if false_positives / total > 0.5:
            print("\n⚠️  HIGH FALSE POSITIVE RATE DETECTED!")
            print("The scanner may need calibration or rule adjustments.")
        elif real / total > 0.8:
            print("\n✅ HIGH ACCURACY RATE - Results appear to be reliable!")
        else:
            print("\n📊 MODERATE ACCURACY - Some verification may be needed.")

if __name__ == "__main__":
    main()
