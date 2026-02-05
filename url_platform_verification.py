#!/usr/bin/env python3
"""
Verify that URLs in reports are real and match their claimed platform types
"""

import json
import requests
import re
from datetime import datetime

class URLPlatformVerifier:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security Scanner URL Verifier'
        })
    
    def check_url_accessibility(self, scan_file):
        """Check if URLs in scan are actually accessible"""
        print(f"\n=== URL Accessibility Check for {scan_file} ===")
        
        with open(scan_file, 'r') as f:
            data = json.load(f)
        
        url = data.get('url', '')
        claimed_platform = data.get('platform_type', '')
        
        print(f"URL: {url}")
        print(f"Claimed Platform: {claimed_platform}")
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            print(f"Status Code: {response.status_code}")
            print(f"Final URL: {response.url}")
            print(f"Content-Type: {response.headers.get('content-type', 'Unknown')}")
            
            # Detect actual platform
            detected_platform = self.detect_platform(response)
            print(f"Detected Platform: {detected_platform}")
            
            # Check if platform matches
            platform_match = claimed_platform.lower() == detected_platform.lower()
            print(f"Platform Match: {'✓ YES' if platform_match else '✗ NO'}")
            
            # Check for common platform indicators
            self.analyze_platform_indicators(response, claimed_platform)
            
            return {
                'accessible': True,
                'status_code': response.status_code,
                'claimed_platform': claimed_platform,
                'detected_platform': detected_platform,
                'platform_match': platform_match
            }
            
        except Exception as e:
            print(f"Error accessing URL: {e}")
            return {
                'accessible': False,
                'error': str(e),
                'claimed_platform': claimed_platform
            }
    
    def detect_platform(self, response):
        """Detect the actual platform from response"""
        content = response.text.lower()
        headers = dict(response.headers)
        
        # Bubble.io indicators
        if ('bubble.io' in response.url or 
            'x-bubble' in str(headers).lower() or
            'bubbleapps.io' in response.url):
            return 'bubble'
        
        # OutSystems indicators
        if ('outsystems' in content or 
            'outsystems.net' in response.url or
            'outsystems' in str(headers).lower()):
            return 'outsystems'
        
        # React/Next.js indicators
        if ('react' in content or 
            '_next' in content or
            '__next' in content):
            return 'react'
        
        # WordPress indicators
        if ('wp-content' in content or 
            'wp-includes' in content or
            'wordpress' in content):
            return 'wordpress'
        
        # Generic indicators
        if any(tech in content for tech in ['html', 'javascript', 'css']):
            return 'generic'
        
        return 'unknown'
    
    def analyze_platform_indicators(self, response, claimed_platform):
        """Analyze specific platform indicators"""
        content = response.text
        headers = dict(response.headers)
        
        print(f"\nPlatform Analysis:")
        
        if claimed_platform.lower() == 'bubble':
            bubble_indicators = [
                ('Bubble Apps URL', 'bubbleapps.io' in response.url),
                ('Bubble Headers', any('bubble' in k.lower() for k in headers.keys())),
                ('Bubble Content', 'bubble' in content.lower()),
                ('Session Pattern', bool(re.search(r'\d+x\d+', content)))
            ]
            
            for indicator, found in bubble_indicators:
                print(f"  {indicator}: {'✓' if found else '✗'}")
        
        elif claimed_platform.lower() == 'outsystems':
            outsystems_indicators = [
                ('OutSystems URL', 'outsystems' in response.url),
                ('OutSystems Headers', any('outsystems' in str(v).lower() for v in headers.values())),
                ('OutSystems Content', 'outsystems' in content.lower())
            ]
            
            for indicator, found in outsystems_indicators:
                print(f"  {indicator}: {'✓' if found else '✗'}")
        
        # Check for common security headers
        security_headers = [
            'content-security-policy',
            'x-frame-options', 
            'x-content-type-options',
            'strict-transport-security',
            'permissions-policy'
        ]
        
        print(f"\nSecurity Headers Present:")
        for header in security_headers:
            present = header in headers
            print(f"  {header}: {'✓' if present else '✗'}")
    
    def check_vulnerability_urls(self, scan_file):
        """Check URLs mentioned in vulnerability instances"""
        print(f"\n=== Vulnerability URL Check for {scan_file} ===")
        
        with open(scan_file, 'r') as f:
            data = json.load(f)
        
        vulnerabilities = data.get('vulnerabilities', [])
        url_count = 0
        
        for vuln in vulnerabilities:
            instances = vuln.get('instances', [])
            for instance in instances:
                instance_url = instance.get('url', '')
                if instance_url and instance_url != data.get('url', ''):
                    url_count += 1
                    print(f"Additional URL found: {instance_url}")
                    
                    try:
                        response = self.session.get(instance_url, timeout=5)
                        print(f"  Status: {response.status_code}")
                    except Exception as e:
                        print(f"  Error: {e}")
        
        if url_count == 0:
            print("No additional URLs found in vulnerability instances")

def main():
    verifier = URLPlatformVerifier()
    
    # Get a sample of scan files
    import glob
    scan_files = glob.glob('data/scans/*.json')
    scan_files.sort()
    
    # Test a few different files
    test_files = scan_files[::10][:5]  # Every 10th file, max 5 files
    
    print("🌐 URL & PLATFORM VERIFICATION")
    print("=" * 60)
    
    results = []
    for scan_file in test_files:
        result = verifier.check_url_accessibility(scan_file)
        verifier.check_vulnerability_urls(scan_file)
        results.append(result)
        print("\n" + "-" * 60)
    
    # Summary
    print(f"\n📊 SUMMARY")
    print("=" * 60)
    
    accessible_count = sum(1 for r in results if r.get('accessible', False))
    platform_match_count = sum(1 for r in results if r.get('platform_match', False))
    
    print(f"Files checked: {len(results)}")
    print(f"Accessible URLs: {accessible_count}/{len(results)}")
    print(f"Platform matches: {platform_match_count}/{len(results)}")
    
    if len(results) > 0:
        print(f"Accessibility rate: {(accessible_count/len(results)*100):.1f}%")
        print(f"Platform accuracy: {(platform_match_count/len(results)*100):.1f}%")

if __name__ == "__main__":
    main()
