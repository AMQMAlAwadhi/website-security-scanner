#!/usr/bin/env python3
"""
Forensic verification script to detect evidence tampering and timestamp inconsistencies
in security scan reports.
"""

import json
import requests
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import re

class ForensicVerifier:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security Scanner Forensic Verifier'
        })
        
    def calculate_content_hash(self, content: str) -> str:
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def extract_timestamps(self, scan_data: Dict) -> Dict[str, datetime]:
        """Extract various timestamps from scan data"""
        timestamps = {}
        
        # Main scan timestamp
        if 'timestamp' in scan_data:
            try:
                timestamps['scan_timestamp'] = datetime.fromisoformat(scan_data['timestamp'].replace('Z', '+00:00'))
            except:
                pass
        
        # Vulnerability timestamps
        vuln_timestamps = []
        for vuln in scan_data.get('vulnerabilities', []):
            if 'timestamp' in vuln:
                try:
                    vuln_ts = datetime.fromisoformat(vuln['timestamp'].replace('Z', '+00:00'))
                    vuln_timestamps.append(vuln_ts)
                except:
                    pass
        
        if vuln_timestamps:
            timestamps['first_vulnerability'] = min(vuln_timestamps)
            timestamps['last_vulnerability'] = max(vuln_timestamps)
            timestamps['vulnerability_span'] = timestamps['last_vulnerability'] - timestamps['first_vulnerability']
        
        return timestamps
    
    def verify_live_content(self, scan_file: str) -> Dict[str, Any]:
        """Verify if evidence matches live content"""
        print(f"\n=== Forensic Analysis of {scan_file} ===")
        
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        url = scan_data.get('url', '')
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        results = {
            'scan_file': scan_file,
            'url': url,
            'evidence_matches': 0,
            'evidence_mismatches': 0,
            'missing_evidence': 0,
            'timestamp_issues': [],
            'content_hash_mismatches': [],
            'detailed_analysis': []
        }
        
        # Extract timestamps
        timestamps = self.extract_timestamps(scan_data)
        results['timestamps'] = timestamps
        
        print(f"Analyzing {len(vulnerabilities)} vulnerabilities for {url}")
        
        try:
            # Get current live content
            live_response = self.session.get(url, timeout=15)
            live_content = live_response.text
            live_hash = self.calculate_content_hash(live_content)
            
            print(f"Live content hash: {live_hash[:16]}...")
            print(f"Live response status: {live_response.status_code}")
            
            # Analyze each vulnerability
            for i, vuln in enumerate(vulnerabilities, 1):
                vuln_analysis = self._analyze_vulnerability_forensics(vuln, live_content, live_response)
                results['detailed_analysis'].append(vuln_analysis)
                
                # Update counters
                if vuln_analysis['evidence_status'] == 'matches':
                    results['evidence_matches'] += 1
                elif vuln_analysis['evidence_status'] == 'mismatch':
                    results['evidence_mismatches'] += 1
                elif vuln_analysis['evidence_status'] == 'missing':
                    results['missing_evidence'] += 1
                
                # Check for timestamp anomalies
                if vuln_analysis.get('timestamp_anomaly'):
                    results['timestamp_issues'].append(vuln_analysis['timestamp_anomaly'])
                
                # Check for content hash mismatches
                if vuln_analysis.get('content_hash_mismatch'):
                    results['content_hash_mismatches'].append(vuln_analysis['content_hash_mismatch'])
            
            # Calculate forensic scores
            total_vulns = len(vulnerabilities)
            if total_vulns > 0:
                results['evidence_consistency_rate'] = (results['evidence_matches'] / total_vulns) * 100
                results['evidence_inconsistency_rate'] = (results['evidence_mismatches'] / total_vulns) * 100
            else:
                results['evidence_consistency_rate'] = 0
                results['evidence_inconsistency_rate'] = 0
            
            # Check for systematic issues
            results['systematic_issues'] = self._detect_systematic_issues(results)
            
        except Exception as e:
            results['error'] = str(e)
            print(f"Error during forensic analysis: {e}")
        
        return results
    
    def _analyze_vulnerability_forensics(self, vuln: Dict, live_content: str, live_response: requests.Response) -> Dict[str, Any]:
        """Analyze individual vulnerability for forensic evidence"""
        analysis = {
            'vulnerability_type': vuln.get('type', ''),
            'severity': vuln.get('severity', ''),
            'evidence': vuln.get('evidence', ''),
            'evidence_status': 'unknown',
            'timestamp_anomaly': None,
            'content_hash_mismatch': None
        }
        
        evidence = vuln.get('evidence', '')
        
        # Check evidence presence
        if not evidence:
            analysis['evidence_status'] = 'missing'
        elif evidence in live_content:
            analysis['evidence_status'] = 'matches'
            analysis['live_evidence_found'] = True
        else:
            analysis['evidence_status'] = 'mismatch'
            analysis['live_evidence_found'] = False
            
            # Check if evidence might be in headers
            if evidence.lower() in str(live_response.headers).lower():
                analysis['evidence_status'] = 'matches_header'
                analysis['live_evidence_found'] = True
        
        # Check timestamp consistency
        vuln_timestamp = vuln.get('timestamp', '')
        if vuln_timestamp:
            try:
                vuln_time = datetime.fromisoformat(vuln_timestamp.replace('Z', '+00:00'))
                current_time = datetime.now()
                
                # Check if timestamp is in the future
                if vuln_time > current_time + timedelta(minutes=5):
                    analysis['timestamp_anomaly'] = f"Future timestamp: {vuln_timestamp}"
                
                # Check if timestamp is very old (more than 30 days)
                if vuln_time < current_time - timedelta(days=30):
                    analysis['timestamp_anomaly'] = f"Very old timestamp: {vuln_timestamp}"
                    
            except:
                analysis['timestamp_anomaly'] = f"Invalid timestamp format: {vuln_timestamp}"
        
        # Special analysis for secret vulnerabilities
        if 'secret' in analysis['vulnerability_type'].lower():
            analysis.update(self._analyze_secret_forensics(vuln, live_content))
        
        return analysis
    
    def _analyze_secret_forensics(self, vuln: Dict, live_content: str) -> Dict[str, Any]:
        """Special forensic analysis for secret detection vulnerabilities"""
        secret_analysis = {
            'is_bubble_session_id': False,
            'is_false_positive_pattern': False,
            'pattern_analysis': ''
        }
        
        evidence = vuln.get('evidence', '')
        
        # Check for Bubble session ID pattern
        if re.match(r'^\d{13,}x\d+', evidence):
            secret_analysis['is_bubble_session_id'] = True
            secret_analysis['pattern_analysis'] = 'Bubble session ID pattern detected'
            secret_analysis['false_positive_likelihood'] = 'high'
        
        # Check for other false positive patterns
        false_positive_patterns = [
            r'^test_.*$',
            r'^demo_.*$',
            r'^example_.*$',
            r'^\d{4}-\d{4}-\d{4}-\d{4}$',  # Credit card test numbers
        ]
        
        for pattern in false_positive_patterns:
            if re.match(pattern, evidence, re.IGNORECASE):
                secret_analysis['is_false_positive_pattern'] = True
                secret_analysis['pattern_analysis'] = f'False positive pattern: {pattern}'
                secret_analysis['false_positive_likelihood'] = 'high'
                break
        
        return secret_analysis
    
    def _detect_systematic_issues(self, results: Dict) -> List[str]:
        """Detect systematic issues in the scan results"""
        issues = []
        
        # High evidence inconsistency rate
        if results.get('evidence_inconsistency_rate', 0) > 50:
            issues.append(f"High evidence inconsistency rate: {results['evidence_inconsistency_rate']:.1f}%")
        
        # Many missing evidence entries
        if results.get('missing_evidence', 0) > len(results.get('detailed_analysis', [])) * 0.3:
            issues.append(f"Many missing evidence entries: {results['missing_evidence']}")
        
        # Timestamp anomalies
        if len(results.get('timestamp_issues', [])) > 0:
            issues.append(f"Timestamp anomalies detected: {len(results['timestamp_issues'])}")
        
        # Systematic secret false positives
        secret_false_positives = [
            d for d in results.get('detailed_analysis', [])
            if d.get('is_bubble_session_id') or d.get('is_false_positive_pattern')
        ]
        
        if len(secret_false_positives) > 3:
            issues.append(f"Systematic secret false positives: {len(secret_false_positives)}")
        
        return issues

def main():
    verifier = ForensicVerifier()
    
    # Get scan files
    import glob
    scan_files = glob.glob('data/scans/*.json')
    scan_files.sort()
    
    # Select a representative sample
    sample_files = scan_files[::8][:6]  # Every 8th file, max 6 files
    
    print(f"Analyzing {len(sample_files)} representative scan files...")
    
    # Quick analysis of first file
    if sample_files:
        result = verifier.verify_live_content(sample_files[0])
        
        print(f"\n📊 QUICK FORENSIC RESULTS")
        print("=" * 60)
        print(f"Evidence matches: {result.get('evidence_matches', 0)}")
        print(f"Evidence mismatches: {result.get('evidence_mismatches', 0)}")
        print(f"Missing evidence: {result.get('missing_evidence', 0)}")
        print(f"Consistency rate: {result.get('evidence_consistency_rate', 0):.1f}%")
        
        if result.get('systematic_issues'):
            print(f"\n⚠️  Systematic Issues:")
            for issue in result['systematic_issues']:
                print(f"  • {issue}")
    
    return verifier

if __name__ == "__main__":
    main()
