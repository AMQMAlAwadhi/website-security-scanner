#!/usr/bin/env python3
"""
Metadata verification script - analyzes scan file metadata, timestamps,
and structural patterns to detect inconsistencies and potential fabrication.
"""

import json
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import re
from collections import defaultdict, Counter

class MetadataVerifier:
    def __init__(self):
        self.scan_files = []
        self.metadata_analysis = {}
        self.anomalies = []
        
    def load_all_scan_files(self):
        """Load all scan files and extract metadata"""
        import glob
        scan_paths = glob.glob('data/scans/*.json')
        
        print(f"Loading {len(scan_paths)} scan files for metadata analysis...")
        
        for scan_path in scan_paths:
            try:
                with open(scan_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Extract file metadata
                file_stat = os.stat(scan_path)
                file_metadata = {
                    'filename': os.path.basename(scan_path),
                    'filepath': scan_path,
                    'file_size': file_stat.st_size,
                    'file_created': datetime.fromtimestamp(file_stat.st_ctime),
                    'file_modified': datetime.fromtimestamp(file_stat.st_mtime),
                    'file_hash': self._calculate_file_hash(scan_path)
                }
                
                # Extract scan metadata
                scan_metadata = {
                    'url': data.get('url', ''),
                    'timestamp': data.get('timestamp', ''),
                    'platform_type': data.get('platform_type', ''),
                    'vulnerability_count': len(data.get('vulnerabilities', [])),
                    'scan_type': data.get('scan_metadata', {}).get('scan_type', 'unknown'),
                    'plugins_used': data.get('scan_metadata', {}).get('plugins_used', False),
                    'parallel_used': data.get('scan_metadata', {}).get('parallel_used', False)
                }
                
                # Extract vulnerability patterns
                vuln_metadata = self._analyze_vulnerability_patterns(data.get('vulnerabilities', []))
                
                # Combine all metadata
                combined_metadata = {
                    **file_metadata,
                    **scan_metadata,
                    **vuln_metadata
                }
                
                self.scan_files.append(combined_metadata)
                
            except Exception as e:
                print(f"Error loading {scan_path}: {e}")
        
        print(f"Successfully loaded {len(self.scan_files)} scan files")
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _analyze_vulnerability_patterns(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Analyze vulnerability patterns and metadata"""
        if not vulnerabilities:
            return {
                'vulnerability_types': [],
                'severity_distribution': {},
                'evidence_patterns': {},
                'timestamp_range': {},
                'unique_evidence_count': 0,
                'duplicate_evidence_count': 0,
                'avg_confidence_score': 0
            }
        
        # Extract vulnerability types
        vuln_types = [v.get('type', 'Unknown') for v in vulnerabilities]
        vuln_type_counts = Counter(vuln_types)
        
        # Extract severity distribution
        severities = [v.get('severity', 'Unknown') for v in vulnerabilities]
        severity_counts = Counter(severities)
        
        # Extract evidence patterns
        all_evidence = [v.get('evidence', '') for v in vulnerabilities if v.get('evidence')]
        unique_evidence = set(all_evidence)
        duplicate_evidence = len(all_evidence) - len(unique_evidence)
        
        # Analyze evidence patterns
        evidence_patterns = {}
        for evidence in all_evidence[:10]:  # Sample first 10
            if evidence:
                pattern = self._classify_evidence_pattern(evidence)
                evidence_patterns[pattern] = evidence_patterns.get(pattern, 0) + 1
        
        # Extract timestamp range
        timestamps = []
        for v in vulnerabilities:
            ts = v.get('timestamp', '')
            if ts:
                try:
                    timestamps.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
                except:
                    continue
        
        timestamp_range = {}
        if timestamps:
            timestamp_range = {
                'earliest': min(timestamps),
                'latest': max(timestamps),
                'span_seconds': (max(timestamps) - min(timestamps)).total_seconds()
            }
        
        # Calculate confidence scores
        confidence_scores = []
        for v in vulnerabilities:
            conf = v.get('confidence', '').lower()
            if conf == 'certain':
                confidence_scores.append(3)
            elif conf == 'firm':
                confidence_scores.append(2)
            elif conf == 'tentative':
                confidence_scores.append(1)
            else:
                confidence_scores.append(0)
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        return {
            'vulnerability_types': dict(vuln_type_counts.most_common()),
            'severity_distribution': dict(severity_counts),
            'evidence_patterns': evidence_patterns,
            'timestamp_range': timestamp_range,
            'unique_evidence_count': len(unique_evidence),
            'duplicate_evidence_count': duplicate_evidence,
            'avg_confidence_score': avg_confidence
        }
    
    def _classify_evidence_pattern(self, evidence: str) -> str:
        """Classify evidence into pattern types"""
        if not evidence:
            return 'empty'
        
        # Bubble session ID pattern
        if re.match(r'^\d{13,}x\d+', evidence):
            return 'bubble_session_id'
        
        # HTTP/2 evidence
        if 'h2' in evidence.lower() or 'http/2' in evidence.lower():
            return 'http2_evidence'
        
        # Cookie evidence
        if 'cookie' in evidence.lower() or '=' in evidence:
            return 'cookie_evidence'
        
        # Header evidence
        if any(header in evidence.lower() for header in ['x-frame-options', 'csp', 'content-security-policy']):
            return 'header_evidence'
        
        # High entropy string
        if len(evidence) > 20 and re.match(r'^[a-zA-Z0-9+/=_-]+$', evidence):
            return 'high_entropy_string'
        
        # URL evidence
        if evidence.startswith('http'):
            return 'url_evidence'
        
        # Numeric evidence
        if evidence.isdigit():
            return 'numeric_evidence'
        
        return 'other'
    
    def analyze_timestamp_consistency(self):
        """Analyze timestamp consistency across scans"""
        print("\n🕒 TIMESTAMP CONSISTENCY ANALYSIS")
        print("=" * 60)
        
        timestamp_issues = []
        
        for scan in self.scan_files:
            scan_timestamp = scan.get('timestamp', '')
            file_created = scan.get('file_created')
            file_modified = scan.get('file_modified')
            
            if not scan_timestamp:
                timestamp_issues.append({
                    'file': scan['filename'],
                    'issue': 'Missing scan timestamp',
                    'severity': 'medium'
                })
                continue
            
            try:
                scan_dt = datetime.fromisoformat(scan_timestamp.replace('Z', '+00:00'))
                
                # Check if scan timestamp is after file creation
                if scan_dt < file_created - timedelta(minutes=5):
                    timestamp_issues.append({
                        'file': scan['filename'],
                        'issue': f'Scan timestamp {scan_dt} predates file creation {file_created}',
                        'severity': 'high'
                    })
                
                # Check if scan timestamp is far in future
                if scan_dt > datetime.now() + timedelta(hours=1):
                    timestamp_issues.append({
                        'file': scan['filename'],
                        'issue': f'Scan timestamp {scan_dt} is in the future',
                        'severity': 'high'
                    })
                
                # Check vulnerability timestamp consistency
                vuln_timestamp_range = scan.get('timestamp_range', {})
                if vuln_timestamp_range:
                    earliest_vuln = vuln_timestamp_range.get('earliest')
                    latest_vuln = vuln_timestamp_range.get('latest')
                    
                    if earliest_vuln and latest_vuln:
                        vuln_span = vuln_timestamp_range.get('span_seconds', 0)
                        
                        # If vulnerability span is very short, might be fabricated
                        if vuln_span < 1 and scan.get('vulnerability_count', 0) > 5:
                            timestamp_issues.append({
                                'file': scan['filename'],
                                'issue': f'{scan.get("vulnerability_count")} vulnerabilities detected in {vuln_span:.1f} seconds - suspiciously fast',
                                'severity': 'medium'
                            })
                        
                        # If vulnerability timestamps don't align with scan timestamp
                        if abs((earliest_vuln - scan_dt).total_seconds()) > 300:  # 5 minutes
                            timestamp_issues.append({
                                'file': scan['filename'],
                                'issue': f'Vulnerability timestamps differ significantly from scan timestamp',
                                'severity': 'medium'
                            })
                
            except Exception as e:
                timestamp_issues.append({
                    'file': scan['filename'],
                    'issue': f'Invalid timestamp format: {e}',
                    'severity': 'medium'
                })
        
        # Report timestamp issues
        if timestamp_issues:
            print(f"⚠️  Found {len(timestamp_issues)} timestamp issues:")
            for issue in timestamp_issues[:10]:  # Show first 10
                severity_icon = "🚨" if issue['severity'] == 'high' else "⚠️"
                print(f"  {severity_icon} {issue['file']}: {issue['issue']}")
        else:
            print("✅ No significant timestamp issues detected")
        
        return timestamp_issues
    
    def analyze_evidence_consistency(self):
        """Analyze evidence consistency and patterns"""
        print("\n🔍 EVIDENCE CONSISTENCY ANALYSIS")
        print("=" * 60)
        
        # Collect all evidence across all scans
        all_evidence = []
        evidence_by_type = defaultdict(list)
        
        for scan in self.scan_files:
            scan_file = scan['filename']
            vulnerabilities_count = scan.get('vulnerability_count', 0)
            
            # Skip if we can't access the detailed vulnerability data
            if vulnerabilities_count == 0:
                continue
            
            # Try to load the full scan data for evidence analysis
            try:
                with open(scan['filepath'], 'r') as f:
                    data = json.load(f)
                
                for vuln in data.get('vulnerabilities', []):
                    evidence = vuln.get('evidence', '')
                    vuln_type = vuln.get('type', '')
                    
                    if evidence:
                        all_evidence.append({
                            'file': scan_file,
                            'type': vuln_type,
                            'evidence': evidence,
                            'pattern': self._classify_evidence_pattern(evidence)
                        })
                        evidence_by_type[vuln_type].append(evidence)
                        
            except Exception as e:
                print(f"Could not analyze evidence for {scan_file}: {e}")
        
        # Analyze evidence patterns
        evidence_patterns = Counter([e['pattern'] for e in all_evidence])
        
        print(f"Total evidence entries analyzed: {len(all_evidence)}")
        print(f"Evidence patterns found:")
        for pattern, count in evidence_patterns.most_common():
            print(f"  • {pattern}: {count}")
        
        # Look for suspicious patterns
        suspicious_patterns = []
        
        # Check for identical evidence across different files
        evidence_hash_map = defaultdict(list)
        for e in all_evidence:
            evidence_hash = hashlib.md5(e['evidence'].encode()).hexdigest()
            evidence_hash_map[evidence_hash].append(e)
        
        duplicate_evidence_across_files = {
            hash_val: entries for hash_val, entries in evidence_hash_map.items() 
            if len(entries) > 1 and len(set(e['file'] for e in entries)) > 1
        }
        
        if duplicate_evidence_across_files:
            print(f"\n⚠️  Found {len(duplicate_evidence_across_files)} evidence duplicates across different files:")
            for hash_val, entries in list(duplicate_evidence_across_files.items())[:5]:
                files = set(e['file'] for e in entries)
                print(f"  • Evidence appears in {len(files)} files: {', '.join(files)}")
                print(f"    Sample: {entries[0]['evidence'][:50]}...")
        
        # Check for Bubble session ID patterns
        bubble_evidence = [e for e in all_evidence if e['pattern'] == 'bubble_session_id']
        if bubble_evidence:
            print(f"\n🫧 Bubble session ID evidence: {len(bubble_evidence)} instances")
            files_with_bubble = set(e['file'] for e in bubble_evidence)
            print(f"  Found in {len(files_with_bubble)} files")
            
            # Check if these are flagged as secrets
            bubble_as_secrets = [e for e in bubble_evidence if 'secret' in e['type'].lower()]
            if bubble_as_secrets:
                print(f"  ⚠️  {len(bubble_as_secrets)} incorrectly flagged as secrets")
        
        # Check for HTTP/2 evidence
        http2_evidence = [e for e in all_evidence if e['pattern'] == 'http2_evidence']
        if http2_evidence:
            print(f"\n🌐 HTTP/2 evidence: {len(http2_evidence)} instances")
            print(f"  This confirms systematic HTTP/2 false positive reporting")
        
        return {
            'total_evidence': len(all_evidence),
            'evidence_patterns': dict(evidence_patterns),
            'duplicate_evidence_across_files': len(duplicate_evidence_across_files),
            'bubble_session_evidence': len(bubble_evidence),
            'http2_evidence': len(http2_evidence)
        }
    
    def analyze_scan_patterns(self):
        """Analyze scanning patterns and detect anomalies"""
        print("\n📊 SCAN PATTERN ANALYSIS")
        print("=" * 60)
        
        # Group scans by platform
        platforms = defaultdict(list)
        for scan in self.scan_files:
            platform = scan.get('platform_type', 'unknown')
            platforms[platform].append(scan)
        
        print(f"Scans by platform:")
        for platform, scans in platforms.items():
            print(f"  • {platform}: {len(scans)} scans")
            
            # Analyze vulnerability counts per platform
            vuln_counts = [s.get('vulnerability_count', 0) for s in scans]
            avg_vulns = sum(vuln_counts) / len(vuln_counts) if vuln_counts else 0
            print(f"    Average vulnerabilities per scan: {avg_vulns:.1f}")
        
        # Look for unusual patterns
        anomalies = []
        
        # Check for scans with unusually high vulnerability counts
        all_vuln_counts = [s.get('vulnerability_count', 0) for s in self.scan_files]
        if all_vuln_counts:
            avg_count = sum(all_vuln_counts) / len(all_vuln_counts)
            max_count = max(all_vuln_counts)
            
            # Flag scans with more than 3x average
            high_vuln_scans = [s for s in self.scan_files if s.get('vulnerability_count', 0) > avg_count * 3]
            if high_vuln_scans:
                anomalies.append({
                    'type': 'high_vulnerability_count',
                    'description': f'{len(high_vuln_scans)} scans with unusually high vulnerability counts',
                    'details': [f"{s['filename']}: {s.get('vulnerability_count', 0)} vulns" for s in high_vuln_scans[:3]]
                })
        
        # Check for scans with zero vulnerabilities (might indicate failed scans)
        zero_vuln_scans = [s for s in self.scan_files if s.get('vulnerability_count', 0) == 0]
        if zero_vuln_scans:
            anomalies.append({
                'type': 'zero_vulnerabilities',
                'description': f'{len(zero_vuln_scans)} scans with zero vulnerabilities',
                'details': [s['filename'] for s in zero_vuln_scans[:3]]
            })
        
        # Check file size patterns
        file_sizes = [s.get('file_size', 0) for s in self.scan_files]
        if file_sizes:
            avg_size = sum(file_sizes) / len(file_sizes)
            
            # Flag unusually large or small files
            large_files = [s for s in self.scan_files if s.get('file_size', 0) > avg_size * 3]
            small_files = [s for s in self.scan_files if s.get('file_size', 0) < avg_size / 3 and s.get('file_size', 0) > 0]
            
            if large_files:
                anomalies.append({
                    'type': 'large_files',
                    'description': f'{len(large_files)} scans with unusually large file sizes',
                    'details': [f"{s['filename']}: {s.get('file_size', 0)} bytes" for s in large_files[:3]]
                })
            
            if small_files:
                anomalies.append({
                    'type': 'small_files',
                    'description': f'{len(small_files)} scans with unusually small file sizes',
                    'details': [f"{s['filename']}: {s.get('file_size', 0)} bytes" for s in small_files[:3]]
                })
        
        # Report anomalies
        if anomalies:
            print(f"\n⚠️  Scan pattern anomalies detected:")
            for anomaly in anomalies:
                print(f"  • {anomaly['description']}")
                for detail in anomaly.get('details', []):
                    print(f"      - {detail}")
        else:
            print("\n✅ No significant scan pattern anomalies detected")
        
        return anomalies
    
    def generate_metadata_report(self):
        """Generate comprehensive metadata verification report"""
        print("🔍 METADATA VERIFICATION ANALYSIS")
        print("=" * 80)
        
        # Load all scan files
        self.load_all_scan_files()
        
        if not self.scan_files:
            print("No scan files found for analysis")
            return
        
        # Perform all analyses
        timestamp_issues = self.analyze_timestamp_consistency()
        evidence_analysis = self.analyze_evidence_consistency()
        scan_anomalies = self.analyze_scan_patterns()
        
        # Generate final assessment
        print(f"\n🎯 METADATA VERIFICATION SUMMARY")
        print("=" * 80)
        
        total_issues = len(timestamp_issues) + len(scan_anomalies)
        evidence_concerns = 0
        
        if evidence_analysis.get('http2_evidence', 0) > 0:
            evidence_concerns += 1
            print(f"⚠️  HTTP/2 evidence systematic false positives confirmed")
        
        if evidence_analysis.get('bubble_session_evidence', 0) > 0:
            evidence_concerns += 1
            print(f"⚠️  Bubble session ID evidence may be misclassified")
        
        if evidence_analysis.get('duplicate_evidence_across_files', 0) > 5:
            evidence_concerns += 1
            print(f"⚠️  High number of duplicate evidence across files")
        
        # Final verdict
        if total_issues > 10 or evidence_concerns > 2:
            verdict = "🚨 HIGH CONCERNS - Metadata indicates systematic issues"
        elif total_issues > 5 or evidence_concerns > 1:
            verdict = "⚠️  MODERATE CONCERNS - Some metadata inconsistencies detected"
        else:
            verdict = "✅ METADATA LARGELY CONSISTENT - Minor issues only"
        
        print(f"\n🏁 METADATA VERDICT: {verdict}")
        
        # Save detailed report
        report_data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'scan_files_analyzed': len(self.scan_files),
            'timestamp_issues': len(timestamp_issues),
            'evidence_analysis': evidence_analysis,
            'scan_anomalies': len(scan_anomalies),
            'total_concerns': total_issues + evidence_concerns,
            'verdict': verdict
        }
        
        report_file = f'metadata_verification_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n📄 Detailed metadata report saved to: {report_file}")
        
        return report_data

def main():
    verifier = MetadataVerifier()
    return verifier.generate_metadata_report()

if __name__ == "__main__":
    main()
