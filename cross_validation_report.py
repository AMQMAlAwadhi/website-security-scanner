#!/usr/bin/env python3
"""
Cross-validation report - combines all verification methods to provide
final definitive assessment of report authenticity.
"""

import json
from datetime import datetime
from typing import Dict, List, Any

class CrossValidationReport:
    def __init__(self):
        self.verification_methods = [
            "Live Content Verification",
            "Evidence Consistency Analysis", 
            "Metadata Forensic Analysis",
            "Pattern Recognition",
            "Timestamp Anomaly Detection",
            "File Structure Analysis"
        ]
        
        self.findings = {
            "confirmed_authentic": [],
            "confirmed_false_positives": [],
            "systematic_issues": [],
            "fabrication_indicators": [],
            "reliability_score": 0
        }
    
    def load_previous_reports(self):
        """Load data from previous verification reports"""
        reports = {}
        
        # Try to load previous verification reports
        import glob
        
        report_files = {
            'verification': glob.glob('verification_report_*.json'),
            'forensic': glob.glob('forensic_report_*.json'),
            'final': glob.glob('final_verification_report_*.json'),
            'metadata': glob.glob('metadata_verification_report_*.json')
        }
        
        for report_type, files in report_files.items():
            if files:
                # Get the most recent report
                latest_file = max(files)
                try:
                    with open(latest_file, 'r') as f:
                        reports[report_type] = json.load(f)
                    print(f"✓ Loaded {report_type} report: {latest_file}")
                except Exception as e:
                    print(f"✗ Could not load {report_type} report: {e}")
        
        return reports
    
    def analyze_systematic_false_positives(self, reports: Dict):
        """Analyze systematic false positive patterns"""
        print("\n🔍 SYSTEMATIC FALSE POSITIVE ANALYSIS")
        print("=" * 60)
        
        systematic_fps = []
        
        # HTTP/2 false positives
        if 'final' in reports:
            final_data = reports['final']
            http2_fps = final_data.get('findings', {}).get('false_positive_findings', [])
            http2_count = len([fp for fp in http2_fps if 'HTTP/2' in fp.get('type', '')])
            
            if http2_count > 0:
                systematic_fps.append({
                    'issue': 'HTTP/2 Detection',
                    'count': http2_count,
                    'severity': 'HIGH',
                    'description': 'HTTP/2 reported but not actually supported by targets',
                    'confidence': 'CERTAIN'
                })
        
        # Bubble session ID false positives  
        if 'metadata' in reports:
            metadata_data = reports['metadata']
            bubble_evidence = metadata_data.get('evidence_analysis', {}).get('bubble_session_evidence', 0)
            
            if bubble_evidence > 0:
                systematic_fps.append({
                    'issue': 'Bubble Session ID Classification',
                    'count': bubble_evidence,
                    'severity': 'HIGH', 
                    'description': 'Bubble session IDs incorrectly classified as secrets',
                    'confidence': 'CERTAIN'
                })
        
        # Evidence duplication
        if 'metadata' in reports:
            duplicate_evidence = metadata_data.get('evidence_analysis', {}).get('duplicate_evidence_across_files', 0)
            
            if duplicate_evidence > 50:  # High threshold
                systematic_fps.append({
                    'issue': 'Evidence Duplication',
                    'count': duplicate_evidence,
                    'severity': 'MEDIUM',
                    'description': 'Same evidence appears across multiple scan files',
                    'confidence': 'HIGH'
                })
        
        # Report findings
        print(f"Found {len(systematic_fps)} systematic false positive patterns:")
        for fp in systematic_fps:
            severity_icon = "🚨" if fp['severity'] == 'HIGH' else "⚠️"
            print(f"  {severity_icon} {fp['issue']}: {fp['count']} instances ({fp['confidence']} confidence)")
            print(f"      {fp['description']}")
        
        self.findings['systematic_issues'] = systematic_fps
        return systematic_fps
    
    def analyze_fabrication_indicators(self, reports: Dict):
        """Analyze indicators of potential fabrication"""
        print("\n🕵️ FABRICATION INDICATOR ANALYSIS")
        print("=" * 60)
        
        fabrication_indicators = []
        
        # Timestamp anomalies
        if 'metadata' in reports:
            metadata_data = reports['metadata']
            timestamp_issues = metadata_data.get('timestamp_issues', 0)
            
            if timestamp_issues > 20:
                fabrication_indicators.append({
                    'indicator': 'Timestamp Anomalies',
                    'count': timestamp_issues,
                    'severity': 'HIGH',
                    'description': 'Scan timestamps predate file creation or are inconsistent',
                    'fabrication_likelihood': 'MEDIUM'
                })
        
        # Suspicious scan speeds
        if 'metadata' in reports:
            # Check for impossibly fast scans
            metadata_data = reports['metadata']
            # This would need more detailed analysis from the metadata report
        
        # Evidence consistency issues
        if 'verification' in reports:
            verification_data = reports['verification']
            inconsistency_rate = verification_data.get('summary', {}).get('false_positive_rate', 0)
            
            if inconsistency_rate > 30:
                fabrication_indicators.append({
                    'indicator': 'High Evidence Inconsistency',
                    'rate': inconsistency_rate,
                    'severity': 'HIGH',
                    'description': f'{inconsistency_rate:.1f}% evidence inconsistency rate',
                    'fabrication_likelihood': 'HIGH'
                })
        
        # File size anomalies
        if 'metadata' in reports:
            metadata_data = reports['metadata']
            # Check for unusually large files that might contain fabricated data
        
        # Report findings
        print(f"Found {len(fabrication_indicators)} potential fabrication indicators:")
        for indicator in fabrication_indicators:
            severity_icon = "🚨" if indicator['severity'] == 'HIGH' else "⚠️"
            print(f"  {severity_icon} {indicator['indicator']}: {indicator.get('count', indicator.get('rate', 'N/A'))}")
            print(f"      {indicator['description']}")
            print(f"      Fabrication likelihood: {indicator['fabrication_likelihood']}")
        
        self.findings['fabrication_indicators'] = fabrication_indicators
        return fabrication_indicators
    
    def calculate_reliability_score(self, reports: Dict):
        """Calculate overall reliability score based on all evidence"""
        print("\n📊 RELIABILITY SCORE CALCULATION")
        print("=" * 60)
        
        score_factors = {}
        
        # Base score starts at 100
        base_score = 100
        
        # Deductions for systematic issues
        systematic_deductions = 0
        for issue in self.findings.get('systematic_issues', []):
            if issue['severity'] == 'HIGH':
                systematic_deductions += 25
            elif issue['severity'] == 'MEDIUM':
                systematic_deductions += 15
            else:
                systematic_deductions += 5
        
        score_factors['systematic_issues_deduction'] = systematic_deductions
        
        # Deductions for fabrication indicators
        fabrication_deductions = 0
        for indicator in self.findings.get('fabrication_indicators', []):
            if indicator['severity'] == 'HIGH':
                fabrication_deductions += 30
            elif indicator['severity'] == 'MEDIUM':
                fabrication_deductions += 15
            else:
                fabrication_deductions += 5
        
        score_factors['fabrication_indicators_deduction'] = fabrication_deductions
        
        # Bonus for authentic findings
        authentic_bonus = 0
        if 'final' in reports:
            authentic_count = len(reports['final'].get('findings', {}).get('authentic_vulnerabilities', []))
            authentic_bonus = min(authentic_count * 2, 20)  # Max 20 points
        
        score_factors['authentic_findings_bonus'] = authentic_bonus
        
        # Calculate final score
        final_score = max(0, base_score - systematic_deductions - fabrication_deductions + authentic_bonus)
        
        score_factors['final_score'] = final_score
        
        # Print calculation
        print(f"Base score: {base_score}")
        print(f"Systematic issues deduction: -{systematic_deductions}")
        print(f"Fabrication indicators deduction: -{fabrication_deductions}")
        print(f"Authentic findings bonus: +{authentic_bonus}")
        print(f"Final reliability score: {final_score}/100")
        
        self.findings['reliability_score'] = final_score
        return final_score
    
    def generate_final_assessment(self, reports: Dict):
        """Generate final comprehensive assessment"""
        print("\n🎯 FINAL COMPREHENSIVE ASSESSMENT")
        print("=" * 80)
        
        # Analyze all aspects
        self.analyze_systematic_false_positives(reports)
        self.analyze_fabrication_indicators(reports)
        reliability_score = self.calculate_reliability_score(reports)
        
        # Generate assessment
        if reliability_score >= 75:
            reliability_level = "HIGH"
            assessment = "✅ REPORTS APPEAR LARGELY AUTHENTIC"
            recommendation = "Can be used with minor verification"
        elif reliability_score >= 50:
            reliability_level = "MODERATE"
            assessment = "⚠️  REPORTS HAVE MODERATE RELIABILITY CONCERNS"
            recommendation = "Manual verification recommended for critical findings"
        elif reliability_score >= 25:
            reliability_level = "LOW"
            assessment = "🚨 REPORTS HAVE SIGNIFICANT RELIABILITY ISSUES"
            recommendation = "Extensive manual verification required"
        else:
            reliability_level = "VERY LOW"
            assessment = "🚨 REPORTS LIKELY CONTAIN FABRICATED RESULTS"
            recommendation = "Do not trust without complete manual re-verification"
        
        print(f"\n🏁 FINAL ASSESSMENT")
        print("=" * 80)
        print(f"Reliability Score: {reliability_score}/100 ({reliability_level})")
        print(f"Assessment: {assessment}")
        print(f"Recommendation: {recommendation}")
        
        # Specific findings summary
        print(f"\n📋 KEY FINDINGS SUMMARY")
        print("-" * 40)
        
        systematic_count = len(self.findings.get('systematic_issues', []))
        fabrication_count = len(self.findings.get('fabrication_indicators', []))
        
        print(f"Systematic false positives: {systematic_count}")
        print(f"Fabrication indicators: {fabrication_count}")
        
        if systematic_count > 0:
            print(f"\n⚠️  Systematic Issues:")
            for issue in self.findings['systematic_issues']:
                print(f"  • {issue['issue']}: {issue['count']} instances")
        
        if fabrication_count > 0:
            print(f"\n🚨 Fabrication Indicators:")
            for indicator in self.findings['fabrication_indicators']:
                print(f"  • {indicator['indicator']}: {indicator.get('fabrication_likelihood', 'UNKNOWN')} likelihood")
        
        # Actionable recommendations
        print(f"\n💡 ACTIONABLE RECOMMENDATIONS")
        print("-" * 40)
        
        recommendations = []
        
        if any(issue['issue'] == 'HTTP/2 Detection' for issue in self.findings.get('systematic_issues', [])):
            recommendations.append("🔧 Fix HTTP/2 detection algorithm - currently 100% false positive")
        
        if any(issue['issue'] == 'Bubble Session ID Classification' for issue in self.findings.get('systematic_issues', [])):
            recommendations.append("🔧 Update secret detection to ignore Bubble session IDs")
        
        if reliability_score < 50:
            recommendations.append("🔍 Implement live evidence verification for all findings")
            recommendations.append("📊 Add evidence consistency checks in real-time")
        
        if fabrication_count > 0:
            recommendations.append("🕒 Fix timestamp consistency in scan generation")
            recommendations.append("📝 Review evidence duplication logic")
        
        for rec in recommendations:
            print(f"  {rec}")
        
        # Save comprehensive report
        comprehensive_report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'verification_methods_used': self.verification_methods,
            'findings': self.findings,
            'reliability_score': reliability_score,
            'reliability_level': reliability_level,
            'assessment': assessment,
            'recommendation': recommendation,
            'actionable_recommendations': recommendations,
            'previous_reports_analyzed': list(reports.keys())
        }
        
        report_file = f'cross_validation_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(comprehensive_report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Comprehensive cross-validation report saved to: {report_file}")
        
        return comprehensive_report

def main():
    validator = CrossValidationReport()
    
    print("🔍 CROSS-VALIDATION ANALYSIS")
    print("=" * 80)
    print("Combining all verification methods for final assessment...")
    
    # Load previous reports
    reports = validator.load_previous_reports()
    
    if not reports:
        print("No previous verification reports found. Run other verification scripts first.")
        return
    
    # Generate final assessment
    final_report = validator.generate_final_assessment(reports)
    
    return final_report

if __name__ == "__main__":
    main()
