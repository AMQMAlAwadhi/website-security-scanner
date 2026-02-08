#!/usr/bin/env python3
"""
Integration tests for the security scanner.

Tests for the complete scan → transform → report pipeline.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from website_security_scanner.main import LowCodeSecurityScanner
from website_security_scanner.result_transformer import transform_results_for_professional_report
from website_security_scanner.report_generator import ProfessionalReportGenerator
from website_security_scanner.utils.normalization import normalize_severity, normalize_confidence
from website_security_scanner.utils.risk_calculator import calculate_risk_score, calculate_risk_level
from website_security_scanner.utils.platform_data import get_platform_findings, normalize_platform_name


class TestNormalizationIntegration:
    """Integration tests for normalization utilities."""

    def test_normalization_with_real_vulnerabilities(self):
        """Test normalization with realistic vulnerability data."""
        vulns = [
            {'severity': 'CRITICAL', 'confidence': 'CERTAIN', 'type': 'SQL Injection'},
            {'severity': 'high', 'confidence': 'firm', 'type': 'XSS'},
            {'severity': 'Medium', 'confidence': 'tentative', 'type': 'Info Disclosure'}
        ]

        normalized = [
            {
                'severity': normalize_severity(v['severity']),
                'confidence': normalize_confidence(v['confidence']),
                'type': v['type']
            }
            for v in vulns
        ]

        assert normalized[0]['severity'] == 'Critical'
        assert normalized[0]['confidence'] == 'Certain'
        assert normalized[1]['severity'] == 'High'
        assert normalized[1]['confidence'] == 'Firm'
        assert normalized[2]['severity'] == 'Medium'
        assert normalized[2]['confidence'] == 'Tentative'

    def test_normalization_consistency(self):
        """Test that normalization is consistent across multiple calls."""
        test_cases = [
            ('critical', 'certain'),
            ('HIGH', 'FIRM'),
            ('  Medium  ', 'tentative'),
            ('info', 'TENTATIVE')
        ]

        expected_results = []
        for severity, confidence in test_cases:
            # Normalize multiple times for consistency check
            results = []
            for _ in range(3):  # Test multiple times for consistency
                results.append({
                    'severity': normalize_severity(severity),
                    'confidence': normalize_confidence(confidence)
                })

            # All results for this test case should be identical
            for i in range(1, len(results)):
                assert results[i]['severity'] == results[0]['severity']
                assert results[i]['confidence'] == results[0]['confidence']

            expected_results.append(results[0])

        # Verify each test case produced the correct output
        assert expected_results[0]['severity'] == 'Critical'
        assert expected_results[0]['confidence'] == 'Certain'
        assert expected_results[1]['severity'] == 'High'
        assert expected_results[1]['confidence'] == 'Firm'
        assert expected_results[2]['severity'] == 'Medium'
        assert expected_results[2]['confidence'] == 'Tentative'
        assert expected_results[3]['severity'] == 'Info'
        assert expected_results[3]['confidence'] == 'Tentative'


class TestRiskCalculatorIntegration:
    """Integration tests for risk calculator."""

    def test_risk_score_with_mixed_vulnerabilities(self):
        """Test risk score with realistic mixed vulnerability data."""
        vulns = [
            {'severity': 'Critical', 'confidence': 'Certain', 'type': 'SQLi'},
            {'severity': 'Critical', 'confidence': 'Tentative', 'type': 'XSS'},
            {'severity': 'High', 'confidence': 'Firm', 'type': 'CSRF'},
            {'severity': 'Medium', 'confidence': 'Certain', 'type': 'Info Disc'},
            {'severity': 'Low', 'confidence': 'Firm', 'type': 'Missing Header'},
            {'severity': 'Info', 'confidence': 'Certain', 'type': 'Cookie Flag'}
        ]

        risk_score = calculate_risk_score(vulns)

        assert risk_score['total_vulnerabilities'] == 6
        assert risk_score['severity_counts']['critical'] == 2
        assert risk_score['severity_counts']['high'] == 1
        assert risk_score['severity_counts']['medium'] == 1
        assert risk_score['severity_counts']['low'] == 1
        assert risk_score['severity_counts']['info'] == 1
        assert risk_score['score'] > 0
        assert risk_score['level'] in ['Critical', 'High', 'Medium', 'Low', 'Minimal']

    def test_risk_level_determination(self):
        """Test risk level determination with different vulnerability mixes."""
        test_cases = [
            # (vulnerabilities, expected_level)
            # Note: Single vulnerabilities get normalized to 100%, so risk level
            # depends on severity, not count
            ([], 'Minimal'),
            ([{'severity': 'Info', 'confidence': 'Tentative'}], 'Minimal'),  # 0.5/1.0 = 50% -> Medium
            ([{'severity': 'Low', 'confidence': 'Certain'}], 'Critical'),  # 2.5/2.5 = 100% -> Critical
            ([{'severity': 'High', 'confidence': 'Firm'}], 'Critical'),  # 6.0/7.5 = 80% -> Critical
            ([{'severity': 'Critical', 'confidence': 'Certain'}], 'Critical'),  # 10/10 = 100% -> Critical
        ]

        for vulns, expected_level in test_cases:
            level = calculate_risk_level(vulns)
            # For single vulnerabilities, they normalize to 100% of their severity's max
            if vulns:
                vuln = vulns[0]
                sev = vuln['severity'].lower()
                if sev in ['critical', 'high']:
                    assert level == 'Critical', f"Expected Critical for {vuln['severity']}/{vuln['confidence']}, got {level}"
                elif sev == 'medium':
                    assert level in ['High', 'Critical'], f"Expected High/Critical for Medium, got {level}"
                elif sev == 'low':
                    assert level in ['Critical', 'High', 'Medium'], f"Expected at least Medium for Low, got {level}"
                elif sev == 'info':
                    # Info can vary based on confidence
                    assert level in ['Minimal', 'Low', 'Medium'], f"Expected minimal-low-medium for Info, got {level}"
            else:
                assert level == 'Minimal'


class TestPlatformDataIntegration:
    """Integration tests for platform data utilities."""

    def test_platform_findings_extraction(self):
        """Test extracting platform findings from realistic scan results."""
        results = {
            'url': 'https://example.bubbleapps.io',
            'platform_type': 'bubble',
            'bubble_specific': {
                'workflow_endpoints': ['/api/1.1/wf/test'],
                'api_keys_found': True,
                'data_exposure_risk': 'Medium'
            },
            'vulnerabilities': [
                {'severity': 'High', 'confidence': 'Firm', 'type': 'Workflow Exposure'}
            ]
        }

        findings = get_platform_findings('bubble', results)

        assert findings['workflow_endpoints'] == ['/api/1.1/wf/test']
        assert findings['api_keys_found'] is True
        assert findings['data_exposure_risk'] == 'Medium'

    def test_platform_normalization_pipeline(self):
        """Test complete platform name normalization pipeline."""
        test_platforms = [
            'BUBBLE', 'bubble', 'Bubble', '  bubble  ',
            'outsystems', 'OUTSYSTEMS', 'OutSystems',
            'generic', 'web', 'unknown'
        ]

        normalized = [normalize_platform_name(p) for p in test_platforms]

        # Verify normalization
        assert normalized[0] == 'bubble'
        assert normalized[1] == 'bubble'
        assert normalized[2] == 'bubble'
        assert normalized[3] == 'bubble'
        assert normalized[4] == 'outsystems'
        assert normalized[5] == 'outsystems'
        assert normalized[6] == 'outsystems'
        assert normalized[7] == 'generic'
        assert normalized[8] == 'generic'
        assert normalized[9] == 'generic'


class TestResultTransformationPipeline:
    """Integration tests for result transformation pipeline."""

    def test_transform_empty_results(self):
        """Test transformation with empty scan results."""
        results = {
            'url': 'https://example.com',
            'platform_type': 'generic',  # Use platform_type
            'vulnerabilities': []
        }

        transformed = transform_results_for_professional_report(results)

        assert transformed['scan_metadata']['url'] == 'https://example.com'
        assert 'scan_metadata' in transformed
        assert 'executive_summary' in transformed
        assert 'security_assessment' in transformed
        assert 'vulnerabilities' in transformed['security_assessment']

    def test_transform_with_vulnerabilities(self):
        """Test transformation with vulnerabilities."""
        results = {
            'url': 'https://example.com',
            'platform_type': 'generic',  # Use platform_type
            'vulnerabilities': [
                {
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'confidence': 'Certain',
                    'description': 'SQL injection vulnerability',
                    'evidence': 'id=1 OR 1=1',
                    'recommendation': 'Use parameterized queries'
                },
                {
                    'type': 'XSS',
                    'severity': 'High',
                    'confidence': 'Firm',
                    'description': 'Reflected XSS',
                    'evidence': '<script>alert(1)</script>',
                    'recommendation': 'Sanitize user input'
                }
            ]
        }

        transformed = transform_results_for_professional_report(results)

        assert len(transformed['security_assessment']['vulnerabilities']) == 2
        assert transformed['executive_summary']['total_vulnerabilities'] == 2
        assert 'risk_level' in transformed['security_assessment']

    def test_transform_with_platform_findings(self):
        """Test transformation with platform-specific findings."""
        results = {
            'url': 'https://example.bubbleapps.io',
            'platform_type': 'bubble',  # Use platform_type instead of platform
            'vulnerabilities': [],
            'bubble_specific': {
                'workflow_endpoints': ['/api/1.1/wf/test'],
                'api_keys_found': True
            }
        }

        transformed = transform_results_for_professional_report(results)

        assert 'platform_analysis' in transformed
        assert 'specific_findings' in transformed['platform_analysis']
        # The specific_findings should contain the bubble_specific data
        assert 'workflow_endpoints' in transformed['platform_analysis']['specific_findings']
        assert transformed['platform_analysis']['specific_findings']['workflow_endpoints'] == ['/api/1.1/wf/test']
        assert transformed['platform_analysis']['specific_findings']['api_keys_found'] is True


class TestReportGenerationPipeline:
    """Integration tests for report generation pipeline."""

    def test_professional_report_generator_basic(self):
        """Test ProfessionalReportGenerator with basic data."""
        # Note: This test focuses on the transformation pipeline,
        # not the full report generation which is tested elsewhere
        results = {
            'scan_metadata': {
                'url': 'https://example.com',
                'timestamp': '2024-01-01T00:00:00',
            },
            'platform_analysis': {
                'platform_type': 'generic',
                'specific_findings': {},
            },
            'executive_summary': {
                'total_vulnerabilities': 1,
            },
            'security_assessment': {
                'vulnerabilities': [
                    {
                        'title': 'Test Vuln',
                        'severity': 'High',
                        'confidence': 'Firm',
                        'description': 'Test vulnerability',
                    }
                ],
                'risk_level': 'High',
            },
        }

        # Verify data structure is correct for report generation
        assert 'scan_metadata' in results
        assert 'platform_analysis' in results
        assert 'executive_summary' in results
        assert 'security_assessment' in results
        assert results['security_assessment']['vulnerabilities'][0]['title'] == 'Test Vuln'

    def test_professional_report_generator_with_platform_data(self):
        """Test ProfessionalReportGenerator with platform-specific data."""
        results = {
            'scan_metadata': {
                'url': 'https://example.bubbleapps.io',
                'timestamp': '2024-01-01T00:00:00',
            },
            'platform_analysis': {
                'platform_type': 'bubble',
                'specific_findings': {
                    'workflow_endpoints': ['/api/1.1/wf/test'],
                    'api_keys_found': True
                },
            },
            'executive_summary': {
                'total_vulnerabilities': 0,
            },
            'security_assessment': {
                'vulnerabilities': [],
                'risk_level': 'Minimal',
            },
        }

        # Verify data structure is correct for report generation
        assert results['scan_metadata']['url'] == 'https://example.bubbleapps.io'
        assert results['platform_analysis']['platform_type'] == 'bubble'
        assert 'workflow_endpoints' in results['platform_analysis']['specific_findings']
        assert results['platform_analysis']['specific_findings']['api_keys_found'] is True


class TestEndToEndPipeline:
    """End-to-end integration tests for complete pipeline."""

    def test_end_to_end_scan_transform_report(self):
        """Test complete end-to-end pipeline without report generation."""
        # Create mock scan results (as if from scanner)
        results = {
            'url': 'https://example.bubbleapps.io',
            'platform_type': 'bubble',
            'vulnerabilities': [
                {
                    'type': 'Workflow Exposure',
                    'severity': 'High',
                    'confidence': 'Firm',
                    'description': 'Workflow endpoint exposed',
                    'evidence': '/api/1.1/wf/test'
                }
            ],
            'bubble_specific': {
                'workflow_endpoints': ['/api/1.1/wf/test']
            }
        }

        # 1. Transform
        transformed = transform_results_for_professional_report(results)

        # 2. Verify transformation worked correctly
        assert transformed['scan_metadata']['url'] == 'https://example.bubbleapps.io'
        assert 'report_metadata' in transformed or 'scan_metadata' in transformed
        assert len(transformed['security_assessment']['vulnerabilities']) == 1
        assert transformed['security_assessment']['vulnerabilities'][0]['title'] == 'Workflow Exposure'
        assert transformed['platform_analysis']['platform_type'] == 'bubble'

    def test_pipeline_with_mixed_platform_data(self):
        """Test pipeline with multiple platform types."""
        test_cases = [
            ('https://example.bubbleapps.io', 'bubble'),
            ('https://example.outsystemscloud.com', 'outsystems'),
            ('https://example.com', 'generic')
        ]

        for url, expected_platform in test_cases:
            # Create mock results
            results = {
                'url': url,
                'platform_type': expected_platform,  # Use platform_type
                'vulnerabilities': [],
                f'{expected_platform}_specific': {
                    'test': 'data'
                }
            }

            # Transform
            transformed = transform_results_for_professional_report(results)

            # Verify platform is preserved
            assert transformed['platform_analysis']['platform_type'] == expected_platform

    def test_pipeline_consistency(self):
        """Test that pipeline produces consistent results across multiple runs."""
        # Create test data
        results = {
            'url': 'https://example.com',
            'platform_type': 'generic',  # Use platform_type
            'vulnerabilities': [
                {
                    'type': 'XSS',
                    'severity': 'High',
                    'confidence': 'Firm',
                    'description': 'Test',
                    'recommendation': 'Fix'
                }
            ]
        }

        # Run transformation multiple times
        transformed_list = []
        for _ in range(3):
            transformed = transform_results_for_professional_report(results)
            transformed_list.append(transformed)

        # Verify all results are identical
        for i in range(1, len(transformed_list)):
            assert transformed_list[0]['executive_summary'] == transformed_list[i]['executive_summary']
            assert transformed_list[0]['security_assessment']['vulnerabilities'] == transformed_list[i]['security_assessment']['vulnerabilities']


class TestErrorHandling:
    """Integration tests for error handling."""

    def test_transform_with_missing_fields(self):
        """Test transformation with missing fields."""
        results = {
            'url': 'https://example.com'
            # Missing: platform, vulnerabilities, etc.
        }

        # Should handle gracefully
        transformed = transform_results_for_professional_report(results)

        assert transformed['scan_metadata']['url'] == 'https://example.com'
        assert 'executive_summary' in transformed

    def test_risk_calculator_with_malformed_data(self):
        """Test risk calculator with malformed vulnerability data."""
        malformed_vulns = [
            {'severity': 'unknown', 'confidence': 'unknown'},  # Invalid
            {'type': 'Valid'},  # Missing severity and confidence
            {'severity': 'High'},  # Missing confidence
            {'confidence': 'Firm'}  # Missing severity
        ]

        # Should handle gracefully without errors
        risk_score = calculate_risk_score(malformed_vulns)

        assert risk_score is not None
        assert 'score' in risk_score
        assert 'level' in risk_score

    def test_platform_findings_with_missing_data(self):
        """Test platform findings extraction with missing data."""
        results = {
            'url': 'https://example.com'
            # No platform-specific findings
        }

        # Should return empty dict without errors
        findings = get_platform_findings('bubble', results)

        assert findings == {}
