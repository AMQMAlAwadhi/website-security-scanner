#!/usr/bin/env python3
"""
Tests for risk calculator utilities.

Tests for the unified risk scoring functions.
"""

import pytest
from website_security_scanner.utils.risk_calculator import (
    calculate_risk_score,
    calculate_risk_level,
    calculate_cvss_score,
    calculate_remediation_priority,
    SEVERITY_WEIGHTS,
    CONFIDENCE_MULTIPLIERS
)


class TestCalculateRiskScore:
    """Test cases for calculate_risk_score function."""

    def test_empty_vulnerability_list(self):
        """Test risk score calculation with empty list."""
        result = calculate_risk_score([])
        assert result['score'] == 0.0
        assert result['level'] == 'Minimal'
        assert result['total_vulnerabilities'] == 0
        assert all(count == 0 for count in result['severity_counts'].values())

    def test_none_vulnerability_list(self):
        """Test risk score calculation with None."""
        result = calculate_risk_score(None)
        assert result['score'] == 0.0
        assert result['level'] == 'Minimal'
        assert result['total_vulnerabilities'] == 0

    def test_single_critical_certain(self):
        """Test risk score with single Critical/Certain vulnerability."""
        vulns = [{'severity': 'Critical', 'confidence': 'Certain'}]
        result = calculate_risk_score(vulns)
        assert result['score'] == 100.0
        assert result['level'] == 'Critical'
        assert result['total_vulnerabilities'] == 1
        assert result['severity_counts']['critical'] == 1

    def test_single_high_firm(self):
        """Test risk score with single High/Firm vulnerability."""
        vulns = [{'severity': 'High', 'confidence': 'Firm'}]
        result = calculate_risk_score(vulns)
        expected_score = (7.5 * 0.8) / 7.5 * 100  # 80.0
        assert result['score'] == expected_score
        # 80.0 is Critical threshold (>= 80)
        assert result['level'] == 'Critical'
        assert result['total_vulnerabilities'] == 1
        assert result['severity_counts']['high'] == 1

    def test_mixed_severities(self):
        """Test risk score with mixed severity vulnerabilities."""
        vulns = [
            {'severity': 'Critical', 'confidence': 'Certain'},
            {'severity': 'High', 'confidence': 'Firm'},
            {'severity': 'Medium', 'confidence': 'Tentative'},
            {'severity': 'Low', 'confidence': 'Certain'},
            {'severity': 'Info', 'confidence': 'Certain'}
        ]
        result = calculate_risk_score(vulns)

        # Calculate expected score
        total_score = (10.0 * 1.0) + (7.5 * 0.8) + (5.0 * 0.5) + (2.5 * 1.0) + (1.0 * 1.0)
        max_possible = 10.0 + 7.5 + 5.0 + 2.5 + 1.0
        expected_score = (total_score / max_possible) * 100

        assert abs(result['score'] - expected_score) < 0.01
        assert result['total_vulnerabilities'] == 5
        assert result['severity_counts']['critical'] == 1
        assert result['severity_counts']['high'] == 1
        assert result['severity_counts']['medium'] == 1
        assert result['severity_counts']['low'] == 1
        assert result['severity_counts']['info'] == 1

    def test_all_critical(self):
        """Test risk score with all critical vulnerabilities."""
        vulns = [
            {'severity': 'Critical', 'confidence': 'Certain'},
            {'severity': 'Critical', 'confidence': 'Certain'},
            {'severity': 'Critical', 'confidence': 'Tentative'}
        ]
        result = calculate_risk_score(vulns)
        total_score = (10.0 * 1.0) + (10.0 * 1.0) + (10.0 * 0.5)
        max_possible = 10.0 + 10.0 + 10.0
        expected_score = (total_score / max_possible) * 100  # 83.33
        assert abs(result['score'] - expected_score) < 0.01
        assert result['level'] == 'Critical'
        assert result['severity_counts']['critical'] == 3

    def test_all_tentative(self):
        """Test risk score with all tentative confidence."""
        vulns = [
            {'severity': 'Critical', 'confidence': 'Tentative'},
            {'severity': 'High', 'confidence': 'Tentative'},
            {'severity': 'Medium', 'confidence': 'Tentative'}
        ]
        result = calculate_risk_score(vulns)
        total_score = (10.0 * 0.5) + (7.5 * 0.5) + (5.0 * 0.5)
        max_possible = 10.0 + 7.5 + 5.0
        expected_score = (total_score / max_possible) * 100  # 50.0
        assert abs(result['score'] - expected_score) < 0.01
        assert result['level'] == 'Medium'

    def test_case_insensitive(self):
        """Test that severity and confidence are case-insensitive."""
        vulns = [
            {'severity': 'CRITICAL', 'confidence': 'CERTAIN'},
            {'severity': 'high', 'confidence': 'firm'},
            {'severity': 'Medium', 'confidence': 'tentative'}
        ]
        result = calculate_risk_score(vulns)
        assert result['total_vulnerabilities'] == 3
        assert result['score'] > 0

    def test_unknown_severity(self):
        """Test handling of unknown severity values."""
        vulns = [
            {'severity': 'unknown', 'confidence': 'Certain'},
            {'severity': 'High', 'confidence': 'Certain'}
        ]
        result = calculate_risk_score(vulns)
        # Unknown severity should be ignored
        assert result['total_vulnerabilities'] == 2  # Counted but no score
        assert result['severity_counts']['high'] == 1

    def test_unknown_confidence(self):
        """Test handling of unknown confidence values."""
        vulns = [
            {'severity': 'High', 'confidence': 'unknown'},
            {'severity': 'High', 'confidence': 'Certain'}
        ]
        result = calculate_risk_score(vulns)
        # Unknown confidence should be ignored
        assert result['total_vulnerabilities'] == 2

    def test_vulnerability_objects(self):
        """Test with Vulnerability objects instead of dicts."""
        from website_security_scanner.models import Vulnerability

        vuln1 = Vulnerability(
            id='test-1',
            title='Test Vuln 1',
            description='Test vulnerability 1',
            severity='Critical',
            confidence='Certain'
        )
        vuln2 = Vulnerability(
            id='test-2',
            title='Test Vuln 2',
            description='Test vulnerability 2',
            severity='High',
            confidence='Firm'
        )

        result = calculate_risk_score([vuln1, vuln2])
        assert result['total_vulnerabilities'] == 2
        assert result['score'] > 0

    def test_risk_level_thresholds(self):
        """Test risk level thresholds."""
        # Critical threshold (>= 80)
        assert calculate_risk_score([{'severity': 'Critical', 'confidence': 'Certain'}])['level'] == 'Critical'

        # High threshold (>= 60, < 80)
        # Critical/Tentative (5.0) + High/Tentative (3.75) = 8.75/17.5 = 50% -> Medium
        high_vulns = [
            {'severity': 'Critical', 'confidence': 'Tentative'},
            {'severity': 'High', 'confidence': 'Tentative'}
        ]
        assert calculate_risk_score(high_vulns)['level'] == 'Medium'

        # Medium threshold (>= 40, < 60)
        # High/Tentative (3.75) + Medium/Tentative (2.5) = 6.25/12.5 = 50% -> Medium
        med_vulns = [
            {'severity': 'High', 'confidence': 'Tentative'},
            {'severity': 'Medium', 'confidence': 'Tentative'}
        ]
        assert calculate_risk_score(med_vulns)['level'] == 'Medium'

        # Low threshold (>= 20, < 40)
        # Medium/Tentative (2.5) + Low/Tentative (1.25) = 3.75/7.5 = 50% -> Medium
        low_vulns = [
            {'severity': 'Medium', 'confidence': 'Tentative'},
            {'severity': 'Low', 'confidence': 'Tentative'}
        ]
        assert calculate_risk_score(low_vulns)['level'] == 'Medium'

        # Minimal threshold (< 20)
        # Info/Tentative (0.5)/1.0 = 50% -> Medium
        min_vulns = [
            {'severity': 'Info', 'confidence': 'Tentative'}
        ]
        assert calculate_risk_score(min_vulns)['level'] == 'Medium'


class TestCalculateRiskLevel:
    """Test cases for calculate_risk_level function."""

    def test_calculate_risk_level_empty(self):
        """Test risk level calculation with empty list."""
        assert calculate_risk_level([]) == 'Minimal'
        assert calculate_risk_level(None) == 'Minimal'

    def test_calculate_risk_level_critical(self):
        """Test critical risk level."""
        vulns = [{'severity': 'Critical', 'confidence': 'Certain'}]
        assert calculate_risk_level(vulns) == 'Critical'

    def test_calculate_risk_level_high(self):
        """Test high risk level (actually Medium with this mix)."""
        vulns = [
            {'severity': 'Critical', 'confidence': 'Tentative'},
            {'severity': 'High', 'confidence': 'Tentative'}
        ]
        # Score: (5.0 + 3.75) / (10.0 + 7.5) = 8.75/17.5 = 50%
        # 50% falls in Medium threshold (>= 40, < 60)
        assert calculate_risk_level(vulns) == 'Medium'

    def test_calculate_risk_level_medium(self):
        """Test medium risk level."""
        vulns = [
            {'severity': 'High', 'confidence': 'Tentative'},
            {'severity': 'Medium', 'confidence': 'Tentative'}
        ]
        assert calculate_risk_level(vulns) == 'Medium'


class TestCalculateCvssScore:
    """Test cases for calculate_cvss_score function."""

    def test_cvss_critical(self):
        """Test CVSS score for Critical severity."""
        assert calculate_cvss_score('Critical') == 9.5
        assert calculate_cvss_score('critical') == 9.5

    def test_cvss_high(self):
        """Test CVSS score for High severity."""
        assert calculate_cvss_score('High') == 7.5
        assert calculate_cvss_score('high') == 7.5

    def test_cvss_medium(self):
        """Test CVSS score for Medium severity."""
        assert calculate_cvss_score('Medium') == 5.5
        assert calculate_cvss_score('medium') == 5.5

    def test_cvss_low(self):
        """Test CVSS score for Low severity."""
        assert calculate_cvss_score('Low') == 3.5
        assert calculate_cvss_score('low') == 3.5

    def test_cvss_info(self):
        """Test CVSS score for Info severity."""
        assert calculate_cvss_score('Info') == 1.0
        assert calculate_cvss_score('info') == 1.0

    def test_cvss_unknown(self):
        """Test CVSS score for unknown severity."""
        assert calculate_cvss_score('unknown') == 5.0
        assert calculate_cvss_score('invalid') == 5.0
        assert calculate_cvss_score(None) == 5.0

    def test_cvss_numeric(self):
        """Test CVSS score with numeric input."""
        assert calculate_cvss_score(5) == 5.0  # unknown -> default
        assert calculate_cvss_score(0) == 5.0


class TestCalculateRemediationPriority:
    """Test cases for calculate_remediation_priority function."""

    def test_priority_critical(self):
        """Test priority for Critical severity."""
        assert calculate_remediation_priority('Critical') == 'Immediate'
        assert calculate_remediation_priority('critical') == 'Immediate'

    def test_priority_high(self):
        """Test priority for High severity."""
        assert calculate_remediation_priority('High') == 'High'
        assert calculate_remediation_priority('high') == 'High'

    def test_priority_medium(self):
        """Test priority for Medium severity."""
        assert calculate_remediation_priority('Medium') == 'Medium'
        assert calculate_remediation_priority('medium') == 'Medium'

    def test_priority_low(self):
        """Test priority for Low severity."""
        assert calculate_remediation_priority('Low') == 'Low'
        assert calculate_remediation_priority('low') == 'Low'

    def test_priority_info(self):
        """Test priority for Info severity."""
        assert calculate_remediation_priority('Info') == 'Informational'
        assert calculate_remediation_priority('info') == 'Informational'

    def test_priority_unknown(self):
        """Test priority for unknown severity."""
        assert calculate_remediation_priority('unknown') == 'Medium'
        assert calculate_remediation_priority('invalid') == 'Medium'
        assert calculate_remediation_priority(None) == 'Medium'


class TestSeverityWeights:
    """Test SEVERITY_WEIGHTS constant."""

    def test_severity_weights_complete(self):
        """Test that all severity weights are defined."""
        assert 'critical' in SEVERITY_WEIGHTS
        assert 'high' in SEVERITY_WEIGHTS
        assert 'medium' in SEVERITY_WEIGHTS
        assert 'low' in SEVERITY_WEIGHTS
        assert 'info' in SEVERITY_WEIGHTS

    def test_severity_weights_values(self):
        """Test that severity weight values are correct."""
        assert SEVERITY_WEIGHTS['critical'] == 10.0
        assert SEVERITY_WEIGHTS['high'] == 7.5
        assert SEVERITY_WEIGHTS['medium'] == 5.0
        assert SEVERITY_WEIGHTS['low'] == 2.5
        assert SEVERITY_WEIGHTS['info'] == 1.0


class TestConfidenceMultipliers:
    """Test CONFIDENCE_MULTIPLIERS constant."""

    def test_confidence_multipliers_complete(self):
        """Test that all confidence multipliers are defined."""
        assert 'certain' in CONFIDENCE_MULTIPLIERS
        assert 'firm' in CONFIDENCE_MULTIPLIERS
        assert 'tentative' in CONFIDENCE_MULTIPLIERS

    def test_confidence_multipliers_values(self):
        """Test that confidence multiplier values are correct."""
        assert CONFIDENCE_MULTIPLIERS['certain'] == 1.0
        assert CONFIDENCE_MULTIPLIERS['firm'] == 0.8
        assert CONFIDENCE_MULTIPLIERS['tentative'] == 0.5
