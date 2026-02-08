#!/usr/bin/env python3
"""
Tests for normalization utilities.

Tests for the unified severity and confidence normalization functions.
"""

import pytest
from website_security_scanner.utils.normalization import (
    normalize_severity,
    normalize_confidence,
    get_severity_rank,
    get_confidence_rank,
    compare_severity,
    SEVERITY_LEVELS,
    CONFIDENCE_LEVELS
)


class TestNormalizeSeverity:
    """Test cases for normalize_severity function."""

    def test_normalize_standard_severity(self):
        """Test normalization of standard severity levels."""
        assert normalize_severity('Critical') == 'Critical'
        assert normalize_severity('critical') == 'Critical'
        assert normalize_severity('CRITICAL') == 'Critical'
        assert normalize_severity('High') == 'High'
        assert normalize_severity('high') == 'High'
        assert normalize_severity('Medium') == 'Medium'
        assert normalize_severity('medium') == 'Medium'
        assert normalize_severity('Low') == 'Low'
        assert normalize_severity('low') == 'Low'
        assert normalize_severity('Info') == 'Info'
        assert normalize_severity('info') == 'Info'

    def test_normalize_severity_variations(self):
        """Test normalization of severity variations."""
        assert normalize_severity('crit') == 'Critical'
        assert normalize_severity('med') == 'Medium'
        assert normalize_severity('moderate') == 'Medium'
        assert normalize_severity('information') == 'Info'
        assert normalize_severity('informational') == 'Info'

    def test_normalize_severity_numeric(self):
        """Test normalization of numeric severity values."""
        assert normalize_severity(5) == 'Critical'
        assert normalize_severity('5') == 'Critical'
        assert normalize_severity(4) == 'High'
        assert normalize_severity('4') == 'High'
        assert normalize_severity(3) == 'Medium'
        assert normalize_severity('3') == 'Medium'
        assert normalize_severity(2) == 'Low'
        assert normalize_severity('2') == 'Low'
        assert normalize_severity(1) == 'Info'
        assert normalize_severity('1') == 'Info'

    def test_normalize_severity_edge_cases(self):
        """Test normalization of edge cases."""
        assert normalize_severity(None) == 'Info'
        assert normalize_severity('') == 'Info'
        assert normalize_severity('  ') == 'Info'
        assert normalize_severity('unknown') == 'Info'
        assert normalize_severity('invalid') == 'Info'
        assert normalize_severity(0) == 'Info'
        assert normalize_severity(10) == 'Critical'  # >= 5 maps to Critical
        assert normalize_severity(-1) == 'Info'

    def test_normalize_severity_whitespace(self):
        """Test normalization handles whitespace correctly."""
        assert normalize_severity('  Critical  ') == 'Critical'
        assert normalize_severity('\tHigh\t') == 'High'
        assert normalize_severity('\n Medium \n') == 'Medium'


class TestNormalizeConfidence:
    """Test cases for normalize_confidence function."""

    def test_normalize_standard_confidence(self):
        """Test normalization of standard confidence levels."""
        assert normalize_confidence('Certain') == 'Certain'
        assert normalize_confidence('certain') == 'Certain'
        assert normalize_confidence('CERTAIN') == 'Certain'
        assert normalize_confidence('Firm') == 'Firm'
        assert normalize_confidence('firm') == 'Firm'
        assert normalize_confidence('Tentative') == 'Tentative'
        assert normalize_confidence('tentative') == 'Tentative'

    def test_normalize_confidence_variations(self):
        """Test normalization of confidence variations."""
        assert normalize_confidence('definite') == 'Certain'
        assert normalize_confidence('confirmed') == 'Certain'
        assert normalize_confidence('high') == 'Certain'
        assert normalize_confidence('strong') == 'Firm'
        assert normalize_confidence('good') == 'Firm'
        assert normalize_confidence('medium') == 'Firm'
        assert normalize_confidence('possible') == 'Tentative'
        assert normalize_confidence('potential') == 'Tentative'
        assert normalize_confidence('low') == 'Tentative'
        assert normalize_confidence('weak') == 'Tentative'

    def test_normalize_confidence_numeric(self):
        """Test normalization of numeric confidence values."""
        assert normalize_confidence(3) == 'Certain'
        assert normalize_confidence('3') == 'Certain'
        assert normalize_confidence(2) == 'Firm'
        assert normalize_confidence('2') == 'Firm'
        assert normalize_confidence(1) == 'Tentative'
        assert normalize_confidence('1') == 'Tentative'

    def test_normalize_confidence_edge_cases(self):
        """Test normalization of edge cases."""
        assert normalize_confidence(None) == 'Tentative'
        assert normalize_confidence('') == 'Tentative'
        assert normalize_confidence('  ') == 'Tentative'
        assert normalize_confidence('unknown') == 'Tentative'
        assert normalize_confidence('invalid') == 'Tentative'
        assert normalize_confidence(0) == 'Tentative'
        assert normalize_confidence(10) == 'Certain'  # >= 3 maps to Certain
        assert normalize_confidence(-1) == 'Tentative'

    def test_normalize_confidence_whitespace(self):
        """Test normalization handles whitespace correctly."""
        assert normalize_confidence('  Certain  ') == 'Certain'
        assert normalize_confidence('\tFirm\t') == 'Firm'
        assert normalize_confidence('\n Tentative \n') == 'Tentative'


class TestGetSeverityRank:
    """Test cases for get_severity_rank function."""

    def test_get_severity_rank_standard(self):
        """Test getting rank for standard severity levels."""
        assert get_severity_rank('Critical') == 5
        assert get_severity_rank('High') == 4
        assert get_severity_rank('Medium') == 3
        assert get_severity_rank('Low') == 2
        assert get_severity_rank('Info') == 1

    def test_get_severity_rank_normalizes(self):
        """Test that get_severity_rank normalizes input."""
        assert get_severity_rank('critical') == 5
        assert get_severity_rank('HIGH') == 4
        assert get_severity_rank('med') == 3
        assert get_severity_rank(5) == 5
        assert get_severity_rank('3') == 3

    def test_get_severity_rank_unknown(self):
        """Test that unknown severities are normalized to Info (rank 1)."""
        # Unknown severities are normalized to 'Info' which has rank 1
        assert get_severity_rank('unknown') == 1
        assert get_severity_rank('invalid') == 1
        assert get_severity_rank(None) == 1


class TestGetConfidenceRank:
    """Test cases for get_confidence_rank function."""

    def test_get_confidence_rank_standard(self):
        """Test getting rank for standard confidence levels."""
        assert get_confidence_rank('Certain') == 3
        assert get_confidence_rank('Firm') == 2
        assert get_confidence_rank('Tentative') == 1

    def test_get_confidence_rank_normalizes(self):
        """Test that get_confidence_rank normalizes input."""
        assert get_confidence_rank('certain') == 3
        assert get_confidence_rank('FIRM') == 2
        assert get_confidence_rank('tentative') == 1
        assert get_confidence_rank(3) == 3
        assert get_confidence_rank('2') == 2

    def test_get_confidence_rank_unknown(self):
        """Test that unknown confidences are normalized to Tentative (rank 1)."""
        # Unknown confidences are normalized to 'Tentative' which has rank 1
        assert get_confidence_rank('unknown') == 1
        assert get_confidence_rank('invalid') == 1
        assert get_confidence_rank(None) == 1


class TestCompareSeverity:
    """Test cases for compare_severity function."""

    def test_compare_severity_less_than(self):
        """Test comparison when first severity is less than second."""
        assert compare_severity('Low', 'High') == -1
        assert compare_severity('Info', 'Critical') == -1
        assert compare_severity('Medium', 'High') == -1

    def test_compare_severity_greater_than(self):
        """Test comparison when first severity is greater than second."""
        assert compare_severity('Critical', 'Low') == 1
        assert compare_severity('High', 'Medium') == 1
        assert compare_severity('Medium', 'Info') == 1

    def test_compare_severity_equal(self):
        """Test comparison when severities are equal."""
        assert compare_severity('Critical', 'Critical') == 0
        assert compare_severity('High', 'high') == 0
        assert compare_severity('Medium', 'Medium') == 0

    def test_compare_severity_normalizes(self):
        """Test that compare_severity normalizes input."""
        assert compare_severity('critical', 'low') == 1
        assert compare_severity('HIGH', 'medium') == 1
        assert compare_severity(5, 2) == 1

    def test_compare_severity_unknown(self):
        """Test comparison with unknown severities."""
        assert compare_severity('unknown', 'High') == -1
        assert compare_severity('Critical', 'invalid') == 1
        assert compare_severity('unknown', 'invalid') == 0


class TestSeverityLevels:
    """Test SEVERITY_LEVELS constant."""

    def test_severity_levels_complete(self):
        """Test that all severity levels are defined."""
        assert 'Critical' in SEVERITY_LEVELS
        assert 'High' in SEVERITY_LEVELS
        assert 'Medium' in SEVERITY_LEVELS
        assert 'Low' in SEVERITY_LEVELS
        assert 'Info' in SEVERITY_LEVELS

    def test_severity_levels_values(self):
        """Test that severity level values are correct."""
        assert SEVERITY_LEVELS['Critical'] == 5
        assert SEVERITY_LEVELS['High'] == 4
        assert SEVERITY_LEVELS['Medium'] == 3
        assert SEVERITY_LEVELS['Low'] == 2
        assert SEVERITY_LEVELS['Info'] == 1


class TestConfidenceLevels:
    """Test CONFIDENCE_LEVELS constant."""

    def test_confidence_levels_complete(self):
        """Test that all confidence levels are defined."""
        assert 'Certain' in CONFIDENCE_LEVELS
        assert 'Firm' in CONFIDENCE_LEVELS
        assert 'Tentative' in CONFIDENCE_LEVELS

    def test_confidence_levels_values(self):
        """Test that confidence level values are correct."""
        assert CONFIDENCE_LEVELS['Certain'] == 3
        assert CONFIDENCE_LEVELS['Firm'] == 2
        assert CONFIDENCE_LEVELS['Tentative'] == 1
