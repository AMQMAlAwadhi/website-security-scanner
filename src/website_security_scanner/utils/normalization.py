#!/usr/bin/env python3
"""
Unified Normalization Utilities

Standard severity and confidence normalization for the website-security-scanner.
This ensures consistent normalization across all components.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Optional


# Standard severity levels
SEVERITY_LEVELS = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1
}

# Standard confidence levels
CONFIDENCE_LEVELS = {
    'Certain': 3,
    'Firm': 2,
    'Tentative': 1
}


def normalize_severity(severity: Optional[str]) -> str:
    """
    Normalize severity to a standard label.

    This function ensures consistent severity levels across all components
    of the security scanner. It handles various input formats and case
    variations.

    Args:
        severity: Severity level in any format (string, number, etc.)

    Returns:
        Normalized severity label (Critical, High, Medium, Low, Info)
    """
    if not severity:
        return "Info"

    sev_map = {k.lower(): k for k in SEVERITY_LEVELS.keys()}

    # Handle string input
    if isinstance(severity, str):
        sev_lower = severity.lower().strip()

        # Direct mapping
        if sev_lower in sev_map:
            return sev_map[sev_lower]

        # Handle common variations
        if sev_lower in {'critical', 'crit'}:
            return 'Critical'
        elif sev_lower in {'high'}:
            return 'High'
        elif sev_lower in {'medium', 'med', 'moderate'}:
            return 'Medium'
        elif sev_lower in {'low'}:
            return 'Low'
        elif sev_lower in {'info', 'information', 'informational'}:
            return 'Info'

    # Handle numeric input (1-5 scale)
    try:
        num_severity = int(severity)
        if num_severity >= 5:
            return 'Critical'
        elif num_severity == 4:
            return 'High'
        elif num_severity == 3:
            return 'Medium'
        elif num_severity == 2:
            return 'Low'
        elif num_severity == 1:
            return 'Info'
    except (ValueError, TypeError):
        pass

    # Default fallback
    return "Info"


def normalize_confidence(confidence: Optional[str]) -> str:
    """
    Normalize confidence to a standard label.

    This function ensures consistent confidence levels across all components
    of the security scanner. It handles various input formats and case
    variations.

    Args:
        confidence: Confidence level in any format (string, number, etc.)

    Returns:
        Normalized confidence label (Certain, Firm, Tentative)
    """
    if not confidence:
        return "Tentative"

    conf_map = {k.lower(): k for k in CONFIDENCE_LEVELS.keys()}

    # Handle string input
    if isinstance(confidence, str):
        conf_lower = confidence.lower().strip()

        # Direct mapping
        if conf_lower in conf_map:
            return conf_map[conf_lower]

        # Handle common variations
        if conf_lower in {'certain', 'definite', 'confirmed', 'high'}:
            return 'Certain'
        elif conf_lower in {'firm', 'strong', 'good', 'medium'}:
            return 'Firm'
        elif conf_lower in {'tentative', 'possible', 'potential', 'low', 'weak'}:
            return 'Tentative'

    # Handle numeric input (1-3 scale)
    try:
        num_confidence = int(confidence)
        if num_confidence >= 3:
            return 'Certain'
        elif num_confidence == 2:
            return 'Firm'
        elif num_confidence == 1:
            return 'Tentative'
    except (ValueError, TypeError):
        pass

    # Default fallback
    return "Tentative"


def get_severity_rank(severity: str) -> int:
    """
    Get numeric rank for severity level.

    Args:
        severity: Severity level

    Returns:
        Numeric rank (higher = more severe)
    """
    normalized = normalize_severity(severity)
    return SEVERITY_LEVELS.get(normalized, 0)


def get_confidence_rank(confidence: str) -> int:
    """
    Get numeric rank for confidence level.

    Args:
        confidence: Confidence level

    Returns:
        Numeric rank (higher = more confident)
    """
    normalized = normalize_confidence(confidence)
    return CONFIDENCE_LEVELS.get(normalized, 0)


def compare_severity(sev1: str, sev2: str) -> int:
    """
    Compare two severity levels.

    Args:
        sev1: First severity level
        sev2: Second severity level

    Returns:
        -1 if sev1 < sev2, 0 if equal, 1 if sev1 > sev2
    """
    rank1 = get_severity_rank(sev1)
    rank2 = get_severity_rank(sev2)

    if rank1 < rank2:
        return -1
    elif rank1 > rank2:
        return 1
    else:
        return 0
