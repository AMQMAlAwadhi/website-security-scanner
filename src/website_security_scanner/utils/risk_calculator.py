#!/usr/bin/env python3
"""
Unified Risk Calculator

Standard risk scoring algorithm for the website-security-scanner.
This ensures consistent risk calculation across all components.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Dict, List, Any, Union


# Standard severity weights (aligned with ProfessionalReportGenerator)
SEVERITY_WEIGHTS = {
    'critical': 10.0,
    'high': 7.5,
    'medium': 5.0,
    'low': 2.5,
    'info': 1.0
}

# Standard confidence multipliers
CONFIDENCE_MULTIPLIERS = {
    'certain': 1.0,
    'firm': 0.8,
    'tentative': 0.5
}


def calculate_risk_score(
    vulnerabilities: List[Union[Dict[str, Any], 'Vulnerability']]
) -> Dict[str, Any]:
    """
    Calculate overall risk score based on severity and confidence distribution.

    This is the unified risk calculation algorithm used across all components
    of the security scanner. It weights vulnerabilities by severity and confidence
    to produce a normalized 0-100 risk score.

    Args:
        vulnerabilities: List of vulnerability dicts or Vulnerability objects

    Returns:
        Dictionary containing:
            - score: Normalized risk score (0-100)
            - level: Risk level category (Critical, High, Medium, Low, Minimal)
            - severity_counts: Count of vulnerabilities by severity
            - total_vulnerabilities: Total number of vulnerabilities
    """
    if not vulnerabilities:
        return {
            'score': 0.0,
            'level': 'Minimal',
            'severity_counts': {sev: 0 for sev in SEVERITY_WEIGHTS.keys()},
            'total_vulnerabilities': 0
        }

    total_score = 0.0
    max_possible_score = 0.0
    severity_counts = {sev: 0 for sev in SEVERITY_WEIGHTS.keys()}

    for vuln in vulnerabilities:
        # Extract severity and confidence from dict or object
        if isinstance(vuln, dict):
            severity = vuln.get('severity', 'info').lower()
            confidence = vuln.get('confidence', 'tentative').lower()
        else:
            severity = getattr(vuln, 'severity', 'info').lower()
            confidence = getattr(vuln, 'confidence', 'tentative').lower()

        if severity in SEVERITY_WEIGHTS and confidence in CONFIDENCE_MULTIPLIERS:
            weight = SEVERITY_WEIGHTS[severity]
            multiplier = CONFIDENCE_MULTIPLIERS[confidence]
            score = weight * multiplier

            total_score += score
            severity_counts[severity] += 1
            max_possible_score += weight * 1.0

    # Normalize to 0-100 scale
    normalized_score = 0.0
    if max_possible_score > 0:
        normalized_score = min(100.0, (total_score / max_possible_score) * 100)

    # Determine risk level
    risk_level = _determine_risk_level(normalized_score)

    return {
        'score': round(normalized_score, 2),
        'level': risk_level,
        'severity_counts': severity_counts,
        'total_vulnerabilities': len(vulnerabilities)
    }


def calculate_risk_level(
    vulnerabilities: List[Union[Dict[str, Any], 'Vulnerability']]
) -> str:
    """
    Calculate risk level category without computing full score.

    Args:
        vulnerabilities: List of vulnerability dicts or Vulnerability objects

    Returns:
        Risk level category (Critical, High, Medium, Low, Minimal)
    """
    risk_score = calculate_risk_score(vulnerabilities)
    return risk_score['level']


def _determine_risk_level(score: float) -> str:
    """
    Determine risk level category from normalized score.

    Args:
        score: Normalized risk score (0-100)

    Returns:
        Risk level category
    """
    if score >= 80:
        return 'Critical'
    elif score >= 60:
        return 'High'
    elif score >= 40:
        return 'Medium'
    elif score >= 20:
        return 'Low'
    else:
        return 'Minimal'


def calculate_cvss_score(severity: str) -> float:
    """
    Map severity level to CVSS score.

    Args:
        severity: Severity level (Critical, High, Medium, Low, Info)

    Returns:
        CVSS score (0-10)
    """
    severity_scores = {
        'critical': 9.5,
        'high': 7.5,
        'medium': 5.5,
        'low': 3.5,
        'info': 1.0
    }
    return severity_scores.get(str(severity).lower(), 5.0)


def calculate_remediation_priority(severity: str) -> str:
    """
    Map severity level to remediation priority.

    Args:
        severity: Severity level (Critical, High, Medium, Low, Info)

    Returns:
        Remediation priority (Immediate, High, Medium, Low, Informational)
    """
    priority_map = {
        'critical': 'Immediate',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'info': 'Informational'
    }
    return priority_map.get(str(severity).lower(), 'Medium')
