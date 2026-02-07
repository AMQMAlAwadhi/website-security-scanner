#!/usr/bin/env python3
"""
Unified Platform Data Utilities

Platform-specific findings mapping and data extraction for the website-security-scanner.
This ensures consistent handling of platform-specific data across all components.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from typing import Dict, Any, List, Optional


# Platform-specific field mappings
PLATFORM_FIELD_MAPPINGS = {
    'bubble': {
        'findings_key': 'bubble_specific',
        'alternative_keys': ['bubble_specific_findings', 'bubble_findings'],
        'api_patterns': ['api.bubble.io', 'bubble.io/api'],
        'identifier_patterns': ['_bubble', 'bubble_f_', 'bubble_']
    },
    'outsystems': {
        'findings_key': 'outsystems_specific',
        'alternative_keys': ['outsystems_specific_findings', 'outsystems_findings'],
        'api_patterns': ['outsystems.com', 'outsystemscloud.com'],
        'identifier_patterns': ['outsystems', 'os_', 'screen_']
    },
    'airtable': {
        'findings_key': 'airtable_specific',
        'alternative_keys': ['airtable_specific_findings', 'airtable_findings'],
        'api_patterns': ['api.airtable.com', 'airtable.com/api'],
        'identifier_patterns': ['airtable', 'rec_', 'tbl_', 'view_']
    },
    'shopify': {
        'findings_key': 'shopify_specific',
        'alternative_keys': ['shopify_specific_findings', 'shopify_findings'],
        'api_patterns': ['shopify.com', 'myshopify.com'],
        'identifier_patterns': ['shopify', 'shopify_', 'cdn.shopify.com']
    },
    'webflow': {
        'findings_key': 'webflow_specific',
        'alternative_keys': ['webflow_specific_findings', 'webflow_findings'],
        'api_patterns': ['webflow.com', 'webflow.io'],
        'identifier_patterns': ['webflow', 'w-', 'data-wf-']
    },
    'wix': {
        'findings_key': 'wix_specific',
        'alternative_keys': ['wix_specific_findings', 'wix_findings'],
        'api_patterns': ['wix.com', 'wix-code.com'],
        'identifier_patterns': ['wix', 'wix-', 'wix_']
    },
    'mendix': {
        'findings_key': 'mendix_specific',
        'alternative_keys': ['mendix_specific_findings', 'mendix_findings'],
        'api_patterns': ['mendix.com', 'mendixcloud.com'],
        'identifier_patterns': ['mendix', 'mx_', 'mxdata_']
    },
    'generic': {
        'findings_key': 'generic_specific',
        'alternative_keys': ['generic_analysis', 'generic_findings', 'web_specific'],
        'api_patterns': [],
        'identifier_patterns': []
    }
}


def get_platform_findings(
    platform: str,
    results: Dict[str, Any],
    default_fallback: bool = True
) -> Dict[str, Any]:
    """
    Extract platform-specific findings from scan results.

    This function handles the various ways platform-specific findings may be
    stored in scan results, providing a consistent interface across all
    components of the security scanner.

    Args:
        platform: Platform type (bubble, outsystems, airtable, etc.)
        results: Raw scan results dictionary
        default_fallback: Whether to return empty dict if not found

    Returns:
        Platform-specific findings dictionary
    """
    if not platform or not results:
        return {}

    platform_lower = platform.lower().strip()

    # Get platform configuration
    platform_config = PLATFORM_FIELD_MAPPINGS.get(platform_lower)

    if not platform_config:
        # Unknown platform - try direct lookup
        return results.get(f"{platform_lower}_specific", {})

    # Try primary key
    findings_key = platform_config['findings_key']
    if findings_key in results:
        return results[findings_key]

    # Try alternative keys
    for alt_key in platform_config.get('alternative_keys', []):
        if alt_key in results:
            return results[alt_key]

    # Special handling for generic platform
    if platform_lower == 'generic':
        generic_keys = ['generic_analysis', 'generic_findings', 'web_specific']
        for key in generic_keys:
            if key in results:
                return results[key]

    # Return empty dict or None
    return {} if default_fallback else None


def get_platform_identifiers(platform: str) -> List[str]:
    """
    Get platform identifier patterns for detection.

    Args:
        platform: Platform type

    Returns:
        List of identifier patterns
    """
    platform_lower = platform.lower().strip()
    platform_config = PLATFORM_FIELD_MAPPINGS.get(platform_lower)

    if platform_config:
        return platform_config.get('identifier_patterns', [])

    return []


def get_api_patterns(platform: str) -> List[str]:
    """
    Get API URL patterns for a platform.

    Args:
        platform: Platform type

    Returns:
        List of API URL patterns
    """
    platform_lower = platform.lower().strip()
    platform_config = PLATFORM_FIELD_MAPPINGS.get(platform_lower)

    if platform_config:
        return platform_config.get('api_patterns', [])

    return []


def set_platform_findings(
    platform: str,
    results: Dict[str, Any],
    findings: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Set platform-specific findings in scan results.

    Args:
        platform: Platform type
        results: Scan results dictionary to update
        findings: Platform-specific findings to set

    Returns:
        Updated scan results dictionary
    """
    if not platform or not results:
        return results

    platform_lower = platform.lower().strip()
    platform_config = PLATFORM_FIELD_MAPPINGS.get(platform_lower)

    if platform_config:
        findings_key = platform_config['findings_key']
        results[findings_key] = findings
    else:
        # Unknown platform - use convention
        results[f"{platform_lower}_specific"] = findings

    return results


def normalize_platform_name(platform: str) -> str:
    """
    Normalize platform name to standard format.

    Args:
        platform: Platform name in any format

    Returns:
        Normalized platform name
    """
    if not platform:
        return 'generic'

    platform_lower = str(platform).lower().strip()

    # Map common variations to standard names
    platform_mapping = {
        'bubble': 'bubble',
        'outsystems': 'outsystems',
        'airtable': 'airtable',
        'shopify': 'shopify',
        'webflow': 'webflow',
        'wix': 'wix',
        'mendix': 'mendix',
        'generic': 'generic',
        'web': 'generic',
        'unknown': 'generic'
    }

    return platform_mapping.get(platform_lower, platform_lower)


def get_supported_platforms() -> List[str]:
    """
    Get list of supported platforms.

    Returns:
        List of supported platform names
    """
    return list(PLATFORM_FIELD_MAPPINGS.keys())


def extract_platform_from_results(results: Dict[str, Any]) -> str:
    """
    Extract platform type from scan results.

    Args:
        results: Scan results dictionary

    Returns:
        Platform type (normalized)
    """
    # Try explicit platform field
    platform = results.get('platform_type') or results.get('platform')
    if platform:
        return normalize_platform_name(platform)

    # Try to infer from platform-specific findings
    for platform_name in PLATFORM_FIELD_MAPPINGS.keys():
        findings = get_platform_findings(platform_name, results, default_fallback=False)
        if findings:
            return platform_name

    # Default to generic
    return 'generic'
