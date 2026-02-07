"""
Utility Modules
Low-Code Platform Security Scanner

Professional utility functions for security scanning operations.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from .logger import setup_scanner_logger, get_logger, ScannerLogger
from .utils import (
    normalize_url,
    is_valid_url,
    extract_domain,
    calculate_security_score,
)
from .evidence_verifier import EvidenceVerifier, verify_vulnerabilities
from .rate_limiter import RateLimiter, ThrottledSession
from .risk_calculator import (
    calculate_risk_score,
    calculate_risk_level,
    calculate_cvss_score,
    calculate_remediation_priority,
)
from .normalization import (
    normalize_severity,
    normalize_confidence,
    get_severity_rank,
    get_confidence_rank,
    compare_severity,
)
from .platform_data import (
    get_platform_findings,
    get_platform_identifiers,
    get_api_patterns,
    set_platform_findings,
    normalize_platform_name,
    get_supported_platforms,
    extract_platform_from_results,
)

__all__ = [
    "setup_scanner_logger",
    "get_logger",
    "ScannerLogger",
    "normalize_url",
    "is_valid_url",
    "extract_domain",
    "calculate_security_score",
    "EvidenceVerifier",
    "verify_vulnerabilities",
    "RateLimiter",
    "ThrottledSession",
    "calculate_risk_score",
    "calculate_risk_level",
    "calculate_cvss_score",
    "calculate_remediation_priority",
    "normalize_severity",
    "normalize_confidence",
    "get_severity_rank",
    "get_confidence_rank",
    "compare_severity",
    "get_platform_findings",
    "get_platform_identifiers",
    "get_api_patterns",
    "set_platform_findings",
    "normalize_platform_name",
    "get_supported_platforms",
    "extract_platform_from_results",
]
