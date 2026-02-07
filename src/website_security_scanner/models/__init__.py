"""
Website Security Scanner - Data Models

Unified data structures for the website-security-scanner.
"""

from .vulnerability import EnhancedVulnerability, ScanResult
from .vulnerability_unified import Vulnerability

__all__ = [
    'Vulnerability',
    'EnhancedVulnerability',
    'ScanResult'
]
