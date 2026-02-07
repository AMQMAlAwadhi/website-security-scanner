"""
Enhanced Security Report Generator with Professional Features (DEPRECATED)

This module is deprecated. Use ProfessionalReportGenerator directly instead.

This module now imports from report_generator_deprecated for backward compatibility.

Example:
    # Old way (deprecated):
    from website_security_scanner.enhanced_report_generator import EnhancedReportGenerator

    # New way:
    from website_security_scanner.report_generator import ProfessionalReportGenerator
    generator = ProfessionalReportGenerator()

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

from .report_generator_deprecated import EnhancedReportGenerator

__all__ = ['EnhancedReportGenerator']
