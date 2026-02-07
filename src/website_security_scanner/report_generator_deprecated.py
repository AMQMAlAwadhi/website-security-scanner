#!/usr/bin/env python3
"""
Deprecated EnhancedReportGenerator Wrapper

This module provides backward compatibility for EnhancedReportGenerator.
It has been deprecated in favor of using ProfessionalReportGenerator directly.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import warnings
from typing import Dict, Any, List

from .report_generator import ProfessionalReportGenerator


class EnhancedReportGenerator(ProfessionalReportGenerator):
    """
    Deprecated: Enhanced report generator.

    This class is deprecated. Use ProfessionalReportGenerator directly instead.
    All features of EnhancedReportGenerator are now available in ProfessionalReportGenerator.

    Example:
        # Old way (deprecated):
        from website_security_scanner.enhanced_report_generator import EnhancedReportGenerator
        generator = EnhancedReportGenerator()

        # New way:
        from website_security_scanner.report_generator import ProfessionalReportGenerator
        generator = ProfessionalReportGenerator()
    """

    def __init__(self):
        """Initialize with deprecation warning."""
        super().__init__()
        warnings.warn(
            "EnhancedReportGenerator is deprecated. "
            "Use ProfessionalReportGenerator directly instead. "
            "All features are now available in ProfessionalReportGenerator.",
            DeprecationWarning,
            stacklevel=2
        )

    def generate_report(self, scan_results, output_path=None, enhanced=True):
        """
        Generate report with deprecation warning.

        Args:
            scan_results: Scan results dictionary
            output_path: Output file path (optional)
            enhanced: Whether to use enhanced features (default: True)

        Returns:
            Path to generated report file
        """
        warnings.warn(
            "EnhancedReportGenerator.generate_report() is deprecated. "
            "Use ProfessionalReportGenerator.generate_report() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super().generate_report(scan_results, output_path, enhanced)

    def generate_html_content(self, scan_results, enhanced=True):
        """Generate HTML content with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator.generate_html_content() is deprecated. "
            "Use ProfessionalReportGenerator.generate_html_content() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super().generate_html_content(scan_results, enhanced)

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Calculate risk score with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._calculate_risk_score() is deprecated. "
            "Use ProfessionalReportGenerator._calculate_risk_score() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._calculate_risk_score(vulnerabilities)

    def _generate_compliance_metrics(self, results: Dict) -> Dict[str, Any]:
        """Generate compliance metrics with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_compliance_metrics() is deprecated. "
            "Use ProfessionalReportGenerator._generate_compliance_metrics() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_compliance_metrics(results)

    def _generate_remediation_priorities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate remediation priorities with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_remediation_priorities() is deprecated. "
            "Use ProfessionalReportGenerator._generate_remediation_priorities() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_remediation_priorities(vulnerabilities)

    def _estimate_remediation_effort(self, vuln: Dict) -> str:
        """Estimate remediation effort with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._estimate_remediation_effort() is deprecated. "
            "Use ProfessionalReportGenerator._estimate_remediation_effort() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._estimate_remediation_effort(vuln)

    def _assess_business_impact(self, vuln: Dict) -> str:
        """Assess business impact with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._assess_business_impact() is deprecated. "
            "Use ProfessionalReportGenerator._assess_business_impact() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._assess_business_impact(vuln)

    def _generate_enhanced_html(self, results: Dict) -> str:
        """Generate enhanced HTML with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_enhanced_html() is deprecated. "
            "Use ProfessionalReportGenerator._generate_enhanced_html() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_enhanced_html(results)

    def _get_enhanced_styles(self) -> str:
        """Get enhanced styles with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._get_enhanced_styles() is deprecated. "
            "Use ProfessionalReportGenerator._get_enhanced_styles() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._get_enhanced_styles()

    def _get_risk_color(self, risk_level: str) -> str:
        """Get risk color with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._get_risk_color() is deprecated. "
            "Use ProfessionalReportGenerator._get_risk_color() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._get_risk_color(risk_level)

    def _generate_enhanced_header(self, results, risk_score, compliance) -> str:
        """Generate enhanced header with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_enhanced_header() is deprecated. "
            "Use ProfessionalReportGenerator._generate_enhanced_header() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_enhanced_header(results, risk_score, compliance)

    def _generate_enhanced_executive_summary(self, results, risk_score, compliance) -> str:
        """Generate enhanced executive summary with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_enhanced_executive_summary() is deprecated. "
            "Use ProfessionalReportGenerator._generate_enhanced_executive_summary() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_enhanced_executive_summary(results, risk_score, compliance)

    def _prepare_chart_data(self, vulns, risk_score) -> Dict:
        """Prepare chart data with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._prepare_chart_data() is deprecated. "
            "Use ProfessionalReportGenerator._prepare_chart_data() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._prepare_chart_data(vulns, risk_score)

    def _generate_enhanced_risk_dashboard(self, chart_data, risk_score) -> str:
        """Generate enhanced risk dashboard with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_enhanced_risk_dashboard() is deprecated. "
            "Use ProfessionalReportGenerator._generate_enhanced_risk_dashboard() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_enhanced_risk_dashboard(chart_data, risk_score)

    def _generate_enhanced_remediation_priorities(self, remediation) -> str:
        """Generate enhanced remediation priorities with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_enhanced_remediation_priorities() is deprecated. "
            "Use ProfessionalReportGenerator._generate_enhanced_remediation_priorities() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_enhanced_remediation_priorities(remediation)

    def _generate_enhanced_findings(self, results) -> str:
        """Generate enhanced findings with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_enhanced_findings() is deprecated. "
            "Use ProfessionalReportGenerator._generate_enhanced_findings() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_enhanced_findings(results)

    def _generate_enhanced_footer(self) -> str:
        """Generate enhanced footer with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._generate_enhanced_footer() is deprecated. "
            "Use ProfessionalReportGenerator._generate_enhanced_footer() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._generate_enhanced_footer()

    def _get_enhanced_scripts(self, chart_data) -> str:
        """Get enhanced scripts with deprecation warning."""
        warnings.warn(
            "EnhancedReportGenerator._get_enhanced_scripts() is deprecated. "
            "Use ProfessionalReportGenerator._get_enhanced_scripts() directly instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return super()._get_enhanced_scripts(chart_data)
