#!/usr/bin/env python3
"""
Webflow Security Analyzer
Low-Code Platform Security Scanner
"""

import re
from typing import Any, Dict, List

import requests
from bs4 import BeautifulSoup

from .generic import GenericWebAnalyzer
from ..utils.evidence_builder import EvidenceBuilder


class WebflowAnalyzer(GenericWebAnalyzer):
    """Webflow-specific security analyzer built on generic web checks."""

    WEBFLOW_MARKERS = [
        r'webflow\.js',
        r'data-wf-site',
        r'data-wf-page',
        r'uploads-ssl\.webflow\.com',
    ]

    WEBFLOW_API_PATTERN = re.compile(r'https?://api\.webflow\.com/[^"\']+', re.IGNORECASE)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        results = super().analyze(url, response, soup)

        html_content = str(soup)
        js_content = self._extract_javascript(soup)

        markers = self._detect_webflow_markers(html_content)
        api_endpoints = self._detect_webflow_api_endpoints(html_content + "\n" + js_content)

        for endpoint in api_endpoints:
            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Webflow API endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Webflow API Endpoint Exposure",
                "Info",
                f"Webflow API endpoint referenced in client content: {endpoint}",
                evidence,
                "Ensure API endpoints are protected and do not expose sensitive data.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
            )

        self.findings["webflow_markers"] = markers
        self.findings["webflow_api_endpoints"] = api_endpoints

        results["webflow_findings"] = self.findings
        results["vulnerabilities"] = self.vulnerabilities
        return results

    def _detect_webflow_markers(self, html_content: str) -> List[str]:
        markers = []
        for pattern in self.WEBFLOW_MARKERS:
            if re.search(pattern, html_content, re.IGNORECASE):
                markers.append(pattern)
        return markers

    def _detect_webflow_api_endpoints(self, content: str) -> List[str]:
        endpoints = []
        for match in self.WEBFLOW_API_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        return endpoints
