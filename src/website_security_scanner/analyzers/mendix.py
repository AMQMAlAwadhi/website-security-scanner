#!/usr/bin/env python3
"""
Mendix Security Analyzer
Low-Code Platform Security Scanner
"""

import re
from typing import Any, Dict, List

import requests
from bs4 import BeautifulSoup

from .generic import GenericWebAnalyzer
from ..utils.evidence_builder import EvidenceBuilder


class MendixAnalyzer(GenericWebAnalyzer):
    """Mendix-specific security analyzer built on generic web checks."""

    MENDIX_MARKERS = [
        r'/mxclientsystem/',
        r'mxui',
        r'mendix',
        r'window\.mx',
    ]

    MENDIX_REST_PATTERN = re.compile(r'/rest/[^\s"\'<>]+', re.IGNORECASE)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        results = super().analyze(url, response, soup)

        html_content = str(soup)
        js_content = self._extract_javascript(soup)

        markers = self._detect_mendix_markers(html_content + "\n" + js_content)
        rest_endpoints = self._detect_mendix_rest_endpoints(html_content + "\n" + js_content)

        for endpoint in rest_endpoints:
            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Mendix REST endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Mendix REST Endpoint Exposure",
                "Low",
                f"Mendix REST endpoint referenced in client content: {endpoint}",
                evidence,
                "Ensure REST endpoints are protected and require authentication.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200", "CWE-306"],
            )

        self.findings["mendix_markers"] = markers
        self.findings["mendix_rest_endpoints"] = rest_endpoints

        results["mendix_findings"] = self.findings
        results["vulnerabilities"] = self.vulnerabilities
        return results

    def _detect_mendix_markers(self, content: str) -> List[str]:
        markers = []
        for pattern in self.MENDIX_MARKERS:
            if re.search(pattern, content, re.IGNORECASE):
                markers.append(pattern)
        return markers

    def _detect_mendix_rest_endpoints(self, content: str) -> List[str]:
        endpoints = []
        for match in self.MENDIX_REST_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        return endpoints
