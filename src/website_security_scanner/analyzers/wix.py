#!/usr/bin/env python3
"""
Wix Security Analyzer
Low-Code Platform Security Scanner
"""

import re
from typing import Any, Dict, List

import requests
from bs4 import BeautifulSoup

from .generic import GenericWebAnalyzer
from ..utils.evidence_builder import EvidenceBuilder


class WixAnalyzer(GenericWebAnalyzer):
    """Wix-specific security analyzer built on generic web checks."""

    WIX_MARKERS = [
        r'wixstatic\.com',
        r'static\.parastorage\.com',
        r'wixBiSession',
        r'wixRenderer',
        r'wixData',
    ]

    WIX_API_PATTERN = re.compile(r'/_api/[^\s"\'<>]+', re.IGNORECASE)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        results = super().analyze(url, response, soup)

        html_content = str(soup)
        js_content = self._extract_javascript(soup)

        markers = self._detect_wix_markers(html_content + "\n" + js_content)
        api_endpoints = self._detect_wix_api_endpoints(html_content + "\n" + js_content)
        collections = self._detect_wix_data_collections(html_content + "\n" + js_content)

        for endpoint in api_endpoints:
            evidence = EvidenceBuilder.exact_match(
                endpoint,
                "Wix API endpoint referenced in client content",
            )
            self.add_enriched_vulnerability(
                "Wix API Endpoint Exposure",
                "Info",
                f"Wix API endpoint referenced in client content: {endpoint}",
                evidence,
                "Review access controls on exposed endpoints.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
            )

        for collection in collections:
            evidence = EvidenceBuilder.exact_match(
                collection,
                "Wix data collection referenced in client code",
            )
            self.add_enriched_vulnerability(
                "Wix Data Collection Exposure",
                "Info",
                f"Wix data collection referenced in client code: {collection}",
                evidence,
                "Review collection permissions and ensure access controls are enforced.",
                category="Information Disclosure",
                owasp="A01:2021 - Broken Access Control",
                cwe=["CWE-200"],
            )

        self.findings["wix_markers"] = markers
        self.findings["wix_api_endpoints"] = api_endpoints
        self.findings["wix_collections"] = collections

        results["wix_findings"] = self.findings
        results["vulnerabilities"] = self.vulnerabilities
        return results

    def _detect_wix_markers(self, content: str) -> List[str]:
        markers = []
        for pattern in self.WIX_MARKERS:
            if re.search(pattern, content, re.IGNORECASE):
                markers.append(pattern)
        return markers

    def _detect_wix_api_endpoints(self, content: str) -> List[str]:
        endpoints = []
        for match in self.WIX_API_PATTERN.finditer(content or ""):
            endpoint = match.group(0)
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        return endpoints

    def _detect_wix_data_collections(self, content: str) -> List[str]:
        collections = []
        matches = re.findall(r'wixData\.query\(["\']([^"\']+)["\']', content, re.IGNORECASE)
        for name in matches:
            if name not in collections:
                collections.append(name)
        return collections
