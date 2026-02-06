#!/usr/bin/env python3
"""
Shopify Security Analyzer
Low-Code Platform Security Scanner

Platform-specific analyzer for Shopify storefronts.
"""

import re
from typing import Any, Dict, List

import requests
from bs4 import BeautifulSoup

from .generic import GenericWebAnalyzer
from ..utils.evidence_builder import EvidenceBuilder


class ShopifyAnalyzer(GenericWebAnalyzer):
    """Shopify-specific security analyzer built on generic web checks."""

    SHOPIFY_ASSET_PATTERNS = [
        r'cdn\.shopify\.com',
        r'shopifycloud',
        r'shopifyassets',
    ]

    STOREFRONT_TOKEN_PATTERN = re.compile(
        r'(storefrontAccessToken|storefront_api_token)["\']\s*[:=]\s*["\']([A-Za-z0-9_-]{16,})["\']',
        re.IGNORECASE,
    )

    PUBLIC_JSON_ENDPOINTS = [
        "/products.json",
        "/collections.json",
        "/blogs.json",
        "/pages.json",
        "/cart.js",
    ]

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        results = super().analyze(url, response, soup)

        html_content = str(soup)
        js_content = self._extract_javascript(soup)

        assets = self._detect_shopify_assets(html_content)
        tokens = self._detect_storefront_tokens(js_content)
        public_json = self._detect_public_json_endpoints(html_content + "\n" + js_content)
        checkout_tokens = self._detect_checkout_api_tokens(html_content)

        if tokens:
            for token in tokens:
                evidence = EvidenceBuilder.exact_match(
                    token,
                    "Potential Shopify Storefront API token exposed in client-side code",
                )
                self.add_enriched_vulnerability(
                    "Shopify Storefront Access Token Exposure",
                    "High",
                    "Potential Storefront API access token found in client-side code.",
                    evidence,
                    "Rotate the token and ensure it is not exposed in client-side assets.",
                    category="API Security",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-798", "CWE-200"],
                )

        if public_json:
            for endpoint in public_json:
                evidence = EvidenceBuilder.exact_match(
                    endpoint,
                    "Public Shopify JSON endpoint referenced in client content",
                )
                self.add_enriched_vulnerability(
                    "Public Shopify JSON Endpoint",
                    "Info",
                    f"Public Shopify JSON endpoint referenced: {endpoint}",
                    evidence,
                    "Review whether publicly accessible endpoints expose sensitive data.",
                    category="Information Disclosure",
                    owasp="A01:2021 - Broken Access Control",
                    cwe=["CWE-200"],
                )

        if checkout_tokens:
            for token in checkout_tokens:
                evidence = EvidenceBuilder.exact_match(
                    token,
                    "Checkout API token exposed in markup",
                )
                self.add_enriched_vulnerability(
                    "Shopify Checkout API Token Exposure",
                    "Medium",
                    "Checkout API token appears in client-side markup.",
                    evidence,
                    "Review token scope and rotate if unnecessary; avoid embedding sensitive tokens in client code.",
                    category="API Security",
                    owasp="A02:2021 - Cryptographic Failures",
                    cwe=["CWE-798", "CWE-200"],
                )

        self.findings["shopify_assets"] = assets
        self.findings["storefront_tokens"] = tokens
        self.findings["public_json_endpoints"] = public_json
        self.findings["checkout_tokens"] = checkout_tokens

        results["shopify_findings"] = self.findings
        results["vulnerabilities"] = self.vulnerabilities
        return results

    def _detect_shopify_assets(self, html_content: str) -> List[str]:
        assets = []
        for pattern in self.SHOPIFY_ASSET_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                assets.append(pattern)
        return assets

    def _detect_storefront_tokens(self, js_content: str) -> List[str]:
        tokens = []
        for match in self.STOREFRONT_TOKEN_PATTERN.finditer(js_content or ""):
            token_value = match.group(2)
            if token_value and token_value not in tokens:
                tokens.append(token_value)
        return tokens

    def _detect_public_json_endpoints(self, content: str) -> List[str]:
        found = []
        for endpoint in self.PUBLIC_JSON_ENDPOINTS:
            if endpoint in content:
                found.append(endpoint)
        return found

    def _detect_checkout_api_tokens(self, html_content: str) -> List[str]:
        tokens = []
        matches = re.findall(r'shopify-checkout-api-token["\']?\s*content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for token in matches:
            if token and token not in tokens:
                tokens.append(token)
        return tokens
