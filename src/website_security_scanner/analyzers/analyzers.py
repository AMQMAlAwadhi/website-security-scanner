#!/usr/bin/env python3
"""
Advanced Security Analyzers Module
Low-Code Platform Security Scanner

This module contains specialized analyzers for different low-code platforms
and security vulnerability detection methods.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import base64
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class BaseAnalyzer:
    """Base class for all security analyzers"""

    def __init__(self, session: requests.Session):
        self.session = session
        self.vulnerabilities = []
        self.findings = {}

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Base analyze method to be overridden by subclasses"""
        raise NotImplementedError("Subclasses must implement analyze method")

    def add_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        description: str,
        evidence: str = "",
        recommendation: str = "",
        confidence: str = "Firm",
        category: str = "General",
        owasp: str = "N/A",
        cwe: List[str] = None,
    ):
        """Add a vulnerability to the findings with detailed metadata for professional reporting"""
        vulnerability = {
            "type": vuln_type,
            "title": vuln_type,  # Using type as title for consistency
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": recommendation,
            "confidence": confidence,
            "category": category,
            "owasp": owasp,
            "cwe": cwe or ["N/A"],
            "impact": "Potential compromise of application security and data integrity.",
        }
        self.vulnerabilities.append(vulnerability)

    def _check_session_tokens_in_url(self, url: str):
        """Check for session tokens in URL parameters"""
        parsed_url = urlparse(url)
        query_params = parsed_url.query

        if not query_params:
            return

        # Patterns that indicate session tokens
        session_patterns = [
            r"session[_-]?(?:id|code|state|token)",
            r"(?:access|auth)[_-]?token",
            r"(?:state|code|nonce)=[\w\-\.]+",
            r"(?:client|tab)[_-]id",
        ]

        for pattern in session_patterns:
            if re.search(pattern, query_params, re.IGNORECASE):
                self.add_vulnerability(
                    "Session Token in URL",
                    "Medium",
                    "Session token or authentication parameter found in URL query string",
                    f"URL contains session-like parameter: {url[:100]}...",
                    "Transmit session tokens in HTTP cookies or POST body, not in URLs. "
                    "URLs may be logged, bookmarked, or leaked via Referer headers.",
                )
                break

    def _check_secrets_in_javascript(self, js_content: str, url: str):
        """Check for hardcoded secrets and credentials in JavaScript"""

        # Comprehensive secret patterns matching Burp's JS Miner
        secret_patterns = [
            # Burp Suite JS Miner compatible patterns
            (r'(?:api[_-]?key|apikey|stripe_public_key_live|stripe_key)[\'":\s]*[\'"]([a-zA-Z0-9\-_]{20,})[\'"]', "API Key"),
            (r'(?:secret|password|pwd|passwd)[\'":\s]*[\'"]([^\s\'"]{8,})[\'"]', "Password/Credential"),
            (r'(?:token|auth[_-]?token|access[_-]?token)[\'":\s]*[\'"]([a-zA-Z0-9\-_.]{20,})[\'"]', "Authentication Token"),
            (r'(?:private[_-]?key|privateKey|PRIVATE[_-]?KEY)[\'":\s]*[\'"](-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----)[\'"]', "Private Key"),
            (r'(?:aws[_-]?access[_-]?key|aws_secret_key)[\'":\s]*[\'"]([A-Za-z0-9/+=]{40})[\'"]', "AWS Secret Key"),
            (r'(?:bearer\s+)([a-zA-Z0-9\-_.]{50,})', "Bearer Token"),
            (r'(?:x-api-key|Authorization:\s*Bearer\s+)([a-zA-Z0-9\-_.]{20,})', "API Key/Token"),
            (r'(?:client[_-]?secret|client_secret)[\'":\s]*[\'"]([a-zA-Z0-9\-_.]{20,})[\'"]', "Client Secret"),
            (r'(?:google[_-]?api[_-]?key)[\'":\s]*[\'"]([AIzaSy0-9A-Za-z\-_]{35})[\'"]', "Google API Key"),
            (r'(?:firebase[_-]?api[_-]?key)[\'":\s]*[\'"]([AIzaSy0-9A-Za-z\-_]{35})[\'"]', "Firebase API Key"),
            (r'(?:jwt|jsonwebtoken)[\'":\s]*[\'"]([a-zA-Z0-9\-_.]{50,})[\'"]', "JWT Token"),
            (r'(?:stripe[_-]?secret[_-]?key)[\'":\s]*[\'"](sk_[a-zA-Z0-9]{24,})[\'"]', "Stripe Secret Key"),
            (r'(?:stripe[_-]?publishable[_-]?key)[\'":\s]*[\'"](pk_[a-zA-Z0-9]{24,})[\'"]', "Stripe Publishable Key"),
            (r'(?:mailchimp[_-]?api[_-]?key)[\'":\s]*[\'"]([a-f0-9]{32}-[a-f0-9]{8})[\'"]', "Mailchimp API Key"),
            (r'(?:github[_-]?token|github[_-]?api[_-]?key)[\'":\s]*[\'"](ghp_[a-zA-Z0-9]{36})[\'"]', "GitHub Token"),
            (r'(?:twilio[_-]?account[_-]?sid|twilio[_-]?auth[_-]?token)[\'":\s]*[\'"]([a-f0-9]{32})[\'"]', "Twilio Credential"),
            (r'(?:slack[_-]?token|slack[_-]?api[_-]?key)[\'":\s]*[\'"](xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{24,})[\'"]', "Slack Token"),
            (r'(?:redis[_-]?url|redis[_-]?connection)[\'":\s]*[\'"](redis://[^\\s\'"]+)[\'"]', "Redis Connection"),
            (r'(?:database[_-]?url|db[_-]?url|postgres[_-]?url)[\'":\s]*[\'"](postgresql://[^\\s\'"]+)[\'"]', "Database URL"),
            (r'(?:mysql[_-]?url|mysql[_-]?connection)[\'":\s]*[\'"](mysql://[^\\s\'"]+)[\'"]', "MySQL Connection"),
            (r'(?:mongodb[_-]?url|mongo[_-]?connection)[\'":\s]*[\'"](mongodb://[^\\s\'"]+)[\'"]', "MongoDB Connection"),
            (r'(?:azure[_-]?storage[_-]?key|azure[_-]?account[_-]?key)[\'":\s]*[\'"]([A-Za-z0-9+/]{40,})[\'"]', "Azure Storage Key"),
            (r'(?:stripe_public_key_live|stripe_key_live)[\'":\s]*[\'"](pk_live_[a-zA-Z0-9]{24,})[\'"]', "Stripe Live Key"),
            (r'(?:twilio[_-]?api[_-]?key)[\'":\s]*[\'"](SK[a-f0-9]{32})[\'"]', "Twilio API Key"),
            (r'(?:sendgrid[_-]?api[_-]?key)[\'":\s]*[\'"](SG\.[a-zA-Z0-9\-_.]{16,}\.[a-zA-Z0-9\-_.]{16,})[\'"]', "SendGrid API Key"),
            (r'(?:mapbox[_-]?access[_-]?token)[\'":\s]*[\'"](pk\.[a-zA-Z0-9\.]{60,})[\'"]', "Mapbox Token"),
            (r'(?:paypal[_-]?client[_-]?id|paypal[_-]?client[_-]?secret)[\'":\s]*[\'"]([a-zA-Z0-9\-_.]{20,})[\'"]', "PayPal Credential"),
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Skip common false positives
                if match.lower() in [
                    "password",
                    "secret",
                    "token",
                    "key",
                    "xxxx",
                    "****",
                    "placeholder",
                ]:
                    continue
                if len(match) > 5:
                    self.add_vulnerability(
                        f"[JS Miner] {secret_type}",
                        "High" if "Key" in secret_type or "Secret" in secret_type else "Medium",
                        f"Hardcoded {secret_type.lower()} found in JavaScript code",
                        f"{secret_type}: {match[:30]}... (found in {url})",
                        f"Remove hardcoded {secret_type.lower()} from client-side code. Use environment variables or secure backend configuration.",
                        confidence="Certain",
                        category="Information Exposure",
                        owasp="A01:2021-Broken Access Control",
                        cwe=["CWE-798"],
                    )

    def _check_cookie_security(self, response: requests.Response):
        """Check for cookie security issues"""

        raw_cookies = []
        for header_name, header_value in response.headers.items():
            if header_name.lower() == "set-cookie":
                raw_cookies.append(header_value)

        for cookie_str in raw_cookies:
            cookie_parts = [p.strip().lower() for p in cookie_str.split(";")]
            cookie_name = cookie_str.split("=")[0] if "=" in cookie_str else "unknown"

            # Check for HttpOnly flag
            if "httponly" not in cookie_parts:
                self.add_vulnerability(
                    "Cookie without HttpOnly flag set",
                    "Low",
                    f"Cookie '{cookie_name}' does not have HttpOnly flag set, making it accessible via JavaScript",
                    f"Cookie: {cookie_name}",
                    "Set HttpOnly flag on all cookies that don't need to be accessed by JavaScript.",
                    confidence="Certain",
                    category="Insecure Configuration",
                    owasp="A05:2021-Security Misconfiguration",
                    cwe=["CWE-1004"],
                )

            # Check for Secure flag on HTTPS
            if "secure" not in cookie_parts:
                self.add_vulnerability(
                    "Cookie without Secure flag set",
                    "Medium",
                    f"Cookie '{cookie_name}' does not have Secure flag set, allowing transmission over HTTP",
                    f"Cookie: {cookie_name}",
                    "Set Secure flag on all cookies to ensure they are only transmitted over HTTPS.",
                    confidence="Certain",
                    category="Insecure Configuration",
                    owasp="A05:2021-Security Misconfiguration",
                    cwe=["CWE-614"],
                )

            # Check for SameSite attribute
            if not any(p.startswith("samesite") for p in cookie_parts):
                self.add_vulnerability(
                    "Cookie without SameSite attribute",
                    "Low",
                    f"Cookie '{cookie_name}' does not have SameSite attribute, making it vulnerable to CSRF",
                    f"Cookie: {cookie_name}",
                    "Set SameSite attribute (Strict or Lax) to prevent CSRF attacks.",
                    confidence="Certain",
                    category="Insecure Configuration",
                    owasp="A01:2021-Broken Access Control",
                    cwe=["CWE-1275"],
                )

    def _check_csp_policy(self, response: requests.Response):
        """Check Content Security Policy for security issues"""

        csp_header = response.headers.get("Content-Security-Policy", "")

        if not csp_header:
            self.add_vulnerability(
                "Missing Content Security Policy",
                "Medium",
                "No Content-Security-Policy header found",
                "CSP header not present",
                "Implement a Content Security Policy to prevent XSS and other injection attacks.",
            )
            return

        # Check for unsafe-inline in script-src
        if "'unsafe-inline'" in csp_header and "script-src" in csp_header:
            self.add_vulnerability(
                "Content Security Policy: allows untrusted script execution",
                "Medium",
                "CSP allows 'unsafe-inline' scripts, which permits inline JavaScript execution",
                f"CSP: {csp_header[:100]}...",
                "Remove 'unsafe-inline' from script-src directive. Use nonces or hashes for inline scripts.",
            )

        # Check for unsafe-inline in style-src
        if "'unsafe-inline'" in csp_header and "style-src" in csp_header:
            self.add_vulnerability(
                "Content Security Policy: allows untrusted style execution",
                "Low",
                "CSP allows 'unsafe-inline' styles, which permits inline CSS",
                f"CSP: {csp_header[:100]}...",
                "Remove 'unsafe-inline' from style-src directive. Use nonces or hashes for inline styles.",
            )

        # Check for missing or permissive form-action
        if "form-action" not in csp_header:
            self.add_vulnerability(
                "Content Security Policy: allows form hijacking",
                "Low",
                "CSP does not restrict form submission targets via form-action directive",
                "No form-action directive found",
                "Add 'form-action' directive to CSP to restrict where forms can be submitted.",
            )

    def _check_clickjacking(self, response: requests.Response):
        """Check for clickjacking protection"""

        x_frame_options = response.headers.get("X-Frame-Options", "")
        csp_header = response.headers.get("Content-Security-Policy", "")

        # Check for frame-ancestors in CSP
        has_frame_ancestors = "frame-ancestors" in csp_header

        if not x_frame_options and not has_frame_ancestors:
            self.add_vulnerability(
                "Frameable response (potential Clickjacking)",
                "Medium",
                "Response can be framed - no X-Frame-Options or CSP frame-ancestors directive",
                "Missing both X-Frame-Options header and CSP frame-ancestors",
                "Add X-Frame-Options: DENY or SAMEORIGIN header.",
            )

    def _check_information_disclosure(
        self, js_content: str, html_content: str, response: requests.Response
    ):
        """Check for information disclosure vulnerabilities"""

        # Check for email addresses
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        emails = re.findall(email_pattern, js_content + html_content)
        if emails:
            unique_emails = list(set(emails))[:5]
            self.add_vulnerability(
                "Email addresses disclosed",
                "Information",
                f"Email addresses found in page content ({len(unique_emails)} unique)",
                f"Examples: {', '.join(unique_emails)}",
                "Consider obscuring or removing email addresses.",
            )

        # Check for SSN
        ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
        ssns = re.findall(ssn_pattern, js_content + html_content)
        if ssns:
            self.add_vulnerability(
                "Social security numbers disclosed",
                "High",
                "Potential Social Security Numbers (SSN) found in content",
                f"Matches found: {len(ssns)}",
                "Remove sensitive identification numbers from client-side code.",
            )

        # Check for Credit Card Numbers
        cc_pattern = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
        ccs = re.findall(cc_pattern, js_content + html_content)
        if ccs:
            self.add_vulnerability(
                "Credit card numbers disclosed",
                "Critical",
                "Potential Credit Card Numbers found in content",
                f"Matches found: {len(ccs)}",
                "Ensure PCI compliance and never expose full credit card numbers.",
            )

    def _check_reflected_input(
        self, url: str, response: requests.Response, html_content: str
    ):
        """Check for reflected input that could lead to XSS"""

        parsed_url = urlparse(url)
        query_params = parsed_url.query

        if not query_params:
            return

        param_values = []
        for param in query_params.split("&"):
            if "=" in param:
                value = param.split("=", 1)[1]
                if len(value) > 3:
                    param_values.append(value)

        for value in param_values:
            from urllib.parse import unquote

            decoded_value = unquote(value)

            if decoded_value in html_content:
                self.add_vulnerability(
                    "Input returned in response (reflected)",
                    "High",
                    "User input from URL parameter is reflected in the response without proper encoding",
                    f"Parameter value reflected: {decoded_value[:30]}...",
                    "Properly encode/escape all user input before including in HTML output.",
                )
                break

    def _check_cacheable_https(self, response: requests.Response, url: str):
        """Check for cacheable HTTPS responses with sensitive data"""

        if not url.startswith("https://"):
            return

        cache_control = response.headers.get("Cache-Control", "").lower()

        is_cacheable = not any(
            directive in cache_control for directive in ["no-cache", "no-store", "private"]
        )

        if is_cacheable:
            content_type = response.headers.get("Content-Type", "").lower()
            if any(ct in content_type for ct in ["html", "json"]):
                self.add_vulnerability(
                    "Cacheable HTTPS response",
                    "Low",
                    "Response may be cached by proxies and browsers, potentially exposing sensitive data",
                    f"URL: {url[:100]}...",
                    "Add 'Cache-Control: no-cache, no-store, must-revalidate' for sensitive responses.",
                )

    def _check_open_redirection(self, js_content: str):
        """Check for potential DOM-based open redirection"""
        redirection_patterns = [
            r"window\.location\.(?:href|assign|replace)\s*=\s*[^;]+location\.search",
            r"window\.open\([^)]+location\.search",
            r"document\.location\.(?:href|assign|replace)\s*=\s*[^;]+location\.search",
        ]

        for pattern in redirection_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                self.add_vulnerability(
                    "Open redirection (DOM-based)",
                    "Medium",
                    "Potential DOM-based open redirection found in JavaScript",
                    f"Pattern match: {pattern}",
                    "Sanitize and validate all user-controlled input before using it in redirection functions.",
                )
                break

    def _check_hsts(self, response: requests.Response):
        """Check for Strict-Transport-Security header"""
        hsts = response.headers.get("Strict-Transport-Security", "")
        if not hsts:
            self.add_vulnerability(
                "Strict transport security not enforced",
                "Low",
                "The application does not enforce HSTS",
                "Missing Strict-Transport-Security header",
                "Implement HSTS header with a sufficient max-age value.",
            )

    def _check_content_type_options(self, response: requests.Response):
        """Check for X-Content-Type-Options header"""
        cto = response.headers.get("X-Content-Type-Options", "")
        if cto.lower() != "nosniff":
            self.add_vulnerability(
                "Content type is not specified or nosniff missing",
                "Low",
                "X-Content-Type-Options header is missing or not set to nosniff",
                f"Current value: {cto or 'Missing'}",
                "Set X-Content-Type-Options: nosniff to prevent MIME sniffing.",
            )

    def _check_vulnerable_dependencies(self, js_content: str):
        """Check for known vulnerable JavaScript dependencies"""
        # Simple version-based check for common libraries
        vulnerable_libs = [
            (r"jQuery\s+v?(1\.[0-9]\.[0-9]|2\.[0-1]\.[0-9])", "jQuery", "CVE-2015-9251"),
            (r"Handlebars\s+v?([0-3]\.[0-9]\.[0-9])", "Handlebars", "Multiple vulnerabilities"),
        ]

        for pattern, name, vuln in vulnerable_libs:
            match = re.search(pattern, js_content, re.IGNORECASE)
            if match:
                self.add_vulnerability(
                    "Vulnerable JavaScript dependency",
                    "Medium",
                    f"Known vulnerable version of {name} detected: {match.group(0)}",
                    f"Vulnerability: {vuln}",
                    f"Update {name} to the latest secure version.",
                )

    def _check_ajax_header_manipulation(self, js_content: str):
        """Check for DOM-based Ajax request header manipulation"""
        patterns = [
            r"\.setRequestHeader\s*\([^,]+,\s*[^)]*location\.search",
            r"\.setRequestHeader\s*\([^,]+,\s*[^)]*window\.location",
        ]

        for pattern in patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                self.add_vulnerability(
                    "Ajax request header manipulation (DOM-based)",
                    "Medium",
                    "Potential Ajax request header manipulation found in JavaScript",
                    f"Pattern match: {pattern}",
                    "Ensure that headers are not set directly from user-controlled input.",
                )
                break

    def _check_linkfinder(self, js_content: str):
        """Extract potential endpoints from JavaScript (Linkfinder-style)"""
        # Simple regex to find path-like strings in JS
        pattern = r"['\"](/[a-zA-Z0-9\-_/]+)['\"]"
        paths = re.findall(pattern, js_content)
        if paths:
            unique_paths = list(set(paths))[:10]
            self.add_vulnerability(
                "Linkfinder Analysed JS files",
                "Information",
                f"Potential endpoints discovered in JavaScript code ({len(set(paths))} total)",
                f"Discovered paths: {', '.join(unique_paths)}",
                "Review discovered endpoints for unauthorized access or information disclosure.",
            )

    def _check_robots_txt(self, url: str):
        """Check for robots.txt file and its contents"""
        try:
            parsed_url = urlparse(url)
            robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
            resp = self.session.get(robots_url, timeout=5)
            if resp.status_code == 200:
                self.add_vulnerability(
                    "Robots.txt file",
                    "Information",
                    "Robots.txt file found",
                    resp.text[:200],
                    "Review robots.txt to ensure no sensitive paths are exposed to crawlers.",
                )
        except Exception:
            pass


class BubbleAnalyzer(BaseAnalyzer):
    """Specialized analyzer for Bubble.io applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.api_endpoints = []
        self.workflow_patterns = []
        self.database_schemas = []
        self.privacy_rules = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive Bubble.io security analysis"""

        # Extract JavaScript content for analysis
        js_content = self._extract_javascript(soup)
        html_content = str(soup)

        # Analyze API endpoints
        self._analyze_api_endpoints(js_content)

        # Check for workflow exposure
        self._analyze_workflows(js_content)

        # Check for database schema exposure
        self._analyze_database_exposure(js_content)

        # Check for privacy rules implementation
        self._analyze_privacy_rules(js_content)

        # Check for authentication vulnerabilities
        self._analyze_authentication(url, response, soup)

        # Check for client-side data exposure
        self._analyze_client_side_data(js_content)

        # Analyze form security
        self._analyze_forms(soup)

        # Perform generic security checks (newly added)
        self._check_session_tokens_in_url(url)
        self._check_secrets_in_javascript(js_content, url)
        self._check_cookie_security(response)
        self._check_csp_policy(response)
        self._check_clickjacking(response)
        self._check_information_disclosure(js_content, html_content, response)
        self._check_reflected_input(url, response, html_content)
        self._check_cacheable_https(response, url)
        self._check_base64_data(url, html_content)
        self._check_path_relative_stylesheets(soup)
        
        # Enhanced Bubble-specific vulnerability checks
        self._check_bubble_vulnerabilities(js_content, url, response, soup)
        
        # Burp Suite compatible enhanced checks
        self._check_strict_transport_security(response)
        self._check_detailed_error_messages(response, html_content)
        self._check_secret_input_headers(url, response)
        self._check_private_ip_disclosure(html_content)
        self._check_tls_certificate_issues(url)

        return {
            "api_endpoints": self.api_endpoints,
            "workflow_patterns": self.workflow_patterns,
            "database_schemas": self.database_schemas,
            "privacy_rules": self.privacy_rules,
            "vulnerabilities": self.vulnerabilities,
            "bubble_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract all JavaScript content from the page"""
        js_content = ""

        # Extract inline scripts
        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        # Extract external scripts (attempt to fetch)
        for script in soup.find_all("script", src=True):
            try:
                script_url = urljoin(soup.base.get("href", ""), script["src"])
                script_response = self.session.get(script_url, timeout=5)
                if script_response.status_code == 200:
                    js_content += script_response.text + "\n"
            except Exception:
                pass  # Skip if unable to fetch external script

        return js_content

    def _check_bubble_vulnerabilities(self, js_content: str, url: str, response: requests.Response, soup: BeautifulSoup):
        """Enhanced Bubble-specific vulnerability checks matching Burp Suite findings"""
        
        # Check for Social Security Numbers
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        ssn_matches = re.findall(ssn_pattern, js_content)
        if ssn_matches:
            self.add_vulnerability(
                "Social security numbers disclosed",
                "Critical",
                "Social Security Numbers found in client-side code",
                f"SSNs found: {len(ssn_matches)} instances",
                "Remove SSNs from client-side code immediately. This is a severe privacy violation.",
                confidence="Certain",
                category="Information Disclosure",
                owasp="A01:2021 – Broken Access Control",
                cwe=["CWE-359"]
            )
        
        # Check for Credit Card Numbers
        cc_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'
        cc_matches = re.findall(cc_pattern, js_content)
        if cc_matches:
            self.add_vulnerability(
                "Credit card numbers disclosed",
                "Critical",
                "Credit Card Numbers found in client-side code",
                f"CC numbers found: {len(cc_matches)} instances",
                "Remove credit card numbers from client-side code immediately. This violates PCI DSS compliance.",
                confidence="Certain",
                category="Information Disclosure",
                owasp="A01:2021 – Broken Access Control",
                cwe=["CWE-359"]
            )
        
        # Check for open redirection patterns
        redirect_patterns = [
            r'window\.location\s*=\s*["\']?[\+\s]*["\']?[^"\']*["\']?',
            r'document\.location\s*=\s*["\']?[^"\']*["\']?',
            r'location\.href\s*=\s*["\']?[^"\']*["\']?',
            r'location\.replace\(\s*["\']?[^"\']*["\']?\)',
        ]
        
        for pattern in redirect_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Check if redirect target contains user input or external domains
                if any(unsafe in match.lower() for unsafe in ['http', 'window', 'document', 'user', 'input', 'getparam']):
                    self.add_vulnerability(
                        "Open redirection (DOM-based)",
                        "Medium",
                        "Potential open redirection vulnerability in client-side JavaScript",
                        match[:100] + "..." if len(match) > 100 else match,
                        "Validate and sanitize all redirect targets. Use whitelist of allowed destinations.",
                        confidence="Firm",
                        category="DOM-based",
                        owasp="A01:2021 – Broken Access Control",
                        cwe=["CWE-601"]
                    )
        
        # Check for AJAX header manipulation
        ajax_patterns = [
            r'XMLHttpRequest.*setRequestHeader',
            r'fetch.*headers.*=',
            r'\.setRequestHeader.*["\']Authorization["\']',
            r'\.setRequestHeader.*["\']Cookie["\']',
        ]
        
        for pattern in ajax_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                self.add_vulnerability(
                    "Ajax request header manipulation (DOM-based)",
                    "Low",
                    "AJAX requests that manipulate headers detected",
                    pattern,
                    "Ensure proper validation of header manipulation to prevent request forgery attacks.",
                    confidence="Firm",
                    category="DOM-based",
                    owasp="A01:2021 – Broken Access Control",
                    cwe=["CWE-116"]
                )
        
        # Check for vulnerable JavaScript dependencies
        vuln_libs = [
            r'jquery[\s-]?([0-3]\.[0-9]+\.[0-9]+)',  # Old jQuery versions
            r'angularjs?[\s-]?([12]\.[0-9]+\.[0-9]+)',  # Old Angular versions
            r'bootstrap[\s-]?([3-4]\.[0-9]+\.[0-9]+)',  # Old Bootstrap versions
        ]
        
        for pattern in vuln_libs:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                version = match[0] if isinstance(match, tuple) else match
                self.add_vulnerability(
                    "Vulnerable JavaScript dependency",
                    "High",
                    f"Potentially vulnerable JavaScript library detected: {pattern.split('[')[0]} version {version}",
                    f"Library: {pattern.split('[')[0]}, Version: {version}",
                    "Update to the latest secure version of the library.",
                    confidence="Firm",
                    category="Third-party Risk",
                    owasp="A06:2021 – Vulnerable and Outdated Components",
                    cwe=["CWE-1104"]
                )

    def _analyze_api_endpoints(self, js_content: str):
        """Analyze Bubble API endpoints for security issues"""

        # Bubble API patterns
        api_patterns = [
            r'api/1\.1/wf/([^"\']+)',  # Workflow APIs
            r'api/1\.1/obj/([^"\']+)',  # Object APIs
            r'version-test/api/([^"\']+)',  # Version test APIs
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                endpoint = f"api/{match}"
                self.api_endpoints.append(endpoint)

                # Check if endpoint is exposed without authentication
                if self._check_unauthenticated_access(endpoint):
                    self.add_vulnerability(
                        "Bubble API Exposure",
                        "High",
                        f"Unauthenticated access to API endpoint: {endpoint}",
                        endpoint,
                        "Implement proper authentication and privacy rules",
                    )

    def _analyze_workflows(self, js_content: str):
        """Analyze Bubble workflows for security vulnerabilities"""

        workflow_patterns = [
            r"workflow_([a-zA-Z0-9_]+)",
            r'Workflow\s*:\s*"([^"]+)"',
            r'run_workflow\([^)]*"([^"]+)"',
        ]

        for pattern in workflow_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.workflow_patterns.append(match)

                # Check for sensitive workflow names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["admin", "delete", "payment", "auth", "login"]
                ):
                    self.add_vulnerability(
                        "Sensitive Workflow Exposure",
                        "High",
                        f"Potentially sensitive workflow exposed: {match}",
                        match,
                        "Review workflow privacy settings and access controls",
                    )

    def _analyze_database_exposure(self, js_content: str):
        """Check for database schema and data exposure"""

        # Look for Thing definitions (Bubble's data structure)
        thing_patterns = [
            r"Thing\s*:\s*{([^}]+)}",
            r"_thing\s*=\s*{([^}]+)}",
            r"database_schema\s*[=:]\s*{([^}]+)}",
        ]

        for pattern in thing_patterns:
            matches = re.findall(pattern, js_content, re.MULTILINE | re.DOTALL)
            for match in matches:
                self.database_schemas.append(match)

                # Check for sensitive field exposure
                if any(
                    field in match.lower()
                    for field in ["password", "ssn", "credit_card", "api_key", "token"]
                ):
                    self.add_vulnerability(
                        "Sensitive Data Schema Exposure",
                        "Critical",
                        "Database schema with sensitive fields exposed in client code",
                        match[:200] + "..." if len(match) > 200 else match,
                        "Remove sensitive field definitions from client-side code",
                    )

    def _analyze_privacy_rules(self, js_content: str):
        """Analyze privacy rules implementation"""

        privacy_patterns = [
            r"privacy_rules?\s*[=:]\s*([^;]+)",
            r"can_view\s*[=:]\s*([^;]+)",
            r"can_edit\s*[=:]\s*([^;]+)",
        ]

        privacy_rule_count = 0
        for pattern in privacy_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            privacy_rule_count += len(matches)
            self.privacy_rules.extend(matches)

        if privacy_rule_count == 0:
            self.add_vulnerability(
                "Missing Privacy Rules",
                "High",
                "No privacy rules detected in client-side code",
                "No privacy rule patterns found",
                "Implement comprehensive privacy rules for data protection",
            )

    def _analyze_authentication(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ):
        """Analyze authentication mechanisms"""

        # Check for authentication tokens in JavaScript
        js_content = self._extract_javascript(soup)

        token_patterns = [
            r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'auth["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'session["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in token_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 10:  # Likely a real token
                    self.add_vulnerability(
                        "Authentication Token Exposure",
                        "Critical",
                        "Authentication token exposed in client-side code",
                        f"Token: {match[:10]}...",
                        "Store authentication tokens securely, not in client-side code",
                    )

    def _analyze_client_side_data(self, js_content: str):
        """Analyze client-side data exposure"""

        # Look for hardcoded sensitive data
        sensitive_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)', "API Key"),
            (r'secret["\']?\s*[:=]\s*["\']([^"\']+)', "Secret"),
            (r'password["\']?\s*[:=]\s*["\']([^"\']+)', "Password"),
            (r'private[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)', "Private Key"),
        ]

        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:  # Skip obviously fake/placeholder values
                    self.add_vulnerability(
                        f"{data_type} Exposure",
                        "Critical",
                        f"{data_type} found in client-side code",
                        f"{data_type}: {match[:10]}...",
                        f"Remove {data_type.lower()} from client-side code and use server-side handling",
                    )

    def _analyze_forms(self, soup: BeautifulSoup):
        """Analyze forms for security issues"""

        forms = soup.find_all("form")
        for form in forms:
            form_action = form.get("action", "")
            form_method = form.get("method", "GET").upper()

            # Check for CSRF protection
            csrf_token = form.find("input", {"name": re.compile(r"csrf|_token", re.I)})
            if not csrf_token and form_method == "POST":
                self.add_vulnerability(
                    "Missing CSRF Protection",
                    "Medium",
                    f"Form without CSRF protection: {form_action}",
                    f"Form action: {form_action}",
                    "Implement CSRF tokens for all forms",
                )

            # Check for password fields without proper attributes
            password_fields = form.find_all("input", {"type": "password"})
            for pwd_field in password_fields:
                if not pwd_field.get("autocomplete"):
                    self.add_vulnerability(
                        "Missing Password Field Security",
                        "Low",
                        "Password field without autocomplete attribute",
                        f"Field name: {pwd_field.get('name', 'unnamed')}",
                        "Add appropriate autocomplete attributes to password fields",
                    )

    def _check_unauthenticated_access(self, endpoint: str) -> bool:
        """Check if an API endpoint allows unauthenticated access"""
        try:
            # Attempt to access the endpoint without authentication
            test_response = self.session.get(endpoint, timeout=5)
            # If we get a 200 response, it might be accessible without auth
            return test_response.status_code == 200
        except Exception:
            return False


class OutSystemsAnalyzer(BaseAnalyzer):
    """Specialized analyzer for OutSystems applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.rest_apis = []
        self.screen_actions = []
        self.entities = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive OutSystems security analysis"""

        js_content = self._extract_javascript(soup)
        html_content = str(soup)

        # Analyze REST APIs
        self._analyze_rest_apis(js_content)

        # Analyze screen actions
        self._analyze_screen_actions(js_content)

        # Check for entity exposure
        self._analyze_entities(js_content)

        # Check session management
        self._analyze_session_management(js_content)

        # Analyze role-based access
        self._analyze_roles(js_content)

        # Check for session tokens in URL
        self._check_session_tokens_in_url(url)

        # Check for secrets in JavaScript
        self._check_secrets_in_javascript(js_content, url)

        # Check cookie security
        self._check_cookie_security(response)

        # Check Content Security Policy
        self._check_csp_policy(response)

        # Check for clickjacking vulnerabilities
        self._check_clickjacking(response)

        # Check for information disclosure
        self._check_information_disclosure(js_content, html_content, response)

        # Check for reflected input (XSS)
        self._check_reflected_input(url, response, html_content)

        # Check for path-relative stylesheet import
        self._check_path_relative_stylesheets(soup)

        # Check for cacheable HTTPS responses
        self._check_cacheable_https(response, url)

        # Check for Base64 encoded data
        self._check_base64_data(url, html_content)

        # Enhanced vulnerability checks for Burp Suite compatibility
        self._check_strict_transport_security(response)
        self._check_detailed_error_messages(response, html_content)
        self._check_secret_input_headers(url, response)
        self._check_private_ip_disclosure(html_content)
        self._check_tls_certificate_issues(url)

        return {
            "rest_apis": self.rest_apis,
            "screen_actions": self.screen_actions,
            "entities": self.entities,
            "vulnerabilities": self.vulnerabilities,
            "outsystems_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content for analysis"""
        js_content = ""

        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        return js_content

    def _analyze_rest_apis(self, js_content: str):
        """Analyze OutSystems REST API exposure"""

        rest_patterns = [
            r'/rest/([^"\'?\s]+)',
            r'RestService_([^"\'?\s]+)',
            r'CallRestAPI\([^)]*["\']([^"\']+)["\']',
        ]

        for pattern in rest_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.rest_apis.append(match)

                # Check for sensitive API names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["admin", "internal", "private", "secret"]
                ):
                    self.add_vulnerability(
                        "Sensitive REST API Exposure",
                        "High",
                        f"Potentially sensitive REST API exposed: {match}",
                        match,
                        "Review API permissions and authentication requirements",
                    )

    def _analyze_screen_actions(self, js_content: str):
        """Analyze OutSystems screen actions"""

        action_patterns = [
            r'ScreenAction_([^"\'()\s]+)',
            r'OnClick["\']?\s*[:=]\s*["\']?([^"\';\s]+)',
            r'ServerAction_([^"\'()\s]+)',
        ]

        for pattern in action_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.screen_actions.append(match)

                # Check for privileged actions
                if any(
                    priv in match.lower()
                    for priv in ["delete", "admin", "elevate", "privilege"]
                ):
                    self.add_vulnerability(
                        "Privileged Action Exposure",
                        "Medium",
                        f"Privileged screen action found: {match}",
                        match,
                        "Ensure proper authorization checks for privileged actions",
                    )

    def _analyze_entities(self, js_content: str):
        """Check for OutSystems entity exposure"""

        entity_patterns = [
            r'Entity["\']?\s*[:=]\s*["\']([^"\']+)',
            r'GetEntity\([^)]*["\']([^"\']+)',
            r"entity_([a-zA-Z0-9_]+)",
        ]

        for pattern in entity_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                self.entities.append(match)

                # Check for sensitive entity names
                if any(
                    sensitive in match.lower()
                    for sensitive in ["user", "account", "payment", "personal"]
                ):
                    self.add_vulnerability(
                        "Sensitive Entity Exposure",
                        "Medium",
                        f"Sensitive entity structure exposed: {match}",
                        match,
                        "Review entity permissions and data access rules",
                    )

    def _analyze_session_management(self, js_content: str):
        """Analyze session management implementation"""

        session_patterns = [
            r'session[_-]?id["\']?\s*[:=]\s*["\']([^"\']+)',
            r"GetUserId\(\)",
            r'session["\']?\s*[:=]\s*["\']([^"\']+)',
        ]

        session_found = False
        for pattern in session_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                session_found = True
                break

        if not session_found:
            self.add_vulnerability(
                "Session Management Issues",
                "Medium",
                "No clear session management implementation found",
                "No session patterns detected",
                "Implement secure session management with proper timeout and validation",
            )

    def _analyze_roles(self, js_content: str):
        """Analyze role-based access control"""

        role_patterns = [
            r'CheckRole\([^)]*["\']([^"\']+)',
            r'UserHasRole\([^)]*["\']([^"\']+)',
            r'role["\']?\s*[:=]\s*["\']([^"\']+)',
        ]

        roles_found = 0
        for pattern in role_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            roles_found += len(matches)

        if roles_found == 0:
            self.add_vulnerability(
                "Missing Role-Based Access Control",
                "High",
                "No role-based access control implementation detected",
                "No RBAC patterns found",
                "Implement proper role-based access control for sensitive operations",
            )

class AirtableAnalyzer(BaseAnalyzer):
    """Specialized analyzer for Airtable applications"""

    def __init__(self, session: requests.Session):
        super().__init__(session)
        self.base_ids = []
        self.api_keys = []
        self.table_ids = []

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Comprehensive Airtable security analysis"""

        js_content = self._extract_javascript(soup)
        html_content = str(soup)

        # Analyze base ID exposure
        self._analyze_base_ids(js_content + html_content)

        # Check for API key exposure
        self._analyze_api_keys(js_content + html_content)

        # Analyze table structure exposure
        self._analyze_tables(js_content + html_content)

        # Check permissions and sharing settings
        self._analyze_permissions(js_content)

        return {
            "base_ids": self.base_ids,
            "api_keys": self.api_keys,
            "table_ids": self.table_ids,
            "vulnerabilities": self.vulnerabilities,
            "airtable_specific_findings": self.findings,
        }

    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content for analysis"""
        js_content = ""

        for script in soup.find_all("script"):
            if script.string:
                js_content += script.string + "\n"

        return js_content

    def _analyze_base_ids(self, content: str):
        """Check for Airtable base ID exposure"""

        # Airtable base IDs follow pattern: app[14 characters]
        base_pattern = r"app[A-Za-z0-9]{14}"
        matches = re.findall(base_pattern, content)

        for match in matches:
            if match not in self.base_ids:
                self.base_ids.append(match)

                self.add_vulnerability(
                    "Airtable Base ID Exposure",
                    "Medium",
                    f"Airtable base ID exposed in client code: {match}",
                    match,
                    "Avoid exposing base IDs in client-side code; use server-side proxies",
                )

    def _analyze_api_keys(self, content: str):
        """Check for Airtable API key exposure"""

        # Airtable API keys follow pattern: key[14 characters]
        key_pattern = r"key[A-Za-z0-9]{14}"
        matches = re.findall(key_pattern, content)

        for match in matches:
            if match not in self.api_keys:
                self.api_keys.append(match)

                self.add_vulnerability(
                    "Airtable API Key Exposure",
                    "Critical",
                    f"Airtable API key exposed in client code: {match}",
                    f"API Key: {match}",
                    "Never expose API keys in client-side code; use server-side authentication",
                )

    def _analyze_tables(self, content: str):
        """Analyze table structure exposure"""

        # Airtable table IDs follow pattern: tbl[14 characters]
        table_pattern = r"tbl[A-Za-z0-9]{14}"
        matches = re.findall(table_pattern, content)

        for match in matches:
            if match not in self.table_ids:
                self.table_ids.append(match)

        # Check for table schema information
        schema_patterns = [
            r"fields?\s*[:=]\s*\[[^\]]+\]",
            r"column[s]?\s*[:=]\s*\[[^\]]+\]",
            r"schema\s*[:=]\s*{[^}]+}",
        ]

        for pattern in schema_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                self.add_vulnerability(
                    "Table Schema Exposure",
                    "Low",
                    "Table schema information exposed in client code",
                    f"Schema patterns found: {len(matches)}",
                    "Minimize schema information exposure in client-side code",
                )
                break

    def _analyze_permissions(self, js_content: str):
        """Analyze Airtable permissions and access controls"""

        permission_patterns = [
            r'permission[s]?\s*[:=]\s*["\']([^"\']+)',
            r'access[_-]?level\s*[:=]\s*["\']([^"\']+)',
            r'share[d]?\s*[:=]\s*["\']([^"\']+)',
        ]

        permissions_found = False
        for pattern in permission_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                permissions_found = True
                # Check for overly permissive settings
                for match in matches:
                    if any(
                        perm in match.lower() for perm in ["public", "anyone", "edit"]
                    ):
                        self.add_vulnerability(
                            "Permissive Access Control",
                            "Medium",
                            f"Potentially permissive access setting: {match}",
                            match,
                            "Review and restrict access permissions as needed",
                        )

        if not permissions_found:
            self.add_vulnerability(
                "Unknown Permission Model",
                "Low",
                "Could not determine permission/access control implementation",
                "No permission patterns detected",
                "Ensure proper access controls are implemented and documented",
            )


class GenericWebAnalyzer(BaseAnalyzer):
    """Generic web application security analyzer"""

    def __init__(self, session: requests.Session):
        super().__init__(session)

    def analyze(
        self, url: str, response: requests.Response, soup: BeautifulSoup
    ) -> Dict[str, Any]:
        """Generic web application security analysis"""

        # Analyze forms for common issues
        self._analyze_forms(soup)

        # Check for common vulnerabilities
        self._analyze_common_vulns(response, soup)

        # Analyze JavaScript for sensitive data
        self._analyze_javascript_security(soup)

        # Check external resources
        self._analyze_external_resources(soup, url)

        return {
            "vulnerabilities": self.vulnerabilities,
            "generic_findings": self.findings,
        }

    def _analyze_forms(self, soup: BeautifulSoup):
        """Analyze forms for security issues"""

        forms = soup.find_all("form")
        for form in forms:
            method = form.get("method", "GET").upper()
            action = form.get("action", "")

            # Check for password fields sent over GET
            if method == "GET":
                password_fields = form.find_all("input", {"type": "password"})
                if password_fields:
                    self.add_vulnerability(
                        "Password Field in GET Form",
                        "High",
                        "Password field found in form using GET method",
                        f"Form action: {action}",
                        "Use POST method for forms containing sensitive data",
                    )

            # Check for forms without CSRF protection
            csrf_field = form.find("input", {"name": re.compile(r"csrf|_token", re.I)})
            if not csrf_field and method == "POST":
                self.add_vulnerability(
                    "Missing CSRF Protection",
                    "Medium",
                    f"POST form without CSRF token: {action}",
                    f"Form action: {action}",
                    "Implement CSRF protection for all state-changing forms",
                )

    def _analyze_common_vulns(self, response: requests.Response, soup: BeautifulSoup):
        """Check for common web vulnerabilities"""

        content = response.text.lower()

        # Check for potential XSS vulnerabilities
        xss_indicators = [
            r"<script[^>]*>.*?document\.write.*?</script>",
            r"<script[^>]*>.*?innerHTML.*?</script>",
            r"eval\s*\([^)]*\)",
            r'setTimeout\s*\([^)]*[\'"][^\'"]*[\'"]\s*[^)]*\)',
        ]

        for pattern in xss_indicators:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                self.add_vulnerability(
                    "Potential XSS Vulnerability",
                    "High",
                    "Code patterns that might be vulnerable to XSS found",
                    "Dynamic content manipulation detected",
                    "Validate and sanitize all user inputs and use safe DOM manipulation",
                )
                break

        # Check for SQL injection indicators
        sql_indicators = [
            r'sql\s*=\s*[\'"][^\'"]*\+',
            r'query\s*=\s*[\'"][^\'"]*\+',
            r'select\s+[*\w]+\s+from\s+\w+\s+where\s+[^\'"]*\+',
        ]

        for pattern in sql_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                self.add_vulnerability(
                    "Potential SQL Injection",
                    "Critical",
                    "Code patterns suggesting SQL injection vulnerability",
                    "Dynamic SQL construction detected",
                    "Use parameterized queries and input validation",
                )
                break

    def _analyze_javascript_security(self, soup: BeautifulSoup):
        """Analyze JavaScript for security issues"""

        scripts = soup.find_all("script")
        for script in scripts:
            if script.string:
                content = script.string

                # Check for hardcoded secrets
                secret_patterns = [
                    (r'password\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "Password"),
                    (r'secret\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "Secret"),
                    (r'token\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "Token"),
                    (r'api[_-]?key\s*[=:]\s*[\'"]([^\'"]+)[\'"]', "API Key"),
                ]

                for pattern, secret_type in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if len(match) > 5:  # Skip short/placeholder values
                            self.add_vulnerability(
                                f"Hardcoded {secret_type}",
                                "Critical",
                                f"{secret_type} hardcoded in JavaScript",
                                f"{secret_type}: {match[:10]}...",
                                f"Remove {secret_type.lower()} from client-side code",
                            )

    def _analyze_external_resources(self, soup: BeautifulSoup, base_url: str):
        """Analyze external resources for security issues"""

        parsed_base = urlparse(base_url)
        base_scheme = parsed_base.scheme

        # Check for mixed content
        if base_scheme == "https":
            http_resources = soup.find_all(
                ["img", "script", "link", "iframe"], src=re.compile(r"^http://", re.I)
            )

            if http_resources:
                self.add_vulnerability(
                    "Mixed Content",
                    "Medium",
                    f"Found {len(http_resources)} HTTP resources on HTTPS page",
                    f"{len(http_resources)} insecure resources",
                    "Serve all resources over HTTPS to prevent mixed content issues",
                )

        # Check for external JavaScript from untrusted domains
        external_scripts = soup.find_all("script", src=True)
        untrusted_domains = []

        for script in external_scripts:
            src = script.get("src", "")
            parsed_src = urlparse(src)

            if parsed_src.netloc and parsed_src.netloc != parsed_base.netloc:
                # Check against known CDN domains (simplified check)
                trusted_domains = [
                    "cdnjs.cloudflare.com",
                    "ajax.googleapis.com",
                    "code.jquery.com",
                    "unpkg.com",
                    "jsdelivr.net",
                ]

                if not any(trusted in parsed_src.netloc for trusted in trusted_domains):
                    untrusted_domains.append(parsed_src.netloc)

        if untrusted_domains:
            self.add_vulnerability(
                "External JavaScript from Untrusted Sources",
                "Medium",
                f"External scripts loaded from potentially untrusted domains: {', '.join(set(untrusted_domains))}",
                f"Domains: {', '.join(set(untrusted_domains))}",
                "Review external script sources and implement Content Security Policy",
            )


class SecurityReportGenerator:
    """Generate comprehensive security reports"""

    def __init__(self):
        self.vulnerability_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}

    def calculate_security_score(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Tuple[int, Dict[str, int]]:
        """Calculate overall security score based on vulnerabilities"""
        score = 100
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            severity_counts[severity] += 1
            score -= self.vulnerability_weights.get(severity, 1)

        return max(0, score), severity_counts

    def _check_strict_transport_security(self, response: requests.Response):
        """Check for Strict Transport Security implementation"""
        hsts_header = response.headers.get("Strict-Transport-Security", "")
        if not hsts_header:
            self.add_vulnerability(
                "Strict transport security not enforced",
                "Low",
                "HTTP Strict Transport Security (HSTS) is not enabled on this server",
                "HSTS header not present",
                "Implement HSTS to prevent SSL stripping attacks. Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
                confidence="Certain",
                category="Transport Security",
                owasp="A02:2021 – Cryptographic Failures",
                cwe=["CWE-319", "CWE-523"]
            )

    def _check_detailed_error_messages(self, response: requests.Response, html_content: str):
        """Check for detailed error messages that could leak information"""
        error_patterns = [
            r"exception in|exception caught|stack trace|at\s+\w+\.\w+\(",
            r"sql\s+exception|database\s+error|ora-\d+|mysql_error",
            r"error\s+in|warning\s+in|fatal\s+error|php\s+error",
            r"null\s+pointer|array\s+index|out\s+of\s+bounds",
            r"system\.out\.print|console\.error|debug\s+trace",
            r"debug\s+information|debug\s+mode|development\s+error",
            r"internal\s+server\s+error\s+500|bad\s+gateway\s+502|service\s+unavailable\s+503",
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                self.add_vulnerability(
                    "Detailed Error Messages Revealed",
                    "Medium",
                    "Application reveals detailed error information that could aid attackers",
                    f"Found {len(matches)} error message(s)",
                    "Configure generic error pages and log detailed errors server-side only.",
                    confidence="Firm",
                    category="Information Disclosure",
                    owasp="A01:2021 – Broken Access Control",
                    cwe=["CWE-200", "CWE-209"]
                )
                break

    def _check_path_relative_stylesheets(self, soup: BeautifulSoup):
        """Check for path-relative stylesheet imports"""
        link_elements = soup.find_all("link", {"rel": "stylesheet"})
        for link in link_elements:
            href = link.get("href", "")
            if href and not href.startswith(("http://", "https://", "//", "/", "data:")):
                # Path-relative import
                self.add_vulnerability(
                    "Path-relative style sheet import",
                    "Low",
                    "Stylesheet is imported using a path-relative URL, which can be vulnerable to path traversal",
                    f"Relative stylesheet path: {href}",
                    "Use absolute paths or ensure proper path validation to prevent traversal attacks.",
                    confidence="Firm",
                    category="Insecure Configuration",
                    owasp="A01:2021 – Broken Access Control",
                    cwe=["CWE-22"]
                )

    def _check_secret_input_headers(self, url: str, response: requests.Response):
        """Check for potential secret input via headers"""
        headers_to_check = [
            "X-Forwarded-Host",
            "X-Original-URL", 
            "X-Rewrite-URL",
            "X-Originating-IP",
            "X-Real-IP",
            "X-Client-IP"
        ]
        
        found_secrets = []
        for header in headers_to_check:
            value = response.headers.get(header, "")
            if value and any(char in value.lower() for char in ["@", ":", "/", "\\"]):
                # Potential command injection or SSRF
                if any(pattern in value.lower() for pattern in ["localhost", "127.0.0.1", "169.254", "10.", "192.168", "172."]):
                    found_secrets.append(f"{header}: {value}")
        
        if found_secrets:
            self.add_vulnerability(
                "Secret input: header",
                "Medium",
                "Potentially exploitable header input detected",
                f"Headers: {', '.join(found_secrets)}",
                "Validate and sanitize all header inputs to prevent injection attacks.",
                confidence="Firm",
                category="Input Validation",
                owasp="A03:2021 – Injection",
                cwe=["CWE-94", "CWE-20"]
            )

    def _check_private_ip_disclosure(self, content: str):
        """Check for private IP addresses disclosure"""
        private_ip_patterns = [
            r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # Loopback
            r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",      # Private A
            r"\b192\.168\.\d{1,3}\.\d{1,3}\b",          # Private C
            r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",  # Private B
            r"\b169\.254\.\d{1,3}\.\d{1,3}\b",          # Link-local
        ]
        
        found_ips = []
        for pattern in private_ip_patterns:
            matches = re.findall(pattern, content)
            found_ips.extend(matches)
        
        if found_ips:
            unique_ips = list(set(found_ips))[:5]  # Limit to 5 unique IPs
            self.add_vulnerability(
                "Private IP addresses disclosed",
                "Low",
                "Private/internal IP addresses are disclosed in the response",
                f"IPs found: {', '.join(unique_ips)}",
                "Remove internal IP addresses from responses to prevent network reconnaissance.",
                confidence="Certain",
                category="Information Disclosure",
                owasp="A01:2021 – Broken Access Control",
                cwe=["CWE-200"]
            )

    def _check_tls_certificate_issues(self, url: str):
        """Check for TLS certificate problems"""
        try:
            import ssl
            import socket
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return
                
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    if not cert:
                        self.add_vulnerability(
                            "TLS certificate",
                            "Medium",
                            "Server's TLS certificate could not be validated",
                            "Certificate validation failed",
                            "Install a valid TLS certificate from a trusted CA.",
                            confidence="Certain",
                            category="Transport Security",
                            owasp="A02:2021 – Cryptographic Failures",
                            cwe=["CWE-295", "CWE-326"]
                        )
                        
                    # Check expiration
                    if cert:
                        import datetime
                        expiry = cert.get('notAfter')
                        if expiry:
                            try:
                                exp_date = datetime.datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                                if exp_date < datetime.datetime.now():
                                    self.add_vulnerability(
                                        "TLS certificate expired",
                                        "Medium",
                                        "TLS certificate has expired",
                                        f"Expired on: {expiry}",
                                        "Renew the TLS certificate immediately.",
                                        confidence="Certain",
                                        category="Transport Security",
                                        owasp="A02:2021 – Cryptographic Failures",
                                        cwe=["CWE-295"]
                                    )
                            except:
                                pass  # Date parsing failed, skip
        except:
            pass  # SSL check failed, skip

    def generate_executive_summary(
        self, analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive summary of security findings"""
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        score, severity_counts = self.calculate_security_score(vulnerabilities)

        total_vulns = sum(severity_counts.values())
        risk_level = "Low"

        if severity_counts["Critical"] > 0:
            risk_level = "Critical"
        elif severity_counts["High"] > 0:
            risk_level = "High"
        elif severity_counts["Medium"] > 2:
            risk_level = "Medium"

        return {
            "security_score": score,
            "risk_level": risk_level,
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "platform_type": analysis_results.get("platform_type", "Unknown"),
            "scan_timestamp": analysis_results.get("timestamp", "Unknown"),
        }

    def generate_recommendations_matrix(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on vulnerabilities"""
        recommendations = []

        # Group vulnerabilities by type
        vuln_groups = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(vuln)

        # Generate recommendations for each group
        for vuln_type, vulns in vuln_groups.items():
            highest_severity = max(
                vulns,
                key=lambda x: self.vulnerability_weights.get(
                    x.get("severity", "Low"), 1
                ),
            )

            recommendation = {
                "category": vuln_type,
                "priority": highest_severity.get("severity", "Low"),
                "count": len(vulns),
                "description": highest_severity.get(
                    "recommendation", "Review and remediate this vulnerability"
                ),
                "effort_estimate": self._estimate_effort(vuln_type, len(vulns)),
                "impact": self._assess_impact(highest_severity.get("severity", "Low")),
            }
            recommendations.append(recommendation)

        # Sort by priority (Critical > High > Medium > Low)
        priority_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        recommendations.sort(
            key=lambda x: priority_order.get(x["priority"], 0), reverse=True
        )

        return recommendations

    def _estimate_effort(self, vuln_type: str, count: int) -> str:
        """Estimate remediation effort"""
        base_efforts = {
            "API Key Exposure": "High",
            "SQL Injection": "High",
            "XSS": "Medium",
            "Missing CSRF Protection": "Medium",
            "Security Headers": "Low",
            "SSL/TLS Issues": "Medium",
        }

        base_effort = base_efforts.get(vuln_type, "Medium")

        # Adjust based on count
        if count > 5:
            if base_effort == "Low":
                return "Medium"
            elif base_effort == "Medium":
                return "High"

        return base_effort

    def _assess_impact(self, severity: str) -> str:
        """Assess business impact of vulnerability"""
        impact_mapping = {
            "Critical": "Severe - Immediate data breach risk",
            "High": "High - Significant security risk",
            "Medium": "Medium - Moderate security concern",
            "Low": "Low - Minor security improvement",
        }
        return impact_mapping.get(severity, "Unknown impact")


def get_analyzer_for_platform(
    platform_type: str, session: requests.Session
) -> BaseAnalyzer:
    """Factory function to get appropriate analyzer for platform"""
    analyzers = {
        "bubble": BubbleAnalyzer,
        "outsystems": OutSystemsAnalyzer,
        "airtable": AirtableAnalyzer,
        "unknown": GenericWebAnalyzer,
    }

    analyzer_class = analyzers.get(platform_type.lower(), GenericWebAnalyzer)
    return analyzer_class(session)


def analyze_platform_security(
    url: str,
    platform_type: str,
    response: requests.Response,
    soup: BeautifulSoup,
    session: requests.Session,
) -> Dict[str, Any]:
    """Main function to analyze platform security using appropriate analyzer"""
    analyzer = get_analyzer_for_platform(platform_type, session)
    results = analyzer.analyze(url, response, soup)

    # Generate additional analysis
    report_generator = SecurityReportGenerator()
    results["executive_summary"] = report_generator.generate_executive_summary(results)
    results["recommendations_matrix"] = (
        report_generator.generate_recommendations_matrix(
            results.get("vulnerabilities", [])
        )
    )

    return results
