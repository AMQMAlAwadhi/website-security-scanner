#!/usr/bin/env python3
"""
Universal Low-Code Platform Analyzer
Comprehensive security analysis for all low-code platforms
"""

import re
import json
import base64
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urljoin
import requests
from bs4 import BeautifulSoup

from .base import BaseAnalyzer
from .advanced_checks import AdvancedChecksMixin


class UniversalLowCodeAnalyzer(AdvancedChecksMixin, BaseAnalyzer):
    """Universal analyzer for all low-code platforms"""
    
    def __init__(self, session: requests.Session, platform: str = "generic"):
        super().__init__(session)
        self.platform = platform
        self._last_request = None
        self._last_response = None
        
        # Platform-specific configurations
        self.platform_configs = self._load_platform_configs()
        
        # Common vulnerability patterns across all platforms
        self.common_patterns = {
            'api_keys': [
                r'["\']([A-Za-z0-9]{20,})["\']',
                r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ],
            'credentials': [
                r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'username["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'email["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ],
            'endpoints': [
                r'["\']([^"\']*/api/[^"\']*)["\']',
                r'["\']([^"\']*/rest/[^"\']*)["\']',
                r'["\']([^"\']*/v[0-9]+/[^"\']*)["\']',
                r'["\']([^"\']*/services/[^"\']*)["\']',
            ],
            'database_queries': [
                r'SELECT\s+[^;]+',
                r'INSERT\s+INTO\s+[^;]+',
                r'UPDATE\s+[^;]+',
                r'DELETE\s+FROM\s+[^;]+',
            ],
            'sensitive_data': [
                r'["\']([^"\']*ssn[^"\']*)["\']',
                r'["\']([^"\']*credit[_-]?card[^"\']*)["\']',
                r'["\']([^"\']*password[^"\']*)["\']',
                r'["\']([^"\']*token[^"\']*)["\']',
            ]
        }
    
    def analyze(self, url: str, response: requests.Response, soup: BeautifulSoup) -> Dict[str, Any]:
        """Universal analysis method for all low-code platforms"""
        self._record_http_context(url, response)
        
        # Extract content
        js_content = self._extract_javascript(soup)
        html_content = str(soup)
        
        # Platform-specific analysis
        platform_results = self._analyze_platform_specific(js_content, html_content, response)
        
        # Common security checks (apply to all platforms)
        common_results = self._analyze_common_security(js_content, html_content, response, url)
        
        # HTTP security analysis
        http_results = self._analyze_http_security(response)
        
        # Client-side security
        client_results = self._analyze_client_security(js_content, html_content)
        
        # API security analysis
        api_results = self._analyze_api_security(js_content, html_content, url)
        
        return {
            'platform': self.platform,
            'platform_specific': platform_results,
            'common_security': common_results,
            'http_security': http_results,
            'client_security': client_results,
            'api_security': api_results,
            'vulnerabilities': self.vulnerabilities,
            'findings': self.findings
        }
    
    def _record_http_context(self, url: str, response: requests.Response):
        """Record HTTP context for enriched vulnerability reporting"""
        self._last_request = response.request if hasattr(response, 'request') else None
        self._last_response = response
    
    def _build_http_instance(self, evidence_list: List[Any] = None) -> Dict[str, Any]:
        """Build HTTP request/response instance for reporting"""
        if not self._last_response:
            return {}
        
        # Build request text (start line + headers only)
        req_txt = ""
        if self._last_request:
            method = getattr(self._last_request, 'method', 'GET')
            url = getattr(self._last_request, 'url', '')
            req_txt = f"{method} {url} HTTP/1.1\r\n"
            
            # Add request headers
            headers = getattr(self._last_request, 'headers', {})
            for key, value in headers.items():
                req_txt += f"{key}: {value}\r\n"
        
        # Build response text (status line + headers only)
        resp_txt = f"HTTP/1.1 {self._last_response.status_code} {self._last_response.reason}\r\n"
        for key, value in self._last_response.headers.items():
            resp_txt += f"{key}: {value}\r\n"
        
        return {
            "url": getattr(self._last_response, "url", None) or getattr(self._last_request, "url", ""),
            "request": req_txt,
            "response": resp_txt,
            "evidence": evidence_list or [],
        }
    
    def _add_enriched_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        description: str,
        evidence: Any = "",
        recommendation: str = "",
        confidence: str = "Firm",
        category: str = "General",
        owasp: str = "N/A",
        cwe: List[str] = None,
        background: str = "",
        impact: str = "",
        references: List[str] = None,
    ):
        """Add enriched vulnerability with HTTP context and metadata"""
        # Handle evidence parameter
        if isinstance(evidence, dict) or isinstance(evidence, list):
            evidence_list = evidence if isinstance(evidence, list) else [evidence]
        else:
            evidence_list = [evidence] if evidence else []
        
        # Add base vulnerability
        super().add_vulnerability(
            vuln_type, severity, description, evidence if isinstance(evidence, str) else str(evidence),
            recommendation, confidence, category, owasp, cwe
        )
        
        # Enrich with additional metadata
        vuln = self.vulnerabilities[-1]
        vuln["background"] = background or ""
        vuln["impact"] = impact or ""
        vuln["references"] = references or []
        
        # Add HTTP instances if response exists
        if self._last_response is not None:
            vuln["instances"] = [self._build_http_instance(evidence_list=evidence_list)]
    
    def _load_platform_configs(self) -> Dict[str, Any]:
        """Load platform-specific configurations"""
        return {
            'salesforce': {
                'api_patterns': [r'/services/data/v[0-9]+', r'/apex/', r'/sobjects/'],
                'sensitive_patterns': [r'SOQL', r'Visualforce', r'Lightning'],
                'auth_patterns': [r'OAuth', r'JWT', r'Session']
            },
            'powerapps': {
                'api_patterns': [r'/api/data/v[0-9]+', r'/providers/Microsoft\.PowerApps'],
                'sensitive_patterns': [r'Power Automate', r'Dataverse', r'Canvas'],
                'auth_patterns': [r'Bearer', r'Azure AD']
            },
            'appian': {
                'api_patterns': [r'/suite/webapi/', r'/suite/rest/'],
                'sensitive_patterns': [r'SAIL', r'Process Model', r'Expression'],
                'auth_patterns': [r'Basic', r'OAuth']
            },
            'mendix': {
                'api_patterns': [r'/odata/', r'/rest/', r'/xas/'],
                'sensitive_patterns': [r'Nanoflow', r'Microflow', r'Module'],
                'auth_patterns': [r'Mendix', r'OAuth']
            },
            'retool': {
                'api_patterns': [r'/api/v[0-9]+', r'/retool/'],
                'sensitive_patterns': [r'Query', r'Resource', r'Trigger'],
                'auth_patterns': [r'JWT', r'API Key']
            },
            'webflow': {
                'api_patterns': [r'/api/v[0-9]+', r'/_api/'],
                'sensitive_patterns': [r'CMS', r'Collection', r'Form'],
                'auth_patterns': [r'Bearer', r'OAuth']
            },
            'zapier': {
                'api_patterns': [r'/api/v[0-9]+', r'/webhooks/'],
                'sensitive_patterns': [r'Zap', r'Trigger', r'Action'],
                'auth_patterns': [r'API Key', r'OAuth']
            },
            'aem': {
                'api_patterns': [r'/content/dam/', r'/bin/', r'/etc/'],
                'sensitive_patterns': [r'Sling', r'OSGi', r'Workflow'],
                'auth_patterns': [r'Basic', r'Token']
            }
        }
    
    def _analyze_platform_specific(self, js_content: str, html_content: str, response: requests.Response) -> Dict[str, Any]:
        """Platform-specific security analysis"""
        config = self.platform_configs.get(self.platform, {})
        results = {}
        
        # Analyze platform-specific API patterns
        api_endpoints = []
        for pattern in config.get('api_patterns', []):
            matches = re.findall(pattern, js_content + html_content, re.IGNORECASE)
            api_endpoints.extend(matches)
        
        if api_endpoints:
            results['api_endpoints'] = list(set(api_endpoints))
            
            # Check for exposed sensitive APIs
            for endpoint in api_endpoints:
                if any(sensitive in endpoint.lower() for sensitive in ['admin', 'config', 'debug', 'internal']):
                    self._add_enriched_vulnerability(
                        f"Sensitive {self.platform.title()} API Endpoint",
                        "High",
                        f"Sensitive API endpoint exposed: {endpoint}",
                        {"type": "regex", "pattern": rf"(?i){re.escape(endpoint)}"},
                        "Restrict access to sensitive API endpoints",
                        category="API Security",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-862"],
                        background=f"Sensitive {self.platform.title()} API endpoints should not be exposed to client-side code.",
                        impact="Attackers can potentially access administrative functions or sensitive data through exposed APIs.",
                        references=[
                            f"https://developer.{self.platform.replace('_', '')}.com/docs/security",
                            "https://owasp.org/www-project-api-security/"
                        ]
                    )
        
        # Analyze platform-specific patterns
        sensitive_patterns = config.get('sensitive_patterns', [])
        for pattern in sensitive_patterns:
            if re.search(pattern, js_content + html_content, re.IGNORECASE):
                self._add_enriched_vulnerability(
                    f"{self.platform.title()} Platform Pattern Exposure",
                    "Medium",
                    f"Platform-specific pattern detected: {pattern}",
                    {"type": "regex", "pattern": rf"(?i){pattern}"},
                    "Review platform-specific code exposure",
                    category="Information Disclosure",
                    owasp="A05:2021 - Security Misconfiguration"
                )
        
        return results
    
    def _analyze_common_security(self, js_content: str, html_content: str, response: requests.Response, url: str) -> Dict[str, Any]:
        """Common security checks for all platforms"""
        results = {}
        
        # Check for API key exposure
        for pattern in self.common_patterns['api_keys']:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 15:  # Filter false positives
                    self._add_enriched_vulnerability(
                        "API Key Exposure",
                        "Critical",
                        f"API key exposed in client-side code: {match[:10]}...",
                        {"type": "regex", "pattern": rf"(?i){re.escape(match[:20])}"},
                        "Remove API keys from client-side code, use server-side proxy",
                        category="Secret Management",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe=["CWE-798"],
                        background="API keys embedded in client-side code can be extracted by anyone with access to the application.",
                        impact="Exposed API keys allow attackers to directly access backend services and data.",
                        references=[
                            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html"
                        ]
                    )
        
        # Check for credentials exposure
        for pattern in self.common_patterns['credentials']:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 5 and not match.startswith(('http', 'data', 'mail')):
                    self._add_enriched_vulnerability(
                        "Credential Exposure",
                        "High",
                        f"Potential credential found: {match[:8]}...",
                        {"type": "regex", "pattern": rf"(?i){re.escape(match[:15])}"},
                        "Remove hardcoded credentials from client-side code",
                        category="Authentication",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        cwe=["CWE-256"]
                    )
        
        # Check for session tokens in URL
        if re.search(r'[?&](session|token|sid)=', url, re.IGNORECASE):
            self._add_enriched_vulnerability(
                "Session Token in URL",
                "Medium",
                "Session token found in URL parameters",
                {"type": "regex", "pattern": r"(?i)[?&](session|token|sid)=[^&\s]*"},
                "Use secure cookies for session management",
                category="Session Management",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe=["CWE-384"],
                background="Session tokens in URLs can be logged, bookmarked, or shared accidentally.",
                impact="Session hijacking and unauthorized access to user accounts.",
                references=[
                    "https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html"
                ]
            )
        
        return results
    
    def _analyze_http_security(self, response: requests.Response) -> Dict[str, Any]:
        """HTTP security header analysis"""
        results = {}
        
        # Check security headers
        security_headers = {
            'X-Frame-Options': response.headers.get("X-Frame-Options", ""),
            'Content-Security-Policy': response.headers.get("Content-Security-Policy", ""),
            'Strict-Transport-Security': response.headers.get("Strict-Transport-Security", ""),
            'X-Content-Type-Options': response.headers.get("X-Content-Type-Options", ""),
            'Referrer-Policy': response.headers.get("Referrer-Policy", ""),
            'Permissions-Policy': response.headers.get("Permissions-Policy", ""),
        }
        
        # CSP Analysis
        csp = security_headers['Content-Security-Policy']
        if not csp:
            self._add_enriched_vulnerability(
                "Missing Content Security Policy",
                "Low",
                "No CSP header found",
                [],
                "Implement Content Security Policy",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"],
                background="CSP helps prevent XSS and data injection attacks.",
                impact="Without CSP, the application is vulnerable to XSS and content injection attacks.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                    "https://owasp.org/www-project-secure-headers/"
                ]
            )
        elif 'unsafe-inline' in csp:
            self._add_enriched_vulnerability(
                "Weak Content Security Policy",
                "Medium",
                f"CSP contains unsafe-inline directive",
                {"type": "exact", "pattern": f"Content-Security-Policy: {csp[:100]}..."},
                "Remove unsafe-inline from CSP",
                category="Security Headers",
                owasp="A03:2021 - Injection",
                cwe=["CWE-79"]
            )
        
        # HSTS Analysis
        hsts = security_headers['Strict-Transport-Security']
        if not hsts:
            self._add_enriched_vulnerability(
                "Missing HSTS Header",
                "Low",
                "No HSTS header found",
                [],
                "Implement HTTP Strict Transport Security",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-523"]
            )
        
        # X-Frame-Options Analysis
        xfo = security_headers['X-Frame-Options']
        if not xfo:
            self._add_enriched_vulnerability(
                "Missing Clickjacking Protection",
                "Low",
                "No X-Frame-Options header",
                [],
                "Implement X-Frame-Options header",
                category="Security Headers",
                owasp="A05:2021 - Security Misconfiguration",
                cwe=["CWE-693"]
            )
        
        results['security_headers'] = security_headers
        return results
    
    def _analyze_client_security(self, js_content: str, html_content: str) -> Dict[str, Any]:
        """Client-side security analysis"""
        results = {}
        
        # Check for reflected input (XSS)
        if 'document.location' in js_content or 'window.location' in js_content:
            self._add_enriched_vulnerability(
                "Potential XSS Vector",
                "Medium",
                "Location object manipulation detected",
                {"type": "regex", "pattern": r"(?i)(document\.location|window\.location)"},
                "Validate and sanitize all user input",
                category="Cross-Site Scripting",
                owasp="A03:2021 - Injection",
                cwe=["CWE-79"]
            )
        
        # Check for eval() usage
        if re.search(r'eval\s*\(', js_content):
            self._add_enriched_vulnerability(
                "Unsafe Dynamic Code Execution",
                "High",
                "eval() function detected in JavaScript",
                {"type": "regex", "pattern": r"(?i)eval\s*\("},
                "Avoid eval() and use safer alternatives",
                category="Code Injection",
                owasp="A03:2021 - Injection",
                cwe=["CWE-94"]
            )
        
        # Check for innerHTML usage
        if re.search(r'\.innerHTML\s*=', js_content):
            self._add_enriched_vulnerability(
                "Potential DOM XSS",
                "Medium",
                "innerHTML assignment detected",
                {"type": "regex", "pattern": r"(?i)\.innerHTML\s*="},
                "Use textContent or sanitize HTML before assignment",
                category="Cross-Site Scripting",
                owasp="A03:2021 - Injection",
                cwe=["CWE-79"]
            )
        
        return results
    
    def _analyze_api_security(self, js_content: str, html_content: str, url: str) -> Dict[str, Any]:
        """API security analysis"""
        results = {}
        
        # Find API endpoints
        api_endpoints = []
        for pattern in self.common_patterns['endpoints']:
            matches = re.findall(pattern, js_content + html_content, re.IGNORECASE)
            api_endpoints.extend(matches)
        
        if api_endpoints:
            results['endpoints'] = list(set(api_endpoints))
            
            # Check for unauthenticated endpoints
            for endpoint in api_endpoints:
                if any(method in endpoint.lower() for method in ['get', 'post', 'put', 'delete']):
                    self._add_enriched_vulnerability(
                        "Unauthenticated API Endpoint",
                        "Medium",
                        f"Potential unauthenticated API endpoint: {endpoint}",
                        {"type": "regex", "pattern": rf"(?i){re.escape(endpoint)}"},
                        "Implement proper authentication for all API endpoints",
                        category="API Security",
                        owasp="A01:2021 - Broken Access Control",
                        cwe=["CWE-306"]
                    )
        
        return results
    
    def _extract_javascript(self, soup: BeautifulSoup) -> str:
        """Extract JavaScript content from page"""
        js_content = ""
        
        # Extract from script tags
        for script in soup.find_all('script'):
            if script.string:
                js_content += script.string + "\n"
        
        # Extract from event handlers
        for tag in soup.find_all(attrs={'onclick': True, 'onload': True, 'onerror': True}):
            for attr in ['onclick', 'onload', 'onerror']:
                if tag.get(attr):
                    js_content += tag.get(attr) + "\n"
        
        return js_content
