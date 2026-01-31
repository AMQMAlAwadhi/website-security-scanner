#!/usr/bin/env python3
"""
Platform Detection Module
Universal Low-Code Platform Security Scanner

Detects low-code platforms based on URL patterns, HTML content, and API signatures.
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup


class PlatformDetector:
    """Universal platform detection for low-code platforms"""
    
    # Platform signatures
    PLATFORM_SIGNATURES = {
        # Current platforms
        'bubble': {
            'domains': ['bubble.io', 'bubbleapps.io'],
            'html_patterns': [
                r'<script[^>]*bubble\.io',
                r'<script[^>]*bubble\.apps\.io',
                r'bubble\.io[^"\']*\.js',
                r'__BUBBLE__',
                r'bubble_main_'
            ],
            'api_patterns': [
                r'bubble\.io/api/[^"\']*',
                r'bubbleapps\.io/api/[^"\']*'
            ],
            'headers': ['x-bubble-server', 'x-bubble-app']
        },
        
        'outsystems': {
            'domains': ['outsystems.cloud', 'outsystems.net', 'outsystems.com'],
            'html_patterns': [
                r'<script[^>]*outsystems\.com',
                r'OutSystemsUI',
                r'OutSystemsNow',
                r'RichWidgets',
                r'SilkUI'
            ],
            'api_patterns': [
                r'/api/[a-zA-Z0-9_-]+',
                r'/rest/[a-zA-Z0-9_-]+'
            ],
            'headers': ['x-outsystems-version']
        },
        
        'airtable': {
            'domains': ['airtable.com', 'airtable.co'],
            'html_patterns': [
                r'<script[^>]*airtable\.com',
                r'airtable\.com[^"\']*\.js',
                r'__AIRTABLE__',
                r'block-[^"\']*\.airtable\.com'
            ],
            'api_patterns': [
                r'api\.airtable\.com/v[^"\']*',
                r'airtable\.com/v[^"\']*'
            ],
            'headers': ['x-airtable-base-id']
        },
        
        # NEW: Major low-code platforms to add
        'salesforce': {
            'domains': ['force.com', 'salesforce.com', 'my.salesforce.com'],
            'html_patterns': [
                r'<script[^>]*salesforce\.com',
                r'Visualforce',
                r'Lightning',
                r'aura\.framework',
                r'lwc\.framework'
            ],
            'api_patterns': [
                r'/services/data/v[^"\']*',
                r'/apex/[a-zA-Z0-9_-]+'
            ],
            'headers': ['x-salesforce-sf']
        },
        
        'microsoft_powerapps': {
            'domains': ['powerapps.com', 'powerappsportals.com', 'dynamics.com'],
            'html_patterns': [
                r'<script[^>]*powerapps\.com',
                r'pa_[a-zA-Z0-9_-]+',
                r'pcf_[a-zA-Z0-9_-]+',
                r'PowerApps'
            ],
            'api_patterns': [
                r'/api/data/v[^"\']*',
                r'/providers/Microsoft\.PowerApps'
            ],
            'headers': ['x-ms-powerapps']
        },
        
        'appian': {
            'domains': ['appian.com', 'appiancloud.com'],
            'html_patterns': [
                r'<script[^>]*appian\.com',
                r'appian\.suite',
                r'sail-[a-zA-Z0-9_-]+',
                r'Appian'
            ],
            'api_patterns': [
                r'/suite/webapi[^"\']*',
                r'/suite/rest[^"\']*'
            ],
            'headers': ['x-appian-suite']
        },
        
        'mendix': {
            'domains': ['mendix.com', 'mendixcloud.com'],
            'html_patterns': [
                r'<script[^>]*mendix\.com',
                r'mx-[a-zA-Z0-9_-]+',
                r'Mendix',
                r'mxui_[a-zA-Z0-9_-]+'
            ],
            'api_patterns': [
                r'/odata/[a-zA-Z0-9_-]+',
                r'/rest/[a-zA-Z0-9_-]+'
            ],
            'headers': ['x-mendix-session']
        },
        
        'retool': {
            'domains': ['retool.com', 'tryretool.com'],
            'html_patterns': [
                r'<script[^>]*retool\.com',
                r'retool_[a-zA-Z0-9_-]+',
                r'Retool',
                r'__RETOOL__'
            ],
            'api_patterns': [
                r'/api/v[^"\']*',
                r'/retool[?/][a-zA-Z0-9_-]+'
            ],
            'headers': ['x-retool-version']
        },
        
        'webflow': {
            'domains': ['webflow.com', 'webflow.io'],
            'html_patterns': [
                r'<script[^>]*webflow\.com',
                r'data-wf-page',
                r'wf-[a-zA-Z0-9_-]+',
                r'Webflow'
            ],
            'api_patterns': [
                r'/api/v[^"\']*',
                r'/webflow[?/][a-zA-Z0-9_-]+'
            ],
            'headers': ['x-webflow-request']
        },
        
        'zapier': {
            'domains': ['zapier.com', 'zapier-apps.com'],
            'html_patterns': [
                r'<script[^>]*zapier\.com',
                r'zapier-[a-zA-Z0-9_-]+',
                r'Zapier'
            ],
            'api_patterns': [
                r'/api/v[^"\']*',
                r'/zapier[?/][a-zA-Z0-9_-]+'
            ],
            'headers': ['x-zapier-version']
        },
        
        'adobe_experience_manager': {
            'domains': ['adobe.com', 'aem.live'],
            'html_patterns': [
                r'<script[^>]*adobe\.com',
                r'/etc.clientlibs',
                r'AEM',
                r'CQ_WCM'
            ],
            'api_patterns': [
                r'/content/dam[^"\']*',
                r'/bin/[a-zA-Z0-9_-]+'
            ],
            'headers': ['x-aem-build']
        }
    }
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def detect_platform(self, url: str, response: requests.Response = None) -> Tuple[str, float]:
        """
        Detect the low-code platform with confidence score.
        
        Returns:
            Tuple[str, float]: (platform_name, confidence_score)
        """
        if response is None:
            try:
                response = self.session.get(url, timeout=10)
            except requests.RequestException:
                return "unknown", 0.0
        
        soup = BeautifulSoup(response.content, 'html.parser')
        html_content = str(soup)
        headers = dict(response.headers)
        
        platform_scores = {}
        
        for platform, signatures in self.PLATFORM_SIGNATURES.items():
            score = self._calculate_platform_score(
                url, html_content, headers, signatures
            )
            platform_scores[platform] = score
        
        # Return platform with highest score
        best_platform = max(platform_scores, key=platform_scores.get)
        confidence = platform_scores[best_platform]
        
        # Minimum confidence threshold
        if confidence < 0.3:
            return "generic", confidence
        
        return best_platform, confidence
    
    def _calculate_platform_score(self, url: str, html: str, headers: Dict[str, str], signatures: Dict) -> float:
        """Calculate confidence score for a platform"""
        score = 0.0
        
        # Domain matching (highest weight)
        domain = urlparse(url).netloc.lower()
        for domain_pattern in signatures.get('domains', []):
            if domain_pattern in domain:
                score += 0.4
        
        # HTML pattern matching
        for pattern in signatures.get('html_patterns', []):
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.2
        
        # API pattern matching
        for pattern in signatures.get('api_patterns', []):
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.2
        
        # Header matching
        for header in signatures.get('headers', []):
            if header.lower() in [h.lower() for h in headers.keys()]:
                score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0
    
    def get_all_supported_platforms(self) -> List[str]:
        """Get list of all supported platforms"""
        return list(self.PLATFORM_SIGNATURES.keys()) + ['generic', 'unknown']
    
    def get_platform_info(self, platform: str) -> Dict:
        """Get detailed information about a platform"""
        platform_configs = {
            'salesforce': {
                'name': 'Salesforce Platform',
                'description': 'Enterprise CRM and application platform',
                'analyzer': 'SalesforceAnalyzer',
                'common_vulnerabilities': [
                    'SOQL injection',
                    'Visualforce XSS',
                    'Lightning component security',
                    'API access control bypass',
                    'Field-level security bypass'
                ],
                'security_headers': ['X-Content-Type-Options', 'Strict-Transport-Security'],
                'api_endpoints': ['/services/data/', '/apex/', '/sobjects/']
            },
            'microsoft_powerapps': {
                'name': 'Microsoft Power Apps',
                'description': 'Microsoft low-code application platform',
                'analyzer': 'PowerAppsAnalyzer',
                'common_vulnerabilities': [
                    'Power Automate flow injection',
                    'Dataverse data exposure',
                    'Canvas app XSS',
                    'Connector abuse',
                    'Permission model bypass'
                ],
                'security_headers': ['X-Content-Type-Options', 'Content-Security-Policy'],
                'api_endpoints': ['/api/data/', '/providers/Microsoft.PowerApps/']
            },
            'appian': {
                'name': 'Appian',
                'description': 'Enterprise process automation platform',
                'analyzer': 'AppianAnalyzer',
                'common_vulnerabilities': [
                    'SAIL interface XSS',
                    'Process model exposure',
                    'Data store access bypass',
                    'Web API injection',
                    'Expression language injection'
                ],
                'security_headers': ['X-Frame-Options', 'X-Content-Type-Options'],
                'api_endpoints': ['/suite/webapi/', '/suite/rest/']
            },
            'mendix': {
                'name': 'Mendix',
                'description': 'Enterprise application development platform',
                'analyzer': 'MendixAnalyzer',
                'common_vulnerabilities': [
                    'OData injection',
                    'Nanoflow security bypass',
                    'Module security misconfiguration',
                    'Widget parameter injection',
                    'Database query injection'
                ],
                'security_headers': ['X-Content-Type-Options', 'Strict-Transport-Security'],
                'api_endpoints': ['/odata/', '/rest/', '/xas/']
            },
            'retool': {
                'name': 'Retool',
                'description': 'Internal tools builder platform',
                'analyzer': 'RetoolAnalyzer',
                'common_vulnerabilities': [
                    'Query template injection',
                    'Resource connection abuse',
                    'JavaScript injection',
                    'API key exposure',
                    'Permission escalation'
                ],
                'security_headers': ['X-Content-Type-Options', 'Content-Security-Policy'],
                'api_endpoints': ['/api/v1/', '/retool/']
            },
            'webflow': {
                'name': 'Webflow',
                'description': 'Visual website development platform',
                'analyzer': 'WebflowAnalyzer',
                'common_vulnerabilities': [
                    'CMS collection exposure',
                    'Form submission abuse',
                    'Custom code injection',
                    'Asset path traversal',
                    'API endpoint exposure'
                ],
                'security_headers': ['X-Content-Type-Options', 'Content-Security-Policy'],
                'api_endpoints': ['/api/v1/', '/_api/']
            },
            'zapier': {
                'name': 'Zapier',
                'description': 'Automation and integration platform',
                'analyzer': 'ZapierAnalyzer',
                'common_vulnerabilities': [
                    'Zap injection',
                    'Webhook abuse',
                    'Action parameter injection',
                    'Authentication bypass',
                    'Data exposure in logs'
                ],
                'security_headers': ['X-Content-Type-Options', 'Strict-Transport-Security'],
                'api_endpoints': ['/api/v1/', '/webhooks/']
            },
            'adobe_experience_manager': {
                'name': 'Adobe Experience Manager',
                'description': 'Enterprise content management platform',
                'analyzer': 'AEMAnalyzer',
                'common_vulnerabilities': [
                    'Sling injection',
                    'OSGi console exposure',
                    'Repository traversal',
                    'Workflow security bypass',
                    'Template injection'
                ],
                'security_headers': ['X-Content-Type-Options', 'Content-Security-Policy'],
                'api_endpoints': ['/content/dam/', '/bin/', '/etc/']
            }
        }
        
        return platform_configs.get(platform, {})
