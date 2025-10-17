import re
import logging
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self):
        self.security_patterns = {
            'eval_usage': [
                r'\beval\s*\(',
                r'new\s+Function\s*\(',
                r'setTimeout\s*\(\s*[^"\']',
                r'setInterval\s*\(\s*[^"\']',
            ],
            'third_party_imports': [
                r'importScripts\s*\(\s*[\'"](https?://[^\'"]+)[\'"]',
            ],
            'cache_poisoning_risk': [
                r'fetch\([^)]*\)\.then\([^)]*cache\.put',
                r'cache\.put\([^)]*fetch\([^)]*\)',
                r'workbox\.strategies\.(?:CacheFirst|StaleWhileRevalidate)',
            ],
            'background_sync': [
                r'self\.addEventListener\s*\(\s*[\'"]sync[\'"]',
                r'self\.registration\.sync\.register',
                r'BackgroundSync',
            ],
            'aggressive_activation': [
                r'self\.skipWaiting\s*\(\s*\)',
                r'clients\.claim\s*\(\s*\)',
                r'skipWaiting.*clients\.claim',
            ],
            'mixed_origin_issues': [
                r'fetch\([^)]*(?:https?:[^)]*)',
                r'mode:\s*[\'"]?cors[\'"]?',
                r'credentials:\s*[\'"]?include[\'"]?',
            ],
            'client_side_auth': [
                r'response\.status\s*===\s*401',
                r'response\.status\s*===\s*403',
                r'redirect.*login',
                r'window\.location.*login',
            ]
        }
        
        self.sensitive_route_patterns = [
            r'/api/',
            r'/auth',
            r'/user',
            r'/admin',
            r'/profile',
            r'/account',
            r'/settings',
            r'/billing',
            r'/payment',
            r'/token',
            r'/session',
            r'/private',
            r'/secure',
        ]
        
        self.compiled_security = {
            key: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            for key, patterns in self.security_patterns.items()
        }
        
        self.compiled_sensitive_routes = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.sensitive_route_patterns
        ]
    
    def analyze_security_patterns(self, script_content: str, routes: List[str] = None) -> Dict[str, Any]:
        if not script_content:
            return self._empty_findings()
        
        findings = {
            'patterns_detected': {},
            'security_flags': [],
            'sensitive_routes': [],
            'risk_indicators': []
        }
        
        try:
            findings['patterns_detected'] = self._detect_security_patterns(script_content)
            
            if routes:
                findings['sensitive_routes'] = self._analyze_sensitive_routes(routes)
            
            findings['security_flags'] = self._generate_security_flags(findings['patterns_detected'])
            
            findings['risk_indicators'] = self._generate_risk_indicators(findings)
            
        except Exception as e:
            logger.error(f"Error in security analysis: {e}")
        
        return findings
    
    def _detect_security_patterns(self, script_content: str) -> Dict[str, bool]:
        detected = {}
        
        for pattern_name, patterns in self.compiled_security.items():
            detected[pattern_name] = False
            
            for pattern in patterns:
                if pattern.search(script_content):
                    detected[pattern_name] = True
                    break
        
        return detected
    
    def _analyze_sensitive_routes(self, routes: List[str]) -> List[str]:
        sensitive = []
        
        for route in routes:
            for pattern in self.compiled_sensitive_routes:
                if pattern.search(route):
                    sensitive.append(route)
                    break
        
        return sensitive
    
    def _generate_security_flags(self, patterns: Dict[str, bool]) -> List[str]:
        flags = []
        
        flag_mapping = {
            'eval_usage': 'EVAL_USAGE',
            'third_party_imports': 'THIRD_PARTY_IMPORTS',
            'cache_poisoning_risk': 'CACHE_POISONING_RISK',
            'background_sync': 'BACKGROUND_SYNC',
            'aggressive_activation': 'AGGRESSIVE_ACTIVATION',
            'mixed_origin_issues': 'MIXED_ORIGIN_ISSUES',
            'client_side_auth': 'CLIENT_SIDE_AUTH'
        }
        
        for pattern_key, flag_name in flag_mapping.items():
            if patterns.get(pattern_key):
                flags.append(flag_name)
        
        return flags
    
    def _generate_risk_indicators(self, findings: Dict[str, Any]) -> List[str]:
        indicators = []
        
        if findings.get('sensitive_routes'):
            indicators.append('SENSITIVE_CACHING')
        
        patterns = findings.get('patterns_detected', {})
        if patterns.get('aggressive_activation') and patterns.get('cache_poisoning_risk'):
            indicators.append('AGGRESSIVE_CACHING')
        
        if patterns.get('client_side_auth') and findings.get('sensitive_routes'):
            indicators.append('AUTH_BYPASS_RISK')
        
        return indicators
    
    def _empty_findings(self) -> Dict[str, Any]:
        return {
            'patterns_detected': {},
            'security_flags': [],
            'sensitive_routes': [],
            'risk_indicators': []
        }
    
    def has_third_party_imports(self, import_urls: List[str], base_domain: str) -> List[str]:
        third_party = []
        base_domain_clean = self._extract_domain(base_domain)
        
        for url in import_urls:
            try:
                url_domain = self._extract_domain(url)
                if url_domain != base_domain_clean:
                    third_party.append(url)
            except Exception:
                continue
        
        return third_party
    
    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
    
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain