from typing import List, Dict, Pattern, Tuple
import re

SENSITIVE_ROUTES: Dict[str, List[str]] = {
    'authentication': [
        '/api/auth', '/api/login', '/api/logout', '/api/register', '/api/session',
        '/api/token', '/api/oauth', '/api/sso', '/auth', '/login', '/logout',
        '/register', '/session', '/token',
    ],
    'user_data': [
        '/api/user', '/api/users', '/api/profile', '/api/profiles', '/api/account',
        '/api/accounts', '/api/me', '/api/self', '/user', '/users', '/profile',
        '/profiles', '/account', '/accounts', '/me', '/self',
    ],
    'administration': [
        '/api/admin', '/api/administrator', '/api/management', '/api/manage',
        '/api/dashboard', '/api/system', '/admin', '/administrator', '/management',
        '/manage', '/dashboard', '/system',
    ],
    'financial': [
        '/api/billing', '/api/payment', '/api/payments', '/api/subscription',
        '/api/subscriptions', '/api/invoice', '/api/invoices', '/api/transaction',
        '/api/transactions', '/api/order', '/api/orders', '/billing', '/payment',
        '/payments', '/subscription', '/subscriptions', '/invoice', '/invoices',
        '/transaction', '/transactions', '/order', '/orders',
    ],
    'settings': [
        '/api/settings', '/api/preferences', '/api/config', '/api/configuration',
        '/settings', '/preferences', '/config', '/configuration',
    ],
    'data_operations': [
        '/api/data', '/api/export', '/api/import', '/api/backup', '/api/restore',
        '/api/migrate', '/data', '/export', '/import', '/backup', '/restore', '/migrate',
    ],
    'file_operations': [
        '/api/upload', '/api/download', '/api/file', '/api/files', '/api/document',
        '/api/documents', '/upload', '/download', '/file', '/files', '/document',
        '/documents',
    ],
}

SENSITIVE_KEYWORDS: Dict[str, List[str]] = {
    'auth_keywords': [
        'auth', 'authenticate', 'authentication', 'login', 'logout', 'register',
        'signin', 'signout', 'signup', 'session', 'token', 'jwt', 'oauth', 'sso',
        'password', 'credential', 'permission', 'authorization',
    ],
    'user_keywords': [
        'user', 'users', 'profile', 'profiles', 'account', 'accounts', 'member',
        'members', 'customer', 'customers', 'client', 'clients', 'person', 'people',
    ],
    'admin_keywords': [
        'admin', 'administrator', 'management', 'manage', 'dashboard', 'system',
        'superuser', 'root', 'moderator', 'moderation',
    ],
    'financial_keywords': [
        'billing', 'payment', 'payments', 'subscription', 'subscriptions', 'invoice',
        'invoices', 'transaction', 'transactions', 'order', 'orders', 'purchase',
        'purchases', 'price', 'pricing', 'fee', 'fees', 'tax', 'taxes',
    ],
    'security_keywords': [
        'security', 'secure', 'private', 'privilege', 'permission', 'access',
        'control', 'audit', 'log', 'logs', 'monitor', 'monitoring',
    ],
    'sensitivity_keywords': [
        'sensitive', 'confidential', 'secret', 'private', 'personal', 'protected',
        'restricted', 'internal', 'classified',
    ],
}

def compile_sensitive_route_patterns() -> Dict[str, Pattern]:
    compiled: Dict[str, Pattern] = {}
    for category, routes in SENSITIVE_ROUTES.items():
        pattern_string = '|'.join(re.escape(route) for route in routes)
        compiled[category] = re.compile(pattern_string, re.IGNORECASE)
    return compiled

def compile_sensitive_keyword_patterns() -> Dict[str, Pattern]:
    compiled: Dict[str, Pattern] = {}
    for category, keywords in SENSITIVE_KEYWORDS.items():
        pattern_string = '|'.join(re.escape(keyword) for keyword in keywords)
        compiled[category] = re.compile(r'\b(' + pattern_string + r')\b', re.IGNORECASE)
    return compiled

SENSITIVE_ROUTE_PATTERNS = compile_sensitive_route_patterns()
SENSITIVE_KEYWORD_PATTERNS = compile_sensitive_keyword_patterns()

ROUTE_RISK_LEVELS: Dict[str, str] = {
    'authentication': 'CRITICAL',
    'user_data': 'HIGH',
    'administration': 'HIGH',
    'financial': 'HIGH',
    'settings': 'MEDIUM',
    'data_operations': 'MEDIUM',
    'file_operations': 'MEDIUM',
}

CONTEXT_SENSITIVE_PATTERNS: Dict[str, str] = {
    'api_with_sensitive': r'/api/(?:auth|user|admin|billing|payment)',
    'sensitive_in_cache': r'cache.*(?:auth|user|token|password)',
    'sensitive_in_route': r'registerRoute.*(?:/api/|/auth|/user|/admin)',
    'precache_sensitive': r'precache.*(?:/api/|/auth|/user|/admin)',
}

COUNTRY_SPECIFIC_PATTERNS: Dict[str, List[str]] = {
    'eu_gdpr': ['gdpr', 'compliance', 'consent', 'privacy', 'data_protection', 'right_to_be_forgotten'],
    'us_hipaa': ['hipaa', 'phi', 'protected_health', 'medical', 'healthcare', 'patient'],
    'california_ccpa': ['ccpa', 'california_consumer', 'opt_out', 'do_not_sell'],
}

def is_sensitive_route(route: str) -> Tuple[bool, List[str]]:
    if not route:
        return False, []
    matches: List[str] = []
    for category, pattern in SENSITIVE_ROUTE_PATTERNS.items():
        if pattern.search(route):
            matches.append(category)
    return (len(matches) > 0, matches)

def contains_sensitive_keywords(text: str) -> Tuple[bool, List[str]]:
    if not text:
        return False, []
    matches: List[str] = []
    for category, pattern in SENSITIVE_KEYWORD_PATTERNS.items():
        if pattern.search(text):
            matches.append(category)
    return (len(matches) > 0, matches)

def get_route_risk_level(route: str) -> str:
    is_sensitive, categories = is_sensitive_route(route)
    if not is_sensitive:
        return 'LOW'
    risk_values = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    levels = [ROUTE_RISK_LEVELS.get(cat, 'LOW') for cat in categories]
    return max(levels, key=lambda lvl: risk_values.get(lvl, 0))
