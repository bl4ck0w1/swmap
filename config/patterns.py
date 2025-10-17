import re
from typing import Dict, List, Pattern
SW_REGISTRATION_PATTERNS: Dict[str, str] = {
    'navigator_register_single_quote': r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*'([^']+)'",
    'navigator_register_double_quote': r'navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*"([^"]+)"',
    'navigator_register_template': r'navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*`([^`]+)`',
    'new_serviceworker': r"new\s+ServiceWorker\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'workbox_register': r"workbox\s*\.\s*.*\.register\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'workbox_precache': r"workbox\s*\.\s*precaching\s*\.\s*.*\(\s*['\"`]([^'\"`]+)['\"`]",
    'dynamic_import_sw': r"import\s*\(\s*['\"]([^'\"]*sw[^'\"]*)['\"]",
    'dynamic_import_worker': r"import\s*\(\s*['\"]([^'\"]*worker[^'\"]*)['\"]",
    'serviceworker_container': r"\.serviceWorker\s*\.\s*register\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'window_navigator_register': r"window\s*\.\s*navigator\s*\.\s*serviceWorker\s*\.\s*register",
    'self_navigator_register': r"self\s*\.\s*navigator\s*\.\s*serviceWorker\s*\.\s*register",
    'minified_register_a': r"navigator\.serviceWorker\.register\(['\"`]([^'\"`]+)['\"`]",
    'minified_register_b': r"\.serviceWorker\.register\(['\"`]([^'\"`]+)['\"`]",
    'minified_register_c': r"serviceWorker\.register\(['\"`]([^'\"`]+)['\"`]",
}

WORKBOX_PATTERNS: Dict[str, str] = {
    'workbox_global': r'workbox\.[a-zA-Z]',
    'workbox_self': r'self\.workbox',
    'wb_manifest': r'self\.__WB_MANIFEST',
    'wb_manifest_global': r'__WB_MANIFEST',
    'wb_version_specific': r'workbox-\d+\.\d+\.\d+',
    'wb_version_general': r'workbox-[0-9]+\.[0-9]+',
    'wb_import_from': r'from\s+[\'"]workbox-',
    'wb_import_require': r'require\s*\(\s*[\'"]workbox-',
    'wb_import_scripts': r'importScripts\s*\(\s*[\'"]workbox-',
    'wb_precaching': r'workbox\.precaching',
    'wb_routing': r'workbox\.routing',
    'wb_strategies': r'workbox\.strategies',
    'wb_core': r'workbox\.core',
    'wb_cacheable_response': r'workbox\.cacheableResponse',
    'wb_background_sync': r'workbox\.backgroundSync',
    'wb_broadcast_update': r'workbox\.broadcastUpdate',
    'wb_expiration': r'workbox\.expiration',
    'wb_google_analytics': r'workbox\.googleAnalytics',
    'wb_navigation_preload': r'workbox\.navigationPreload',
    'wb_range_requests': r'workbox\.rangeRequests',
    'wb_precache_and_route': r'workbox\.precaching\.precacheAndRoute',
    'wb_register_route': r'workbox\.routing\.registerRoute',
    'wb_set_cache_name': r'workbox\.core\.setCacheNameDetails',
    'wb_minified_a': r'w\.precaching',
    'wb_minified_b': r'w\.routing',
    'wb_minified_c': r'w\.strategies',
}

CACHE_PATTERNS: Dict[str, str] = {
    'caches_open': r"caches\s*\.\s*open\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'cache_storage_open': r"cacheStorage\s*\.\s*open\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'cache_add': r"cache\s*\.\s*add\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'cache_add_all': r"cache\s*\.\s*addAll\s*\(\s*(\[[^\]]*?\])",
    'cache_put': r"cache\s*\.\s*put\s*\(\s*[^,]+,\s*[^)]+\)",
    'cache_match': r"cache\s*\.\s*match\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'cache_delete': r"cache\s*\.\s*delete\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    'cache_first': r"new\s+CacheFirst\s*\(",
    'network_first': r"new\s+NetworkFirst\s*\(",
    'stale_while_revalidate': r"new\s+StaleWhileRevalidate\s*\(",
    'network_only': r"new\s+NetworkOnly\s*\(",
    'cache_only': r"new\s+CacheOnly\s*\(",
    'wb_cache_first': r"workbox\.strategies\.CacheFirst",
    'wb_network_first': r"workbox\.strategies\.NetworkFirst",
    'wb_stale_while_revalidate': r"workbox\.strategies\.StaleWhileRevalidate",
    'cache_name_assignment': r"cacheName\s*:\s*['\"`]([^'\"`]+)['\"`]",
    'cache_name_variable': r"const\s+(\w+)\s*=\s*['\"`]([^'\"`]+)['\"`]",
}

SECURITY_PATTERNS: Dict[str, str] = {
    'eval_usage': r'\beval\s*\(',
    'function_constructor': r'new\s+Function\s*\(',
    'settimeout_string': r'setTimeout\s*\(\s*[^"\']',
    'setinterval_string': r'setInterval\s*\(\s*[^"\']',
    'exec_script': r'execScript\s*\(',
    'inner_html': r'\.innerHTML\s*=',
    'outer_html': r'\.outerHTML\s*=',
    'document_write': r'document\.write\s*\(',
    'document_writeln': r'document\.writeln\s*\(',
    'window_access': r'window\.',
    'document_access': r'document\.',
    'local_storage': r'localStorage',
    'session_storage': r'sessionStorage',
    'import_scripts_basic': r"importScripts\s*\(\s*['\"]([^'\"]+)['\"]",
    'import_scripts_template': r"importScripts\s*\(\s*`([^`]+)`",
    'import_scripts_multiple': r"importScripts\s*\(\s*([^)]+)\s*\)",
    'background_sync': r"self\.addEventListener\s*\(\s*['\"]sync['\"]",
    'sync_registration': r"self\.registration\.sync\.register",
    'periodic_sync': r"self\.registration\.periodicSync\.register",
    'skip_waiting': r'self\.skipWaiting\s*\(\s*\)',
    'clients_claim': r'clients\.claim\s*\(\s*\)',
    'skip_waiting_claim': r'skipWaiting.*clients\.claim',
    'auth_check_status': r'response\.status\s*===\s*401',
    'auth_check_unauthorized': r'response\.status\s*===\s*403',
    'redirect_login': r'redirect.*login',
    'location_login': r'window\.location.*login',
    'location_replace_login': r'location\.replace.*login',
    'fetch_cross_origin': r'fetch\([^)]*(?:https?:[^)]*)',
    'mode_cors': r'mode:\s*[\'"]?cors[\'"]?',
    'credentials_include': r'credentials:\s*[\'"]?include[\'"]?',
    'credentials_same_origin': r'credentials:\s*[\'"]?same-origin[\'"]?',
}

ROUTE_PATTERNS: Dict[str, str] = {
    'api_routes_simple': r'[\'"`](/api/[a-zA-Z0-9_\-./]+)[\'"`]',
    'api_routes_complex': r'[\'"`](/api/v\d+/[a-zA-Z0-9_\-./]+)[\'"`]',
    'api_routes_rest': r'[\'"`](/api/(?:users?|auth|admin|profile|settings)[a-zA-Z0-9_\-./]*)[\'"`]',
    'auth_routes': r'[\'"`](/auth[a-zA-Z0-9_\-./]*)[\'"`]',
    'login_routes': r'[\'"`](/login[a-zA-Z0-9_\-./]*)[\'"`]',
    'logout_routes': r'[\'"`](/logout[a-zA-Z0-9_\-./]*)[\'"`]',
    'register_routes': r'[\'"`](/register[a-zA-Z0-9_\-./]*)[\'"`]',
    'session_routes': r'[\'"`](/session[a-zA-Z0-9_\-./]*)[\'"`]',
    'token_routes': r'[\'"`](/token[a-zA-Z0-9_\-./]*)[\'"`]',
    'user_routes': r'[\'"`](/user[a-zA-Z0-9_\-./]*)[\'"`]',
    'profile_routes': r'[\'"`](/profile[a-zA-Z0-9_\-./]*)[\'"`]',
    'account_routes': r'[\'"`](/account[a-zA-Z0-9_\-./]*)[\'"`]',
    'settings_routes': r'[\'"`](/settings[a-zA-Z0-9_\-./]*)[\'"`]',
    'preferences_routes': r'[\'"`](/preferences[a-zA-Z0-9_\-./]*)[\'"`]',
    'admin_routes': r'[\'"`](/admin[a-zA-Z0-9_\-./]*)[\'"`]',
    'dashboard_routes': r'[\'"`](/dashboard[a-zA-Z0-9_\-./]*)[\'"`]',
    'management_routes': r'[\'"`](/manage[a-zA-Z0-9_\-./]*)[\'"`]',
    'billing_routes': r'[\'"`](/billing[a-zA-Z0-9_\-./]*)[\'"`]',
    'payment_routes': r'[\'"`](/payment[a-zA-Z0-9_\-./]*)[\'"`]',
    'subscription_routes': r'[\'"`](/subscription[a-zA-Z0-9_\-./]*)[\'"`]',
    'invoice_routes': r'[\'"`](/invoice[a-zA-Z0-9_\-./]*)[\'"`]',
    'data_routes': r'[\'"`](/data[a-zA-Z0-9_\-./]*)[\'"`]',
    'export_routes': r'[\'"`](/export[a-zA-Z0-9_\-./]*)[\'"`]',
    'import_routes': r'[\'"`](/import[a-zA-Z0-9_\-./]*)[\'"`]',
    'backup_routes': r'[\'"`](/backup[a-zA-Z0-9_\-./]*)[\'"`]',
    'generic_meaningful_routes': r'[\'"`](/[a-zA-Z0-9_\-./]{2,50})[\'"`]',
    'cache_manifest_routes': r'url:\s*[\'"`](/[^\'"`]+)[\'"`]',
    'precache_routes': r'[\'"`](/[^\'"`]+\.(?:html|css|js|json|png|jpg|jpeg|gif|svg))[\'"`]',
}

def compile_patterns(patterns_dict: Dict[str, str]) -> Dict[str, Pattern]:
    compiled = {}
    for name, pattern in patterns_dict.items():
        try:
            compiled[name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            print(f"Warning: Invalid pattern '{name}': {e}")
            continue
    return compiled

SW_REGISTRATION_PATTERNS_COMPILED = compile_patterns(SW_REGISTRATION_PATTERNS)
WORKBOX_PATTERNS_COMPILED = compile_patterns(WORKBOX_PATTERNS)
CACHE_PATTERNS_COMPILED = compile_patterns(CACHE_PATTERNS)
SECURITY_PATTERNS_COMPILED = compile_patterns(SECURITY_PATTERNS)
ROUTE_PATTERNS_COMPILED = compile_patterns(ROUTE_PATTERNS)