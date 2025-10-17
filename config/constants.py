import os
from typing import Dict, Any, List
DEFAULT_CONFIG = {
    'parallel_workers': 6,
    'request_timeout': 15,
    'max_redirects': 5,
    'max_sw_bytes': 512 * 1024,  
    'max_html_bytes': 1024 * 1024,  
    'max_routes_per_sw': 50,
    'max_import_script_depth': 2,
    'default_output_format': 'tsv',
    'enable_colors': True,
    'show_progress': True,
    'enable_probing': True,
    'deep_analysis': False,
    'risk_threshold': 0,
    'validate_ssl': True,
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 SWMap-Security-Scanner/1.0.0',
    'default_headers': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
    }
}

SCAN_LIMITS = {
    'max_targets_per_scan': 10000,
    'max_targets_per_batch': 1000,
    'max_requests_per_second': 50,
    'max_concurrent_connections': 20,
    'max_connection_retries': 2,
    'connection_pool_size': 10,
    'max_memory_bytes': 512 * 1024 * 1024,  
    'max_cached_responses': 1000,
    'max_analysis_time_per_sw': 30,  
    'max_pattern_matches_per_sw': 1000,
    'max_output_lines': 100000,
    'max_log_file_size': 100 * 1024 * 1024,  
}

HTTP_CONFIG = {
    'connect_timeout': 5.0,
    'read_timeout': 10.0,
    'pool_timeout': 1.0,
    'retry_status_codes': [429, 500, 502, 503, 504],
    'retry_backoff_factor': 0.5,
    'retry_max_delay': 60.0,
    'pool_connections': 10,
    'pool_maxsize': 20,
    'max_keepalive': 10,
    'security_headers': {
        'User-Agent': DEFAULT_CONFIG['user_agent'],
        'X-SWMap-Scanner': '1.0.0',
        'X-Security-Scan': 'true'
    },
    'blocked_headers': [
        'Authorization',
        'Proxy-Authorization', 
        'Cookie',  
        'X-Forwarded-For',
        'X-Real-IP',
    ]
}

SECURITY_CONTROLS = {
    'max_url_length': 2048,
    'allowed_schemes': ['http', 'https'],
    'blocked_domains': [
        'localhost',
        '127.0.0.1',
        '::1',
        '0.0.0.0',
        '*.local',
        '*.internal',
    ],
    
    'max_content_length': 10 * 1024 * 1024,  # 10 MB
    'blocked_content_types': [
        'application/octet-stream',
        'application/x-download',
        'application/x-executable',
    ],
    
    'max_pattern_length': 1000,
    'max_pattern_matches': 10000,
    
    'allowed_file_extensions': ['.js', '.html', '.txt', '.json'],
    'max_path_depth': 20,
    'max_string_length': 10 * 1024 * 1024, 
    'max_list_items': 100000,
}

COMMON_SW_FILENAMES = [
    '/sw.js',
    '/service-worker.js',
    '/worker.js',
    '/serviceworker.js',
    '/sw.min.js',
    '/service-worker.min.js',
    '/worker.min.js',
    '/app/sw.js',
    '/static/sw.js',
    '/assets/sw.js',
    '/js/sw.js',
    '/dist/sw.js',
    '/build/sw.js',
    '/public/sw.js',
    '/src/sw.js',
    '/scripts/sw.js',
    '/sw/v1.js',
    '/sw/v2.js',
    '/service-worker/v1.js',
]

RISK_LEVELS = {
    'CRITICAL': 90,
    'HIGH': 70,
    'MEDIUM': 40,
    'LOW': 20,
    'INFO': 0
}

EXIT_CODES = {
    'SUCCESS': 0,
    'USAGE_ERROR': 1,
    'NETWORK_ERROR': 2,
    'CONFIG_ERROR': 3,
    'SECURITY_ERROR': 4,
    'UNKNOWN_ERROR': 255
}

ENV_VARS = {
    'SWMAP_API_KEY': 'api_key',
    'SWMAP_PROXY': 'proxy_url',
    'SWMAP_USER_AGENT': 'user_agent',
    'SWMAP_TIMEOUT': 'timeout',
    'SWMAP_PARALLEL': 'parallel_workers',
    'SWMAP_OUTPUT_FORMAT': 'output_format',
    'SWMAP_LOG_LEVEL': 'log_level',
    'SWMAP_LOG_FILE': 'log_file',
}

def get_version() -> str:
    return "1.0.0"

def get_user_agent() -> str:
    return DEFAULT_CONFIG['user_agent']

def get_default_headers() -> Dict[str, str]:
    return DEFAULT_CONFIG['default_headers'].copy()

def is_valid_parallel_count(count: int) -> bool:
    return 1 <= count <= SCAN_LIMITS['max_concurrent_connections']

def is_valid_timeout(timeout: int) -> bool:
    return 1 <= timeout <= 300

def is_valid_max_bytes(max_bytes: int) -> bool:
    """Validate max bytes value"""
    return 1024 <= max_bytes <= 100 * 1024 * 1024  