from typing import Dict, List, Tuple
RISK_WEIGHTS: Dict[str, int] = {
    'WIDENED_SCOPE': 40,           
    'OVERLY_BROAD_SCOPE': 35,      
    'SCOPE_MISMATCH': 25,         
    'SENSITIVE_CACHING': 35,       
    'CACHE_POISONING_RISK': 30,    
    'AGGRESSIVE_CACHING': 25,      
    'NO_CACHE_VALIDATION': 20,    
    'EVAL_USAGE': 25,              
    'DYNAMIC_CODE_EXECUTION': 30,  
    'THIRD_PARTY_IMPORTS': 20,     
    'UNSANITIZED_INPUT': 25,      
    'CLIENT_SIDE_AUTH': 30,       
    'AUTH_BYPASS_RISK': 35,       
    'TOKEN_EXPOSURE': 25,         
    'AGGRESSIVE_ACTIVATION': 20,   
    'IMMEDIATE_CLAIM': 15,        
    'MIXED_ORIGIN_ISSUES': 15,    
    'BACKGROUND_SYNC': 10,        
    'PUSH_NOTIFICATIONS': 10,      
    'WORKBOX_PRECACHING': 15,      
    'WORKBOX_RUNTIME_CACHING': 10,
    'WORKBOX_STRATEGIES': 5,     
    'NO_HTTPS': 25,                
    'DEBUGGING_ENABLED': 10,       
    'VERSION_MISMATCH': 5,        
}

RISK_THRESHOLDS: Dict[str, int] = {
    'CRITICAL': 90,    
    'HIGH': 70,        
    'MEDIUM': 40,      
    'LOW': 20,         
    'INFO': 0,         
}

SECURITY_FLAGS: Dict[str, Dict[str, str]] = {
    'WIDENED_SCOPE': {
        'description': 'Service-Worker-Allowed header widens scope beyond default',
        'impact': 'HIGH',
        'remediation': 'Restrict scope to minimal required paths',
        'reference': 'https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers#scope'
    },
    
    'SENSITIVE_CACHING': {
        'description': 'Sensitive routes (API, auth, user data) detected in cache',
        'impact': 'HIGH', 
        'remediation': 'Avoid caching sensitive data or implement proper validation',
        'reference': 'https://web.dev/service-worker-caching-and-http-caching/'
    },
    
    'CACHE_POISONING_RISK': {
        'description': 'Patterns indicating potential cache poisoning vulnerability',
        'impact': 'HIGH',
        'remediation': 'Implement request validation and cache invalidation',
        'reference': 'https://portswigger.net/web-security/web-cache-poisoning'
    },
    
    'EVAL_USAGE': {
        'description': 'eval() or Function constructor detected in Service Worker',
        'impact': 'HIGH',
        'remediation': 'Remove eval usage and use safer alternatives',
        'reference': 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'
    },
    
    'CLIENT_SIDE_AUTH': {
        'description': 'Client-side authentication patterns detected',
        'impact': 'HIGH',
        'remediation': 'Move authentication logic server-side',
        'reference': 'https://cheatsheetseries.owasp.org/cheatsheets/Service_Worker_Security_Cheat_Sheet.html'
    },
    
    'THIRD_PARTY_IMPORTS': {
        'description': 'Third-party scripts imported without integrity checks',
        'impact': 'MEDIUM',
        'remediation': 'Add integrity attributes or host scripts first-party',
        'reference': 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'
    },
    
    'AGGRESSIVE_ACTIVATION': {
        'description': 'skipWaiting() and clients.claim() used together',
        'impact': 'MEDIUM',
        'remediation': 'Implement careful update strategy with user confirmation',
        'reference': 'https://developer.chrome.com/docs/workbox/handling-service-worker-updates/'
    },
    
    'MIXED_ORIGIN_ISSUES': {
        'description': 'Cross-origin fetches without proper CORS handling',
        'impact': 'MEDIUM',
        'remediation': 'Implement proper CORS headers and credentials handling',
        'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'
    },
    
    'BACKGROUND_SYNC': {
        'description': 'Background sync functionality detected',
        'impact': 'LOW',
        'remediation': 'Ensure proper error handling and user notifications',
        'reference': 'https://developer.mozilla.org/en-US/docs/Web/API/Background_Sync_API'
    }
}

RISK_CALCULATION_RULES = {
    'base_scores': {
        'has_swa_header': 20,
        'workbox_detected': 10,
        'has_import_scripts': 5,
        'has_cache_operations': 5,
    },
    
    'multipliers': {
        'critical_combination': 1.5,  
        'sensitive_environment': 1.3,  
        'large_scope': 1.2,           
    },
    
    'bonus_scores': {
        'root_scope': 20,             
        'multiple_caches': 10,        
        'complex_routing': 15,        
        'background_features': 10,   
    }
}

RISK_COMBINATIONS: List[Tuple[List[str], int]] = [
    (['WIDENED_SCOPE', 'SENSITIVE_CACHING'], 25),
    (['EVAL_USAGE', 'CLIENT_SIDE_AUTH'], 30),
    (['CACHE_POISONING_RISK', 'AGGRESSIVE_ACTIVATION'], 20),
    (['THIRD_PARTY_IMPORTS', 'NO_CACHE_VALIDATION'], 15),
    (['BACKGROUND_SYNC', 'SENSITIVE_CACHING'], 20),
]

ENVIRONMENT_RISK_ADJUSTMENTS = {
    'financial': 1.5,     
    'healthcare': 1.4,     
    'government': 1.3,    
    'ecommerce': 1.2,      
    'social': 1.1,         
    'general': 1.0,        
}

def calculate_risk_score(found_flags: List[str], context: Dict = None) -> int:
    context = context or {}
    base_score = 0
    for flag in found_flags:
        base_score += RISK_WEIGHTS.get(flag, 0)
    
    for combination, bonus in RISK_COMBINATIONS:
        if all(pattern in found_flags for pattern in combination):
            base_score += bonus
    
    environment = context.get('environment', 'general')
    multiplier = ENVIRONMENT_RISK_ADJUSTMENTS.get(environment, 1.0)
    base_score = int(base_score * multiplier)
    
    if context.get('has_swa_header'):
        base_score += RISK_CALCULATION_RULES['base_scores']['has_swa_header']
    if context.get('workbox_detected'):
        base_score += RISK_CALCULATION_RULES['base_scores']['workbox_detected']
    
    return min(100, base_score)

def get_risk_level(score: int) -> str:
    for level, threshold in sorted(RISK_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
        if score >= threshold:
            return level
    return 'INFO'