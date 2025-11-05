import re
import logging
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_SENSITIVE_ROUTE_RE = [
    r'/api(?:/|$)',
    r'/auth(?:/|$)',
    r'/user(?:/|$)',
    r'/admin(?:/|$)',
    r'/profile(?:/|$)',
    r'/account(?:/|$)',
    r'/settings(?:/|$)',
    r'/billing(?:/|$)',
    r'/payment(?:/|$)',
    r'/token(?:/|$)',
    r'/session(?:/|$)',
    r'/private(?:/|$)',
    r'/secure(?:/|$)',
    r'/graphql(?:/|$)',
]
_COMPILED_SENSITIVE = [re.compile(p, re.IGNORECASE) for p in _SENSITIVE_ROUTE_RE]
_WB_ROUTE_RE = re.compile( r'workbox\.routing\.registerRoute\s*\(\s*(?P<matcher>[^,]+?)\s*,\s*(?P<handler>[^)]+)\)', re.IGNORECASE | re.DOTALL )
_WB_STRATEGY_RE = re.compile( r'workbox\.strategies\.(?P<strategy>[A-Za-z]+)\s*\(', re.IGNORECASE)

_PATTERNS = {
    "eval_like": [r'\beval\s*\(', r'new\s+Function\s*\(',
                  r'setTimeout\s*\(\s*[^"\']', r'setInterval\s*\(\s*[^"\']'],
    "third_party_imports": [r'importScripts\s*\(\s*[\'"](https?://[^\'"]+)[\'"]'],
    "cache_ops": [r'caches?\.\s*open\s*\(', r'cache\.put\s*\(', r'addAll\s*\(',
                  r'precacheAndRoute\s*\(', r'__WB_MANIFEST'],
    "authy_fetch": [r'credentials\s*:\s*[\'"]include[\'"]',
                    r'headers\s*:\s*\{[^}]*authorization\s*:',
                    r'fetch\s*\(\s*["\'](?:/|https?://)[^"\']*(?:auth|login|token|session)[^"\']*["\']',
                    r'request\.clone\s*\('],
    "activation_aggr": [r'self\.skipWaiting\s*\(\s*\)', r'clients\.claim\s*\(\s*\)'],
    "broadcast_leak": [r'new\s+BroadcastChannel\s*\(', r'postMessage\s*\('],
}

_FRAMEWORKS = {
    "angular": [r'ngsw-worker\.js', r'ngsw\.json', r'ngsw:'],
    "flutter": [r'flutter_service_worker\.js', r'AssetManifest\.json', r'RESOURCES\s*=\s*\{'],
}

class SecurityAnalyzer:
    def __init__(self):
        self._compiled: Dict[str, List[re.Pattern]] = {
            k: [re.compile(p, re.IGNORECASE | re.DOTALL) for p in v]
            for k, v in _PATTERNS.items()
        }

    def analyze_security_patterns(
        self, script_content: str, routes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        if not script_content:
            return self._empty()

        concerns: List[str] = []
        patterns = self._scan_patterns(script_content)

        wb_routes = self._extract_workbox_routes(script_content)
        wb_sensitive = self._workbox_sensitive_hits(wb_routes)

        if wb_sensitive:
            concerns.append("workbox_routes_cover_sensitive_paths")

        if patterns["cache_ops"]["__WB_MANIFEST"] or "precacheAndRoute" in patterns["cache_ops"]["_hits"]:
            concerns.append("precaching_detected")

        if any(patterns["authy_fetch"].values()):
            concerns.append("credentialed_fetch_or_auth_headers_detected")

        if any(patterns["activation_aggr"].values()):
            concerns.append("aggressive_activation_flags_present")

        if any(patterns["broadcast_leak"].values()):
            concerns.append("client_messaging_channel_present")

        sensitive_routes = sorted(set(self._match_sensitive(routes or []) |
                                      self._match_sensitive(self._wb_route_examples(wb_routes))))

        frameworks, probes = self._infer_frameworks(script_content)

        out = {
            "patterns_detected": patterns,
            "workbox_routes": wb_routes,           
            "sensitive_routes": sensitive_routes,   
            "concerns": sorted(set(concerns)),
            "frameworks": frameworks,               
            "suggested_probes": probes,             
        }

        out["security_flags"] = self._compat_flags(patterns)
        out["risk_indicators"] = self._compat_indicators(patterns, sensitive_routes, wb_sensitive)
        return out

    def _scan_patterns(self, code: str) -> Dict[str, Dict[str, Any]]:
        res: Dict[str, Dict[str, Any]] = {}
        for name, plist in self._compiled.items():
            hits = []
            present = False
            for rx in plist:
                if rx.search(code):
                    hits.append(rx.pattern)
                    present = True
            res[name] = {"present": present, "_hits": hits}

        res.setdefault("cache_ops", {})
        res["cache_ops"]["__WB_MANIFEST"] = "__WB_MANIFEST" in code
        return res

    def _extract_workbox_routes(self, code: str) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        for m in _WB_ROUTE_RE.finditer(code or ""):
            raw_handler = m.group("handler") or ""
            strat = None
            sm = _WB_STRATEGY_RE.search(raw_handler)
            if sm:
                strat = sm.group("strategy")
            matcher = (m.group("matcher") or "").strip()
            out.append({"matcher": matcher, "strategy": (strat or "").lower(), "raw": m.group(0)})
        return out

    def _wb_route_examples(self, wb_routes: List[Dict[str, str]]) -> List[str]:
        samples: List[str] = []
        for r in wb_routes:
            m = r["matcher"]
            
            for s in re.findall(r'["\'](\/[^"\']+)["\']', m):
                samples.append(s)
                
            for s in re.findall(r'new\s+RegExp\s*\(\s*["\']([^"\']+)["\']', m, flags=re.IGNORECASE):
                if not s.startswith("^"): s = "/" + s.lstrip("/")
                samples.append(s)
            for s in re.findall(r'/(\/[^/][^/]+)/[gimuy]*', m):
                samples.append("/" + s)
        return samples

    def _workbox_sensitive_hits(self, wb_routes: List[Dict[str, str]]) -> List[Dict[str, str]]:
        hits: List[Dict[str, str]] = []
        for r in wb_routes:
            for p in _COMPILED_SENSITIVE:
                if p.search(r["matcher"]) or any(p.search(x) for x in self._wb_route_examples([r])):
                    hits.append(r)
                    break
        return hits

    def _match_sensitive(self, paths: List[str]) -> set:
        out = set()
        for p in paths:
            for rx in _COMPILED_SENSITIVE:
                if rx.search(p):
                    out.add(p)
                    break
        return out

    def _infer_frameworks(self, code: str) -> Tuple[List[str], List[str]]:
        fw = []
        probes = []
        if any(re.search(p, code, re.IGNORECASE) for p in _FRAMEWORKS["angular"]):
            fw.append("angular")
            probes.append("/ngsw.json")
        if any(re.search(p, code, re.IGNORECASE) for p in _FRAMEWORKS["flutter"]):
            fw.append("flutter")
            probes.extend([
                "/flutter_service_worker.js",
                "/assets/AssetManifest.json",
                "/assets/FontManifest.json",
            ])
        return sorted(set(fw)), sorted(set(probes))

    def _compat_flags(self, patterns: Dict[str, Dict[str, Any]]) -> List[str]:
        flags = []
        if patterns["eval_like"]["present"]:
            flags.append("EVAL_USAGE")
        if patterns["third_party_imports"]["present"]:
            flags.append("THIRD_PARTY_IMPORTS")
        if patterns["cache_ops"]["present"]:
            flags.append("CACHE_POISONING_RISK")  
        if patterns["activation_aggr"]["present"]:
            flags.append("AGGRESSIVE_ACTIVATION")
        if patterns["authy_fetch"]["present"]:
            flags.append("CLIENT_SIDE_AUTH")
        return flags

    def _compat_indicators(
        self,
        patterns: Dict[str, Dict[str, Any]],
        sensitive_routes: List[str],
        wb_sensitive: List[Dict[str, str]]
    ) -> List[str]:
        ind = []
        if sensitive_routes:
            ind.append("SENSITIVE_CACHING")
        if patterns["activation_aggr"]["present"] and patterns["cache_ops"]["present"]:
            ind.append("AGGRESSIVE_CACHING")
        if patterns["authy_fetch"]["present"] and sensitive_routes:
            ind.append("AUTH_BYPASS_RISK")
        if wb_sensitive:
            ind.append("WB_SENSITIVE_MATCHERS_PRESENT")
        return ind

    def _empty(self) -> Dict[str, Any]:
        return {
            "patterns_detected": {},
            "workbox_routes": [],
            "sensitive_routes": [],
            "concerns": [],
            "frameworks": [],
            "suggested_probes": [],
            "security_flags": [],
            "risk_indicators": [],
        }

    def has_third_party_imports(self, import_urls: List[str], base_domain: str) -> List[str]:
        base = self._domain(base_domain)
        third = []
        for u in (import_urls or []):
            d = self._domain(u)
            if d and d != base:
                third.append(u)
        return third

    def _domain(self, url: str) -> str:
        try:
            d = (urlparse(url).netloc or "").lower()
            return d.split(":")[0]
        except Exception:
            return ""
