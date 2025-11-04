import re
import json
import logging
from typing import List, Dict, Tuple, Set, Optional

logger = logging.getLogger(__name__)

class SWAnalyzer:

    _WB_SIGNS = [
        r'workbox\.[a-zA-Z]',
        r'self\.__WB_MANIFEST',
        r'workbox-\d+\.\d+\.\d+',
        r'from\s+[\'"]workbox-',
        r'import\s*(?:.*)\s*from\s*[\'"]workbox',
        r'workbox\.precaching\.precacheAndRoute',
        r'workbox\.routing\.registerRoute',
        r'workbox\.strategies',
        r'workbox\.core\.setCacheNameDetails',
    ]

    _CACHE_PATTERNS = [
        r"caches\s*\.\s*open\s*\(\s*['\"`]([^'\"`]+)['\"`]",                 
        r'cacheName\s*:\s*[\'"`]([^\'"`]+)[\'"`]',                             
        r'workbox\.core\.setCacheNameDetails\s*\(\s*\{\s*[^}]*precache\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
        r'workbox\.core\.setCacheNameDetails\s*\(\s*\{\s*[^}]*prefix\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
        r'workbox\.core\.setCacheNameDetails\s*\(\s*\{\s*[^}]*suffix\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
    ]

    _ROUTE_PATTERNS = [
        r'(?:addAll|precacheAndRoute)\s*\(\s*(\[[^\]]+\])',                              
        r'registerRoute\s*\(\s*[\'"`](/[^\'"`]+)[\'"`]',                                  
        r'registerRoute\s*\(\s*new\s+RegExp\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',               
        r'new\s+RegExp\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*\)',                             
        r'url\s*:\s*[\'"`](/[A-Za-z0-9_\-./]+)[\'"`]',                                   
        r'["\'](/[A-Za-z0-9_\-./]+)["\']',                                               
    ]

    _EVENT_SIGNS = {
        "install": re.compile(r"addEventListener\s*\(\s*['\"]install['\"]", re.IGNORECASE),
        "activate": re.compile(r"addEventListener\s*\(\s*['\"]activate['\"]", re.IGNORECASE),
        "fetch": re.compile(r"addEventListener\s*\(\s*['\"]fetch['\"]", re.IGNORECASE),
        "message": re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.IGNORECASE),
        "push": re.compile(r"addEventListener\s*\(\s*['\"]push['\"]", re.IGNORECASE),
        "sync": re.compile(r"addEventListener\s*\(\s*['\"]sync['\"]", re.IGNORECASE),
    }

    _BEHAVIOR_SIGNS = {
        "skip_waiting": re.compile(r"\bself\s*\.\s*skipWaiting\s*\(", re.IGNORECASE),
        "clients_claim": re.compile(r"\bclients\s*\.\s*claim\s*\(", re.IGNORECASE),
        "wb_cleanup_outdated": re.compile(r"cleanupOutdatedCaches\s*\(", re.IGNORECASE),
    }

    _EXTERNAL_RE = re.compile(r"(?:(?:fetch|importScripts)\s*\(\s*|new\s+Request\s*\(\s*)['\"](https?://[^'\"]+)['\"]",
                              re.IGNORECASE)

    _STATIC_EXTS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
                    '.avif', '.woff', '.woff2', '.ttf', '.eot', '.map', '.mp4', '.mp3', '.json'}

    def __init__(self):
        self.compiled_wb = [re.compile(p, re.IGNORECASE) for p in self._WB_SIGNS]
        self.compiled_cache = [re.compile(p, re.IGNORECASE) for p in self._CACHE_PATTERNS]
        self.compiled_routes = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self._ROUTE_PATTERNS]

    def detect_workbox(self, script_content: str) -> Tuple[bool, List[str]]:
        if not script_content:
            return False, []
        mods: Set[str] = set()
        is_wb = False
        try:
            for rx in self.compiled_wb:
                if rx.search(script_content):
                    is_wb = True

            for m in re.findall(r'workbox\.([A-Za-z]+)', script_content):
                mods.add(m.lower())
            for v in re.findall(r'workbox-(\d+\.\d+\.\d+)', script_content):
                mods.add(f"v{v}")
        except Exception as e:
            logger.error(f"Error detecting Workbox: {e}")
        return is_wb, sorted(mods)

    def extract_cache_names(self, script_content: str) -> List[str]:
        if not script_content:
            return []
        names: Set[str] = set()
        try:
            for rx in self.compiled_cache:
                for m in rx.findall(script_content):
                    if isinstance(m, (tuple, list)):
                        for x in m:
                            if isinstance(x, str) and x.strip():
                                names.add(x.strip())
                    else:
                        if isinstance(m, str) and m.strip():
                            names.add(m.strip())

            details = self._extract_wb_cache_name_details(script_content)
            if details:
                pref = details.get("prefix") or ""
                suff = details.get("suffix") or ""
                pre = details.get("precache") or "precache"
                for base in (pre, "runtime"):
                    cand = "-".join([x for x in [pref, base, suff] if x])
                    if cand:
                        names.add(cand)
        except Exception as e:
            logger.error(f"Error extracting cache names: {e}")
        return sorted(names)

    def extract_routes(self, script_content: str, max_routes: int = 50) -> List[str]:
        if not script_content:
            return []

        routes: Set[str] = set()
        try:
            for arr in re.findall(r'(?:addAll|precacheAndRoute)\s*\(\s*(\[[^\]]+\])', script_content,
                                  re.IGNORECASE | re.DOTALL):
                routes.update(self._parse_js_array(arr))

            for url in re.findall(r'["\']url["\']\s*:\s*["\'](\/[^"\']+)["\']', script_content, re.IGNORECASE):
                routes.add(url)

            for s in re.findall(r'registerRoute\s*\(\s*[\'"`](/[^\'"`]+)[\'"`]', script_content, re.IGNORECASE):
                routes.add(s)

            for rxs in re.findall(r'registerRoute\s*\(\s*new\s+RegExp\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', script_content, re.IGNORECASE):
                canon = self._regex_to_hint(rxs)
                if canon:
                    routes.add(canon)

            for rxs in re.findall(r'new\s+RegExp\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*\)', script_content, re.IGNORECASE):
                canon = self._regex_to_hint(rxs)
                if canon:
                    routes.add(canon)

            for s in re.findall(r'[\'"`](/[A-Za-z0-9_\-./]+)[\'"`]', script_content):
                routes.add(s)

        except Exception as e:
            logger.error(f"Error extracting routes: {e}")

        filtered = [r for r in routes if self._is_route_like(r)]
        return sorted(filtered)[:max_routes]

    def extract_behavior_signals(self, script_content: str) -> Dict[str, bool]:
        s = script_content or ""
        out = {
            "install_listener": bool(self._EVENT_SIGNS["install"].search(s)),
            "activate_listener": bool(self._EVENT_SIGNS["activate"].search(s)),
            "fetch_listener": bool(self._EVENT_SIGNS["fetch"].search(s)),
            "message_listener": bool(self._EVENT_SIGNS["message"].search(s)),
            "push_listener": bool(self._EVENT_SIGNS["push"].search(s)),
            "sync_listener": bool(self._EVENT_SIGNS["sync"].search(s)),
            "calls_skipWaiting": bool(self._BEHAVIOR_SIGNS["skip_waiting"].search(s)),
            "calls_clients_claim": bool(self._BEHAVIOR_SIGNS["clients_claim"].search(s)),
            "calls_wb_cleanup_outdated": bool(self._BEHAVIOR_SIGNS["wb_cleanup_outdated"].search(s)),
        }
        return out

    def extract_external_origins(self, script_content: str) -> List[str]:
        if not script_content:
            return []
        out: Set[str] = set(u.strip() for u in self._EXTERNAL_RE.findall(script_content) if u.strip())
        return sorted(out)

    def _extract_wb_cache_name_details(self, s: str) -> Dict[str, Optional[str]]:
        try:
            m = re.search(r'workbox\.core\.setCacheNameDetails\s*\(\s*\{([^}]*)\}', s, re.IGNORECASE | re.DOTALL)
            if not m:
                return {}
            block = m.group(1) or ""
            out = {}
            for key in ("prefix", "suffix", "precache"):
                mm = re.search(rf'{key}\s*:\s*[\'"`]([^\'"`]+)[\'"`]', block, re.IGNORECASE)
                if mm:
                    out[key] = mm.group(1)
            return out
        except Exception:
            return {}

    def _parse_js_array(self, array_str: str) -> List[str]:
        out: List[str] = []
        try:
            jtxt = array_str.strip()
            jtxt = re.sub(r'(\w+)\s*:', r'"\1":', jtxt)  
            jtxt = jtxt.replace("'", '"')
            jtxt = re.sub(r',\s*]', ']', jtxt)
            data = json.loads(jtxt)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and item.startswith('/'):
                        out.append(item)
                    elif isinstance(item, dict) and 'url' in item and str(item['url']).startswith('/'):
                        out.append(str(item['url']))
        except Exception:
            for s in re.findall(r'[\'"`](/[^\'"`]+)[\'"`]', array_str):
                out.append(s)
        return out

    def _regex_to_hint(self, rx: str) -> Optional[str]:

        if not rx:
            return None
        s = rx.strip().strip("^").strip("$")
        m = re.search(r"(/[^/()|?*+\\\s]+)", s)
        if not m:
            m2 = re.search(r"(^[A-Za-z0-9_\-]+/)", s)
            if m2:
                return "/" + m2.group(1).strip("/")
            return None
        base = m.group(1)
        base = re.split(r"[\\\?\*\+\(\)\|\[\]\{\}]", base)[0]
        if not base.endswith("/"):
            base += "/"
        return base if base.startswith("/") else "/" + base.lstrip("/")

    def _is_route_like(self, s: str) -> bool:
        if not s or not s.startswith('/'):
            return False
        low = s.lower()
        if any(low.endswith(ext) for ext in self._STATIC_EXTS):
            return False
        if re.search(r'[a-f0-9]{8,}', s, re.IGNORECASE):
            return False
        return '/' in s[1:]
