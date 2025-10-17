import re
import json
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)

class SWAnalyzer:
    def __init__(self):
        self.workbox_patterns = [
            r'workbox\.[a-zA-Z]',
            r'self\.__WB_MANIFEST',
            r'workbox-\d+\.\d+\.\d+',
            r'from\s+[\'"]workbox-',
            r'import.*workbox',
            r'workbox\.precaching\.precacheAndRoute',
            r'workbox\.routing\.registerRoute',
            r'workbox\.strategies',
        ]

        self.cache_patterns = [
            r"caches\s*\.\s*open\s*\(\s*['\"`]([^'\"`]+)['\"`]",
            r'cacheName\s*:\s*[\'"`]([^\'"`]+)[\'"`]',  
        ]

        self.route_patterns = [
            r'addAll\s*\(\s*(\[[^\]]+\])',
            r'precacheAndRoute\s*\(\s*(\[[^\]]+\])',
            r'registerRoute\s*\(\s*[\'"`](/[^\'"`]+)[\'"`]',
            r'registerRoute\s*\(\s*new\s+RegExp\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'[\'"`](/[A-Za-z0-9_\-./]+)[\'"`]',
        ]

        self.compiled_workbox = [re.compile(p, re.IGNORECASE) for p in self.workbox_patterns]
        self.compiled_cache = [re.compile(p, re.IGNORECASE) for p in self.cache_patterns]
        self.compiled_routes = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.route_patterns]

    def detect_workbox(self, script_content: str) -> Tuple[bool, List[str]]:
        if not script_content:
            return False, []

        detected_modules = set()
        is_workbox = False

        try:
            for pattern in self.compiled_workbox:
                matches = pattern.findall(script_content)
                if matches:
                    is_workbox = True
                    for m in matches:
                        if isinstance(m, str):
                            detected_modules.add(self._normalize_module(m))

            for m in re.findall(r'workbox\.([A-Za-z]+)', script_content):
                detected_modules.add(m.lower())
        except Exception as e:
            logger.error(f"Error detecting Workbox: {e}")

        return is_workbox, sorted(detected_modules)

    def extract_cache_names(self, script_content: str) -> List[str]:
        if not script_content:
            return []
        names = set()
        try:
            for pattern in self.compiled_cache:
                for match in pattern.findall(script_content):
                    if isinstance(match, str) and match.strip():
                        names.add(match.strip())
        except Exception as e:
            logger.error(f"Error extracting cache names: {e}")
        return sorted(names)

    def extract_routes(self, script_content: str, max_routes: int = 50) -> List[str]:
        if not script_content:
            return []

        routes = set()
        try:
            for arr in re.findall(r'(?:addAll|precacheAndRoute)\s*\(\s*(\[[^\]]+\])', script_content,
                                  re.IGNORECASE | re.DOTALL):
                routes.update(self._parse_js_array(arr))

            for url in re.findall(r'["\']url["\']\s*:\s*["\'](\/[^"\']+)["\']', script_content, re.IGNORECASE):
                routes.add(url)

            for s in re.findall(r'registerRoute\s*\(\s*[\'"`](/[^\'"`]+)[\'"`]', script_content, re.IGNORECASE):
                routes.add(s)

            for s in re.findall(r'[\'"`](/[A-Za-z0-9_\-./]+)[\'"`]', script_content):
                routes.add(s)
        except Exception as e:
            logger.error(f"Error extracting routes: {e}")

        filtered = [r for r in routes if self._is_route_like(r)]
        return sorted(filtered)[:max_routes]

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

    def _is_route_like(self, s: str) -> bool:
        if not s or not s.startswith('/'):
            return False
        static_exts = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.map'}
        if any(s.lower().endswith(ext) for ext in static_exts):
            return False
        if re.search(r'[a-f0-9]{8,}', s, re.IGNORECASE):
            return False
        return '/' in s[1:]

    def _normalize_module(self, module_str: str) -> str:
        m = module_str.lower().strip()
        if 'workbox.' in m:
            m = m.split('workbox.')[-1]
        m = re.sub(r'[^a-z.]+', '', m)
        return m
