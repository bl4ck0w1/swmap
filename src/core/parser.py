import re
import logging
from typing import List, Tuple, Optional, Set
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

VENDOR_SW_CANDIDATES = [
    "/service-worker.js",
    "/sw.js",
    "/worker.js",
    "/serviceworker.js",
    "/ngsw-worker.js",
    "/ngsw-worker-es2015.js",
    "/ngsw.json",
    "/firebase-messaging-sw.js",
    "/messaging-sw.js",
    "/OneSignalSDKWorker.js",
    "/OneSignalSDKUpdaterWorker.js",
    "/flutter_service_worker.js",
    "/app/sw.js",
    "/static/sw.js",
    "/assets/sw.js",
    "/js/sw.js",
    "/dist/sw.js",
    "/build/sw.js",
    "/public/sw.js",
]

_BS_OK = False
_LXML_OK = False
try:
    from bs4 import BeautifulSoup  
    _BS_OK = True
except Exception:
    _BS_OK = False

try:
    import lxml  
    _LXML_OK = True
except Exception:
    _LXML_OK = False


def _html_to_soup(html: str):
    if not _BS_OK:
        return None
    parser = "lxml" if _LXML_OK else "html.parser"
    try:
        return BeautifulSoup(html or "", parser)
    except Exception:
        try:
            return BeautifulSoup(html or "", "html.parser")
        except Exception:
            return None


class SWParser:
    _SW_REGISTER_PATTERNS = [
        r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*(['\"])(?P<u1>(?:(?!\1).)+)\1",
        r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*`(?P<u2>[^`]+)`",
        r"workbox\s*\.\s*[a-zA-Z0-9_]+\s*\.\s*register\s*\(\s*(['\"])(?P<u3>(?:(?!\1).)+)\1",
        r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*([a-zA-Z0-9_$\.]+)\s*[,\)]",
    ]

    _SW_SCOPE_PATTERN = re.compile(
        r"serviceWorker\s*\.\s*register\s*\(\s*[^,]+,\s*\{\s*[^}]*scope\s*:\s*(['\"])(?P<scope>(?:(?!\1).)+)\1",
        re.IGNORECASE | re.DOTALL,
    )

    _IMPORT_PATTERNS = [
        r"importScripts\s*\(\s*(['\"])(?P<a1>(?:(?!\1).)+)\1\s*\)",
        r"importScripts\s*\(\s*`(?P<a2>[^`]+)`\s*\)",
        r"importScripts\s*\(\s*(?P<a3>(?:['\"][^'\"]+['\"]\s*,\s*)+['\"][^'\"]+['\"])",
        r"importScripts\s*\(\s*(?P<a4>\[[^\]]+\])\s*\)",
    ]

    _RE_INLINE = re.compile(r'on\w+\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    _RE_META = re.compile(r'<meta[^>]*content\s*=\s*["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
    _RE_ANY_STRING = re.compile(r'["\']([^"\']+)["\']')
    _RE_SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
    _RE_SCRIPT_SRC = re.compile(r"<script[^>]*\ssrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)

    _SW_HINTS = [
        r"sw\.js",
        r"service[-_]?worker",
        r"worker\.js",
        r"ngsw[-_]?worker\.js",
        r"firebase[-_]?messaging[-_]?sw\.js",
        r"flutter[_-]service[_-]worker\.js",
        r"pwabuilder[-_]?sw\.js",
        r"expo[-_]?service[-_]?worker\.js",
        r"sapper[-_]?service[-_]?worker\.js",
        r"next[-_]?static[/\\]service[-_]?worker\.js",
    ]

    def __init__(self):
        self._re_sw = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self._SW_REGISTER_PATTERNS]
        self._re_import = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self._IMPORT_PATTERNS]
        self._re_sw_hint = [re.compile(p, re.IGNORECASE) for p in self._SW_HINTS]

    def find_sw_registrations(self, html_content: str, base_url: str) -> List[str]:
        if not html_content:
            return []

        found: Set[str] = set()
        soup = _html_to_soup(html_content)

        try:
            if soup:
                for s in soup.find_all("script"):
                    code = s.string or ""
                    if code:
                        found.update(self._extract_sw_urls_from_js(code, base_url))

                for s in soup.find_all("script", src=True):
                    src = str(s.get("src") or "").strip()
                    if src and self._looks_like_sw(src):
                        found.add(urljoin(base_url, src))

                for tag in soup.find_all(True):
                    for attr, val in (tag.attrs or {}).items():
                        if isinstance(val, str) and attr.lower().startswith("on"):
                            found.update(self._extract_sw_urls_from_js(val, base_url))

                for m in soup.find_all("meta"):
                    c = m.get("content")
                    if c and isinstance(c, str):
                        found.update(self._extract_sw_urls_from_js(c, base_url))
            else:
                for m in self._RE_SCRIPT.finditer(html_content):
                    found.update(self._extract_sw_urls_from_js(m.group(1) or "", base_url))
                for m in self._RE_SCRIPT_SRC.finditer(html_content):
                    src = m.group(1) or ""
                    if src and self._looks_like_sw(src):
                        found.add(urljoin(base_url, src))
                for m in self._RE_INLINE.finditer(html_content):
                    found.update(self._extract_sw_urls_from_js(m.group(1) or "", base_url))
                for m in self._RE_META.finditer(html_content):
                    found.update(self._extract_sw_urls_from_js(m.group(1) or "", base_url))

        except Exception as e:
            logger.error(f"Error parsing HTML for SW registrations: {e}")

        return sorted(found)

    def extract_import_scripts(self, js_content: str, base_url: str = None) -> List[str]:
        if not js_content:
            return []
        out: Set[str] = set()
        try:
            for rx in self._re_import:
                for m in rx.finditer(js_content):
                    gd = m.groupdict()
                    val = next((gd[k] for k in gd if gd[k]), None)
                    if not val:
                        continue
                    out.update(self._extract_imports_val(val, base_url))
        except Exception as e:
            logger.error(f"Error extracting importScripts: {e}")
        return sorted(out)

    def get_vendor_sw_candidates(self, base_url: str) -> List[str]:
        return [urljoin(base_url, p) for p in VENDOR_SW_CANDIDATES]

    def get_common_sw_paths(self, base_url: str) -> List[str]:
        common = [
            "/sw.js",
            "/service-worker.js",
            "/worker.js",
            "/serviceworker.js",
            "/sw.min.js",
            "/pwa/sw.js",
            "/static/sw.js",
            "/assets/sw.js",
            "/js/sw.js",
            "/dist/sw.js",
            "/build/sw.js",
            "/public/sw.js",
            "/pwabuilder-sw.js",
            "/workbox-sw.js",
            "/workbox-sw.min.js",
            "/expo-service-worker.js",
            "/ngsw-worker.js",
            "/ngsw-worker.min.js",
            "/firebase-messaging-sw.js",
            "/flutter_service_worker.js",
            "/_next/static/service-worker.js",
            "/_nuxt/workbox.js",
            "/service-worker.min.js",
            "/app/sw.js",
            "/app/service-worker.js",
            "/spa/sw.js",
            "/client/sw.js",
            "/frontend/sw.js",
            "/static/js/sw.js",
            "/assets/js/sw.js",
        ]

        for p in VENDOR_SW_CANDIDATES:
            if p not in common:
                common.append(p)

        return [urljoin(base_url, p) for p in common]

    def find_sw_registrations_with_scopes(self, html_content: str, base_url: str) -> List[Tuple[str, Optional[str]]]:
        urls = self.find_sw_registrations(html_content, base_url)
        scope = self.extract_register_options_scope(html_content)
        return [(u, scope) for u in urls]

    def extract_register_options_scope(self, html_or_js: str) -> Optional[str]:
        try:
            m = self._SW_SCOPE_PATTERN.search(html_or_js or "")
            if m:
                return m.group("scope")
        except Exception:
            pass
        return None

    def _extract_sw_urls_from_js(self, js: str, base_url: str) -> Set[str]:
        hits: Set[str] = set()
        if not js:
            return hits

        for rx in self._re_sw:
            for m in rx.finditer(js):
                gd = m.groupdict()
                val = gd.get("u1") or gd.get("u2") or gd.get("u3")
                if val and self._is_valid_sw_url(val):
                    hits.add(urljoin(base_url, val))

                if not val and m.lastindex:
                    try:
                        varname = m.group(m.lastindex)
                        if varname and re.match(r"[A-Za-z_$][A-Za-z0-9_$\.]*", varname):
                            assign = re.search(
                                rf"{re.escape(varname)}\s*=\s*(['\"])(?P<u>(?:(?!\1).)+)\1",
                                js,
                                re.IGNORECASE | re.DOTALL,
                            )
                            if assign:
                                u = assign.group("u")
                                if self._is_valid_sw_url(u):
                                    hits.add(urljoin(base_url, u))
                    except Exception:
                        pass

        for s in self._RE_ANY_STRING.findall(js):
            if self._looks_like_sw(s):
                hits.add(urljoin(base_url, s))

        return hits

    def _extract_imports_val(self, val: str, base_url: Optional[str]) -> Set[str]:
        out: Set[str] = set()

        v = val.strip()

        if v.startswith("[") and v.endswith("]"):
            for s in re.findall(r"['\"]([^'\"]+)['\"]", v, re.IGNORECASE | re.DOTALL):
                if self._is_valid_sw_url(s):
                    out.add(urljoin(base_url, s) if base_url else s)
            return out

        if "," in v and not (v.startswith(("`", "'", '"'))):
            for s in re.findall(r"['\"]([^'\"]+)['\"]", v, re.IGNORECASE | re.DOTALL):
                if self._is_valid_sw_url(s):
                    out.add(urljoin(base_url, s) if base_url else s)
            return out

        s = v.strip("`").strip('"').strip("'")
        if s and self._is_valid_sw_url(s):
            out.add(urljoin(base_url, s) if base_url else s)

        return out

    def _is_valid_sw_url(self, url: str) -> bool:
        if not url or not isinstance(url, str):
            return False
        if url.startswith(("javascript:", "data:", "#")):
            return False
        if any(rx.search(url) for rx in self._re_sw_hint):
            return True
        return url.endswith(".js")

    def _looks_like_sw(self, path: str) -> bool:
        if not path:
            return False
        if any(rx.search(path) for rx in self._re_sw_hint):
            return True
        return False
