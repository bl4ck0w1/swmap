import re
import logging
from typing import List
from urllib.parse import urljoin

logger = logging.getLogger(__name__)
class SWParser:
    def __init__(self):
        self.sw_patterns = [
            r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*['\"]([^'\"]+)['\"]",
            r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*`([^`]+)`",
            r"workbox\s*\.\s*.*\.register\s*\(\s*['\"]([^'\"]+)['\"]",
            r"import\s*\(\s*['\"]([^'\"]*sw[^'\"]*)['\"]",
        ]
        self.import_patterns = [
            r"importScripts\s*\(\s*['\"]([^'\"]+)['\"]",
            r"importScripts\s*\(\s*`([^`]+)`",
        ]
        self.compiled_sw_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.sw_patterns]
        self.compiled_import_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.import_patterns]
        self.re_script = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
        self.re_inline = re.compile(r'on\w+\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
        self.re_meta = re.compile(r'<meta[^>]*content\s*=\s*["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)

    def find_sw_registrations(self, html_content: str, base_url: str) -> List[str]:
        sw_urls = set()
        if not html_content:
            return []
        try:
            content = self._remove_comments(html_content)
            for m in self.re_script.finditer(content):
                sw_urls.update(self._extract_from_script(m.group(1), base_url))
            for m in self.re_inline.finditer(content):
                sw_urls.update(self._extract_from_script(m.group(1), base_url))
            for m in self.re_meta.finditer(content):
                sw_urls.update(self._extract_from_script(m.group(1), base_url))
        except Exception as e:
            logger.error(f"Error parsing HTML for SW registrations: {e}")
        return list(sw_urls)

    def extract_import_scripts(self, js_content: str, base_url: str = None) -> List[str]:
        out = set()
        if not js_content:
            return []
        try:
            for pattern in self.compiled_import_patterns:
                for match in pattern.findall(js_content):
                    if isinstance(match, tuple):
                        for u in match:
                            if u and self._is_valid_sw_url(u):
                                out.add(urljoin(base_url, u) if base_url else u)
                    else:
                        if match and self._is_valid_sw_url(match):
                            out.add(urljoin(base_url, match) if base_url else match)
        except Exception as e:
            logger.error(f"Error extracting importScripts: {e}")
        return list(out)

    def _extract_from_script(self, script_content: str, base_url: str) -> List[str]:
        found = []
        try:
            for pattern in self.compiled_sw_patterns:
                for match in pattern.findall(script_content or ""):
                    u = match[0] if isinstance(match, tuple) and match else match
                    if u and self._is_valid_sw_url(u):
                        found.append(urljoin(base_url, u))
        except Exception as e:
            logger.debug(f"Error in script extraction: {e}")
        return found

    def _is_valid_sw_url(self, url: str) -> bool:
        if not url or not isinstance(url, str):
            return False
        if url.startswith(("javascript:", "data:", "#")):
            return False
        sw_bits = [r'sw\.js', r'service-worker', r'workbox', r'worker\.js']
        if any(re.search(p, url, re.IGNORECASE) for p in sw_bits):
            return True
        return url.endswith(".js")

    def _remove_comments(self, content: str) -> str:
        content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)   
        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)    
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)   
        return content

    def get_common_sw_paths(self, base_url: str) -> List[str]:
        common = [
            "/sw.js",
            "/service-worker.js",
            "/worker.js",
            "/serviceworker.js",
            "/app/sw.js",
            "/static/sw.js",
            "/assets/sw.js",
            "/js/sw.js",
            "/dist/sw.js",
            "/build/sw.js",
            "/public/sw.js",
        ]
        return [urljoin(base_url, p) for p in common]
