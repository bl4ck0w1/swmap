import posixpath
import re
import unicodedata
from urllib.parse import urljoin, urlparse, urlunparse
from typing import List

class URLNormalizer:
    def __init__(self):
        self.path_clean_regex = re.compile(r'/+')

    def normalize_url(self, url: str, base_url: str = None) -> str:
        try:
            if base_url and not url.startswith(("http://", "https://")):
                url = urljoin(base_url, url)

            p = urlparse(url)

            scheme = p.scheme.lower()
            netloc = self._normalize_netloc(p.netloc, scheme)
            path = self._normalize_path(p.path)
            params = p.params
            query = p.query
            fragment = "" 

            return urlunparse((scheme, netloc, path, params, query, fragment))
        except Exception as e:
            raise ValueError(f"URL normalization failed for {url}: {e}")

    def _normalize_netloc(self, netloc: str, scheme: str) -> str:
        netloc = (netloc or "").lower()
        if not netloc:
            return netloc

        if "@" in netloc:
            userinfo, hostport = netloc.split("@", 1)
            userinfo += "@"
        else:
            userinfo, hostport = "", netloc

        host, sep, port = hostport.rpartition(":")
        if sep and port.isdigit():
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                hostport = host 

        return f"{userinfo}{hostport}"

    def _normalize_path(self, path: str) -> str:
        path = unicodedata.normalize("NFKC", path or "/")
        norm = posixpath.normpath(path)
        if path.endswith("/") and not norm.endswith("/"):
            norm += "/"
        if not norm.startswith("/"):
            norm = "/" + norm
        norm = self.path_clean_regex.sub("/", norm)
        return norm

    def calculate_scope(self, sw_url: str, swa_header: str = None) -> str:
        try:
            p = urlparse(sw_url)
            sw_path = self._normalize_path(p.path)
            base_path = sw_path.rsplit("/", 1)[0] + "/"

            scope_path = base_path
            if swa_header:
                header_path = self._normalize_path(swa_header)
                if not header_path.endswith("/"):
                    header_path += "/"
                if sw_path.startswith(header_path):
                    scope_path = header_path

            scope_url = urlunparse((p.scheme, p.netloc, scope_path, "", "", ""))
            return scope_url
        except Exception as e:
            raise ValueError(f"Scope calculation failed for {sw_url}: {e}")

    def extract_routes_from_list(self, routes: List[str]) -> List[str]:
        out = set()
        for r in routes or []:
            if not isinstance(r, str):
                continue
            try:
                r = r.strip().split("?")[0].split("#")[0]
                r = self._normalize_path(r)
                if self._is_valid_route(r):
                    out.add(r)
            except Exception:
                continue
        return sorted(out)

    def _is_valid_route(self, route: str) -> bool:
        if not route or route == "/":
            return False
        static_extensions = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.map'}
        if any(route.lower().endswith(ext) for ext in static_extensions):
            return False
        if re.search(r'[a-f0-9]{8,}', route, re.IGNORECASE):
            return False
        return True
