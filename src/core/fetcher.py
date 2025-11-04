import logging
import time
import random
import re
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import http.client

from ..models.exceptions import NetworkException, SecurityException

logger = logging.getLogger(__name__)

try:
    import httpx  
    _HTTPX_OK = True
except Exception:
    _HTTPX_OK = False

_BROTLI_OK = False
try:
    import brotlicffi as _brotli  
    _BROTLI_OK = True
except Exception:
    try:
        import brotli as _brotli
        _BROTLI_OK = True
    except Exception:
        _BROTLI_OK = False

try:
    import chardet
    _CHARDET_OK = True
except Exception:
    _CHARDET_OK = False


def _classify_block(status: int, headers: Dict[str, str], body_snippet: str) -> Optional[str]:
    h = {k.lower(): v for k, v in (headers or {}).items()}

    if status in (401, 403):
        if 'cf-ray' in h or 'cf-cache-status' in h or 'server' in h and 'cloudflare' in h.get('server', '').lower():
            return "WAF_CLOUDFLARE_403"
        if any(k.startswith('x-akam') for k in h) or 'akamai' in h.get('server', '').lower():
            return "WAF_AKAMAI_403"
        if 'x-azure-ref' in h or 'azure' in h.get('server', '').lower():
            return "WAF_AZURE_403"
        if 'x-cache' in h and 'fastly' in h.get('via', '').lower():
            return "CDN_FASTLY_403"
        return "WAF_ORG_403"

    if status in (406, 409):
        return "WAF_POLICY_BLOCK"

    if status == 429:
        return "RATE_LIMIT_429"

    if status in (500, 502, 503, 504):
        if any(k.startswith('x-akam') for k in h) or 'akamai' in h.get('server', '').lower():
            return "CDN_AKAMAI_5XX"
        if 'cf-ray' in h:
            return "CDN_CLOUDFLARE_5XX"
        return "UPSTREAM_5XX"

    snippet = (body_snippet or "")[:512].lower()
    if "attention required!" in snippet and "cloudflare" in snippet:
        return "WAF_CLOUDFLARE_JS_CHALLENGE"
    if "access denied" in snippet and "reference" in snippet and "akamai" in snippet:
        return "WAF_AKAMAI_BLOCK"
    if "blocked request" in snippet and "policy" in snippet:
        return "WAF_BLOCK_GENERIC"

    return None


def _akamai_suggested_probes(
    url: str,
    headers: Dict[str, str],
    body_snippet: str,
) -> Optional[Tuple[str, str]]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    path = urlparse(url).path or ""
    lower_url = url.lower()
    snippet = (body_snippet or "")[:512].lower()

    if "x-akam-sw-version" in h:
        return "Detected Akamai 3PM SW", "/akam-sw-policy.json,/3pm-status.json"

    if path.endswith("akam-sw.js") or "akam-sw.js" in lower_url:
        return "Detected Akamai 3PM SW", "/akam-sw-policy.json,/3pm-status.json"

    if "aka3pm" in snippet or "akam-sw" in snippet:
        return "Detected Akamai 3PM SW", "/akam-sw-policy.json,/3pm-status.json"

    return None


def _retry_after_sleep(headers: Dict[str, str]) -> Optional[float]:
    ra = None
    for k, v in (headers or {}).items():
        if k.lower() == "retry-after":
            ra = v.strip()
            break
    if not ra:
        return None
    if ra.isdigit():
        return max(0, min(30.0, float(ra)))
    return 5.0  

def _jitter(base: float = 0.9, spread: float = 0.4) -> float:
    return max(0.05, base + random.uniform(0, spread))

def _choose_encoding(content: bytes, fallback: str = "utf-8") -> str:
    if _CHARDET_OK:
        try:
            guess = chardet.detect(content or b"")
            enc = (guess or {}).get("encoding") or fallback
            return enc
        except Exception:
            return fallback
    return fallback


def _try_http2_once(
    url: str,
    headers: Dict[str, str],
    cookies: Optional[str],
    timeout: int,
    max_bytes: int,
    proxy: Optional[str] = None,
) -> Tuple[Optional[str], Dict[str, str], int]:

    if not _HTTPX_OK:
        return None, {}, 0
    try:
        hdrs = headers.copy() if headers else {}
        if cookies:
            hdrs["Cookie"] = cookies

        proxies = None
        if proxy:
            proxies = {"http://": proxy, "https://": proxy}

        with httpx.Client(
            http2=True,
            headers=hdrs,
            timeout=timeout,
            follow_redirects=True,
            verify=True,
            proxies=proxies,
        ) as client:
            resp = client.get(url)
            raw = resp.content[: max_bytes + 1]
            if len(raw) > max_bytes:
                raise SecurityException(f"Response exceeded size limit: {max_bytes} bytes")

            enc = (resp.headers.get("content-encoding") or "").lower()
            if "br" in enc and _BROTLI_OK:
                try:
                    raw = _brotli.decompress(raw)
                except Exception:
                    pass

            encoding = resp.encoding or _choose_encoding(raw)
            text = raw.decode(encoding, errors="replace")

            block_reason = _classify_block(int(resp.status_code), dict(resp.headers), text)
            hdrs_out = dict(resp.headers)
            if block_reason:
                hdrs_out["x-swmap-block-reason"] = block_reason

            ak = _akamai_suggested_probes(url, hdrs_out, text)
            if ak:
                note, csv_probes = ak
                hdrs_out["x-swmap-notes"] = note
                hdrs_out["x-swmap-suggested-probes"] = csv_probes

            return text, hdrs_out, int(resp.status_code)
    except Exception:
        return None, {}, 0


class AdvancedFetcher:
    def __init__(
        self,
        timeout: int = 15,
        max_retries: int = 2,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        prefer_http2_first: bool = True,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or self._get_default_user_agent()
        self.proxy = proxy
        self.prefer_http2_first = bool(prefer_http2_first and _HTTPX_OK)

        self.session = self._create_session()

    def _get_default_user_agent(self) -> str:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.trust_env = True  # honor system/env proxies

        accept_encoding = "gzip, deflate, br" if _BROTLI_OK else "gzip, deflate"

        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": accept_encoding,
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        })

        retry = Retry(
            total=self.max_retries + 1,
            connect=self.max_retries + 1,
            read=self.max_retries + 1,
            backoff_factor=0.6,
            status_forcelist=(408, 425, 429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32, pool_connections=32)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if self.proxy:
            session.proxies.update({
                "http": self.proxy,
                "https": self.proxy,
            })

        return session

    def fetch_url(
        self,
        url: str,
        headers: Dict[str, str] = None,
        cookies: str = None,
        max_bytes: int = 512 * 1024,
        user_agent: Optional[str] = None,
    ) -> Tuple[Optional[str], Dict[str, str], int]:
        if self.prefer_http2_first:
            try:
                base_headers = self.session.headers.copy()
                if headers:
                    base_headers.update(headers)
                if user_agent:
                    base_headers["User-Agent"] = user_agent
                text2, hdrs2, code2 = _try_http2_once(
                    url, base_headers, cookies, self.timeout, max_bytes, proxy=self.proxy
                )
                if text2 is not None:
                    return text2, hdrs2, code2
            except Exception:
                pass

        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                request_headers = self.session.headers.copy()
                if headers:
                    request_headers.update(headers)
                if cookies:
                    request_headers["Cookie"] = cookies
                if user_agent:
                    request_headers["User-Agent"] = user_agent

                logger.debug(f"Fetching URL: {url} (attempt {attempt + 1})")

                try:
                    r = self.session.get(
                        url,
                        headers=request_headers,
                        timeout=self.timeout,
                        stream=False,
                        allow_redirects=True,
                    )
                except (http.client.RemoteDisconnected, urllib3.exceptions.ProtocolError) as e:
                    logger.warning(f"Remote closed early for {url}: {e} — retrying with Connection: close")
                    req_hdrs2 = request_headers.copy()
                    req_hdrs2["Connection"] = "close"
                    r = self.session.get(
                        url,
                        headers=req_hdrs2,
                        timeout=self.timeout,
                        stream=False,
                        allow_redirects=True,
                    )

                status = int(r.status_code)
                raw = r.content or b""

                enc = (r.headers.get("Content-Encoding") or "").lower()
                if "br" in enc and raw and not _BROTLI_OK:
                    if attempt < self.max_retries:
                        logger.debug("Brotli advertised but decoder not available; retrying without 'br'")
                        h2 = request_headers.copy()
                        h2["Accept-Encoding"] = "gzip, deflate"
                        time.sleep(_jitter(0.2, 0.25))
                        r = self.session.get(
                            url, headers=h2, timeout=self.timeout, stream=False, allow_redirects=True
                        )
                        status = int(r.status_code)
                        raw = r.content or b""
                        enc = (r.headers.get("Content-Encoding") or "").lower()
                    else:
                        pass

                if "br" in enc and raw and _BROTLI_OK:
                    try:
                        raw = _brotli.decompress(raw)
                        enc = enc.replace("br", "").strip()
                    except Exception as e:
                        logger.debug(f"Failed to brotli-decompress body: {e}")

                if len(raw) > max_bytes:
                    raise SecurityException(f"Response exceeded size limit: {max_bytes} bytes")

                if status in (429, 503) and attempt < self.max_retries:
                    delay = _retry_after_sleep(dict(r.headers)) or (1.2 * (attempt + 1))
                    delay *= _jitter(0.8, 0.6)
                    logger.debug(f"Server said {status}; sleeping {delay:.2f}s then retrying {url}")
                    time.sleep(delay)
                    continue

                encoding = r.encoding or _choose_encoding(raw)
                try:
                    text = raw.decode(encoding, errors="replace")
                except LookupError:
                    text = raw.decode("utf-8", errors="replace")

                headers_out = dict(r.headers)
                block_reason = _classify_block(status, headers_out, text)
                if block_reason:
                    headers_out["x-swmap-block-reason"] = block_reason

                ak = _akamai_suggested_probes(url, headers_out, text)
                if ak:
                    note, csv_probes = ak
                    headers_out["x-swmap-notes"] = note
                    headers_out["x-swmap-suggested-probes"] = csv_probes

                logger.debug(f"Fetched {url} - {status}")
                return text, headers_out, status

            except requests.exceptions.Timeout as e:
                last_exc = e
                logger.warning(f"Timeout fetching {url} (attempt {attempt + 1})")
                if attempt == self.max_retries:
                    base_headers = self.session.headers.copy()
                    if headers:
                        base_headers.update(headers)
                    if user_agent:
                        base_headers["User-Agent"] = user_agent
                    text2, hdrs2, code2 = _try_http2_once(
                        url, base_headers, cookies, self.timeout, max_bytes, proxy=self.proxy
                    )
                    if text2 is not None:
                        logger.info(f"HTTP/2 fallback succeeded for {url}")
                        return text2, hdrs2, code2
                    raise NetworkException(f"Timeout after {self.max_retries} retries")
                time.sleep(_jitter(0.9, 0.6))

            except requests.exceptions.ConnectionError as e:
                last_exc = e
                logger.warning(f"Connection error fetching {url}: {e}")
                if attempt == self.max_retries:
                    base_headers = self.session.headers.copy()
                    if headers:
                        base_headers.update(headers)
                    if user_agent:
                        base_headers["User-Agent"] = user_agent
                    text2, hdrs2, code2 = _try_http2_once(
                        url, base_headers, cookies, self.timeout, max_bytes, proxy=self.proxy
                    )
                    if text2 is not None:
                        logger.info(f"HTTP/2 fallback succeeded for {url}")
                        return text2, hdrs2, code2
                    raise NetworkException(f"Connection failed after {self.max_retries} retries")
                time.sleep(_jitter(0.9, 0.6))

            except requests.exceptions.RequestException as e:
                last_exc = e
                logger.error(f"Request exception fetching {url}: {e}")
                if attempt == self.max_retries:
                    base_headers = self.session.headers.copy()
                    if headers:
                        base_headers.update(headers)
                    if user_agent:
                        base_headers["User-Agent"] = user_agent
                    text2, hdrs2, code2 = _try_http2_once(
                        url, base_headers, cookies, self.timeout, max_bytes, proxy=self.proxy
                    )
                    if text2 is not None:
                        logger.info(f"HTTP/2 fallback succeeded for {url}")
                        return text2, hdrs2, code2
                    raise NetworkException(f"Request failed: {e}")
                time.sleep(_jitter(0.9, 0.6))

            except SecurityException as e:
                logger.warning(f"Security control triggered for {url}: {e}")
                raise

            except Exception as e:
                last_exc = e
                logger.error(f"Unexpected error fetching {url}: {e}")
                if attempt == self.max_retries:
                    base_headers = self.session.headers.copy()
                    if headers:
                        base_headers.update(headers)
                    if user_agent:
                        base_headers["User-Agent"] = user_agent
                    text2, hdrs2, code2 = _try_http2_once(
                        url, base_headers, cookies, self.timeout, max_bytes, proxy=self.proxy
                    )
                    if text2 is not None:
                        logger.info(f"HTTP/2 fallback succeeded for {url}")
                        return text2, hdrs2, code2
                    raise NetworkException(f"Unexpected error: {e}")
                time.sleep(_jitter(0.9, 0.6))

        raise NetworkException(f"Fetch failed: {last_exc!r}")

    def probe_exists(
        self,
        url: str,
        headers: Dict[str, str] = None,
        cookies: str = None,
    ) -> Tuple[bool, int, Dict[str, str]]:
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)
        if cookies:
            req_headers["Cookie"] = cookies

        try:
            r = self.session.head(url, headers=req_headers, timeout=self.timeout, allow_redirects=True)
            status = int(r.status_code)
            hdrs = dict(r.headers)
            reason = _classify_block(status, hdrs, "")
            if reason:
                hdrs["x-swmap-block-reason"] = reason

            ak = _akamai_suggested_probes(url, hdrs, "")
            if ak:
                note, csv_probes = ak
                hdrs["x-swmap-notes"] = note
                hdrs["x-swmap-suggested-probes"] = csv_probes

            return (200 <= status < 400), status, hdrs
        except Exception:
            try:
                h2 = req_headers.copy()
                h2["Range"] = "bytes=0-0"
                r = self.session.get(url, headers=h2, timeout=self.timeout, stream=False, allow_redirects=True)
                status = int(r.status_code)
                hdrs = dict(r.headers)
                reason = _classify_block(status, hdrs, "")
                if reason:
                    hdrs["x-swmap-block-reason"] = reason

                ak = _akamai_suggested_probes(url, hdrs, "")
                if ak:
                    note, csv_probes = ak
                    hdrs["x-swmap-notes"] = note
                    hdrs["x-swmap-suggested-probes"] = csv_probes

                return (200 <= status < 400), status, hdrs
            except Exception:
                return False, 0, {}

    def validate_url(self, url: str) -> bool:
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return False
            if not p.netloc:
                return False
            if p.netloc.endswith((".local", ".internal")):
                return False
            return True
        except Exception:
            return False

    def close(self):
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass
