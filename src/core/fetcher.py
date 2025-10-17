
import logging
import time
from typing import Optional, Dict, Tuple
import requests
from urllib.parse import urlparse
from ..models.exceptions import NetworkException, SecurityException

logger = logging.getLogger(__name__)


class AdvancedFetcher:
    def __init__(self, timeout: int = 15, max_retries: int = 2, user_agent: str = None):
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or self._get_default_user_agent()
        self.session = self._create_session()

    def _get_default_user_agent(self) -> str:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        return session

    def fetch_url(
        self,
        url: str,
        headers: Dict[str, str] = None,
        cookies: str = None,
        max_bytes: int = 512 * 1024,
    ) -> Tuple[Optional[str], Dict[str, str], int]:
        for attempt in range(self.max_retries + 1):
            try:
                request_headers = self.session.headers.copy()
                if headers:
                    request_headers.update(headers)
                if cookies:
                    request_headers["Cookie"] = cookies

                logger.debug(f"Fetching URL: {url} (attempt {attempt + 1})")

                r = self.session.get(
                    url,
                    headers=request_headers,
                    timeout=self.timeout,
                    stream=True,
                    allow_redirects=True,
                )

                try:
                    cl = int(r.headers.get("Content-Length", "0"))
                    if cl and cl > max_bytes:
                        raise SecurityException(f"Response too large: {cl} bytes")
                except ValueError:
                    pass

                content = b""
                for chunk in r.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    content += chunk
                    if len(content) > max_bytes:
                        raise SecurityException(f"Response exceeded size limit: {max_bytes} bytes")

                encoding = r.encoding or getattr(r, "apparent_encoding", None) or "utf-8"
                try:
                    text = content.decode(encoding, errors="replace")
                except LookupError:
                    text = content.decode("utf-8", errors="replace")

                logger.debug(f"Fetched {url} - {r.status_code}")
                return text, dict(r.headers), r.status_code

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout fetching {url} (attempt {attempt + 1})")
                if attempt == self.max_retries:
                    raise NetworkException(f"Timeout after {self.max_retries} retries")
                time.sleep(1)

            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error fetching {url}: {e}")
                if attempt == self.max_retries:
                    raise NetworkException(f"Connection failed after {self.max_retries} retries")
                time.sleep(1)

            except requests.exceptions.RequestException as e:
                logger.error(f"Request exception fetching {url}: {e}")
                if attempt == self.max_retries:
                    raise NetworkException(f"Request failed: {e}")
                time.sleep(1)

            except SecurityException as e:
                logger.warning(f"Security control triggered for {url}: {e}")
                raise

            except Exception as e:
                logger.error(f"Unexpected error fetching {url}: {e}")
                if attempt == self.max_retries:
                    raise NetworkException(f"Unexpected error: {e}")
                time.sleep(1)

        return None, {}, 0

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
            self.session.close()
