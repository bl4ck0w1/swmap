import re
import os
import ipaddress
from urllib.parse import urlparse, urljoin
from typing import Optional, List, Dict, Any, Tuple
from ..models.exceptions import (
    URLValidationException,
    SecurityException,
    ValidationException,
)

class URLValidator:
    def __init__(self):
        self.domain_pattern = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
        self.private_networks = [
            r"^10\.",
            r"^192\.168\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^127\.",
            r"^169\.254\.",
            r"^::1$",
            r"^fc00::",
            r"^fd00::",
            r"^fe80::",
        ]

        self.suspicious_patterns = [
            r"\.local$",
            r"\.internal$",
            r"\.localhost$",
            r"\.example$",
            r"\.test$",
            r"^localhost$",
            r"^0\.0\.0\.0$",
            r"^255\.255\.255\.255$",
        ]

    def validate_url(self, url: str, base_url: Optional[str] = None) -> Tuple[bool, str]:
        if not url or not isinstance(url, str):
            return False, "URL must be a non-empty string"

        if base_url and not url.startswith(("http://", "https://")):
            try:
                url = urljoin(base_url, url)
            except Exception as e:
                return False, f"URL join failed: {e}"

        try:
            parsed = urlparse(url)

            if parsed.scheme not in ("http", "https"):
                return False, f"Invalid scheme: {parsed.scheme}"

            if not parsed.netloc:
                return False, "Missing network location"

            ok, err = self._validate_netloc(parsed.netloc)
            if not ok:
                return False, err

            ok, err = self._validate_path(parsed.path or "/")
            if not ok:
                return False, err

            ok, err = self._security_checks(parsed)
            if not ok:
                return False, err

            return True, ""

        except Exception as e:
            return False, f"URL parsing error: {e}"

    def _validate_netloc(self, netloc: str) -> Tuple[bool, str]:
        hostname = netloc.split(":", 1)[0]

        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, f"Private or local IP address: {hostname}"
            if ip.is_multicast or ip.is_reserved:
                return False, f"Special IP address: {hostname}"
            return True, ""
        except ValueError:
            pass  

        if not self.domain_pattern.match(hostname):
            return False, f"Invalid domain format: {hostname}"

        for pat in self.suspicious_patterns:
            if re.search(pat, hostname, re.IGNORECASE):
                return False, f"Suspicious domain pattern: {hostname}"

        tld = hostname.split(".")[-1].lower()
        if len(tld) < 2 or len(tld) > 24:
            return False, f"Invalid TLD: {tld}"

        return True, ""

    def _validate_path(self, path: str) -> Tuple[bool, str]:
        if ".." in path:
            return False, "Path contains traversal sequences"
        if re.search(r'[<>"\']', path):
            return False, "Path contains dangerous characters"
        if len(path) > 2048:
            return False, "Path too long"
        return True, ""

    def _security_checks(self, parsed) -> Tuple[bool, str]:
        for pat in self.private_networks:
            if re.search(pat, parsed.netloc):
                return False, "Private network address detected"

        if parsed.username or parsed.password:
            return False, "Credentials in URL are not allowed"

        if parsed.query and len(parsed.query) > 2048:
            return False, "Query string too long"

        return True, ""

    def normalize_url(self, url: str, base_url: Optional[str] = None) -> str:
        valid, err = self.validate_url(url, base_url)
        if not valid:
            raise URLValidationException(f"URL validation failed: {err}")

        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        if parsed.port == 80 and scheme == "http":
            netloc = parsed.hostname or netloc
        elif parsed.port == 443 and scheme == "https":
            netloc = parsed.hostname or netloc

        path = parsed.path or "/"
        if not path.startswith("/"):
            path = "/" + path

        return f"{scheme}://{netloc}{path}"


class InputSanitizer:
    def __init__(self):
        self.dangerous_patterns = [
            r"<script[^>]*>.*?</script>",
            r"on\w+\s*=",
            r"javascript:",
            r"vbscript:",
            r"data:",
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\.\./",
            r"\.\.\\",
            r"[;\|\&\$]",
            r"`.*?`",
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.dangerous_patterns]

    def sanitize_string(self, input_str: str, max_length: int = 4096) -> str:
        if not input_str:
            return ""

        s = input_str[:max_length]
        for p in self.compiled_patterns:
            s = p.sub("", s)
            
        s = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", s)
        s = " ".join(s.split())
        return s

    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in headers.items():
            if not k or v is None:
                continue
            ck = self.sanitize_string(str(k).strip(), 256)
            cv = self.sanitize_string(str(v).strip(), 2048)
            if ck and cv:
                out[ck] = cv
        return out

    def sanitize_filename(self, filename: str) -> str:
        if not filename:
            return "unknown"
        name = filename.split("/")[-1].split("\\")[-1]
        name = re.sub(r'[<>:"/\\|?*\$\']', "_", name)
        if len(name) > 255:
            root, ext = os.path.splitext(name)
            name = root[: max(1, 255 - len(ext))] + ext
        return name or "unknown"

    def validate_integer(self, value: Any, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
        try:
            iv = int(value)
        except (ValueError, TypeError):
            raise ValidationException(f"Invalid integer value: {value}")
        if min_val is not None and iv < min_val:
            raise ValidationException(f"Value {iv} below minimum {min_val}")
        if max_val is not None and iv > max_val:
            raise ValidationException(f"Value {iv} above maximum {max_val}")
        return iv

url_validator = URLValidator()
input_sanitizer = InputSanitizer()
