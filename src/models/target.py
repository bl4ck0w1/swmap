from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import re
import hashlib
import ipaddress
from .exceptions import URLValidationException, ConfigurationException

@dataclass
class ScanConfig:
    parallel: int = 6
    timeout: int = 15
    max_sw_bytes: int = 512 * 1024  
    max_routes: int = 50
    user_agent: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Optional[str] = None
    probe_common_paths: bool = True
    deep_analysis: bool = False
    risk_threshold: int = 0
    output_format: str = "tsv"  
    quiet_mode: bool = False
    verbose: bool = False
    no_risk_assessment: bool = False  

    def validate(self):
        errors = []

        if not (1 <= self.parallel <= 50):
            errors.append("Parallel must be between 1 and 50")

        if not (1 <= self.timeout <= 300):
            errors.append("Timeout must be between 1 and 300 seconds")

        if not (1024 <= self.max_sw_bytes <= 10 * 1024 * 1024):
            errors.append("Max SW bytes must be between 1KB and 10MB")

        if not (0 <= self.max_routes <= 1000):
            errors.append("Max routes must be between 0 and 1000")

        if not (0 <= self.risk_threshold <= 100):
            errors.append("Risk threshold must be between 0 and 100")

        if self.output_format not in ("tsv", "json"):
            errors.append("Output format must be 'tsv' or 'json'")

        if not isinstance(self.no_risk_assessment, bool):
            errors.append("no_risk_assessment must be boolean")

        for k, v in self.headers.items():
            if not k or v is None or v == "":
                errors.append(f"Invalid header: {k}={v}")

        if errors:
            raise ConfigurationException(
                "Configuration validation failed",
                context={"errors": errors, "config": self.to_dict()},
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "parallel": self.parallel,
            "timeout": self.timeout,
            "max_sw_bytes": self.max_sw_bytes,
            "max_routes": self.max_routes,
            "user_agent": self.user_agent,
            "headers": self.headers.copy(),
            "cookies": self.cookies,
            "probe_common_paths": self.probe_common_paths,
            "deep_analysis": self.deep_analysis,
            "risk_threshold": self.risk_threshold,
            "output_format": self.output_format,
            "quiet_mode": self.quiet_mode,
            "verbose": self.verbose,
            "no_risk_assessment": self.no_risk_assessment,
        }


@dataclass(eq=False)
class ScanTarget:
    url: str
    id: Optional[str] = None
    priority: int = 1  
    metadata: Dict[str, Any] = field(default_factory=dict)

    _normalized_url: Optional[str] = None
    _parsed_url: Optional[Any] = None

    def __post_init__(self):
        self._validate_url()
        self._normalize_url()
        if not self.id:
            self.id = self._generate_id()

    def _validate_url(self):
        if not self.url or not isinstance(self.url, str):
            raise URLValidationException("URL must be a non-empty string")

        try:
            parsed = urlparse(self.url)

            if parsed.scheme not in ("http", "https"):
                raise URLValidationException(
                    "URL must use http or https scheme", field="scheme", value=parsed.scheme
                )

            if not parsed.netloc:
                raise URLValidationException(
                    "URL must contain a network location", field="netloc", value=parsed.netloc
                )

            host = parsed.hostname or ""
            if self._is_internal_host(host):
                raise URLValidationException(
                    "URL appears to target internal/private host",
                    field="host",
                    value=host,
                    context={"security_note": "Blocked potential internal target"},
                )

            if parsed.path and ".." in parsed.path:
                raise URLValidationException(
                    "URL path contains potential traversal sequences", field="path", value=parsed.path
                )

        except URLValidationException:
            raise
        except Exception as e:
            raise URLValidationException(f"URL parsing failed: {e}")

    def _normalize_url(self):
        try:
            parsed = urlparse(self.url)
            scheme = parsed.scheme.lower()
            netloc = (parsed.netloc or "").lower()
            host = parsed.hostname or ""
            port = parsed.port
            if port and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                netloc = host 

            path = parsed.path or "/"
            if not path.startswith("/"):
                path = "/" + path

            self._normalized_url = f"{scheme}://{netloc}{path}"
            self._parsed_url = parsed
        except Exception as e:
            raise URLValidationException(f"URL normalization failed: {e}")

    def _generate_id(self) -> str:
        url_hash = hashlib.md5(self.normalized_url.encode("utf-8")).hexdigest()[:8]
        return f"target_{url_hash}"

    def _is_internal_host(self, host: str) -> bool:
        host_clean = host.strip("[]").lower()
        try:
            ip = ipaddress.ip_address(host_clean)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True
        except ValueError:
            pass  

        internal_suffixes = (".local", ".internal", ".localhost")
        if host_clean.endswith(internal_suffixes) or host_clean in ("localhost",):
            return True

        return False

    @property
    def normalized_url(self) -> str:
        return self._normalized_url or self.url

    @property
    def domain(self) -> str:
        if self._parsed_url:
            return (self._parsed_url.hostname or "").lower()
        return (urlparse(self.url).hostname or "").lower()

    @property
    def base_domain(self) -> str:
        parts = (self.domain or "").split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return self.domain

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "base_domain": self.base_domain,
            "priority": self.priority,
            "metadata": self.metadata.copy(),
        }

    def __hash__(self):
        return hash(self.normalized_url)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ScanTarget) and self.normalized_url == other.normalized_url


@dataclass
class TargetBatch:
    targets: List[ScanTarget]
    batch_id: Optional[str] = None
    created_at: float = field(default_factory=lambda: __import__("time").time())

    def __post_init__(self):
        if not self.batch_id:
            target_ids = "".join(sorted(t.id for t in self.targets))
            batch_hash = hashlib.md5(target_ids.encode()).hexdigest()[:12]
            self.batch_id = f"batch_{batch_hash}"

    def add_target(self, target: ScanTarget):
        if target not in self.targets:
            self.targets.append(target)

    def remove_target(self, target: ScanTarget):
        if target in self.targets:
            self.targets.remove(target)

    def filter_by_domain(self, domain: str) -> "TargetBatch":
        filtered = [t for t in self.targets if t.domain == domain.lower()]
        return TargetBatch(filtered, f"{self.batch_id}_filtered_{domain}")

    def filter_by_priority(self, min_priority: int = 1) -> "TargetBatch":
        filtered = [t for t in self.targets if t.priority >= min_priority]
        return TargetBatch(filtered, f"{self.batch_id}_priority_{min_priority}")

    def deduplicate(self) -> "TargetBatch":
        unique_targets = list(set(self.targets))
        return TargetBatch(unique_targets, f"{self.batch_id}_deduplicated")

    def chunk(self, chunk_size: int) -> List["TargetBatch"]:
        chunks: List[TargetBatch] = []
        for i in range(0, len(self.targets), chunk_size):
            chunk_targets = self.targets[i : i + chunk_size]
            chunks.append(TargetBatch(chunk_targets, f"{self.batch_id}_chunk_{i // chunk_size}"))
        return chunks

    @property
    def count(self) -> int:
        return len(self.targets)

    @property
    def domains(self) -> List[str]:
        return sorted({t.domain for t in self.targets})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "target_count": self.count,
            "domains": self.domains,
            "created_at": self.created_at,
            "targets": [t.to_dict() for t in self.targets],
        }
