import re
from urllib.parse import urlparse
from typing import Optional, Tuple
from ..models.exceptions import ScopeCalculationException

class ScopeCalculator:
    def __init__(self):
        self.invalid_scope_patterns = [
            r"\.\./",  
            r"//+",    
            r'[<>"\']', 
        ]
        self.compiled_patterns = [re.compile(p) for p in self.invalid_scope_patterns]

    def calculate_effective_scope(self, sw_url: str, swa_header: Optional[str] = None) -> str:
        try:
            if not sw_url:
                raise ScopeCalculationException("Service Worker URL is required")

            parsed_sw = urlparse(sw_url)
            if not parsed_sw.scheme or not parsed_sw.netloc:
                raise ScopeCalculationException(f"Invalid Service Worker URL: {sw_url}")

            base_scope = self._calculate_base_scope(parsed_sw)
            if swa_header is not None and swa_header.strip() != "":
                effective = self._apply_swa_header(base_scope, swa_header, parsed_sw)
            else:
                effective = base_scope

            final_scope = self._validate_and_normalize_scope(effective, parsed_sw)
            return final_scope

        except ScopeCalculationException:
            raise
        except Exception as e:
            raise ScopeCalculationException(f"Scope calculation failed: {e}")

    def _calculate_base_scope(self, parsed_sw) -> str:
        sw_path = parsed_sw.path or "/"
        if sw_path == "/":
            base_path = "/"
        else:
            base_path = "/".join(sw_path.split("/")[:-1]) or "/"
            if not base_path.endswith("/"):
                base_path += "/"
        return f"{parsed_sw.scheme}://{parsed_sw.netloc}{base_path}"

    def _apply_swa_header(self, base_scope: str, swa_header: str, parsed_sw) -> str:
        swa_value = swa_header.strip()
        if swa_value == "/":
            return f"{parsed_sw.scheme}://{parsed_sw.netloc}/"
        if swa_value.startswith("/"):
            return self._resolve_scope_path(swa_value, parsed_sw)
        raise ScopeCalculationException(f"Invalid Service-Worker-Allowed value: {swa_value}")

    def _resolve_scope_path(self, scope_path: str, parsed_sw) -> str:
        normalized_path = self._normalize_path(scope_path)
        return f"{parsed_sw.scheme}://{parsed_sw.netloc}{normalized_path}"

    def _normalize_path(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        path = re.sub(r"/\.(/|$)", "/", path)
        path = re.sub(r"/\.\.(/|$)", "/", path)
        path = re.sub(r"/+", "/", path)
        if not path.endswith("/"):
            path += "/"
        return path

    def _validate_and_normalize_scope(self, scope: str, parsed_sw) -> str:
        parsed_scope = urlparse(scope)
        
        if parsed_scope.scheme != parsed_sw.scheme:
            raise ScopeCalculationException(f"Scope scheme mismatch: {parsed_scope.scheme} vs {parsed_sw.scheme}")
        if parsed_scope.netloc != parsed_sw.netloc:
            raise ScopeCalculationException(f"Scope domain mismatch: {parsed_scope.netloc} vs {parsed_sw.netloc}")

        for p in self.compiled_patterns:
            if p.search(parsed_scope.path or ""):
                raise ScopeCalculationException(f"Dangerous pattern in scope path: {parsed_scope.path}")

        if (parsed_scope.path or "/").count("/") > 100:
            raise ScopeCalculationException("Scope path too deep")

        scheme = parsed_scope.scheme.lower()
        netloc = parsed_scope.netloc.lower()
        path = self._normalize_path(parsed_scope.path or "/")
        return f"{scheme}://{netloc}{path}"

    def is_scope_widened(self, sw_url: str, swa_header: Optional[str] = None) -> Tuple[bool, str]:
        try:
            base = self.calculate_effective_scope(sw_url, None)
            eff = self.calculate_effective_scope(sw_url, swa_header)
            return (eff != base), eff
        except ScopeCalculationException:
            return False, ""

    def get_scope_risk_level(self, scope: str) -> str:
        if not scope:
            return "low"
        path = urlparse(scope).path or "/"
        if path == "/":
            return "critical"
        segs = [s for s in path.split("/") if s]
        n = len(segs)
        if n == 0:
            return "critical"
        if n == 1:
            return "high"
        if n <= 3:
            return "medium"
        return "low"

scope_calculator = ScopeCalculator()
