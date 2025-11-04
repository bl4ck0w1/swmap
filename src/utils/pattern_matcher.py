import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

@dataclass
class MatchResult:
    pattern_name: str
    matches: List[str]
    match_count: int
    context: Dict[str, Any] = None

    def __post_init__(self):
        if self.context is None:
            self.context = {}

class PatternMatcher:
    def __init__(self):
        self.patterns: Dict[str, str] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}

    def add_pattern(self, name: str, pattern: str, flags: int = re.IGNORECASE) -> None:
        self.patterns[name] = pattern
        try:
            self.compiled_patterns[name] = re.compile(pattern, flags)
        except re.error as e:
            raise ValueError(f"Invalid pattern '{name}': {e}")

    def add_patterns(self, patterns: Dict[str, str]) -> None:
        for name, pattern in patterns.items():
            self.add_pattern(name, pattern)

    def match_single(self, text: str, pattern_name: str) -> Optional[MatchResult]:
        if pattern_name not in self.compiled_patterns:
            return None
        pattern = self.compiled_patterns[pattern_name]
        matches = pattern.findall(text)
        if not matches:
            return None

        flattened: List[str] = []
        for m in matches:
            if isinstance(m, tuple):
                flattened.extend([x for x in m if x])
            else:
                flattened.append(m)

        return MatchResult(pattern_name=pattern_name, matches=flattened, match_count=len(flattened))

    def match_all(self, text: str) -> Dict[str, MatchResult]:
        results: Dict[str, MatchResult] = {}
        for name in self.compiled_patterns.keys():
            r = self.match_single(text, name)
            if r:
                results[name] = r
        return results

    def match_with_context(self, text: str, context_lines: int = 2) -> Dict[str, MatchResult]:
        results = self.match_all(text)
        lines = text.split("\n")
        for name, res in results.items():
            ctx_matches: List[Dict[str, Any]] = []
            for m in res.matches:
                for i, line in enumerate(lines):
                    if m in line:
                        start = max(0, i - context_lines)
                        end = min(len(lines), i + context_lines + 1)
                        ctx_matches.append(
                            {
                                "match": m,
                                "line_number": i + 1,
                                "context": "\n".join(lines[start:end]),
                            }
                        )
                        break
            res.context = {
                "matches_with_context": ctx_matches,
                "total_context_matches": len(ctx_matches),
            }
        return results


class SecurityPatterns:
    def __init__(self):
        self.matcher = PatternMatcher()
        self._load_security_patterns()

    def _load_security_patterns(self):
        sw_patterns = {
            "sw_register_basic": r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*['\"]([^'\"]+)['\"]",
            "sw_register_template": r"navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*`([^`]+)`",
            "sw_register_new": r"new\s+ServiceWorker\s*\(\s*['\"]([^'\"]+)['\"]",
            "sw_register_workbox": r"workbox\s*\.\s*.*\.register\s*\(\s*['\"]([^'\"]+)['\"]",
            "sw_common_names": r"(?:['\"])(?:sw\.js|service-worker\.js|firebase-messaging-sw\.js)(?:['\"])",
        }

        import_patterns = {
            "import_scripts_basic": r"importScripts\s*\(\s*['\"]([^'\"]+)['\"]",
            "import_scripts_template": r"importScripts\s*\(\s*`([^`]+)`",
            "import_scripts_multiple": r"importScripts\s*\(\s*([^)]+)\s*\)",
            "import_scripts_remote": r"importScripts\s*\(\s*['\"]https?://[^'\"]+['\"]",
        }

        cache_patterns = {
            "cache_open": r"caches\s*\.\s*open\s*\(\s*['\"`]([^'\"`]+)['\"`]",
            "cache_storage": r"new\s+CacheStorage\s*\(\s*['\"`]([^'\"`]+)['\"`]",
            "cache_add_all": r"cache\s*\.\s*addAll\s*\(\s*(\[[^\]]+\])",
            "cache_put": r"cache\s*\.\s*put\s*\(\s*[^,]+,\s*[^)]+\)",
        }

        workbox_patterns = {
            "workbox_global": r"workbox\.[a-zA-Z]",
            "workbox_manifest": r"self\.__WB_MANIFEST",
            "workbox_version": r"workbox-\d+\.\d+\.\d+",
            "workbox_import": r"from\s+[\'\"]workbox-",
            "workbox_precache": r"workbox\.precaching\.precacheAndRoute",
            "workbox_routing": r"workbox\.routing\.registerRoute",
            "workbox_strategies": r"workbox\.strategies",
        }

        security_patterns = {
            "eval_usage": r"\beval\s*\(",
            "function_constructor": r"new\s+Function\s*\(",
            "settimeout_string": r'setTimeout\s*\(\s*[^"\']',
            "setinterval_string": r'setInterval\s*\(\s*[^"\']',
            "inner_html": r"\.innerHTML\s*=",
            "document_write": r"document\.write\s*\(",
        }

        route_patterns = {
            "api_routes": r"[\'\"`](/api/[a-zA-Z0-9_\-./]+)[\'\"`]",
            "auth_routes": r"[\'\"`](/auth[a-zA-Z0-9_\-./]*)[\'\"`]",
            "user_routes": r"[\'\"`](/user[a-zA-Z0-9_\-./]*)[\'\"`]",
            "admin_routes": r"[\'\"`](/admin[a-zA-Z0-9_\-./]*)[\'\"`]",
            "generic_routes": r"[\'\"`](/[a-zA-Z0-9_\-./]{2,})[\'\"`]",
            "dashboard_routes": r"[\'\"`](/dashboard[a-zA-Z0-9_\-./]*)[\'\"`]",
            "graphql_routes": r"[\'\"`](/graphql[a-zA-Z0-9_\-./]*)[\'\"`]",
            "versioned_api_routes": r"[\'\"`](/api/v[0-9]+/[a-zA-Z0-9_\-./]*)[\'\"`]",
        }

        sensitive_refs = {
            "manifest_json": r"[\'\"`](/manifest\.json)[\'\"`]",
            "config_json": r"[\'\"`](/config(?:uration)?\.json)[\'\"`]",
            "env_json": r"[\'\"`](/env\.json)[\'\"`]",
        }

        all_patterns: Dict[str, str] = {}
        all_patterns.update(sw_patterns)
        all_patterns.update(import_patterns)
        all_patterns.update(cache_patterns)
        all_patterns.update(workbox_patterns)
        all_patterns.update(security_patterns)
        all_patterns.update(route_patterns)
        all_patterns.update(sensitive_refs)
        self.matcher.add_patterns(all_patterns)

    def analyze_service_worker(self, script_content: str) -> Dict[str, Any]:
        if not script_content:
            return {}
        results = self.matcher.match_with_context(script_content)
        analysis = {
            "registrations": self._extract_category(results, "sw_register"),
            "imports": self._extract_category(results, "import_scripts"),
            "caches": self._extract_category(results, "cache"),
            "workbox": self._extract_category(results, "workbox"),
            "security_issues": self._extract_category(
                results,
                ["eval", "function", "settimeout", "setinterval", "inner_html", "document_write"],
            ),
            "routes": self._extract_category(
                results,
                [
                    "api",
                    "auth",
                    "user",
                    "admin",
                    "generic_routes",
                    "dashboard_routes",
                    "graphql_routes",
                    "versioned_api_routes",
                ],
            ),
            "sensitive_refs": self._extract_category(
                results,
                ["manifest_json", "config_json", "env_json"],
            ),
        }
        analysis["summary"] = {
            "total_patterns_matched": len(results),
            "has_registrations": bool(analysis["registrations"]),
            "has_imports": bool(analysis["imports"]),
            "has_caches": bool(analysis["caches"]),
            "has_workbox": bool(analysis["workbox"]),
            "has_security_issues": bool(analysis["security_issues"]),
            "has_routes": bool(analysis["routes"]),
            "has_sensitive_refs": bool(analysis["sensitive_refs"]),
        }
        return analysis

    def _extract_category(self, results: Dict[str, MatchResult], patterns: Any) -> Dict[str, MatchResult]:
        if isinstance(patterns, str):
            patterns = [patterns]
        out: Dict[str, MatchResult] = {}
        for name, res in results.items():
            if any(p in name for p in patterns):
                out[name] = res
        return out

    def detect_workbox_usage(self, script_content: str) -> Tuple[bool, List[str]]:
        results = self.matcher.match_all(script_content)
        modules = set()
        is_workbox = any("workbox" in n for n in results.keys())
        if is_workbox:
            for name in results.keys():
                if "precache" in name:
                    modules.add("precaching")
                elif "routing" in name:
                    modules.add("routing")
                elif "strategies" in name:
                    modules.add("strategies")
        return is_workbox, sorted(modules)


pattern_matcher = PatternMatcher()
security_patterns = SecurityPatterns()
