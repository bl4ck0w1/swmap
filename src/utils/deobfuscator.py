import re
import logging
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger(__name__)

class DeobfuscationEngine:
    def __init__(self):
        self.string_patterns = {
            "single_quoted": r"'([^'\\]*(\\.[^'\\]*)*)'",
            "double_quoted": r'"([^"\\]*(\\.[^"\\]*)*)"',
            "template_literal": r"`([^`\\]*(\\.[^`\\]*)*)`",
        }

        self.minification_patterns = [
            (r"\s+", " "), 
            (r";\s*;", ";"),
            (r",\s*,", ","),
            (r"\(\s*\)", "()"),
            (r"{\s*}", "{}"),
            (r"\[\s*\]", "[]"),
        ]

        self.compiled_string_patterns = {
            key: re.compile(pattern) for key, pattern in self.string_patterns.items()
        }

    def normalize_code(self, code: str, preserve_strings: bool = True) -> str:
        if not code:
            return ""

        try:
            normalized = code
            string_map: Dict[str, str] = {}
            if preserve_strings:
                normalized, string_map = self._preserve_strings(normalized)
            normalized = self._basic_normalization(normalized)

            if preserve_strings:
                normalized = self._restore_strings(normalized, string_map)

            return normalized

        except Exception as e:
            logger.warning(f"Code normalization failed: {e}")
            return code 

    def _preserve_strings(self, code: str) -> Tuple[str, Dict[str, str]]:
        string_map: Dict[str, str] = {}
        counter = 0

        for string_type, pattern in self.compiled_string_patterns.items():

            def replace_match(match):
                nonlocal counter
                placeholder = f"__STRING_{counter}_{string_type}__"
                string_map[placeholder] = match.group(0)
                counter += 1
                return placeholder

            code = pattern.sub(replace_match, code)

        return code, string_map

    def _restore_strings(self, code: str, string_map: Dict[str, str]) -> str:
        for placeholder, original_string in string_map.items():
            code = code.replace(placeholder, original_string)
        return code

    def _basic_normalization(self, code: str) -> str:
        normalized = code
        
        for pattern, replacement in self.minification_patterns:
            normalized = re.sub(pattern, replacement, normalized)
        normalized = re.sub(r"(?m)(?<!:)//.*$", "", normalized)

        normalized = re.sub(r"/\*.*?\*/", "", normalized, flags=re.DOTALL)

        operators = [
            "=",
            "==",
            "===",
            "!=",
            "!==",
            "+",
            "-",
            "*",
            "/",
            "%",
            "&&",
            "||",
            ">",
            "<",
            ">=",
            "<=",
            "?",
            ":",
            ",",
        ]
        for op in operators:
            normalized = re.sub(r"\s*" + re.escape(op) + r"\s*", f" {op} ", normalized)

        normalized = re.sub(r"\s*\(\s*", "(", normalized)
        normalized = re.sub(r"\s*\)\s*", ")", normalized)
        normalized = re.sub(r"\s*{\s*", "{", normalized)
        normalized = re.sub(r"\s*}\s*", "}", normalized)
        normalized = re.sub(r"\s*\[\s*", "[", normalized)
        normalized = re.sub(r"\s*]\s*", "]", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()

        return normalized

    def extract_meaningful_tokens(self, code: str, min_length: int = 3) -> List[str]:
        if not code:
            return []

        try:
            normalized = self.normalize_code(code, preserve_strings=True)
            tokens = re.findall(r"[a-zA-Z_$][a-zA-Z0-9_$\.]*", normalized)

            keywords = {"if", "for", "var", "let", "const", "function", "return", "typeof", "new", "this", "self"}
            meaningful = []
            for t in tokens:
                if len(t) < min_length and t not in {"if", "for"}:
                    continue
                if t in keywords:
                    continue
                meaningful.append(t)

            return meaningful

        except Exception as e:
            logger.warning(f"Token extraction failed: {e}")
            return []

    def detect_obfuscation_techniques(self, code: str) -> Dict[str, Any]:
        if not code:
            return {}

        results: Dict[str, Any] = {
            "techniques_detected": [],
            "suspicious_patterns": [],
            "obfuscation_score": 0,
        }

        obfuscation_patterns = {
            "hex_encoded": r"\\x[0-9a-fA-F]{2}",
            "unicode_escapes": r"\\u[0-9a-fA-F]{4}",
            "excessive_escaping": r"\\\\+",
            "array_packing": r"\[[^]]{50,}\]",
            "string_concatenation": r"['\"][^'\"]*['\"]\s*\+\s*['\"][^'\"]*['\"]",
            "eval_with_construction": r"eval\s*\(\s*String\s*\.\s*fromCharCode",
            "base64_like": r"[A-Za-z0-9+/]{20,}={0,2}",
        }

        technique_scores: Dict[str, int] = {}

        for technique, pattern in obfuscation_patterns.items():
            matches = re.findall(pattern, code)
            if matches:
                results["techniques_detected"].append(technique)
                technique_scores[technique] = len(matches)

        if technique_scores:
            weights = {
                "hex_encoded": 2,
                "unicode_escapes": 2,
                "excessive_escaping": 1,
                "array_packing": 3,
                "string_concatenation": 2,
                "eval_with_construction": 5,
                "base64_like": 2,
            }
            total = sum(technique_scores.get(k, 0) * weights.get(k, 1) for k in results["techniques_detected"])
            results["obfuscation_score"] = min(100, total * 2)

        variable_pattern = r"\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)"
        variables = re.findall(variable_pattern, code)
        if variables:
            var_names = [v[1] for v in variables]
            entropy_scores = [self._calculate_name_entropy(name) for name in var_names]
            high_entropy_vars = [n for n, s in zip(var_names, entropy_scores) if s > 3.0]
            if high_entropy_vars:
                results["suspicious_patterns"].append("high_entropy_variables")
                results["obfuscation_score"] = min(100, results["obfuscation_score"] + len(high_entropy_vars) * 5)

        return results

    def _calculate_name_entropy(self, name: str) -> float:
        if len(name) <= 1:
            return 0.0

        import math
        from collections import Counter

        freq = Counter(name)
        total = len(name)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

deobfuscator = DeobfuscationEngine()
