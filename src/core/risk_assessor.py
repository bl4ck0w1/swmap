import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class RiskAssessor:
    def __init__(self):
        self.weights = {
            "SWA_HEADER_PRESENT": 12,                  
            "WORKBOX_DETECTED": 8,
            "SCOPE_OVERREACH": 28,                    
            "SENSITIVE_ROUTES_PRESENT": 14,            
            "WB_MATCH_SENSITIVE": 18,                 
            "CREDENTIALLED_FETCH_OR_AUTH_HEADERS": 18, 
            "AGGRESSIVE_ACTIVATION": 10,               
            "PRECACHING_PRESENT": 8,                  
            "POSSIBLE_CACHE_POISONING": 16,            
            "CLIENT_MSG_CHANNEL": 6,                  
            "THIRD_PARTY_IMPORTS": 8,                 
        }
        self.rt_multipliers = {
            "precaching": 1.05,
            "intercepts_majority": 1.10,
            "stale_while_revalidate_suspected": 1.05,
        }
        self.max_score = 100

    def calculate_risk_score(
        self,
        has_swa: bool,
        effective_scope: str,
        security_findings: Dict[str, Any],
        cache_names: List[str],
        routes: List[str],
        workbox_detected: bool = False,
        *,
        sw_url: Optional[str] = None,
        enhanced_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        try:
            score = 0
            breakdown: Dict[str, int] = {}
            rationale: List[str] = []

            if has_swa:
                score += self.weights["SWA_HEADER_PRESENT"]
                breakdown["SWA_HEADER_PRESENT"] = self.weights["SWA_HEADER_PRESENT"]
                rationale.append("Service-Worker-Allowed header present")

            if workbox_detected:
                score += self.weights["WORKBOX_DETECTED"]
                breakdown["WORKBOX_DETECTED"] = self.weights["WORKBOX_DETECTED"]
                rationale.append("Workbox usage detected")

            if self._scope_overreach(has_swa, effective_scope, sw_url):
                score += self.weights["SCOPE_OVERREACH"]
                breakdown["SCOPE_OVERREACH"] = self.weights["SCOPE_OVERREACH"]
                rationale.append("Scope overreach: SW not at '/', but effective scope is '/'")

            sf = security_findings or {}
            flags = sf.get("security_flags") or []
            indicators = sf.get("risk_indicators") or []
            concerns = sf.get("concerns") or []
            frameworks = sf.get("frameworks") or []
            wb_routes = sf.get("workbox_routes") or []
            sensitive_routes = sf.get("sensitive_routes") or []

            if sensitive_routes:
                score += self.weights["SENSITIVE_ROUTES_PRESENT"]
                breakdown["SENSITIVE_ROUTES_PRESENT"] = self.weights["SENSITIVE_ROUTES_PRESENT"]
                rationale.append(f"Sensitive routes referenced: {min(5,len(sensitive_routes))}+ sample(s)")

            if "WB_SENSITIVE_MATCHERS_PRESENT" in indicators:
                score += self.weights["WB_MATCH_SENSITIVE"]
                breakdown["WB_MATCH_SENSITIVE"] = self.weights["WB_MATCH_SENSITIVE"]
                rationale.append("Workbox route matchers cover sensitive paths")

            if "credentialed_fetch_or_auth_headers_detected" in concerns \
               or "CLIENT_SIDE_AUTH" in flags:
                score += self.weights["CREDENTIALLED_FETCH_OR_AUTH_HEADERS"]
                breakdown["CREDENTIALLED_FETCH_OR_AUTH_HEADERS"] = self.weights["CREDENTIALLED_FETCH_OR_AUTH_HEADERS"]
                rationale.append("Credentialed fetch/auth header handling present in SW")

            if "AGGRESSIVE_ACTIVATION" in flags:
                score += self.weights["AGGRESSIVE_ACTIVATION"]
                breakdown["AGGRESSIVE_ACTIVATION"] = self.weights["AGGRESSIVE_ACTIVATION"]
                rationale.append("Aggressive activation (skipWaiting/clients.claim)")

            if "precaching_detected" in concerns:
                score += self.weights["PRECACHING_PRESENT"]
                breakdown["PRECACHING_PRESENT"] = self.weights["PRECACHING_PRESENT"]
                rationale.append("Precache footprint detected")

            if "CACHE_POISONING_RISK" in flags or "AGGRESSIVE_CACHING" in indicators:
                score += self.weights["POSSIBLE_CACHE_POISONING"]
                breakdown["POSSIBLE_CACHE_POISONING"] = self.weights["POSSIBLE_CACHE_POISONING"]
                rationale.append("Cache manipulation patterns observed")

            if "client_messaging_channel_present" in concerns:
                score += self.weights["CLIENT_MSG_CHANNEL"]
                breakdown["CLIENT_MSG_CHANNEL"] = self.weights["CLIENT_MSG_CHANNEL"]
                rationale.append("Client messaging channel (BroadcastChannel/postMessage) present")

            if "THIRD_PARTY_IMPORTS" in flags:
                score += self.weights["THIRD_PARTY_IMPORTS"]
                breakdown["THIRD_PARTY_IMPORTS"] = self.weights["THIRD_PARTY_IMPORTS"]
                rationale.append("Third-party importScripts detected")
                
            if "angular" in frameworks:
                score += 2; breakdown["ANGULAR_FINGERPRINT"] = 2
                rationale.append("Angular SW fingerprint (consider probing /ngsw.json)")
            if "flutter" in frameworks:
                score += 3; breakdown["FLUTTER_FINGERPRINT"] = 3
                rationale.append("Flutter SW fingerprint (large RESOURCES manifests common)")

            score = self._calibrate_runtime(score, enhanced_analysis)

            score = min(int(score), self.max_score)
            return {
                "risk_score": score,
                "rationale": rationale,
                "breakdown": breakdown,
                "security_flags": flags,
                "risk_indicators": indicators,
                "frameworks": frameworks,
            }

        except Exception as e:
            logger.error(f"RiskAssessor failed: {e}")
            return {
                "risk_score": 0,
                "rationale": ["assessor_error"],
                "breakdown": {},
                "security_flags": [],
                "risk_indicators": [],
                "frameworks": [],
            }

    def _scope_overreach(self, has_swa: bool, effective_scope: str, sw_url: Optional[str]) -> bool:

        try:
            scope_path = (urlparse(effective_scope).path or "/").rstrip("/") or "/"
        except Exception:
            scope_path = "/"

        if scope_path != "/":
            return False
        if not has_swa:
            return False
        if not sw_url:
            return False
        try:
            sw_path = (urlparse(sw_url).path or "/").rstrip("/") or "/"
            return sw_path != "/"
        except Exception:
            return False

    def _calibrate_runtime(self, score: int, enhanced: Optional[Dict[str, Any]]) -> int:
        if not enhanced:
            return score
        dyn = (enhanced.get("headless_analysis") or {}) if isinstance(enhanced, dict) else {}
        labels = set(dyn.get("labels") or [])
        conf = float(dyn.get("confidence") or 0.5)
        out = float(score)
        for lbl, mult in self.rt_multipliers.items():
            if lbl in labels:
                out *= max(mult, conf)
        return int(out)

    def prioritize_findings(self, results: List[Any]) -> List[Any]:
        def s(r: Any) -> int:
            return int(getattr(r, "risk_score", 0) or (r.get("risk_score", 0) if isinstance(r, dict) else 0))
        try:
            return sorted(results, key=s, reverse=True)
        except Exception:
            return results

    def generate_risk_summary(self, results: List[Any]) -> Dict[str, Any]:
        scores: List[int] = []
        for r in (results or []):
            try:
                scores.append(int(getattr(r, "risk_score", 0) or (r.get("risk_score", 0) if isinstance(r, dict) else 0)))
            except Exception:
                pass
        if not scores:
            return {"total_targets": 0, "avg": 0, "max": 0, "bins": {"0-19":0,"20-39":0,"40-59":0,"60-79":0,"80-100":0}}
        bins = {"0-19":0,"20-39":0,"40-59":0,"60-79":0,"80-100":0}
        for sc in scores:
            if sc < 20: bins["0-19"] += 1
            elif sc < 40: bins["20-39"] += 1
            elif sc < 60: bins["40-59"] += 1
            elif sc < 80: bins["60-79"] += 1
            else: bins["80-100"] += 1
        return {
            "total_targets": len(scores),
            "avg": round(sum(scores)/len(scores), 2),
            "max": max(scores),
            "bins": bins,
        }
