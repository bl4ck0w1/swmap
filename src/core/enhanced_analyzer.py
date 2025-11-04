from __future__ import annotations
import logging
import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Set, Deque, Tuple
from collections import deque
from urllib.parse import urljoin, urlparse
from .ast_analyzer import ASTAnalyzer, ASTAnalyzerConfig
from .headless_analyzer import HeadlessAnalysisManager, HeadlessConfig
from .fetcher import AdvancedFetcher
from ..utils.logger import get_logger
from ..models.exceptions import SecurityException

logger = get_logger("enhanced_analyzer")

@dataclass
class EnhancedAnalysisConfig:
    enable_ast: bool = True
    ast_max_depth: int = 2                      
    ast_same_origin_only: bool = True
    ast_request_timeout: int = 10               
    ast_total_bytes_cap: int = 1_500_000        
    per_module_bytes_cap: int = 512_000         
    allow_brotli_for_ast: bool = True
    ast_parser_fallback: bool = True            
    ast_node_path: str = "node"
    ast_fallback_max_ms: int = 4000            
    enable_headless: bool = False             
    headless_timeout_ms: int = 30_000
    headless_max_routes: int = 25
    headless_crawl: bool = True
    headless_crawl_limit: int = 50
    headless_backoff_attempts: int = 4
    headless_backoff_ms: int = 500
    headless_prove_interception: bool = True
    headless_prove_precache: bool = True
    headless_prove_swr: bool = True
    headless_login_script: Optional[str] = None
    headless_login_wait_selector: Optional[str] = None
    headless_route_seeds: List[str] = field(default_factory=list)
    headless_extra_headers: Dict[str, str] = field(default_factory=dict)
    headless_offline_replay: bool = False
    headless_offline_wait_ms: int = 1500
    headless_logout_url: Optional[str] = None
    headless_logout_script: Optional[str] = None
    headless_nav_delay_ms: int = 0
    proxy_url: Optional[str] = None


class EnhancedAnalyzer:

    def __init__(self, config: Optional[EnhancedAnalysisConfig] = None):
        self.cfg = config or EnhancedAnalysisConfig()

        self.ast_analyzer: Optional[ASTAnalyzer] = None
        if self.cfg.enable_ast:
            self.ast_analyzer = ASTAnalyzer(
                config=ASTAnalyzerConfig(
                    timeout_sec=max(5, self.cfg.ast_request_timeout),
                    max_depth=0,                 
                    node_path="node",
                )
            )

        self._fetcher = AdvancedFetcher(
            timeout=self.cfg.ast_request_timeout,
            proxy=self.cfg.proxy_url,
        )
        if self.cfg.allow_brotli_for_ast:
            try:
                import brotli  
                enc = self._fetcher.session.headers.get("Accept-Encoding", "")
                if "br" not in enc:
                    self._fetcher.session.headers["Accept-Encoding"] = (enc + ", br").strip(", ")
            except Exception:
                pass

        self.headless_manager: Optional[HeadlessAnalysisManager] = None
        if self.cfg.enable_headless:
            self.headless_manager = HeadlessAnalysisManager(
                enable_headless=True,
                config=HeadlessConfig(
                    timeout_ms=self.cfg.headless_timeout_ms,
                    backoff_attempts=self.cfg.headless_backoff_attempts,
                    backoff_ms=self.cfg.headless_backoff_ms,
                    max_routes=self.cfg.headless_max_routes,
                    crawl_links=self.cfg.headless_crawl,
                    crawl_limit=self.cfg.headless_crawl_limit,
                    prove_interception=self.cfg.headless_prove_interception,
                    prove_precache=self.cfg.headless_prove_precache,
                    prove_swr=self.cfg.headless_prove_swr,
                    login_script_path=self.cfg.headless_login_script,
                    login_wait_selector=self.cfg.headless_login_wait_selector,
                    route_seeds=self.cfg.headless_route_seeds,
                    extra_headers=self.cfg.headless_extra_headers,
                    offline_replay=self.cfg.headless_offline_replay,
                    offline_wait_ms=self.cfg.headless_offline_wait_ms,
                    logout_url=self.cfg.headless_logout_url,
                    logout_script=self.cfg.headless_logout_script,
                    nav_delay_ms=self.cfg.headless_nav_delay_ms,
                    proxy_url=self.cfg.proxy_url,
                ),
            )

    def analyze_service_worker(
        self,
        javascript_code: str,
        target_url: Optional[str] = None,
        static_findings: Optional[Dict[str, Any]] = None,
        base_url_for_ast: Optional[str] = None,
        effective_scope: Optional[str] = None,
        seed_routes: Optional[List[str]] = None,
        request_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:

        out: Dict[str, Any] = {
            "analysis_methods": [],
            "ast_analysis": {},
            "headless_validation": {}, 
            "enhanced_findings": {},
            "confidence_score": 0.5,
            "warnings": [],
        }

        if user_agent and self._fetcher.session.headers.get("User-Agent") != user_agent:
            self._fetcher.user_agent = user_agent
            self._fetcher.session.headers["User-Agent"] = user_agent

        if self.cfg.enable_ast and self.ast_analyzer:
            try:
                if (self.cfg.ast_max_depth or 0) > 0 and base_url_for_ast:
                    merged_ast, modules_meta, warnings = self._ast_recursive_harvest(
                        root_url=base_url_for_ast,
                        root_code=javascript_code,
                        max_depth=self.cfg.ast_max_depth,
                        same_origin_only=self.cfg.ast_same_origin_only,
                        total_bytes_cap=self.cfg.ast_total_bytes_cap,
                        per_module_cap=self.cfg.per_module_bytes_cap,
                        request_headers=request_headers or {},
                        cookies=cookies,
                    )
                    out["ast_analysis"] = {
                        "graph": merged_ast,
                        "modules": modules_meta,
                        "warnings": warnings,
                    }
                    out["warnings"].extend(warnings)
                    out["analysis_methods"].append("ast-recursive")
                    if not merged_ast.get("errors"):
                        out["confidence_score"] *= 1.35
                    out["enhanced_findings"].update(self._from_ast(merged_ast))
                else:
                    ast = self._analyze_ast_resilient(javascript_code)
                    out["ast_analysis"] = ast
                    out["analysis_methods"].append("ast")
                    if not ast.get("errors"):
                        out["confidence_score"] *= 1.25
                    out["enhanced_findings"].update(self._from_ast(ast))
            except Exception as e:
                msg = f"AST analysis failed: {e}"
                logger.debug(msg)
                out["warnings"].append(msg)

        can_run_headless = (
            self.cfg.enable_headless
            and self.headless_manager is not None
            and target_url is not None
            and static_findings is not None
        )

        if can_run_headless:
            routes_seen = (static_findings.get("routes_seen") or
                           static_findings.get("routes") or [])
            cache_names = static_findings.get("cache_names") or []
            workbox_detected = static_findings.get("workbox_detected") or static_findings.get("workbox") or False

            cfg = self.headless_manager.cfg
            orig_max_routes = cfg.max_routes
            orig_crawl_links = cfg.crawl_links
            orig_prove_precache = cfg.prove_precache
            orig_prove_swr = cfg.prove_swr

            if not routes_seen and not cache_names and not workbox_detected:
                cfg.max_routes = min(cfg.max_routes, 3)
                cfg.crawl_links = False
                cfg.prove_precache = False
                cfg.prove_swr = False

            self._sync_headless_identity(
                request_headers=request_headers,
                cookies=cookies,
                user_agent=user_agent,
                seed_routes=seed_routes,
            )
            try:
                seeds_for_run = (seed_routes or []) + (self.headless_manager.cfg.route_seeds or [])
                validated = self.headless_manager.validate_static_findings(
                    static_findings=static_findings,
                    target_url=target_url,
                    seed_routes=seeds_for_run,
                    effective_scope=effective_scope,
                )
                headless_data = validated.get("headless_analysis", {}) or {}

                if not headless_data.get("responses"):
                    headless_data.pop("responses", None)

                if headless_data:
                    out["headless_validation"] = headless_data
                    out["analysis_methods"].append("headless")

                if "validation_confidence" in validated:
                    out["confidence_score"] *= float(validated["validation_confidence"] or 1.0)
            except Exception as e:
                msg = f"Headless validation failed: {e}"
                logger.debug(msg)
                out["warnings"].append(msg)
            finally:
                cfg.max_routes = orig_max_routes
                cfg.crawl_links = orig_crawl_links
                cfg.prove_precache = orig_prove_precache
                cfg.prove_swr = orig_prove_swr

        out["confidence_score"] = min(out["confidence_score"], 1.0)
        return out

    def _sync_headless_identity(
        self,
        request_headers: Optional[Dict[str, str]],
        cookies: Optional[str],
        user_agent: Optional[str],
        seed_routes: Optional[List[str]],
    ) -> None:

        if not self.headless_manager:
            return

        cfg = self.headless_manager.cfg

        merged_headers: Dict[str, str] = dict(cfg.extra_headers or {})
        if request_headers:
            merged_headers.update(request_headers)
        if user_agent:
            merged_headers["User-Agent"] = user_agent
        if cookies:
            merged_headers["Cookie"] = cookies
        cfg.extra_headers = merged_headers

        if seed_routes:
            existing = list(cfg.route_seeds or [])
            for s in seed_routes:
                if s not in existing:
                    existing.append(s)
            cfg.route_seeds = existing

        if self.cfg.proxy_url and cfg.proxy_url != self.cfg.proxy_url:
            cfg.proxy_url = self.cfg.proxy_url


    def _ast_recursive_harvest(
        self,
        root_url: str,
        root_code: str,
        max_depth: int,
        same_origin_only: bool,
        total_bytes_cap: int,
        per_module_cap: int,
        request_headers: Dict[str, str],
        cookies: Optional[str],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
        warnings: List[str] = []
        merged: Dict[str, Any] = self._empty_ast_bucket()
        modules_meta: List[Dict[str, Any]] = []
        root_origin = urlparse(root_url).netloc
        visited: Set[str] = set()
        q: Deque[Tuple[str, Optional[str], int, Optional[str]]] = deque()
        q.append((root_url, root_code, 0, None))

        total_bytes = len((root_code or "").encode("utf-8", errors="ignore"))
        if total_bytes > total_bytes_cap:
            warnings.append("Root SW exceeds global AST bytes cap; parsed root only.")
            ast_root = self._analyze_ast_resilient(root_code or "")
            self._merge_ast(merged, ast_root)
            modules_meta.append({
                "url": root_url, "parent": None, "depth": 0,
                "bytes": total_bytes, "status": 200, "note": "root-only (global bytes cap)"
            })
            return merged, modules_meta, warnings

        while q:
            mod_url, inline_code, depth, parent = q.popleft()
            if mod_url in visited:
                continue
            visited.add(mod_url)

            code: str
            status: int = 200
            truncated: bool = False
            waf_note: Optional[str] = None

            if inline_code is not None:
                code = inline_code
            else:
                if total_bytes >= total_bytes_cap:
                    warnings.append("AST global bytes cap reached; stopping recursion.")
                    break

                try:
                    code, hdrs, status, truncated, waf_note = self._safe_fetch(
                        mod_url, request_headers, cookies, per_module_cap
                    )
                except Exception as e:
                    logger.debug(f"AST recursion fetch failed for {mod_url}: {e}")
                    code, hdrs, status = "", {}, 0

                if truncated:
                    note = f"truncated to {per_module_cap} bytes"
                    warnings.append(f"Module {mod_url} {note}.")
                if waf_note:
                    warnings.append(f"{waf_note} @ {mod_url}")

                total_bytes += len((code or "").encode("utf-8", errors="ignore"))

            ast = self._analyze_ast_resilient(code or "")
            self._merge_ast(merged, ast)
            modules_meta.append({
                "url": mod_url,
                "parent": parent,
                "depth": depth,
                "bytes": len((code or "").encode("utf-8", errors="ignore")),
                "status": status,
                "errors": ast.get("errors", []),
                "truncated": truncated,
                "blocked": bool(waf_note),
                "note": waf_note or ("truncated" if truncated else None),
            })

            if depth < max_depth:
                for src in self._extract_import_sources(ast):
                    child_abs = urljoin(mod_url, src)
                    if same_origin_only and urlparse(child_abs).netloc != root_origin:
                        continue
                    if child_abs in visited:
                        continue
                    q.append((child_abs, None, depth + 1, mod_url))

        for k in (
            "imports", "eventListeners", "cacheOperations", "fetchHandlers",
            "workboxUsage", "routes", "strategies", "dangerousPatterns", "errors",
        ):
            merged.setdefault(k, [])

        return merged, modules_meta, warnings

    def _safe_fetch(
        self,
        url: str,
        headers: Dict[str, str],
        cookies: Optional[str],
        per_module_cap: int,
    ) -> Tuple[str, Dict[str, str], int, bool, Optional[str]]:
        req_headers = headers.copy() if headers else {}
        truncated = False
        waf_note: Optional[str] = None

        try:
            text, hdrs, status = self._fetcher.fetch_url(
                url,
                headers=req_headers,
                cookies=cookies,
                max_bytes=per_module_cap,
            )
            waf_note = self._classify_block(hdrs, status, text)
            return text or "", hdrs, status, False, waf_note

        except SecurityException as e:
            logger.debug(f"Per-module cap triggered on {url}: {e}")
            preview, hdrs, status = self._range_fetch_preview(url, req_headers, cookies, per_module_cap)
            truncated = True
            waf_note = self._classify_block(hdrs, status, preview)
            return preview, hdrs, status, truncated, waf_note

        except Exception as e:
            logger.debug(f"AST fetch exception on {url}: {e}")
            preview, hdrs, status = self._range_fetch_preview(url, req_headers, cookies, per_module_cap)
            truncated = True if preview else False
            waf_note = self._classify_block(hdrs, status, preview)
            return preview, hdrs, status, truncated, waf_note

    def _range_fetch_preview(
        self,
        url: str,
        headers: Dict[str, str],
        cookies: Optional[str],
        cap: int,
    ) -> Tuple[str, Dict[str, str], int]:
        try:
            h = self._fetcher.session.headers.copy()
            h.update(headers or {})
            if cookies:
                h["Cookie"] = cookies
            h["Range"] = f"bytes=0-{max(0, cap - 1)}"
            r = self._fetcher.session.get(
                url,
                headers=h,
                timeout=self._fetcher.timeout,
                stream=True,
                allow_redirects=True,
            )
            content = b""
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                content += chunk
                if len(content) >= cap:
                    break

            encoding = r.encoding or "utf-8"
            try:
                text = (content or b"").decode(encoding, errors="replace")
            except LookupError:
                text = (content or b"").decode("utf-8", errors="replace")
            return text, dict(r.headers), int(r.status_code)
        except Exception as e:
            logger.debug(f"Range preview failed for {url}: {e}")
            return "", {}, 0

    @staticmethod
    def _classify_block(headers: Dict[str, str], status: int, body: str) -> Optional[str]:
        h = {k.lower(): v for k, v in (headers or {}).items()}
        server = h.get("server", "")
        cf = any(k.startswith("cf-") for k in h.keys()) or "cloudflare" in server.lower()
        ak = "akamai" in server.lower() or any("akamai" in k for k in h.keys())
        fastly = "fastly" in server.lower() or "x-served-by" in h
        aws = "awselb" in server.lower() or "amazon" in server.lower()
        sec = h.get("x-akamai-denyreason") or h.get("x-cdn") or h.get("x-bot") or ""

        text = (body or "")[:2048].lower()

        if status in (401, 403, 405, 406, 409, 410, 412, 418, 429, 451, 503):
            if cf:
                return f"blocked-by-cloudflare status={status}"
            if ak:
                return f"blocked-by-akamai status={status}"
            if fastly:
                return f"blocked-by-fastly status={status}"
            if aws:
                return f"blocked-by-aws status={status}"
            if "access denied" in text or "permission denied" in text or "captcha" in text:
                return f"blocked-by-waf status={status}"
        if "captcha" in text:
            return "captcha-challenge"
        if "bot detected" in text or "bot protection" in text or "automated access" in text:
            return "bot-manager-challenge"
        if sec:
            return f"edge-block ({sec})"
        return None

    def _analyze_ast_resilient(self, code: str) -> Dict[str, Any]:
        try:
            return self.ast_analyzer.analyze_with_ast(code or "")
        except Exception as e:
            logger.debug(f"Primary AST parse failed, attempting Node fallback: {e}")
            if not self.cfg.ast_parser_fallback:
                return {"errors": [str(e)]}
            try:
                node_ast = self._node_fallback_parse(code or "")
                if node_ast:
                    return node_ast
            except Exception as e2:
                return {"errors": [f"node-fallback-failed: {e2}"]}
            return {"errors": [str(e)]}

    def _node_fallback_parse(self, code: str) -> Dict[str, Any]:
        js_driver = r"""
(async function(){
  function tryReq(name){ try { return require(name); } catch(_) { return null; } }
  const src = process.env.__SWMAP_CODE__ || "";
  let parser = tryReq("meriyah") || tryReq("esprima") || tryReq("acorn");
  if(!parser){ console.log(JSON.stringify({errors:["no-node-parser"]})); return; }

  let ast;
  try {
    if(parser.parseScript){ ast = parser.parseScript(src, { next: true, module: true, tolerant: true }); }
    else if(parser.parse){ ast = parser.parse(src, { ecmaVersion: "latest", sourceType: "module", allowHashBang: true }); }
    else { ast = parser.parse(src); }
  } catch(e){
    console.log(JSON.stringify({errors:["parse-error:"+String(e && e.message || e)]})); return;
  }

  const out = { imports:[], eventListeners:[], routes:[], dangerousPatterns:[], cacheOperations:[], strategies:[], fetchHandlers:[] };

  function litStr(node){
    if(!node) return null;
    if(node.type==="Literal" && typeof node.value==="string") return node.value;
    if(node.type==="TemplateLiteral" && node.quasis && node.quasis.length===1) return node.quasis[0].value.cooked || null;
    return null;
  }

  function walk(n, parent){
    if(!n || typeof n!=="object") return;
    if(n.type==="ImportDeclaration" && n.source && typeof n.source.value==="string"){
      out.imports.push({type:"esm", source:n.source.value});
    }
    if(n.type==="CallExpression" && n.callee && n.callee.type==="MemberExpression"){
      const obj = n.callee.object && n.callee.object.name || "";
      const prop = n.callee.property && (n.callee.property.name || (n.callee.property.value || ""));
      if(prop==="addEventListener" && n.arguments && n.arguments.length>0){
        const ev = litStr(n.arguments[0]);
        if(ev){ out.eventListeners.push({event:ev}); }
      }
      if(prop==="registerRoute" && n.arguments && n.arguments.length>0){
        const a0 = n.arguments[0];
        const s = litStr(a0);
        if(s && s.startsWith("/")) out.routes.push({type:"literal", expression:s});
        if(a0 && a0.type==="NewExpression" && a0.callee && a0.callee.name==="RegExp" && a0.arguments && a0.arguments[0]){
          const rx = litStr(a0.arguments[0]); if(rx) out.routes.push({type:"regexp", expression:rx});
        }
      }
    }
    if(n.type==="CallExpression" && n.callee){
      if(n.callee.name==="eval"){ out.dangerousPatterns.push({type:"eval"}); }
      if(n.callee.type==="Identifier" && n.callee.name==="Function"){ out.dangerousPatterns.push({type:"functionConstructor"}); }
      if(n.callee.type==="Identifier" && (n.callee.name==="setTimeout"||n.callee.name==="setInterval")){
        if(n.arguments && n.arguments[0] && litStr(n.arguments[0])) {
          out.dangerousPatterns.push({type: (n.callee.name==="setTimeout" ? "setTimeoutString":"setIntervalString")});
        }
      }
    }

    for(const k in n){
      const v = n[k];
      if(Array.isArray(v)){ for(const c of v) walk(c, n); }
      else if(v && typeof v==="object"){ walk(v, n); }
    }
  }
  walk(ast, null);

  console.log(JSON.stringify(out));
})();
"""
        env = os.environ.copy()
        env["__SWMAP_CODE__"] = code
        cmd = [self.cfg.ast_node_path, "--eval", js_driver]
        try:
            proc = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(1, int(self.cfg.ast_fallback_max_ms / 1000)),
                check=False,
            )
        except Exception as e:
            return {"errors": [f"node-exec-failed: {e}"]}

        if proc.returncode != 0:
            return {"errors": [f"node-exit-{proc.returncode}: {proc.stderr.decode('utf-8','ignore')[:200]}"]}

        try:
            out = json.loads(proc.stdout.decode("utf-8", "replace") or "{}")
            if not isinstance(out, dict):
                return {"errors": ["node-parse-invalid-output"]}
            return out
        except Exception as e:
            return {"errors": [f"node-json-failed: {e}"]}

    @staticmethod
    def _empty_ast_bucket() -> Dict[str, Any]:
        return {
            "imports": [],
            "eventListeners": [],
            "cacheOperations": [],
            "fetchHandlers": [],
            "workboxUsage": [],
            "routes": [],
            "strategies": [],
            "dangerousPatterns": [],
            "errors": [],
        }

    @staticmethod
    def _merge_ast(acc: Dict[str, Any], nxt: Dict[str, Any]) -> None:
        for k in (
            "imports", "eventListeners", "cacheOperations", "fetchHandlers",
            "workboxUsage", "routes", "strategies", "dangerousPatterns", "errors",
        ):
            acc.setdefault(k, [])
            if nxt.get(k):
                acc[k].extend(nxt[k])

    @staticmethod
    def _extract_import_sources(ast: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        for imp in ast.get("imports", []):
            src = (imp or {}).get("source")
            if not src or not isinstance(src, str):
                continue
            out.append(src)
        return out

    @staticmethod
    def _regex_to_hint(rx: str) -> Optional[str]:
        if not rx:
            return None
        import re as _re
        s = rx.strip().strip("^").strip("$")
        m = _re.search(r"(/[^/()|?*+\\\s]+)", s)
        if not m:
            m2 = _re.search(r"(^[A-Za-z0-9_\-]+/)", s)
            if m2:
                return "/" + m2.group(1).strip("/")
            return None
        base = m.group(1)
        base = _re.split(r"[\\\?\*\+\(\)\|\[\]\{\}]", base)[0]
        if not base.endswith("/"):
            base += "/"
        return base if base.startswith("/") else "/" + base.lstrip("/")

    @staticmethod
    def _risk_of_danger(typ: Optional[str]) -> str:
        m = {
            "eval": "HIGH",
            "functionConstructor": "HIGH",
            "setTimeoutString": "MEDIUM",
            "setIntervalString": "MEDIUM",
        }
        return m.get(typ or "", "LOW")

    def _from_ast(self, ast: Dict[str, Any]) -> Dict[str, Any]:
        findings = {
            "precise_imports": [],
            "event_handlers": [],
            "cache_precache": [],
            "cache_names": [],
            "route_handlers": [],
            "route_prefix_hints": [],
            "dangerous_operations": [],
            "strategies": [],
            "auth_sensitive_hints": [],
        }

        for imp in ast.get("imports", []):
            if imp.get("source"):
                findings["precise_imports"].append(
                    {"type": imp.get("type", "import"), "source": imp.get("source")}
                )

        for ev in ast.get("eventListeners", []):
            findings["event_handlers"].append(
                {"event": ev.get("event"), "location": ev.get("location", "unknown")}
            )

        cache_names: Set[str] = set()
        for op in ast.get("cacheOperations", []):
            if op.get("type") == "cacheAddAll":
                urls = op.get("urls") or []
                findings["cache_precache"].append({"urls": urls})
            if op.get("cacheName"):
                n = str(op.get("cacheName")).strip()
                if n:
                    cache_names.add(n)
        for wb in ast.get("workboxUsage", []):
            for key in ("prefix", "suffix", "precache"):
                v = wb.get(key)
                if v and isinstance(v, str):
                    cache_names.add(v.strip())
        findings["cache_names"] = sorted(cache_names)

        route_prefixes: Set[str] = set()
        for r in ast.get("routes", []):
            expr = r.get("expression", "")
            typ = r.get("type", "unknown")
            findings["route_handlers"].append(
                {"type": typ, "expression": expr, "location": r.get("location", "unknown")}
            )
            if typ.lower().startswith("regex") or "regexp" in typ.lower():
                hint = self._regex_to_hint(expr)
                if hint:
                    route_prefixes.add(hint)
            elif isinstance(expr, str) and expr.startswith("/"):
                parent = expr if expr.endswith("/") else (expr.rsplit("/", 1)[0] + "/") if "/" in expr[1:] else expr
                if parent and parent.startswith("/"):
                    route_prefixes.add(parent)

        for s in ast.get("strategies", []):
            findings["strategies"].append(
                {
                    "handler": s.get("handler", "fetch"),
                    "strategy": s.get("strategy", "unknown"),
                    "location": s.get("location", "unknown"),
                }
            )

        for d in ast.get("dangerousPatterns", []):
            typ = d.get("type")
            findings["dangerous_operations"].append(
                {
                    "type": typ,
                    "code": d.get("code", ""),
                    "location": d.get("location", "unknown"),
                    "risk_level": self._risk_of_danger(typ),
                }
            )

        auth_tokens = ("/auth", "/login", "/signin", "/oauth", "/token", "/jwt", "/session")
        for r in findings["route_handlers"]:
            e = (r.get("expression") or "").lower()
            if any(tok in e for tok in auth_tokens):
                findings["auth_sensitive_hints"].append(r)

        findings["route_prefix_hints"] = sorted(route_prefixes)
        return findings


enhanced_analyzer = EnhancedAnalyzer()
