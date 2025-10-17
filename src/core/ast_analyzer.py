from __future__ import annotations
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..models.exceptions import AnalysisException
from ..utils.logger import get_logger

logger = get_logger("ast_analyzer")

class ASTAnalyzer:
    def __init__(self, node_path: str = "node", workdir: Optional[str] = None, npm_path: Optional[str] = None):
        self.node_path = node_path
        self.npm_path = npm_path or self._find_npm()
        self.workdir = Path(workdir or Path.home() / ".swmap" / "ast_bridge").resolve()
        self.workdir.mkdir(parents=True, exist_ok=True)

        self.has_node = self._check_node()
        self._ensure_package_layout()
        self.script_path = self.workdir / "ast_analyzer.js"
        if not self.script_path.exists():
            self.script_path.write_text(self._node_script(), encoding="utf-8")
    def analyze_with_ast(self, javascript_code: str) -> Dict[str, Any]:
        """
        Analyze JavaScript code using Babel AST (if available) with safe fallbacks.

        Returns a structured dict with:
        {
          imports: [...],
          eventListeners: [...],
          cacheOperations: [...],
          fetchHandlers: [...],
          workboxUsage: [...],
          routes: [...],
          strategies: [...],
          dangerousPatterns: [...],
          errors: [...]
        }
        """
        if not javascript_code:
            return {
                "imports": [],
                "eventListeners": [],
                "cacheOperations": [],
                "fetchHandlers": [],
                "workboxUsage": [],
                "routes": [],
                "strategies": [],
                "dangerousPatterns": [],
                "errors": ["Empty input"],
            }

        if not self.has_node:
            logger.warning("Node.js not available — using regex fallback for AST analysis.")
            return self._fallback_analysis(javascript_code)

        if not self._ensure_node_modules():
            logger.warning("Failed to prepare Node dependencies — using regex fallback.")
            return self._fallback_analysis(javascript_code)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as code_file:
            code_file.write(javascript_code)
            code_path = code_file.name

        try:
            proc = subprocess.run(
                [self.node_path, str(self.script_path), code_path],
                cwd=str(self.workdir),
                capture_output=True,
                text=True,
                timeout=45,
            )
            if proc.returncode != 0:
                msg = proc.stderr.strip() or "Unknown Node error"
                logger.warning("AST analysis process failed: %s", msg)
                return self._fallback_analysis(javascript_code)

            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError as je:
                logger.warning("AST analysis JSON decode error: %s", je)
                return self._fallback_analysis(javascript_code)

            for k in (
                "imports",
                "eventListeners",
                "cacheOperations",
                "fetchHandlers",
                "workboxUsage",
                "routes",
                "strategies",
                "dangerousPatterns",
                "errors",
            ):
                data.setdefault(k, [])

            logger.info("AST analysis completed successfully (imports=%d, routes=%d)",
                        len(data.get("imports", [])), len(data.get("routes", [])))
            return data

        except subprocess.TimeoutExpired:
            logger.warning("AST analysis timed out — using regex fallback.")
            return self._fallback_analysis(javascript_code)
        except Exception as e:
            logger.warning("AST analysis unexpected failure: %s — using regex fallback.", e)
            return self._fallback_analysis(javascript_code)
        finally:
            try:
                os.unlink(code_path)
            except OSError:
                pass

    def _check_node(self) -> bool:
        try:
            proc = subprocess.run([self.node_path, "--version"], capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                logger.info("Node.js available: %s", proc.stdout.strip())
                return True
        except Exception:
            pass
        logger.info("Node.js not found at '%s'.", self.node_path)
        return False

    def _find_npm(self) -> Optional[str]:
        candidates = ["npm"]
        if platform.system().lower().startswith("win"):
            candidates = ["npm.cmd", "npm"]
        for c in candidates:
            path = shutil.which(c)
            if path:
                return path
        return None

    def _ensure_package_layout(self) -> None:
        pkg_json = self.workdir / "package.json"
        if not pkg_json.exists():
            pkg_json.write_text(
                json.dumps(
                    {
                        "name": "swmap-ast-analyzer",
                        "version": "1.0.0",
                        "private": True,
                        "license": "MIT",
                        "dependencies": {
                            "@babel/parser": "^7.24.0",
                            "@babel/traverse": "^7.24.0",
                            "@babel/generator": "^7.24.0",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

    def _ensure_node_modules(self) -> bool:
        node_modules = self.workdir / "node_modules"
        if node_modules.exists():
            return True
        if not self.npm_path:
            logger.warning("npm executable not found.")
            return False

        logger.info("Installing Node dependencies for AST analysis (one-time) ...")
        try:
            proc = subprocess.run(
                [self.npm_path, "install", "--silent", "--no-audit", "--no-fund"],
                cwd=str(self.workdir),
                capture_output=True,
                text=True,
                timeout=180,
            )
            if proc.returncode != 0:
                logger.warning("npm install failed: %s", (proc.stderr or proc.stdout)[-400:])
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.warning("npm install timed out.")
            return False
        except Exception as e:
            logger.warning("npm install failed: %s", e)
            return False
    def _node_script(self) -> str:
        return r"""
const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;

function safeLoc(n) {
  try { return n && n.loc && n.loc.start ? `Line ${n.loc.start.line}` : 'Unknown'; }
  catch { return 'Unknown'; }
}

function extractArrayElements(node) {
  if (!node || node.type !== 'ArrayExpression') return [];
  return node.elements
    .filter(el => el && el.type === 'StringLiteral')
    .map(el => el.value);
}

function analyzeServiceWorker(code) {
  const results = {
    imports: [],
    eventListeners: [],
    cacheOperations: [],
    fetchHandlers: [],
    workboxUsage: [],
    routes: [],
    strategies: [],
    dangerousPatterns: [],
    errors: []
  };

  try {
    const ast = parser.parse(code, {
      sourceType: 'unambiguous',
      plugins: [
        'dynamicImport',
        'importMeta',
        'bigInt',
        'optionalChaining',
        'nullishCoalescingOperator',
        'classProperties',
        'topLevelAwait'
      ],
      errorRecovery: true
    });

    traverse(ast, {
      ImportDeclaration(path) {
        results.imports.push({
          type: 'import',
          source: path.node.source && path.node.source.value,
          specifiers: (path.node.specifiers || []).map(s => ({
            type: s.type,
            imported: s.imported && s.imported.name,
            local: s.local && s.local.name
          })),
          location: safeLoc(path.node)
        });
      },

      CallExpression(path) {
        const { node } = path;

        // importScripts(...)
        if (node.callee && node.callee.type === 'Identifier' && node.callee.name === 'importScripts') {
          for (const arg of node.arguments || []) {
            if (arg.type === 'StringLiteral') {
              results.imports.push({
                type: 'importScripts',
                source: arg.value,
                location: safeLoc(node)
              });
            }
          }
        }

        // addEventListener('fetch' | 'install' | ...)
        if (node.callee && node.callee.type === 'MemberExpression') {
          const prop = node.callee.property;
          if (prop && prop.type === 'Identifier' && prop.name === 'addEventListener') {
            const first = node.arguments && node.arguments[0];
            if (first && first.type === 'StringLiteral') {
              results.eventListeners.push({
                event: first.value,
                location: safeLoc(node)
              });
              if (first.value === 'fetch') {
                results.fetchHandlers.push({ location: safeLoc(node) });
              }
            }
          }
        }

        // Cache operations
        if (node.callee && node.callee.type === 'MemberExpression') {
          const propName = node.callee.property && node.callee.property.name;
          const obj = node.callee.object;

          // caches.open('name')
          if (propName === 'open' && obj && obj.type === 'Identifier' && obj.name === 'caches') {
            const arg = node.arguments && node.arguments[0];
            results.cacheOperations.push({
              type: 'cacheOpen',
              cacheName: (arg && arg.type === 'StringLiteral') ? arg.value : undefined,
              location: safeLoc(node)
            });
          }

          // cache.addAll([...])
          if (propName === 'addAll') {
            results.cacheOperations.push({
              type: 'cacheAddAll',
              urls: extractArrayElements(node.arguments && node.arguments[0]),
              location: safeLoc(node)
            });
          }

          // workbox.*
          const calleeCode = generate(node.callee).code;
          if (calleeCode.includes('workbox')) {
            results.workboxUsage.push({
              expression: calleeCode,
              type: 'methodCall',
              location: safeLoc(node)
            });
          }

          // workbox.routing.registerRoute(...)
          if (propName === 'registerRoute') {
            results.routes.push({
              type: 'routeRegistration',
              location: safeLoc(node),
              expression: generate(node).code
            });
          }
        }
      },

      VariableDeclarator(path) {
        // new workbox.strategies.*
        const init = path.node.init;
        if (init && init.type === 'NewExpression') {
          const callee = init.callee;
          const className = (callee && callee.type === 'MemberExpression')
            ? generate(callee).code
            : (callee && callee.name);
          if (className && /Strategy/.test(className)) {
            results.strategies.push({
              type: 'strategy',
              className,
              variable: path.node.id && path.node.id.name,
              location: safeLoc(path.node)
            });
          }
        }
      },

      NewExpression(path) {
        const callee = path.node.callee;
        if (callee && callee.type === 'Identifier' && callee.name === 'Function') {
          results.dangerousPatterns.push({
            type: 'functionConstructor',
            location: safeLoc(path.node),
            code: generate(path.node).code
          });
        }
      },

      Identifier(path) {
        if (path.node.name === 'eval' &&
            path.parent &&
            path.parent.type === 'CallExpression' &&
            path.parent.callee === path.node) {
          results.dangerousPatterns.push({
            type: 'eval',
            location: safeLoc(path.parent),
            code: generate(path.parent).code
          });
        }
      }
    });

  } catch (err) {
    results.errors.push(`AST parsing error: ${err && err.message ? err.message : String(err)}`);
  }

  return results;
}

// Main
const codePath = process.argv[2];
const code = fs.readFileSync(codePath, 'utf8');
const out = analyzeServiceWorker(code);
console.log(JSON.stringify(out, null, 2));
"""
    def _fallback_analysis(self, code: str) -> Dict[str, Any]:
        return {
            "imports": self._extract_imports_fallback(code),
            "eventListeners": self._extract_event_listeners_fallback(code),
            "cacheOperations": self._extract_cache_ops_fallback(code),
            "fetchHandlers": [],
            "workboxUsage": self._extract_workbox_fallback(code),
            "routes": self._extract_routes_fallback(code),
            "strategies": [],
            "dangerousPatterns": self._extract_dangerous_fallback(code),
            "errors": ["AST analysis unavailable; regex fallback used"],
        }

    def _extract_imports_fallback(self, code: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for m in re.finditer(r"importScripts\s*\(\s*['\"]([^'\"\)]+)['\"]", code, re.IGNORECASE):
            out.append({"type": "importScripts", "source": m.group(1), "location": "Unknown"})
        return out

    def _extract_event_listeners_fallback(self, code: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for evt in ("fetch", "install", "activate", "message", "sync", "push"):
            pattern = rf"addEventListener\s*\(\s*['\"]({evt})['\"]"
            for _ in re.finditer(pattern, code, re.IGNORECASE):
                out.append({"event": evt, "location": "Unknown"})
        return out

    def _extract_cache_ops_fallback(self, code: str) -> List[Dict[str, Any]]:
        ops: List[Dict[str, Any]] = []
        for m in re.finditer(r"caches\s*\.\s*open\s*\(\s*['\"]([^'\"]+)['\"]", code, re.IGNORECASE):
            ops.append({"type": "cacheOpen", "cacheName": m.group(1), "location": "Unknown"})
        for m in re.finditer(r"cache\s*\.\s*addAll\s*\(\s*(\[[^\]]*\])", code, re.IGNORECASE):
            urls = re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))
            ops.append({"type": "cacheAddAll", "urls": urls, "location": "Unknown"})
        return ops

    def _extract_workbox_fallback(self, code: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for m in re.finditer(r"(workbox\.[a-zA-Z]|workbox\-[a-zA-Z]|self\.__WB_MANIFEST)", code, re.IGNORECASE):
            out.append({"expression": m.group(0), "type": "patternMatch", "location": "Unknown"})
        return out

    def _extract_routes_fallback(self, code: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for patt in (r"registerRoute\s*\(\s*['\"](/[^'\"]+)['\"]", r"route\s*\(\s*['\"](/[^'\"]+)['\"]"):
            for m in re.finditer(patt, code, re.IGNORECASE):
                out.append({"type": "routeRegistration", "location": "Unknown", "expression": m.group(0)})
        return out

    def _extract_dangerous_fallback(self, code: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        patterns = [
            (r"eval\s*\(", "eval"),
            (r"new\s+Function\s*\(", "functionConstructor"),
            (r"setTimeout\s*\(\s*[^'\"]", "setTimeoutString"),
            (r"setInterval\s*\(\s*[^'\"]", "setIntervalString"),
        ]
        for patt, kind in patterns:
            for m in re.finditer(patt, code, re.IGNORECASE):
                out.append({"type": kind, "location": "Unknown", "code": m.group(0)})
        return out

ast_analyzer = ASTAnalyzer()
