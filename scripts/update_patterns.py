#!/usr/bin/env python3
import json
import hashlib
import sys
import os
import urllib.request
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.logger import setup_logging, get_logger
from src.utils.validator import input_sanitizer  


class PatternUpdater:
    def __init__(self, config_dir: str | None = None):
        self.logger = get_logger("pattern_updater")
        self.config_dir = config_dir or os.path.expanduser("~/.swmap")
        self.patterns_dir = os.path.join(self.config_dir, "patterns")
        self.cache_dir = os.path.join(self.config_dir, "cache")

        os.makedirs(self.patterns_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)
        self.pattern_sources: Dict[str, str] = {
            "community_patterns": "https://raw.githubusercontent.com/swmap-community/patterns/main/patterns.json",
            "security_patterns": "https://raw.githubusercontent.com/swmap-security/patterns/main/security.json",
            "workbox_patterns": "https://raw.githubusercontent.com/swmap-community/patterns/main/workbox.json",
        }

        self.backup_sources: Dict[str, str] = {
            "community_patterns": "https://cdn.jsdelivr.net/gh/swmap-community/patterns@main/patterns.json",
            "security_patterns": "https://cdn.jsdelivr.net/gh/swmap-security/patterns@main/security.json",
        }

    def fetch_remote_patterns(self, url: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
        self.logger.info(f"Fetching patterns from: {url}")

        if not url.startswith("https://"):
            self.logger.error(f"Refusing non-HTTPS URL: {url}")
            return None

        headers = {
            "User-Agent": "SWMap-Pattern-Updater/1.0.0",
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate",
        }
        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    self.logger.error(f"HTTP {resp.status} from {url}")
                    return None

                content_type = resp.headers.get("Content-Type", "")
                if "application/json" not in content_type:
                    self.logger.warning(f"Unexpected Content-Type: {content_type}")

                raw = resp.read()
                if len(raw) > 1_048_576:  # 1MB
                    self.logger.error("Pattern file too large")
                    return None

                data = json.loads(raw.decode("utf-8", errors="replace"))
                if not self._looks_like_valid_payload(data):
                    self.logger.error("Invalid pattern payload structure")
                    return None

                self.logger.info("Remote patterns fetched OK")
                return data

        except urllib.error.URLError as e:
            self.logger.error(f"Network error fetching {url}: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parse error from {url}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error fetching {url}: {e}")

        return None

    def load_local_patterns(self) -> Dict[str, Dict[str, str]]:
        local: Dict[str, Dict[str, str]] = {}
        for fname in os.listdir(self.patterns_dir):
            if not fname.endswith("_patterns.json"):
                continue
            path = os.path.join(self.patterns_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                category = fname.replace("_patterns.json", "")
                patterns = self._unwrap_patterns(payload)
                if isinstance(patterns, dict):
                    local[category] = patterns
                else:
                    self.logger.warning(f"Unexpected format in {path} (skipped)")
            except Exception as e:
                self.logger.warning(f"Failed to load {path}: {e}")
        return local

    def save_patterns(self, patterns: Dict[str, str], category: str) -> bool:
        path = os.path.join(self.patterns_dir, f"{category}_patterns.json")
        payload = {
            "patterns": patterns,
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "version": "1.0.0",
                "source": "community",
            },
            "version": "1.0.0",
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Saved {len(patterns)} patterns -> {os.path.basename(path)}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save patterns: {e}")
            return False

    def _unwrap_patterns(self, payload: Any) -> Optional[Dict[str, str]]:
        """
        Accept either:
          { "patterns": {...}, "metadata": {...}, "version": "..." }
        or just:
          { "name": "regex", ... }  (raw category map)
        """
        if isinstance(payload, dict) and "patterns" in payload and isinstance(payload["patterns"], dict):
            return payload["patterns"]
        if isinstance(payload, dict):
            if all(isinstance(v, str) for v in payload.values()):
                return payload
        return None

    def _looks_like_valid_payload(self, data: Any) -> bool:
        if isinstance(data, dict) and "patterns" in data and isinstance(data["patterns"], dict):
            return self._validate_category_map(data["patterns"])
        if isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
            return self._validate_category_map(data)
        return False

    def _validate_category_map(self, categories: Dict[str, Dict[str, str]]) -> bool:
        for cat, patmap in categories.items():
            if not isinstance(patmap, dict):
                return False
            for name, pattern in patmap.items():
                if not isinstance(pattern, str):
                    return False
                if self.is_dangerous_pattern(pattern):
                    self.logger.warning(f"Potentially dangerous pattern in {cat}.{name}")
                    return False
                try:
                    re.compile(pattern)
                except re.error:
                    self.logger.warning(f"Invalid regex in {cat}.{name}")
                    return False
        return True

    def is_dangerous_pattern(self, pattern: str) -> bool:
        dangerous = [
            r"\(\?<[^=!]",          
            r"\(\?P<[^>]+>",        
            r"\.\*\{\d+,\}",        
            r"\(\?:\)\*",           
            r"\\x[0-9a-fA-F]{2}",   
        ]
        if len(pattern) > 1500:
            return True
        return any(re.search(d, pattern) for d in dangerous)

    def merge_category(self, local: Dict[str, str], remote: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, int]]:
        merged = dict(local)
        stats = {"added": 0, "updated": 0, "skipped": 0, "total_local": len(local), "total_remote": len(remote)}
        for name, remote_pat in remote.items():
            if name not in merged:
                merged[name] = remote_pat
                stats["added"] += 1
            else:
                if hashlib.md5(merged[name].encode()).hexdigest() != hashlib.md5(remote_pat.encode()).hexdigest():
                    merged[name] = remote_pat
                    stats["updated"] += 1
                else:
                    stats["skipped"] += 1
        return merged, stats

    def should_update(self, category: str, force: bool = False) -> bool:
        if force:
            return True
        marker = os.path.join(self.patterns_dir, f"{category}_last_update")
        if not os.path.exists(marker):
            return True
        try:
            with open(marker, "r", encoding="utf-8") as f:
                last = datetime.fromisoformat(f.read().strip())
            return last < (datetime.now() - timedelta(days=7))
        except Exception:
            return True

    def mark_updated(self, category: str):
        marker = os.path.join(self.patterns_dir, f"{category}_last_update")
        try:
            with open(marker, "w", encoding="utf-8") as f:
                f.write(datetime.now().isoformat())
        except Exception as e:
            self.logger.warning(f"Failed to mark {category} as updated: {e}")

    def update_patterns(self, force: bool = False, sources: List[str] | None = None) -> Dict[str, Any]:
        self.logger.info("Starting pattern database update")

        results = {"timestamp": datetime.now().isoformat(), "updated_categories": [], "failed_categories": [], "stats": {}}
        local_all = self.load_local_patterns()
        chosen_sources = sources or list(self.pattern_sources.keys())

        for source_name in chosen_sources:
            if source_name not in self.pattern_sources:
                self.logger.warning(f"Unknown source: {source_name}")
                continue

            category = source_name.replace("_patterns", "")
            if not self.should_update(category, force):
                self.logger.info(f"Skipping {category} (recently updated)")
                continue

            remote_payload = self.fetch_remote_patterns(self.pattern_sources[source_name])
            if not remote_payload and source_name in self.backup_sources:
                self.logger.info(f"Trying backup source for {category}")
                remote_payload = self.fetch_remote_patterns(self.backup_sources[source_name])

            if not remote_payload:
                results["failed_categories"].append(category)
                self.logger.error(f"Failed to fetch {category} patterns from all sources")
                continue

            remote_categories = (
                remote_payload["patterns"]
                if ("patterns" in remote_payload and isinstance(remote_payload["patterns"], dict))
                else remote_payload
            )

            if category in remote_categories and isinstance(remote_categories[category], dict):
                remote_map = remote_categories[category]
            else:
                remote_map = {}
                for v in remote_categories.values():
                    if isinstance(v, dict):
                        remote_map.update(v)

            local_map = local_all.get(category, {})
            merged, stats = self.merge_category(local_map, remote_map)

            if self.save_patterns(merged, category):
                self.mark_updated(category)
                results["updated_categories"].append(category)
                results["stats"][category] = {
                    "local_patterns": len(local_map),
                    "remote_patterns": len(remote_map),
                    "merged_patterns": len(merged),
                    "added": stats["added"],
                    "updated": stats["updated"],
                    "skipped": stats["skipped"],
                }
            else:
                results["failed_categories"].append(category)

        self.logger.info(
            f"Update completed: {len(results['updated_categories'])} updated, {len(results['failed_categories'])} failed"
        )
        return results


    def validate_local_patterns(self) -> Dict[str, Any]:
        self.logger.info("Validating local patterns")
        local = self.load_local_patterns()
        out: Dict[str, Any] = {}
        for category, patmap in local.items():
            cat_res = {
                "total_patterns": len(patmap),
                "valid_patterns": 0,
                "invalid_patterns": 0,
                "dangerous_patterns": 0,
                "errors": [],
            }
            for name, pattern in patmap.items():
                try:
                    re.compile(pattern)
                    if self.is_dangerous_pattern(pattern):
                        cat_res["dangerous_patterns"] += 1
                        cat_res["errors"].append(f"Dangerous pattern: {name}")
                    else:
                        cat_res["valid_patterns"] += 1
                except re.error as e:
                    cat_res["invalid_patterns"] += 1
                    cat_res["errors"].append(f"Invalid regex in {name}: {e}")
            out[category] = cat_res
        return out

    def export_patterns(self, output_file: str, categories: List[str] | None = None):
        local = self.load_local_patterns()
        if categories:
            export = {c: local[c] for c in categories if c in local}
        else:
            export = local

        meta = {
            "exported_at": datetime.now().isoformat(),
            "total_categories": len(export),
            "total_patterns": sum(len(v) for v in export.values()),
            "version": "1.0.0",
        }

        data = {"categories": export, "_metadata": meta}
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Exported patterns to: {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to export patterns: {e}")

    def import_patterns(self, import_file: str, merge: bool = True):
        if not os.path.exists(import_file):
            self.logger.error(f"Import file not found: {import_file}")
            return

        try:
            with open(import_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict) and "categories" in data:
                to_import = data["categories"]
            else:
                to_import = data

            if not isinstance(to_import, dict) or not all(isinstance(v, dict) for v in to_import.values()):
                self.logger.error("Invalid import data structure")
                return

            local = self.load_local_patterns() if merge else {}
            for category, patmap in to_import.items():
                if not isinstance(patmap, dict):
                    continue
                if merge and category in local:
                    merged, _ = self.merge_category(local[category], patmap)
                    local[category] = merged
                else:
                    local[category] = patmap

            for category, patmap in local.items():
                self.save_patterns(patmap, category)

            self.logger.info(f"Successfully imported patterns from: {import_file}")

        except Exception as e:
            self.logger.error(f"Failed to import patterns: {e}")

def main():
    import argparse

    parser = argparse.ArgumentParser(description="SWMap Pattern Database Updater")
    parser.add_argument("--update", "-u", action="store_true", help="Update patterns from remote sources")
    parser.add_argument("--force", "-f", action="store_true", help="Force update even if not needed")
    parser.add_argument("--validate", "-V", action="store_true", help="Validate local patterns")
    parser.add_argument("--export", "-e", help="Export patterns to file")
    parser.add_argument("--import", "-i", dest="import_file", help="Import patterns from file")
    parser.add_argument("--merge", action="store_true", default=True, help="Merge imported patterns (default: true)")
    parser.add_argument("--sources", "-s", nargs="+", help="Specific sources/categories to update/export")
    parser.add_argument("--config-dir", help="Configuration directory")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(level=log_level, enable_console=True)
    updater = PatternUpdater(args.config_dir)

    try:
        if args.update:
            results = updater.update_patterns(force=args.force, sources=args.sources)
            print(f"Update completed: {len(results['updated_categories'])} updated")

        elif args.validate:
            results = updater.validate_local_patterns()
            for category, v in results.items():
                print(f"{category}: {v['valid_patterns']}/{v['total_patterns']} valid "
                      f"({v['dangerous_patterns']} dangerous, {v['invalid_patterns']} invalid)")

        elif args.export:
            updater.export_patterns(args.export, args.sources)
            print(f"Patterns exported to: {args.export}")

        elif args.import_file:
            updater.import_patterns(args.import_file, args.merge)
            print(f"Patterns imported from: {args.import_file}")

        else:
            results = updater.update_patterns(force=args.force, sources=args.sources)
            print(f"Update completed: {len(results['updated_categories'])} updated")

    except KeyboardInterrupt:
        print("\nUpdate interrupted by user")
        return 1
    except Exception as e:
        print(f"Update failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
