#!/usr/bin/env python3
"""Validate all JSON files in the ClawDefender threat feed.

Usage:
    python validate-feed.py [--feed-dir <path>]

Checks:
  - All JSON files parse correctly
  - manifest.json has required fields (version, last_updated, files)
  - All files referenced in the manifest exist
  - SHA-256 hashes in the manifest match actual file contents
  - Blocklist entries have required fields
  - Rule packs have required fields and valid actions
  - IoC files have required fields
  - Profile files have required fields
"""

import hashlib
import json
import sys
from pathlib import Path


class FeedValidator:
    def __init__(self, feed_dir: Path):
        self.feed_dir = feed_dir
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def load_json(self, path: Path) -> dict | list | None:
        try:
            with open(path) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            self.error(f"Invalid JSON in {path.name}: {e}")
            return None
        except FileNotFoundError:
            self.error(f"File not found: {path}")
            return None

    def validate_manifest(self) -> dict | None:
        path = self.feed_dir / "manifest.json"
        data = self.load_json(path)
        if data is None:
            return None

        for field in ("version", "last_updated", "feed_format_version", "files"):
            if field not in data:
                self.error(f"manifest.json missing required field: {field}")

        if "files" in data:
            for rel_path, entry in data["files"].items():
                full_path = self.feed_dir / rel_path
                if not full_path.exists():
                    self.error(f"manifest references non-existent file: {rel_path}")
                    continue

                if "sha256" not in entry:
                    self.error(f"manifest entry for {rel_path} missing sha256")
                    continue

                actual_hash = hashlib.sha256(full_path.read_bytes()).hexdigest()
                if actual_hash != entry["sha256"]:
                    self.error(
                        f"SHA-256 mismatch for {rel_path}: "
                        f"manifest={entry['sha256'][:16]}... actual={actual_hash[:16]}..."
                    )

                if "size" in entry:
                    actual_size = full_path.stat().st_size
                    if actual_size != entry["size"]:
                        self.error(f"Size mismatch for {rel_path}: manifest={entry['size']} actual={actual_size}")

        return data

    def validate_blocklist(self) -> None:
        path = self.feed_dir / "blocklist.json"
        data = self.load_json(path)
        if data is None:
            return

        if "version" not in data:
            self.error("blocklist.json missing 'version'")
        if "entries" not in data:
            self.error("blocklist.json missing 'entries'")
            return

        valid_types = {"MaliciousServer", "VulnerableServer", "CompromisedVersion"}
        valid_severities = {"Low", "Medium", "High", "Critical"}

        for i, entry in enumerate(data["entries"]):
            for field in ("id", "entry_type", "name", "severity", "description", "remediation"):
                if field not in entry:
                    self.error(f"blocklist entry {i} missing field: {field}")

            if entry.get("entry_type") not in valid_types:
                self.error(f"blocklist entry {entry.get('id', i)}: invalid entry_type '{entry.get('entry_type')}'")

            if entry.get("severity") not in valid_severities:
                self.error(f"blocklist entry {entry.get('id', i)}: invalid severity '{entry.get('severity')}'")

    def validate_rule_pack(self, filename: str) -> None:
        path = self.feed_dir / "rules" / filename
        data = self.load_json(path)
        if data is None:
            return

        for field in ("id", "name", "version", "author", "description", "category", "rules"):
            if field not in data:
                self.error(f"{filename} missing field: {field}")

        valid_actions = {"block", "prompt", "allow", "log"}
        valid_categories = {"Security", "Privacy", "Development", "ServerSpecific", "FrameworkSpecific"}

        if data.get("category") not in valid_categories:
            self.error(f"{filename}: invalid category '{data.get('category')}'")

        for i, rule in enumerate(data.get("rules", [])):
            for field in ("name", "action", "message"):
                if field not in rule:
                    self.error(f"{filename} rule {i} missing field: {field}")

            if rule.get("action") not in valid_actions:
                self.error(f"{filename} rule '{rule.get('name', i)}': invalid action '{rule.get('action')}'")

    def validate_ioc_hosts(self) -> None:
        path = self.feed_dir / "iocs" / "malicious-hosts.json"
        data = self.load_json(path)
        if data is None:
            return

        if "hosts" not in data:
            self.error("malicious-hosts.json missing 'hosts'")
            return

        for i, host in enumerate(data["hosts"]):
            for field in ("host", "reason", "severity"):
                if field not in host:
                    self.error(f"malicious-hosts entry {i} missing field: {field}")

    def validate_ioc_hashes(self) -> None:
        path = self.feed_dir / "iocs" / "malicious-hashes.json"
        data = self.load_json(path)
        if data is None:
            return

        if "hashes" not in data:
            self.error("malicious-hashes.json missing 'hashes'")
            return

        for i, h in enumerate(data["hashes"]):
            for field in ("hash", "algorithm", "description", "severity"):
                if field not in h:
                    self.error(f"malicious-hashes entry {i} missing field: {field}")

    def validate_ioc_tools(self) -> None:
        path = self.feed_dir / "iocs" / "suspicious-tools.json"
        data = self.load_json(path)
        if data is None:
            return

        if "tools" not in data:
            self.error("suspicious-tools.json missing 'tools'")
            return

        for i, tool in enumerate(data["tools"]):
            for field in ("name", "description", "severity"):
                if field not in tool:
                    self.error(f"suspicious-tools entry {i} missing field: {field}")

    def validate_profiles(self) -> None:
        index_path = self.feed_dir / "profiles" / "index.json"
        data = self.load_json(index_path)
        if data is None:
            return

        for profile_entry in data.get("profiles", []):
            profile_path = self.feed_dir / "profiles" / profile_entry["file"]
            profile = self.load_json(profile_path)
            if profile is None:
                continue

            for field in ("server_package", "profile_version", "expected_tools"):
                if field not in profile:
                    self.error(f"{profile_entry['file']} missing field: {field}")

    def validate_patterns(self) -> None:
        kc_path = self.feed_dir / "patterns" / "killchains.json"
        data = self.load_json(kc_path)
        if data and "patterns" in data:
            for i, pattern in enumerate(data["patterns"]):
                for field in ("id", "name", "severity", "window_seconds", "steps"):
                    if field not in pattern:
                        self.error(f"killchains pattern {i} missing field: {field}")

        inj_path = self.feed_dir / "patterns" / "injection-signatures.json"
        data = self.load_json(inj_path)
        if data and "signatures" in data:
            for i, sig in enumerate(data["signatures"]):
                for field in ("id", "pattern" if "pattern" in sig else "regex", "description", "severity"):
                    if field not in sig:
                        self.error(f"injection-signatures entry {i} missing field: {field}")

    def run(self) -> bool:
        print("Validating ClawDefender threat feed...")
        print(f"Feed directory: {self.feed_dir}\n")

        self.validate_manifest()
        self.validate_blocklist()

        rules_index = self.load_json(self.feed_dir / "rules" / "index.json")
        if rules_index and "packs" in rules_index:
            for pack in rules_index["packs"]:
                self.validate_rule_pack(pack["file"])

        self.validate_ioc_hosts()
        self.validate_ioc_hashes()
        self.validate_ioc_tools()
        self.validate_profiles()
        self.validate_patterns()

        if self.warnings:
            print(f"Warnings ({len(self.warnings)}):")
            for w in self.warnings:
                print(f"  WARNING: {w}")
            print()

        if self.errors:
            print(f"Errors ({len(self.errors)}):")
            for e in self.errors:
                print(f"  ERROR: {e}")
            print(f"\nValidation FAILED with {len(self.errors)} error(s).")
            return False
        else:
            print("Validation PASSED. All files are valid.")
            return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Validate ClawDefender threat feed")
    parser.add_argument(
        "--feed-dir",
        type=Path,
        default=Path(__file__).parent.parent / "feed" / "v1",
        help="Path to feed/v1 directory",
    )
    args = parser.parse_args()

    validator = FeedValidator(args.feed_dir)
    success = validator.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
