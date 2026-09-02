"""Tests for the rule scanner engine."""

import os
import tempfile
import unittest
from pathlib import Path

from app.services.inline_scanner import InlineScanner
from app.services.regex_scanner import RegexFallbackScanner
from app.services.rule_scanner import RuleScanner


class TestRuleScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = RuleScanner()
        self.assertGreater(len(self.scanner._rules), 0, "Rules should be loaded")

    def test_load_rules_from_all_files(self):
        categories = {r.get("category") for r in self.scanner._rules}
        self.assertIn("secrets", categories)
        self.assertIn("injection", categories)

    def test_scan_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            import asyncio
            results = asyncio.run(self.scanner.scan(tmp))
            self.assertEqual(results, [])

    def test_scan_finds_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
            import asyncio
            results = asyncio.run(self.scanner.scan(tmp))
            self.assertGreater(len(results), 0)
            titles = [r["title"] for r in results]
            self.assertTrue(any("AWS" in t for t in titles), f"Expected AWS finding, got: {titles}")

    def test_scan_finds_sql_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            py_file = Path(tmp) / "app.py"
            py_file.write_text('cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n')
            import asyncio
            results = asyncio.run(self.scanner.scan(tmp))
            titles = [r["title"] for r in results]
            self.assertTrue(any("SQL" in t for t in titles), f"Expected SQL injection finding, got: {titles}")

    def test_sensitivity_low_filters_low_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
            import asyncio
            high_results = asyncio.run(self.scanner.scan(tmp, sensitivity="high"))
            low_results = asyncio.run(self.scanner.scan(tmp, sensitivity="low"))
            self.assertGreaterEqual(len(high_results), len(low_results))

    def test_skip_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            nm_dir = Path(tmp) / "node_modules" / "pkg"
            nm_dir.mkdir(parents=True)
            (nm_dir / "index.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE"\n')
            import asyncio
            results = asyncio.run(self.scanner.scan(tmp))
            self.assertEqual(results, [])

    def test_dockerfile_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            df = Path(tmp) / "Dockerfile"
            df.write_text("FROM ubuntu:20.04\nRUN apt-get update\n")
            import asyncio
            results = asyncio.run(self.scanner.scan(tmp))
            titles = [r["title"] for r in results]
            self.assertTrue(
                any("USER" in t.upper() or "root" in t.lower() or "healthcheck" in t.lower() for t in titles),
                f"Expected Docker finding, got: {titles}"
            )

    def test_weak_crypto_rules_ignore_text_and_match_crypto_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prose = root / "app.ts"
            prose.write_text(
                "const description = 'This description mentions DES and MD5 in documentation only';\n"
                "// DES.new(key) and hashlib.md5() are examples in comments\n"
            )
            crypto = root / "crypto.py"
            crypto.write_text(
                "from Crypto.Cipher import DES3\n"
                "cipher = DES3.new(key, DES3.MODE_CBC, iv)\n"
                "digest = hashlib.md5(payload).hexdigest()\n"
            )
            import asyncio
            results = asyncio.run(self.scanner.scan(tmp))

            prose_results = [item for item in results if item["file_path"] == "app.ts"]
            crypto_rule_ids = {item["rule_id"] for item in results if item["file_path"] == "crypto.py"}
            self.assertFalse(any(item["rule_id"] == "sec-weak-crypto-des" for item in prose_results), prose_results)
            self.assertFalse(any(item["rule_id"] == "sec-weak-crypto-md5" for item in prose_results), prose_results)
            self.assertIn("sec-weak-crypto-des", crypto_rule_ids)
            self.assertIn("sec-weak-crypto-md5", crypto_rule_ids)

    def test_exclude_patterns_apply_to_rule_inline_and_regex_scanners(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            (docs / "README.md").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
            src = root / "src"
            src.mkdir()
            (src / "settings.ts").write_text("const awsKey = 'AKIAIOSFODNN7EXAMPLE';\n")
            excludes = ["**/*.md", "docs/**"]

            import asyncio
            rule_results = asyncio.run(self.scanner.scan(tmp, exclude_patterns=excludes))
            inline_results = asyncio.run(InlineScanner().scan(tmp, exclude_patterns=excludes)).findings
            regex_results = asyncio.run(RegexFallbackScanner().scan(tmp, exclude_patterns=excludes)).findings

            self.assertTrue(rule_results)
            self.assertTrue(inline_results)
            self.assertTrue(regex_results)
            self.assertFalse(any("README.md" in item["file_path"] for item in rule_results))
            self.assertFalse(any("README.md" in item.file_path for item in inline_results))
            self.assertFalse(any("README.md" in item.file_path for item in regex_results))


if __name__ == "__main__":
    unittest.main()
