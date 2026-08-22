"""Tests for the rule scanner engine."""

import os
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
