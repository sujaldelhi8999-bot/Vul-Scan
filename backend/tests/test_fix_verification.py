"""Verification suite for the PhantomScan fix audit.

Covers:
1. CRITICAL: persist_findings dedup no longer crashes when findings already exist.
2. HIGH:    WHOIS lookup fails fast (timeout enforced, no audit-log spam).
3. HIGH:    crt.sh 503 responses trigger retries without failing the scan.

Run:  python -m pytest tests/test_fix_verification.py -v
"""

import asyncio
import json
import os
import tempfile
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

_db_fd, _db_path = tempfile.mkstemp(suffix=".sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")

import httpx  # noqa: E402

from app.agents.orchestrator import OrchestratorAgent  # noqa: E402
from app.agents.shadow_recon import ShadowReconAgent  # noqa: E402
from app.database import (  # noqa: E402
    create_finding,
    create_scan,
    get_findings,
    initialize_database,
)
from app.models import FindingCreate  # noqa: E402

FINDING_BASE = {
    "title": "SQL Injection in login",
    "category": "injection",
    "severity": "HIGH",
    "confidence": "CONFIRMED",
    "target": "http://localhost/lab/phantombank",
    "endpoint": "http://localhost/lab/phantombank/login.php",
    "evidence": "1' OR '1'='1",
    "impact": "Full database read",
    "recommendation": "Use parameterized queries",
    "verification": "Re-run scan after remediation",
    "agent": "Analyzer Agent",
    "timestamp": "2026-01-01T00:00:00Z",
}


def make_finding(**overrides) -> dict:
    values = dict(FINDING_BASE)
    values.update(overrides)
    return values


class PersistFindingsRegressionTests(IsolatedAsyncioTestCase):
    """Critical fix: persist_findings must not crash on existing findings."""

    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.agent = OrchestratorAgent()
        self.scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="defend",
            intensity="medium",
            selected_tests=json.dumps([]),
            user_id="local-user",
        )

    def test_original_bug_is_reproducible(self) -> None:
        """Prove the pre-fix comprehension crashes on a real DB row."""
        import asyncio as _asyncio

        async def _probe() -> None:
            await create_finding(self.scan_id, FindingCreate(**make_finding()))
            (row,) = await get_findings(self.scan_id)
            # Pre-fix code: passes row.get(name) for EVERY model field,
            # including columns absent from the findings table (exploited, sources, ...)
            with self.assertRaises(Exception) as ctx:
                FindingCreate(**{name: row.get(name) for name in FindingCreate.model_fields})
            self.assertIn("exploited", str(ctx.exception))

        _asyncio.run(_probe())

    async def test_persist_findings_with_existing_rows_does_not_crash(self) -> None:
        # Seed one finding the way agents do (insert, then re-persist like multi-agent flow)
        await create_finding(self.scan_id, FindingCreate(**make_finding()))

        new_findings = [
            make_finding(),  # exact duplicate of the seeded finding -> must be skipped
            make_finding(title="XSS in search", category="xss", severity="MEDIUM", endpoint="/search.php"),
        ]
        persisted = await self.agent.persist_findings(self.scan_id, new_findings, "http://localhost/lab/phantombank")

        self.assertEqual(len(persisted), 2, "one seeded + one new unique finding")
        titles = {f["title"] for f in persisted}
        self.assertIn("SQL Injection in login", titles)
        self.assertIn("XSS in search", titles)

    async def test_persist_findings_on_empty_scan_still_works(self) -> None:
        persisted = await self.agent.persist_findings(
            self.scan_id,
            [make_finding(title="Header Injection", category="header")],
            "http://localhost/lab/phantombank",
        )
        self.assertEqual(len(persisted), 1)
        self.assertEqual(persisted[0]["title"], "Header Injection")


class WhoisFailureTests(IsolatedAsyncioTestCase):
    """HIGH fix: WHOIS must fail fast without blocking or spamming logs."""

    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.agent = ShadowReconAgent()
        self.agent.scan_id = await create_scan(
            target_url="http://example.com",
            mode="defend",
            intensity="medium",
            selected_tests=json.dumps([]),
            user_id="local-user",
        )

    async def test_whois_socket_error_returns_empty_quickly(self) -> None:
        def _raise_socket_error(domain: str, quiet: bool = False):
            raise OSError("Error trying to connect to socket")

        with patch("app.agents.shadow_recon.whois.whois", side_effect=_raise_socket_error) as mock_whois:
            result = await self.agent._lookup_whois("example.com")
        mock_whois.assert_called_once()
        self.assertEqual(result, {})

    async def test_whois_timeout_is_enforced(self) -> None:
        # Simulate wait_for firing: the 12s bound trips and we degrade gracefully.
        async def _noop_worker(*_args, **_kwargs) -> None:
            await asyncio.sleep(0)

        async def _firing_wait_for(coro, *_args, **_kwargs):
            await coro  # await the wrapped call so no coroutine is orphaned
            raise asyncio.TimeoutError()

        with patch("app.agents.shadow_recon.asyncio.wait_for", new=_firing_wait_for), patch(
            "app.agents.shadow_recon.asyncio.to_thread", new=_noop_worker
        ):
            result = await self.agent._lookup_whois("example.com")
        self.assertEqual(result, {})

    async def test_whois_success_path_returns_parsed_data(self) -> None:
        class FakeWhoisResult(dict):
            pass

        fake = FakeWhoisResult(
            registrar="Test Registrar",
            creation_date="2020-01-01",
            expiration_date="2030-01-01",
            name_servers=["ns1.example.com"],
            org="Example Org",
            dnssec="signed",
        )

        def _fake_whois(domain: str, quiet: bool = False):
            return fake

        with patch("app.agents.shadow_recon.whois.whois", side_effect=_fake_whois):
            result = await self.agent._lookup_whois("example.com")
        self.assertEqual(result["registrar"], "Test Registrar")
        self.assertEqual(result["registrant_org"], "Example Org")
        self.assertIn("dnssec", result["raw"])


class CrtshRetryTests(IsolatedAsyncioTestCase):
    """HIGH fix: crt.sh 503s must retry and never fail the scan."""

    class FakeResponse:
        def __init__(self, status_code: int, data=None) -> None:
            self.status_code = status_code
            self._data = data
            self.request = MagicMock()
            self.response = MagicMock()

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    f"status {self.status_code}", request=self.request, response=self.response
                )

        def json(self):
            return self._data

    def _client_for(self, responses: list[FakeResponse]):
        fake_http_client = MagicMock()
        fake_http_client.get = AsyncMock(side_effect=responses)
        client_instance = MagicMock()
        client_instance.__aenter__ = AsyncMock(return_value=fake_http_client)
        client_instance.__aexit__ = AsyncMock(return_value=False)
        return fake_http_client, client_instance

    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.agent = ShadowReconAgent()
        self.agent.scan_id = await create_scan(
            target_url="http://example.com",
            mode="defend",
            intensity="medium",
            selected_tests=json.dumps([]),
            user_id="local-user",
        )

    async def test_503_then_503_then_200_returns_subdomains(self) -> None:
        payload = [{"name_value": "www.example.com\napi.example.com", "not_before": "2026-01-01", "not_after": "2026-12-31"}]
        fake_http_client, client_instance = self._client_for(
            [
                self.FakeResponse(503),
                self.FakeResponse(503),
                self.FakeResponse(200, payload),
            ]
        )
        with patch("app.agents.shadow_recon.httpx.AsyncClient", return_value=client_instance):
            result = await self.agent._fetch_crtsh_subdomains("example.com")

        self.assertEqual(fake_http_client.get.await_count, 3, "must retry twice after 503s")
        names = {s["subdomain"] for s in result}
        self.assertEqual(names, {"www.example.com", "api.example.com"})

    async def test_persistent_503_returns_empty_without_raising(self) -> None:
        fake_http_client, client_instance = self._client_for(
            [self.FakeResponse(503), self.FakeResponse(503), self.FakeResponse(503)]
        )
        with patch("app.agents.shadow_recon.httpx.AsyncClient", return_value=client_instance):
            result = await self.agent._fetch_crtsh_subdomains("example.com")

        self.assertEqual(fake_http_client.get.await_count, 3)
        self.assertEqual(result, [])


class SastFindingNormalizationTests(IsolatedAsyncioTestCase):
    """SAST/secret/SCA finding shapes (from sast_worker) must normalize and persist."""

    async def asyncSetUp(self) -> None:
        await initialize_database()

    def test_semgrep_finding_normalizes(self) -> None:
        semgrep = {
            "type": "sast",
            "tool": "semgrep",
            "rule_id": "python.lang.security.audit.dangerous-system-call",
            "severity": "HIGH",
            "message": "Detected dangerous system call",
            "file_path": "src/app.py",
            "line_start": 42,
            "code_snippet": "os.system(cmd)",
            "cwe_ids": ["CWE-78"],
            "rule_name": "dangerous-system-call",
        }
        finding = OrchestratorAgent.normalize_finding(semgrep, "https://github.com/owner/repo")

        self.assertEqual(finding.title, "dangerous-system-call")
        self.assertEqual(finding.category, "SAST")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.endpoint, "src/app.py")
        self.assertIn("src/app.py:42", finding.evidence)
        self.assertEqual(finding.module, "semgrep")
        self.assertEqual(finding.cwe, "CWE-78")

    def test_unverified_secret_is_medium(self) -> None:
        secret = {
            "type": "secret",
            "tool": "trufflehog",
            "detector_name": "AWS",
            "secret_type": "AWS Access Key",
            "file_path": "config.py",
            "line_number": 7,
            "matched_content": "AKIA...",
            "verified": False,
        }
        finding = OrchestratorAgent.normalize_finding(secret, "https://github.com/owner/repo")
        self.assertEqual(finding.severity, "MEDIUM")
        self.assertEqual(finding.category, "Secrets · trufflehog")

    def test_verified_secret_is_high(self) -> None:
        secret = {
            "type": "secret",
            "tool": "gitleaks",
            "detector_name": "AWS",
            "secret_type": "AWS Access Key",
            "file_path": "config.py",
            "matched_content": "AKIA...",
            "verified": True,
        }
        finding = OrchestratorAgent.normalize_finding(secret, "https://github.com/owner/repo")
        self.assertEqual(finding.severity, "HIGH")

    def test_sca_finding_gets_cve_and_recommendation(self) -> None:
        sca = {
            "type": "sca",
            "tool": "pip-audit",
            "package_name": "requests",
            "package_version": "2.20.0",
            "vulnerability_id": "GHSA-xxxx-xxxx-xxxx",
            "fixed_version": "2.31.0",
            "advisory_url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
        }
        finding = OrchestratorAgent.normalize_finding(sca, "https://github.com/owner/repo")
        self.assertEqual(finding.title, "Vulnerable dependency: requests (GHSA-xxxx-xxxx-xxxx)")
        self.assertEqual(finding.category, "SCA · pip-audit")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.cve_id, "GHSA-xxxx-xxxx-xxxx")
        self.assertIn("2.31.0", finding.recommendation)
        self.assertIn("GHSA", finding.evidence)

    def test_error_only_dict_is_skipped(self) -> None:
        with self.assertRaises(ValueError):
            OrchestratorAgent.normalize_finding({"error": "Semgrep failed: not installed"}, "x")

    async def test_semgrep_findings_persist_without_duplicates(self) -> None:
        scan_id = await create_scan(
            target_url="https://github.com/owner/repo",
            mode="multi_agent",
            intensity="medium",
            selected_tests=json.dumps(["github"]),
            user_id="local-user",
        )
        findings = [
            {
                "type": "sast",
                "tool": "semgrep",
                "rule_id": "rules.alert",
                "severity": "HIGH",
                "message": "Detected X",
                "file_path": "src/app.py",
                "line_start": 3,
            },
            {
                "type": "sast",
                "tool": "semgrep",
                "rule_id": "rules.alert",
                "severity": "HIGH",
                "message": "Detected X",
                "file_path": "src/app.py",
                "line_start": 3,
            },
        ]
        agent = OrchestratorAgent()
        persisted = await agent.persist_findings(scan_id, findings, "https://github.com/owner/repo")
        self.assertEqual(len(persisted), 1, "duplicate SAST findings must dedup")
        self.assertEqual(persisted[0]["title"], "rules.alert")
        self.assertEqual(persisted[0]["endpoint"], "src/app.py")


if __name__ == "__main__":
    import unittest

    unittest.main()
