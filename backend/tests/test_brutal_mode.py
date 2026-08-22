"""Brutal Mode (Black Ops) safety + capability tests.

Covers:
1. Gate enforcement: env flag, admin role, Private Scope / Lab target, ownership ack.
2. Shell executor: destructive-command filter, budget, closed-session handling, audit rows.
3. Exploitation engine: unsupported categories, SQLi flow against the lab sim, loot capture.
4. Exfiltration: ZIP packing with MANIFEST, checksum, and traversal-safe resolution.
5. AI payload generator: deterministic offline fallback.

Run:  python -m pytest tests/test_brutal_mode.py -v
"""

import asyncio
import io
import os
import tempfile
import zipfile
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

_db_fd, _db_path = tempfile.mkstemp(suffix=".sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")

from app.agents.ai_payload import AIPayloadGenerator  # noqa: E402
from app.agents.brutal_exploit import ExploitationEngine, SUPPORTED_CATEGORIES  # noqa: E402
from app.agents.exfil import ExfiltrationAgent, decrypt_archive, resolve_archive  # noqa: E402
from app.brutal_gate import BrutalGate, BrutalGateError, is_lab_target  # noqa: E402
from app.brutal_sessions import BrutalSession, BrutalSessionManager  # noqa: E402
from app.config import Settings, get_settings  # noqa: E402
from app.database import initialize_database, list_brutal_ops  # noqa: E402
from app.services.reverse_shell import is_dangerous, run_command  # noqa: E402

ADMIN = {"id": "u-admin-test", "role": "admin", "email": "admin@example.com"}
USER = {"id": "u-user-test", "role": "user", "email": "user@example.com"}

LAB_TARGET = "http://localhost:8000/lab/phantombank"
EVIL_TARGET = "http://evil.example.com/"


def set_brutal_mode(enabled: bool) -> None:
    """Flip the kill switch.

    Settings fields are class attributes evaluated once at import time, so
    env changes cannot re-evaluate them — assign the class attribute directly.
    """
    Settings.brutal_mode_enabled = enabled


def make_session(target_url: str = LAB_TARGET, actor: str = "u-admin-test") -> BrutalSession:
    session = BrutalSession(
        session_id="test" + os.urandom(3).hex(),
        target_url=target_url,
        actor=actor,
        created_at=0.0,
    )
    return session


class GateEnforcementTests(IsolatedAsyncioTestCase):
    """The gate must deny every unsafe combination, in order."""

    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.gate = BrutalGate()

    async def test_gate_off_by_default(self) -> None:
        set_brutal_mode(False)
        self.assertFalse(self.gate.is_enabled())
        with self.assertRaises(BrutalGateError) as ctx:
            await self.gate.authorize(ADMIN, LAB_TARGET, True)
        self.assertEqual(ctx.exception.code, "BRUTAL_MODE_DISABLED")

    async def test_gate_denies_non_admin(self) -> None:
        set_brutal_mode(True)
        with self.assertRaises(BrutalGateError) as ctx:
            await self.gate.authorize(USER, LAB_TARGET, True)
        self.assertEqual(ctx.exception.code, "ADMIN_REQUIRED")

    async def test_gate_denies_target_outside_scope(self) -> None:
        set_brutal_mode(True)
        with self.assertRaises(BrutalGateError) as ctx:
            await self.gate.authorize(ADMIN, EVIL_TARGET, True)
        self.assertEqual(ctx.exception.code, "TARGET_NOT_IN_SCOPE")

    async def test_gate_requires_ownership_ack(self) -> None:
        set_brutal_mode(True)
        with self.assertRaises(BrutalGateError) as ctx:
            await self.gate.authorize(ADMIN, LAB_TARGET, False)
        self.assertEqual(ctx.exception.code, "OWNERSHIP_ACK_REQUIRED")
        self.assertEqual(ctx.exception.http_status, 422)

    async def test_gate_allows_lab_with_ack(self) -> None:
        set_brutal_mode(True)
        hostname = await self.gate.authorize(ADMIN, LAB_TARGET, True)
        self.assertEqual(hostname, "localhost")

    async def test_is_lab_target_helper(self) -> None:
        self.assertTrue(is_lab_target("http://127.0.0.1:8000/"))
        self.assertTrue(is_lab_target("localhost"))
        self.assertFalse(is_lab_target("https://not-localhost.com"))


class ShellSafetyTests(IsolatedAsyncioTestCase):
    """The shell executor must never run destructive commands and must audit."""

    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_brutal_mode(True)
        self.session = make_session()
        self.shell = MagicMock()
        self.shell.closed = False
        self.shell.command_count = 0
        self.shell.session_id = self.session.session_id
        self.shell.target_url = self.session.target_url
        self.shell.actor = self.session.actor

    def test_dangerous_pattern_filter(self) -> None:
        for command in ["rm -rf /", "shutdown /s /t 0", "mkfs.ext4 /dev/sda1", "dd if=/dev/zero of=/dev/sda", ":(){ :|:& };:"]:
            self.assertTrue(is_dangerous(command), command)
        for command in ["whoami", "ls -la", "netstat -ano", "cat /etc/passwd", "python3 -c 'print(1)'"]:
            self.assertFalse(is_dangerous(command), command)

    async def test_dangerous_command_is_denied_and_audited(self) -> None:
        result = await run_command(self.shell, "rm -rf /")
        self.assertIn("error", result)
        ops = await list_brutal_ops(self.session.session_id)
        self.assertEqual(ops[0]["action"], "shell_command_blocked")
        self.assertEqual(ops[0]["status"], "denied")

    async def test_closed_shell_rejects_commands(self) -> None:
        self.shell.closed = True
        result = await run_command(self.shell, "whoami")
        self.assertIn("closed", result["error"])

    async def test_empty_command_rejected(self) -> None:
        result = await run_command(self.shell, "   ")
        self.assertIn("empty", result["error"])

    async def test_budget_exhaustion(self) -> None:
        self.shell.command_count = get_settings().brutal_max_commands_per_shell
        result = await run_command(self.shell, "whoami")
        self.assertIn("budget", result["error"])


class ExploitationEngineTests(IsolatedAsyncioTestCase):
    """Exploit flows must capture loot and record timeline events."""

    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_brutal_mode(True)
        self.session = make_session()
        self.engine = ExploitationEngine(self.session)

    async def test_unsupported_category(self) -> None:
        result = await self.engine.exploit("zeroday")
        self.assertFalse(result["success"])
        self.assertIn("Unsupported", result["error"])

    async def test_sqli_flow_captures_loot(self) -> None:
        fake_rows = [
            {"id": 1, "username": "admin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
            {"id": 2, "username": "bob", "password_hash": "e10adc3949ba59abbe56e057f20f883e"},
        ]

        class FakeResponse:
            def __init__(self, data) -> None:
                self._data = data

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict:
                return self._data

        with patch("app.agents.brutal_exploit.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post.return_value = FakeResponse({"rows": fake_rows})
            result = await self.engine.exploit("sqli")

        self.assertTrue(result["success"])
        self.assertEqual(len(result["rows"]), 2)
        self.assertEqual(len(self.session.loot), 1)
        self.assertEqual(self.session.loot[0]["kind"], "database")
        actions = [event["action"] for event in self.session.timeline]
        self.assertIn("exploited", actions)

    async def test_category_map(self) -> None:
        self.assertIn("sqli", SUPPORTED_CATEGORIES)
        self.assertIn("rce", SUPPORTED_CATEGORIES)
        self.assertIn("xss", SUPPORTED_CATEGORIES)


class RealTargetExploitationTests(IsolatedAsyncioTestCase):
    """Private-scope targets must use the findings-driven real engine, gated on EXPLOITATION_ENABLED."""

    REAL_TARGET = "http://192.168.1.50/"

    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_brutal_mode(True)
        self.old_enabled = Settings.exploitation_enabled
        self.addCleanup(self._restore)
        self.session = make_session(target_url=self.REAL_TARGET)

    def _restore(self) -> None:
        Settings.exploitation_enabled = self.old_enabled

    async def test_real_target_gated_off_by_default(self) -> None:
        Settings.exploitation_enabled = False
        engine = ExploitationEngine(self.session)
        result = await engine.exploit("sqli")
        self.assertFalse(result["success"])
        self.assertIn("EXPLOITATION_ENABLED", result["error"])

    async def test_real_sqli_uses_session_findings_and_captures_loot(self) -> None:
        Settings.exploitation_enabled = True
        self.session.findings = [
            {
                "category": "sql_injection",
                "severity": "CRITICAL",
                "endpoint": "http://192.168.1.50/login.php",
            }
        ]

        class FakeResponse:
            status_code = 200
            text = "sqlite_version admin users password"

        with patch("app.agents.exploitation_engine.httpx.AsyncClient") as mock_client:
            mock_client.return_value.get = AsyncMock(return_value=FakeResponse())
            mock_client.return_value.aclose = AsyncMock()
            engine = ExploitationEngine(self.session)
            result = await engine.exploit("sqli")

        self.assertTrue(result["success"])
        self.assertTrue(result.get("real"))
        self.assertEqual(len(self.session.loot), 1)
        self.assertEqual(self.session.loot[0]["kind"], "database")
        actions = [event["action"] for event in self.session.timeline]
        self.assertIn("exploited", actions)


class ExfiltrationTests(IsolatedAsyncioTestCase):
    """Loot packing must be atomic, checksummed and traversal-safe."""

    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_brutal_mode(True)
        self.session = make_session()
        self.session.add_loot("database", "users_dump.json", '{"admin": "hash"}', "sqli")
        self.session.add_loot("file", "/etc/passwd", "root:x:0:0:root:/root:/bin/bash", "lfi")
        self.agent = ExfiltrationAgent(self.session)

    async def test_pack_requires_loot(self) -> None:
        empty = make_session()
        agent = ExfiltrationAgent(empty)
        with self.assertRaises(ValueError):
            await agent.pack()

    async def test_pack_creates_encrypted_zip_with_manifest(self) -> None:
        result = await self.agent.pack()
        self.assertTrue(result["filename"].endswith(".enc"))
        self.assertTrue(result["encrypted"])
        path = resolve_archive(result["file_id"])
        self.assertIsNotNone(path)
        self.assertTrue(path.read_bytes().startswith(b"PHSC"))
        with zipfile.ZipFile(io.BytesIO(decrypt_archive(path.read_bytes(), self.session.session_id))) as archive:
            names = archive.namelist()
            self.assertIn("MANIFEST.txt", names)
            self.assertIn("users_dump.json", names)
            manifest = archive.read("MANIFEST.txt").decode("utf-8")
            self.assertIn("sqli", manifest)
        with self.assertRaises(ValueError):
            decrypt_archive(path.read_bytes(), "wrong-session-id")
        self.assertEqual(result["loot_count"], 2)

    async def test_resolve_guards_against_traversal(self) -> None:
        self.assertIsNone(resolve_archive("../outside.zip"))
        self.assertIsNone(resolve_archive("..\\..\\windows\\system32"))
        self.assertIsNone(resolve_archive("not_a_zip.txt"))
        self.assertIsNone(resolve_archive("malware.exe"))


class AIPayloadFallbackTests(IsolatedAsyncioTestCase):
    """Without an API key the generator must return deterministic payloads."""

    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.old_key = Settings.openrouter_api_key
        Settings.openrouter_api_key = ""
        self.addCleanup(self._restore)
        self.session = make_session()

    def _restore(self) -> None:
        Settings.openrouter_api_key = self.old_key

    async def test_offline_fallback_reverse_shell(self) -> None:
        generator = AIPayloadGenerator(self.session)
        result = await generator.generate("reverse_shell", "linux")
        self.assertIn("payload", result)
        self.assertIn("/dev/tcp/127.0.0.1/4444", result["payload"])
        self.assertIn("Offline", result["explanation"])

    async def test_offline_fallback_webshell(self) -> None:
        generator = AIPayloadGenerator(self.session)
        result = await generator.generate("webshell", "php")
        self.assertIn("<?php", result["payload"])

    async def test_results_are_cached(self) -> None:
        generator = AIPayloadGenerator(self.session)
        first = await generator.generate("lfi", "passwd")
        second = await generator.generate("lfi", "passwd")
        self.assertEqual(first["payload"], second["payload"])
        self.assertTrue(second["cached"])