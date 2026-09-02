import asyncio
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import aiosqlite

os.environ.setdefault("MAX_TOTAL_REQUESTS", "50")
os.environ.setdefault("MAX_REQUESTS_PER_SECOND", "100")

from app.agents.multi_agent_orchestrator import (  # noqa: E402
    AttackAgent,
    ExploitAgent,
    MultiAgentOrchestrator,
    ReconAgent,
    ReportAgent,
    SharedContext,
    WorkflowGraph,
)
from app.database import (  # noqa: E402
    DATABASE_PATH,
    SCHEMA_SQL,
    _migrate_scans_mode_check,
    create_scan,
    initialize_database,
)
from app.models import ScanRequest  # noqa: E402


def make_request(**overrides) -> ScanRequest:
    values = {
        "target_url": "http://localhost/lab/phantombank",
        "mode": "multi_agent",
        "intensity": "low",
        "selected_tests": ["xss"],
    }
    values.update(overrides)
    return ScanRequest(**values)


def make_context(scan_request: ScanRequest, host: SimpleNamespace, scan_id: int) -> SharedContext:
    return SharedContext(
        target_url=scan_request.target_url,
        scan_id=scan_id,
        scan_request=scan_request,
        host=host,
        user_id="local-user",
        authorization_context={"authorization_id": None},
    )


class FakeRunner:
    def __init__(self, results: dict[str, object] | None = None) -> None:
        self.results = results or {}
        self.calls: list[str] = []
        self.limits = None

    async def run_agent(self, event_name: str, agent_name: str, operation, scan_id: int, **kwargs):
        self.calls.append(event_name)
        return {
            "agent": event_name,
            "agent_name": agent_name,
            "status": "complete",
            "result": self.results.get(event_name, {}),
        }

    async def gather_agents(self, *operations, **kwargs):
        return [await operation for operation in operations]


def fake_agent_class(result: object):
    class FakeAgent:
        name = "Fake Agent"

        def __init__(self, *args, **kwargs) -> None:
            pass

        async def run(self, *args, **kwargs):
            return result

        async def run_active_scan(self, *args, **kwargs):
            return result

    return FakeAgent


class WorkflowGraphTests(IsolatedAsyncioTestCase):
    async def test_respects_dependencies_and_runs_ready_nodes_concurrently(self) -> None:
        order: list[str] = []

        async def op(name: str, delay: float, _context):
            async def run(_context):
                order.append(f"{name}:start")
                await asyncio.sleep(delay)
                order.append(f"{name}:end")
                return name

            return run

        graph = WorkflowGraph()
        context = SimpleNamespace()
        a = await op("a", 0.1, context)
        b = await op("b", 0.05, context)
        c = await op("c", 0.1, context)
        d = await op("d", 0.05, context)
        graph.add_node("a", a, dependencies=[])
        graph.add_node("b", b, dependencies=["a"])
        graph.add_node("c", c, dependencies=["a"])
        graph.add_node("d", d, dependencies=["b", "c"])

        started = asyncio.get_running_loop().time()
        results = await graph.execute(context)
        elapsed = asyncio.get_running_loop().time() - started

        self.assertEqual(results["a"], "a")
        self.assertEqual(results["b"], "b")
        self.assertEqual(results["c"], "c")
        self.assertEqual(results["d"], "d")
        self.assertEqual(order[0], "a:start")
        self.assertEqual(order[-1], "d:end")
        self.assertIn("b:start", order)
        self.assertIn("c:start", order)
        self.assertLess(order.index("b:start"), order.index("d:start"))
        self.assertLess(elapsed, 0.45, "dependent levels should run concurrently")

    async def test_independent_nodes_run_in_parallel(self) -> None:
        async def slow(name: str, _context):
            async def run(_context):
                await asyncio.sleep(0.15)
                return name

            return run

        graph = WorkflowGraph()
        context = SimpleNamespace()
        graph.add_node("x", await slow("x", context), dependencies=[])
        graph.add_node("y", await slow("y", context), dependencies=[])
        started = asyncio.get_running_loop().time()
        results = await graph.execute(context)
        elapsed = asyncio.get_running_loop().time() - started
        self.assertEqual(results, {"x": "x", "y": "y"})
        self.assertLess(elapsed, 0.25, "independent nodes must overlap in time")

    async def test_stalled_graph_raises(self) -> None:
        graph = WorkflowGraph()

        async def run(_context):
            return "never"

        graph.add_node("a", run, dependencies=["b"])
        graph.add_node("b", run, dependencies=["a"])
        with self.assertRaises(RuntimeError):
            await graph.execute(SimpleNamespace())

    async def test_failing_node_propagates_and_skips_downstream(self) -> None:
        graph = WorkflowGraph()
        ran: list[str] = []

        async def run(_context):
            ran.append("ok")
            return "ok"

        async def boom(_context):
            ran.append("boom")
            raise RuntimeError("node failure")

        graph.add_node("a", run, dependencies=[])
        graph.add_node("b", boom, dependencies=["a"])
        graph.add_node("c", run, dependencies=["b"])
        with self.assertRaises(RuntimeError):
            await graph.execute(SimpleNamespace())
        self.assertEqual(ran, ["ok", "boom"], "downstream node c must not run after failure")


class AgentRunLedgerTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="multi_agent",
            intensity="low",
            selected_tests=json.dumps(["xss"]),
        )
        self.host = SimpleNamespace(
            publish=self._publish,
            log_action=self._log_action,
        )
        self.published: list[tuple[str, str, dict]] = []

    async def _publish(self, scan_id: int, event: str, payload: dict) -> None:
        self.published.append((event, payload.get("status"), payload))

    async def _log_action(self, action: str, details: str) -> None:
        pass

    async def _runs(self) -> list[dict]:
        async with aiosqlite.connect(str(DATABASE_PATH)) as connection:
            connection.row_factory = aiosqlite.Row
            cursor = await connection.execute(
                "SELECT * FROM agent_runs WHERE scan_id = ? ORDER BY id ASC", (self.scan_id,)
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def test_run_agent_logs_completed_ledger_row(self) -> None:
        orchestrator = MultiAgentOrchestrator(host=self.host)

        async def ok():
            return {"done": True}

        event = await orchestrator.run_agent("fake_node", "Fake Agent", ok, self.scan_id)
        self.assertEqual(event["status"], "complete")
        runs = await self._runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["agent_name"], "Fake Agent")
        self.assertEqual(runs[0]["status"], "completed")
        self.assertIsNone(runs[0]["error_message"])
        self.assertIsNotNone(runs[0]["start_time"])
        self.assertIsNotNone(runs[0]["end_time"])
        self.assertIsInstance(runs[0]["execution_time"], float)
        self.assertGreaterEqual(runs[0]["execution_time"], 0)
        self.assertEqual(runs[0]["attempts"], 1)

    async def test_run_agent_logs_failed_ledger_row_with_error(self) -> None:
        orchestrator = MultiAgentOrchestrator(host=self.host)

        async def boom():
            raise RuntimeError("exploded")

        with self.assertRaises(RuntimeError):
            await orchestrator.run_agent("fake_node", "Fake Agent", boom, self.scan_id)
        runs = await self._runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["status"], "failed")
        self.assertIn("exploded", runs[0]["error_message"])
        self.assertIsNotNone(runs[0]["execution_time"])

    async def test_run_agent_retries_and_records_attempts(self) -> None:
        orchestrator = MultiAgentOrchestrator(host=self.host)
        attempts = 0

        async def flaky():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ValueError("first try fails")
            return {"ok": True}

        event = await orchestrator.run_agent(
            "fake_node", "Fake Agent", flaky, self.scan_id, max_retries=1
        )
        self.assertEqual(event["attempt"], 2)
        runs = await self._runs()
        self.assertEqual(runs[0]["status"], "completed")
        self.assertEqual(runs[0]["attempts"], 2)


class ReconAgentTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="multi_agent",
            intensity="low",
            selected_tests=json.dumps(["xss"]),
        )
        self.host = SimpleNamespace(
            set_progress=self._set_progress,
            publish=self._publish,
        )
        self.progress_calls: list[tuple[int, str]] = []
        self.published: list[tuple[str, dict]] = []

    async def _set_progress(self, scan_id: int, progress: int, phase: str, **kwargs) -> None:
        self.progress_calls.append((progress, phase))

    async def _publish(self, scan_id: int, event: str, payload: dict) -> None:
        self.published.append((event, payload))

    async def test_recon_merges_scanner_and_shadow_recon_into_context(self) -> None:
        runner = FakeRunner(
            {
                "scanner": {"findings": [{"title": "tech"}]},
                "shadow_recon": {"paths": ["/admin"]},
            }
        )
        scan_request = make_request()
        context = make_context(scan_request, self.host, self.scan_id)
        with (
            patch("app.agents.multi_agent_orchestrator.ScannerAgent", fake_agent_class({})),
            patch("app.agents.multi_agent_orchestrator.ShadowReconAgent", fake_agent_class({})),
        ):
            result = await ReconAgent(runner).run(context)
        self.assertEqual(result["scanner_output"]["findings"][0]["title"], "tech")
        self.assertEqual(result["shadow_output"]["paths"], ["/admin"])
        self.assertEqual(context.stages["recon"], result)
        self.assertEqual(self.progress_calls, [(30, "reconnaissance_complete")])
        self.assertEqual(runner.calls, ["scanner", "shadow_recon"])
        self.assertEqual(self.published[0][0], "tci_computed")


class AttackAgentTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="multi_agent",
            intensity="low",
            selected_tests=json.dumps(["xss"]),
        )
        self.host = SimpleNamespace(
            run_ai_decision_maker=self._decision,
            publish=self._publish,
            collect_findings=self._collect,
            persist_findings=self._persist,
            set_progress=self._set_progress,
        )
        self.progress_calls: list[tuple[int, str]] = []
        self.persisted_input: list[dict] | None = None

    async def _decision(self, *args, **kwargs):
        return ["xss", "cors"]

    async def _publish(self, scan_id: int, event: str, payload: dict) -> None:
        pass

    def _collect(self, events: list[dict], target_url: str) -> list[dict]:
        return [{"title": "XSS in search", "category": "xss", "severity": "HIGH"}]

    async def _persist(self, scan_id: int, findings: list[dict], target_url: str) -> list[dict]:
        self.persisted_input = findings
        return findings

    async def _set_progress(self, scan_id: int, progress: int, phase: str, **kwargs) -> None:
        self.progress_calls.append((progress, phase))

    async def test_attack_runs_parallel_engines_and_persists_findings(self) -> None:
        scan_request = make_request(enable_exploitation=False)
        context = make_context(scan_request, self.host, self.scan_id)
        context.stages["recon"] = {
            "scanner_output": {"tech_stack": {"technologies": ["flask"]}},
            "shadow_output": {},
        }
        runner = FakeRunner({"sandbox_manager": {"request_count": 3}})
        with patch.multiple(
            "app.agents.multi_agent_orchestrator",
            AnalyzerAgent=fake_agent_class({}),
            CVEMatcherAgent=fake_agent_class({}),
            BrowserSecurityAgent=fake_agent_class({"pages": []}),
            AuthSecurityAgent=fake_agent_class({}),
            AccessControlAgent=fake_agent_class({}),
            ApiSecurityAgent=fake_agent_class({}),
            SessionSecurityAgent=fake_agent_class({}),
            InjectionAnalysisAgent=fake_agent_class({}),
            InfrastructureAgent=fake_agent_class({}),
            WebSocketSecurityAgent=fake_agent_class({}),
            DependencyAgent=fake_agent_class({}),
            ThreatIntelligenceAgent=fake_agent_class({}),
            SandboxManagerAgent=fake_agent_class({"request_count": 3}),
            AIExplainerAgent=fake_agent_class({"findings": [{"title": "XSS in search", "category": "xss", "severity": "HIGH"}]}),
        ):
            stage = await AttackAgent(runner).run(context)
        self.assertEqual(stage["ai_decision"], ["xss", "cors"])
        self.assertEqual(stage["persisted_findings"][0]["title"], "XSS in search")
        self.assertEqual(stage["request_count"], 3)
        self.assertIn("sandbox_manager", runner.calls)
        self.assertEqual(self.persisted_input, stage["enriched_findings"])
        self.assertEqual(
            self.progress_calls,
            [(65, "analysis_complete"), (78, "explanations_complete"), (86, "findings_persisted")],
        )
        self.assertEqual(context.stages["attack"], stage)


class ExploitAgentTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="multi_agent",
            intensity="low",
            selected_tests=json.dumps(["xss"]),
        )
        self.host = SimpleNamespace(
            set_progress=self._set_progress,
            run_sqli_exploitation=self._sqli,
            run_ai_exploitation=self._ai,
        )
        self.progress_calls: list[tuple[int, str]] = []
        self.sqli_calls = 0
        self.ai_calls = 0

    async def _set_progress(self, scan_id: int, progress: int, phase: str, **kwargs) -> None:
        self.progress_calls.append((progress, phase))

    async def _sqli(self, *args, **kwargs) -> None:
        self.sqli_calls += 1

    async def _ai(self, *args, **kwargs) -> dict:
        self.ai_calls += 1
        return {"status": "complete", "exploitation_results": []}

    def test_stage_skipped_when_exploitation_disabled(self) -> None:
        pass

    async def test_exploit_disabled_leaves_stage_empty(self) -> None:
        scan_request = make_request(enable_exploitation=False)
        context = make_context(scan_request, self.host, self.scan_id)
        context.stages["attack"] = {
            "persisted_findings": [{"title": "XSS", "category": "xss"}],
            "request_count": 4,
            "sandbox_id": None,
        }
        runner = FakeRunner()
        stage = await ExploitAgent(runner).run(context)
        self.assertIsNone(stage["exploitation_result"])
        self.assertIsNone(stage["ai_exploitation"])
        self.assertEqual(self.sqli_calls, 0)
        self.assertEqual(self.ai_calls, 0)
        self.assertEqual(self.progress_calls, [])

    async def test_exploit_enabled_runs_all_exploitation_engines(self) -> None:
        scan_request = make_request(enable_exploitation=True)
        context = make_context(scan_request, self.host, self.scan_id)
        context.stages["attack"] = {
            "persisted_findings": [{"title": "SQLi", "category": "sql_injection"}],
            "request_count": 4,
            "sandbox_id": "sandbox-1",
        }
        runner = FakeRunner({"exploitation": {"exploitation_results": [{"id": 1}]}})
        with patch("app.agents.multi_agent_orchestrator.ExploitationAgent", fake_agent_class({"exploitation_results": [{"id": 1}]})):
            stage = await ExploitAgent(runner).run(context)
        self.assertEqual(stage["exploitation_result"]["exploitation_results"], [{"id": 1}])
        self.assertEqual(stage["ai_exploitation"]["status"], "complete")
        self.assertEqual(self.sqli_calls, 1)
        self.assertEqual(self.ai_calls, 1)
        self.assertEqual(
            self.progress_calls,
            [(87, "exploitation_started"), (89, "exploitation_complete")],
        )


class ReportAgentTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="multi_agent",
            intensity="low",
            selected_tests=json.dumps(["xss"]),
        )
        self.host = SimpleNamespace(
            set_progress=self._set_progress,
            browser_report=lambda result: "# Browser\n",
            run_ai_security_analyst=self._analyst,
            _write_report_files=self._write_files,
        )
        self.progress_calls: list[tuple[int, str]] = []
        self.analyst_calls = 0
        self.write_calls = 0

    async def _set_progress(self, scan_id: int, progress: int, phase: str, **kwargs) -> None:
        self.progress_calls.append((progress, phase))

    async def _analyst(self, **kwargs) -> dict:
        self.analyst_calls += 1
        return {"ai_available": False, "security_summary": {}}

    async def _write_files(self, *args, **kwargs) -> None:
        self.write_calls += 1

    async def test_report_assembles_summary_and_notifies(self) -> None:
        scan_request = make_request(enable_exploitation=False)
        context = make_context(scan_request, self.host, self.scan_id)
        context.stages["recon"] = {
            "scanner_output": {"tech_stack": {}},
            "shadow_output": {},
        }
        context.stages["attack"] = {
            "persisted_findings": [{"title": "XSS", "category": "xss"}],
            "active_result": None,
            "browser_result": {"pages": [{"url": "/"}], "network_events": [], "api_inventory": [], "findings": []},
            "ai_decision": ["xss"],
            "request_count": 2,
        }
        context.stages["exploit"] = {
            "exploitation_result": None,
            "ai_exploitation": None,
            "sqli_results": [],
        }
        runner = FakeRunner(
            {
                "fixer": {"markdown_report": "# Report\n"},
                "notifier": {"delivered": True},
            }
        )
        with (
            patch("app.agents.multi_agent_orchestrator.FixerAgent", fake_agent_class({"markdown_report": "# Report\n"})),
            patch("app.agents.multi_agent_orchestrator.NotifierAgent", fake_agent_class({"delivered": True})),
        ):
            summary = await ReportAgent(runner).run(context)

        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["scan_id"], self.scan_id)
        self.assertEqual(summary["findings"][0]["title"], "XSS")
        self.assertIn("# Report", summary["markdown_report"])
        self.assertIn("# Browser", summary["markdown_report"])
        self.assertEqual(summary["notification"], {"delivered": True})
        self.assertEqual(summary["ai_decision"], ["xss"])
        self.assertEqual(context.summary, summary)
        self.assertEqual(self.analyst_calls, 1)
        self.assertEqual(self.write_calls, 1)
        self.assertEqual(
            self.progress_calls,
            [(93, "report_complete"), (95, "ai_analysis_complete"), (97, "notification_complete")],
        )


class MultiAgentModePlumbingTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()

    async def test_scan_request_accepts_multi_agent_mode(self) -> None:
        request = make_request()
        self.assertEqual(request.mode, "multi_agent")

    async def test_create_scan_accepts_multi_agent_mode(self) -> None:
        scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="multi_agent",
            intensity="low",
            selected_tests=json.dumps(["xss"]),
        )
        self.assertIsInstance(scan_id, int)
        self.assertGreater(scan_id, 0)

    async def test_orchestrator_requires_host(self) -> None:
        with self.assertRaises(RuntimeError):
            await MultiAgentOrchestrator().run(make_context(make_request(), SimpleNamespace(), 1))


class ScansModeMigrationTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fd, self.path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(self.fd)
        self.connection = await aiosqlite.connect(self.path)
        self.connection.row_factory = aiosqlite.Row
        await self.connection.executescript(SCHEMA_SQL)

    async def asyncTearDown(self) -> None:
        await self.connection.close()
        os.unlink(self.path)

    async def test_legacy_scans_constraint_is_upgraded_and_rows_preserved(self) -> None:
        await self.connection.execute("DROP TABLE scans")
        await self.connection.executescript(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                mode TEXT NOT NULL CHECK (mode IN ('defend', 'pentest')),
                intensity TEXT NOT NULL DEFAULT 'medium',
                selected_tests TEXT NOT NULL DEFAULT '[]',
                user_id TEXT NOT NULL DEFAULT 'local-user',
                authorization_id INTEGER,
                authorization_confirmed INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued',
                progress INTEGER NOT NULL DEFAULT 0,
                request_count INTEGER NOT NULL DEFAULT 0,
                sandbox_id TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                completed_at TEXT
            );
            INSERT INTO scans (target_url, mode) VALUES ('http://legacy.test', 'pentest');
            """
        )
        await self.connection.commit()

        await _migrate_scans_mode_check(self.connection)

        cursor = await self.connection.execute("SELECT * FROM scans")
        rows = [dict(row) for row in await cursor.fetchall()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target_url"], "http://legacy.test")
        self.assertEqual(rows[0]["mode"], "pentest")

        await self.connection.execute(
            "INSERT INTO scans (target_url, mode) VALUES (?, ?)",
            ("http://new.test", "multi_agent"),
        )
        await self.connection.commit()
        cursor = await self.connection.execute("SELECT COUNT(*) AS n FROM scans")
        self.assertEqual((await cursor.fetchone())["n"], 2)

        cursor = await self.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
        )
        self.assertIn("multi_agent", str((await cursor.fetchone())["sql"]))

    async def test_migration_is_noop_for_current_schema(self) -> None:
        await _migrate_scans_mode_check(self.connection)
        cursor = await self.connection.execute("SELECT COUNT(*) AS n FROM scans")
        self.assertEqual((await cursor.fetchone())["n"], 0)
