import json
import os
import tempfile
from datetime import datetime, timezone
from unittest import IsolatedAsyncioTestCase

_db_fd, _db_path = tempfile.mkstemp(suffix=".exec.sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")

from fastapi.testclient import TestClient

from app.config import get_settings
get_settings.cache_clear()

from app.database import create_scan, initialize_database, upsert_execution_status, get_execution_status, clear_execution_status, update_authorized_test_job, create_authorized_test_job
from app.services.execution_status import (
    default_agent_states,
    build_pentest_agent_states,
    build_defend_agent_states,
    build_lab_agent_states,
    build_self_audit_agent_states,
    update_authorized_test_execution,
    update_defend_scan_execution,
    update_self_audit_execution,
    is_any_execution_running,
    clear_execution,
)
from main import app
from tests.conftest import create_auth_headers


class AgentStateBuilderTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.names = {a["name"] for a in default_agent_states()}

    def test_default_agent_states_all_idle(self):
        states = default_agent_states()
        self.assertEqual(len(states), 26)
        for s in states:
            self.assertEqual(s["applicability"], "IDLE")
            self.assertIn("name", s)
            self.assertIn("responsibility", s)

    def test_pentest_agent_running_sandbox_not_applicable(self):
        states = build_pentest_agent_states(current_module="xss", detail="Testing XSS")
        by_name = {s["name"]: s for s in states}
        self.assertEqual(by_name["Pentest Agent"]["applicability"], "RUNNING")
        self.assertEqual(by_name["Pentest Agent"]["current_module"], "xss")
        self.assertEqual(by_name["Pentest Agent"]["detail"], "Testing XSS")
        self.assertEqual(by_name["Sandbox Manager Agent"]["applicability"], "NOT_APPLICABLE")
        self.assertEqual(by_name["Self Audit Agent"]["applicability"], "IDLE")

    def test_lab_mode_sandbox_and_pentest_running(self):
        states = build_lab_agent_states()
        by_name = {s["name"]: s for s in states}
        self.assertEqual(by_name["Sandbox Manager Agent"]["applicability"], "RUNNING")
        self.assertEqual(by_name["Pentest Agent"]["applicability"], "RUNNING")
        self.assertEqual(by_name["Self Audit Agent"]["applicability"], "IDLE")
        irrelevant = {"Orchestrator Agent", "Analyzer Agent"}
        for name in irrelevant:
            self.assertEqual(by_name[name]["applicability"], "NOT_APPLICABLE")

    def test_defend_scan_state_machine(self):
        for status, expected in [("queued", "RUNNING"), ("running", "RUNNING"), ("complete", "COMPLETED"), ("error", "FAILED")]:
            with self.subTest(status=status):
                states = build_defend_agent_states(status)
                by_name = {s["name"]: s for s in states}
                for agent in ("Orchestrator Agent", "Scanner Agent", "Shadow Recon Agent", "Analyzer Agent", "CVE Matcher Agent"):
                    self.assertEqual(by_name[agent]["applicability"], expected, f"{agent} should be {expected} when status={status}")

    def test_self_audit_only_self_audit_agent_changes(self):
        for status, expected in [("never_run", "IDLE"), ("queued", "QUEUED"), ("running", "RUNNING"), ("complete", "COMPLETED"), ("error", "FAILED")]:
            with self.subTest(status=status):
                states = build_self_audit_agent_states(status)
                by_name = {s["name"]: s for s in states}
                self.assertEqual(by_name["Self Audit Agent"]["applicability"], expected)
                self.assertEqual(by_name["Sandbox Manager Agent"]["applicability"], "NOT_APPLICABLE")
                self.assertEqual(by_name["Pentest Agent"]["applicability"], "NOT_APPLICABLE")

    def test_external_target_sandbox_not_applicable(self):
        states = build_pentest_agent_states()
        by_name = {s["name"]: s for s in states}
        self.assertEqual(by_name["Sandbox Manager Agent"]["applicability"], "NOT_APPLICABLE")
        self.assertEqual(by_name["Pentest Agent"]["applicability"], "RUNNING")


class ExecutionStatusPersistenceTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await initialize_database()
        await clear_execution_status()

    async def test_authorized_test_full_lifecycle(self):
        await update_authorized_test_execution(
            job_id="test-job-1", lifecycle="QUEUED", target_url="http://localhost/lab/test",
        )
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "QUEUED")
        self.assertEqual(status["execution_type"], "AUTHORIZED_TEST")
        pentest = next(a for a in status["agent_states"] if a["name"] == "Pentest Agent")
        self.assertEqual(pentest["applicability"], "RUNNING")

        await update_authorized_test_execution(
            job_id="test-job-1", lifecycle="RUNNING", progress_percent=50, current_module="csrf",
        )
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "RUNNING")
        self.assertEqual(status["progress_percent"], 50)
        pentest = next(a for a in status["agent_states"] if a["name"] == "Pentest Agent")
        self.assertEqual(pentest["current_module"], "csrf")

        await update_authorized_test_execution(
            job_id="test-job-1", lifecycle="COMPLETED", progress_percent=100, findings_count=3,
        )
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "COMPLETED")
        self.assertEqual(status["progress_percent"], 100)
        self.assertEqual(status["findings_count"], 3)

    async def test_lab_execution_has_sandbox_running(self):
        await update_authorized_test_execution(
            job_id="lab-job-1", lifecycle="RUNNING", target_url="http://localhost/lab/phantombank",
            is_lab=True,
        )
        status = await get_execution_status()
        self.assertEqual(status["execution_type"], "LAB_OPERATION")
        sandbox = next(a for a in status["agent_states"] if a["name"] == "Sandbox Manager Agent")
        self.assertEqual(sandbox["applicability"], "RUNNING")

    async def test_self_audit_independence(self):
        await update_self_audit_execution(lifecycle="running")
        status = await get_execution_status()
        self.assertEqual(status["execution_type"], "SELF_AUDIT")
        self.assertEqual(status["lifecycle"], "RUNNING")
        audit = next(a for a in status["agent_states"] if a["name"] == "Self Audit Agent")
        self.assertEqual(audit["applicability"], "RUNNING")
        pentest = next(a for a in status["agent_states"] if a["name"] == "Pentest Agent")
        self.assertEqual(pentest["applicability"], "NOT_APPLICABLE")

        await update_self_audit_execution(lifecycle="complete")
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "COMPLETED")

    async def test_defend_scan_produces_defend_agent_states(self):
        scan_id = await create_scan(target_url="http://example.com", mode="defend", authorization_confirmed=False)
        await update_defend_scan_execution(
            scan_id=scan_id, lifecycle="running", target_url="http://example.com",
        )
        status = await get_execution_status()
        self.assertEqual(status["execution_type"], "DEFEND_SCAN")
        self.assertEqual(status["scan_id"], scan_id)
        for name in ("Orchestrator Agent", "Scanner Agent"):
            agent = next(a for a in status["agent_states"] if a["name"] == name)
            self.assertEqual(agent["applicability"], "RUNNING")

    async def test_is_any_execution_running(self):
        self.assertFalse(await is_any_execution_running())
        await update_authorized_test_execution(job_id="test", lifecycle="QUEUED")
        self.assertTrue(await is_any_execution_running())
        await update_authorized_test_execution(job_id="test", lifecycle="COMPLETED")
        self.assertFalse(await is_any_execution_running())

    async def test_clear_execution_resets_to_idle(self):
        await update_authorized_test_execution(job_id="test", lifecycle="RUNNING")
        await clear_execution()
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "IDLE")


class ExecutionStatusEndpointTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await initialize_database()
        await clear_execution_status()

    async def test_endpoint_returns_idle_when_no_execution(self):
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/execution/status", headers=headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["lifecycle"], "IDLE")
        self.assertIsNone(payload["execution_type"])
        self.assertEqual(len(payload["agents"]), 26)

    async def test_endpoint_returns_authorized_test_state(self):
        await update_authorized_test_execution(
            job_id="ep-job-1", lifecycle="RUNNING", progress_percent=60,
            target_url="http://localhost/lab/test", current_module="xss",
        )
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/execution/status", headers=headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["lifecycle"], "RUNNING")
        self.assertEqual(payload["execution_type"], "AUTHORIZED_TEST")
        self.assertEqual(payload["job_id"], "ep-job-1")
        self.assertEqual(payload["progress_percent"], 60)
        self.assertEqual(payload["current_module"], "xss")
        pentest = next(a for a in payload["agents"] if a["name"] == "Pentest Agent")
        self.assertEqual(pentest["applicability"], "RUNNING")

    async def test_endpoint_returns_lab_state(self):
        await update_authorized_test_execution(
            job_id="ep-lab-1", lifecycle="RUNNING", is_lab=True,
            target_url="http://localhost/lab/phantombank",
        )
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/execution/status", headers=headers)
        payload = response.json()
        self.assertEqual(payload["execution_type"], "LAB_OPERATION")
        self.assertTrue(payload["is_lab"])

    async def test_endpoint_self_audit_state(self):
        await update_self_audit_execution(lifecycle="running")
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/execution/status", headers=headers)
        payload = response.json()
        self.assertEqual(payload["execution_type"], "SELF_AUDIT")
        self.assertEqual(payload["lifecycle"], "RUNNING")


class ExecutionStatusIntegrationTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await initialize_database()
        await clear_execution_status()

    async def test_authorized_test_running_in_execution_status(self):
        scan_id = await create_scan(target_url="http://localhost/lab/test", mode="pentest")
        job_id = await create_authorized_test_job(
            authorization_id=None, target_url="http://localhost/lab/test",
            normalized_target_origin="http://localhost", selected_modules=["xss"], scan_id=scan_id,
        )
        await update_authorized_test_job(job_id, status="RUNNING")
        await update_authorized_test_execution(
            job_id=job_id, lifecycle="RUNNING", target_url="http://localhost/lab/test",
            scan_id=scan_id, progress_percent=50, current_module="xss",
        )
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "RUNNING")
        self.assertEqual(status["execution_type"], "AUTHORIZED_TEST")
        self.assertEqual(status["progress_percent"], 50)
        self.assertEqual(status["current_module"], "xss")
        pentest = next(a for a in status["agent_states"] if a["name"] == "Pentest Agent")
        self.assertEqual(pentest["applicability"], "RUNNING")

    async def test_completed_authorized_test_does_not_remain_running(self):
        job_id = "completed-not-running"
        await update_authorized_test_execution(job_id=job_id, lifecycle="RUNNING")
        await update_authorized_test_execution(job_id=job_id, lifecycle="COMPLETED", progress_percent=100, findings_count=3)
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "COMPLETED")
        self.assertNotEqual(status["lifecycle"], "RUNNING")
        self.assertEqual(status["progress_percent"], 100)

    async def test_failed_job_shows_failed_agent(self):
        job_id = "failed-job-test"
        await update_authorized_test_execution(job_id=job_id, lifecycle="RUNNING")
        await update_authorized_test_execution(
            job_id=job_id, lifecycle="FAILED",
            error_message="Module execution crashed", error_code="MODULE_ERROR",
        )
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "FAILED")
        self.assertEqual(status["error_message"], "Module execution crashed")
        self.assertEqual(status["error_code"], "MODULE_ERROR")

    async def test_self_audit_independence_from_authorized_test(self):
        await update_authorized_test_execution(job_id="auth-job", lifecycle="RUNNING")
        await update_self_audit_execution(lifecycle="running")
        status = await get_execution_status()
        self.assertEqual(status["execution_type"], "SELF_AUDIT")
        self.assertEqual(status["lifecycle"], "RUNNING")
        audit = next(a for a in status["agent_states"] if a["name"] == "Self Audit Agent")
        self.assertEqual(audit["applicability"], "RUNNING")

    async def test_self_audit_complete(self):
        await update_self_audit_execution(lifecycle="running")
        await update_self_audit_execution(lifecycle="complete", findings_count=5)
        status = await get_execution_status()
        self.assertEqual(status["lifecycle"], "COMPLETED")
        self.assertEqual(status["findings_count"], 5)
        audit = next(a for a in status["agent_states"] if a["name"] == "Self Audit Agent")
        self.assertEqual(audit["applicability"], "COMPLETED")
