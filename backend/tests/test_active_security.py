import os
import tempfile
from datetime import datetime, timezone
from unittest import IsolatedAsyncioTestCase, TestCase

_db_fd, _db_path = tempfile.mkstemp(suffix=".sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("MAX_TOTAL_REQUESTS", "50")
os.environ.setdefault("MAX_REQUESTS_PER_SECOND", "100")

import httpx
from fastapi.testclient import TestClient

from app.config import get_settings

get_settings.cache_clear()

from app.database import (
    create_authorized_target,
    create_authorized_test_job,
    create_finding,
    create_scan,
    get_authorized_test_job,
    get_finding,
    get_findings,
    get_scan_artifacts,
    initialize_database,
    set_scan_artifacts,
    update_authorized_target,
    update_authorized_test_job,
)
from app.lab import set_scenario_state
from app.models import FindingCreate
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine, SecurityTestPlanner
from app.services.authorization import TargetAuthorizationService
from app.services.execution import SafetyLimits
from app.services.jobs import ScanJobManager
from main import app
from tests.conftest import create_auth_headers, create_admin_headers


def limits(max_total_requests: int = 50) -> SafetyLimits:
    return SafetyLimits(
        max_scan_duration=10,
        max_requests_per_second=100,
        max_total_requests=max_total_requests,
        max_concurrent_scans=2,
        max_redirect_depth=0,
        max_response_size=200_000,
    )


async def make_scan(target_url: str = "http://localhost/lab/phantombank") -> int:
    await initialize_database()
    return await create_scan(
        target_url=target_url,
        mode="pentest",
        intensity="low",
        selected_tests='["xss"]',
        user_id="local-user",
        authorization_confirmed=False,
    )


class ActiveGateAndPlannerTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def test_lab_target_allowed(self) -> None:
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://localhost/lab/phantombank", "local-user")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.authorization_status, "TRAINING")

    async def test_localhost_allowed(self) -> None:
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://127.0.0.1:8000/demo", "local-user")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.authorization_status, "ALLOWLIST")

    async def test_external_unverified_blocked(self) -> None:
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("https://example.com", "local-user")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.authorization_status, "BLOCKED")

    async def test_verified_target_accepted(self) -> None:
        authorization_id = await create_authorized_target(
            "local-user",
            "owned.example",
            "https://owned.example",
            "http",
            "demo-hash",
            "2099-01-01T00:00:00+00:00",
        )
        await update_authorized_target(
            authorization_id,
            "VERIFIED",
            "2026-01-01T00:00:00+00:00",
            "2099-01-01T00:00:00+00:00",
        )
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit(
            "https://owned.example/app",
            "local-user",
            authorization_id,
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.authorization_status, "VERIFIED")

    async def test_planner_chooses_relevant_modules(self) -> None:
        attack_surface = {
            "surfaces": [
                {"id": "search", "module_hints": ["xss", "input_security"], "path": "/search", "parameters": ["q"]},
                {"id": "admin", "module_hints": ["access_control"], "path": "/admin", "parameters": []},
            ]
        }
        plan = SecurityTestPlanner().create_plan(attack_surface, ["xss", "graphql", "access_control"])
        self.assertEqual([item["module"] for item in plan["modules"]], ["xss", "access_control"])


class ActiveEngineTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def run_engine(self, selected_modules: list[str], max_total_requests: int = 50) -> dict:
        scan_id = await make_scan()
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://localhost/lab/phantombank", "local-user")
        engine = ActiveSecurityEngine(
            target_url=decision.target_url,
            attack_surface=None,
            selected_modules=selected_modules,
            limits=limits(max_total_requests),
            authorization_context=decision.to_context(),
            workflow_rules={},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id="test-sandbox",
            transport=httpx.ASGITransport(app=app),
        )
        return await engine.run()

    async def test_request_limit_enforced(self) -> None:
        result = await self.run_engine(["xss"], max_total_requests=1)
        self.assertEqual(result["status"], "limited")
        self.assertEqual(result["request_count"], 1)

    async def test_timeout_enforced(self) -> None:
        scan_id = await make_scan()
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit("http://localhost/lab/phantombank", "local-user")
        engine = ActiveSecurityEngine(
            target_url=decision.target_url,
            attack_surface=None,
            selected_modules=["xss"],
            limits=SafetyLimits(
                max_scan_duration=0,
                max_requests_per_second=100,
                max_total_requests=50,
                max_concurrent_scans=2,
                max_redirect_depth=0,
                max_response_size=200_000,
            ),
            authorization_context=decision.to_context(),
            workflow_rules={},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id="timeout-test",
            transport=httpx.ASGITransport(app=app),
        )
        result = await engine.run()
        self.assertEqual(result["status"], "limited")

    async def test_lab_vulnerable_produces_finding(self) -> None:
        result = await self.run_engine(["xss", "access_control", "business_logic"])
        modules = {finding.get("module") for finding in result["findings"]}
        self.assertIn("xss", modules)
        self.assertIn("access_control", modules)
        self.assertIn("business_logic", modules)

    async def test_confidence_and_remediation_are_calculated_from_evidence(self) -> None:
        result = await self.run_engine(["xss"])
        finding = next(item for item in result["findings"] if item.get("module") == "xss")
        self.assertIn(finding["confidence"], ("HIGH", "CONFIRMED"))
        self.assertTrue(finding.get("recommended_fix"))
        self.assertTrue(finding.get("verification"))
        self.assertLess(result["score"]["score"], 100)

    async def test_patched_scenario_passes_selected_checks(self) -> None:
        set_scenario_state("PATCHED")
        result = await self.run_engine(
            [
                "input_security",
                "injection",
                "xss",
                "auth_session",
                "access_control",
                "csrf",
                "file_upload",
                "path_handling",
                "api_security",
                "graphql",
                "websocket",
                "jwt",
                "redirect",
                "cors",
                "security_headers",
                "tls_https",
                "sensitive_exposure",
                "business_logic",
            ]
        )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["findings"], [])

    async def test_finding_saved_shape(self) -> None:
        scan_id = await make_scan()
        finding_id = await create_finding(
            scan_id,
            FindingCreate(
                title="Output encoding demo",
                category="Output Encoding",
                severity="MEDIUM",
                confidence="HIGH",
                target="http://localhost/lab/phantombank",
                endpoint="http://localhost/lab/phantombank/search",
                evidence="safe evidence",
                impact="impact",
                recommendation="fix it",
                verification="rerun",
                agent="Active Security Engine",
                timestamp=datetime.now(timezone.utc),
                parameter="q",
                module="xss",
                recommended_fix="Encode output",
            ),
        )
        saved = await get_finding(finding_id)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["module"], "xss")
        self.assertEqual(saved["parameter"], "q")
        self.assertEqual(saved["recommended_fix"], "Encode output")
        self.assertEqual(saved["verification_status"], "NOT_VERIFIED")

    async def test_active_security_artifact_saved(self) -> None:
        scan_id = await make_scan()
        await set_scan_artifacts(
            scan_id,
            active_security_output={
                "test_plan": {"modules": [{"module": "xss", "surfaces": []}]},
                "events": [{"event": "test_started"}],
                "evidence": [],
                "findings": [],
                "score": {"score": 100},
            },
        )
        artifacts = await get_scan_artifacts(scan_id)
        self.assertIsNotNone(artifacts)
        self.assertEqual(artifacts["active_security_output"]["score"]["score"], 100)

    async def test_job_manager_stop_cancels_queued_scan(self) -> None:
        scan_id = await make_scan("http://localhost/queued")
        manager = ScanJobManager(limits())
        status = await manager.stop(scan_id)
        self.assertEqual(status, "cancelled")


class FindingVerificationApiTests(TestCase):
    def test_active_map_route_returns_lab_plan_and_limits(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.post(
                "/api/active/map",
                json={"target_url": "http://localhost/lab/phantombank", "selected_modules": ["xss"]},
                headers=headers,
            )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["gate"]["authorization_status"], "TRAINING")
        self.assertGreaterEqual(len(payload["surfaces"]), 1)
        self.assertEqual(payload["plan"]["modules"][0]["module"], "xss")
        self.assertIn("max_requests", payload["limits"])

    def test_websocket_snapshot_emitted(self) -> None:
        async def setup() -> int:
            return await make_scan("http://localhost/lab/phantombank")

        import asyncio

        scan_id = asyncio.run(setup())
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            with client.websocket_connect(f"/ws/scan/{scan_id}", headers=headers) as websocket:
                message = websocket.receive_json()
        self.assertEqual(message["event"], "snapshot")
        self.assertEqual(message["scan_id"], scan_id)

    def test_fix_verification_api_marks_patched_lab_finding_fixed(self) -> None:
        import asyncio
        async def run_test() -> None:
            with TestClient(app, base_url="http://localhost") as client:
                # Register and get token + user_id
                email = f"test_{os.urandom(4).hex()}@example.com"
                reg = client.post("/api/auth/register", json={"email": email, "password": "TestPass123!", "name": "Test User"})
                assert reg.status_code == 201, reg.text
                token = reg.json()["token"]
                user_id = reg.json()["user"]["id"]
                headers = {"Authorization": f"Bearer {token}"}

                await initialize_database()
                set_scenario_state("VULNERABLE")
                scan_id = await create_scan(
                    target_url="http://localhost/lab/phantombank",
                    mode="pentest",
                    intensity="low",
                    selected_tests='["xss"]',
                    user_id=user_id,
                )
                finding_id = await create_finding(
                    scan_id,
                    {
                        "title": "HTML-like input marker reflected without encoding",
                        "category": "Output Encoding",
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "target": "http://localhost/lab/phantombank",
                        "endpoint": "http://localhost/lab/phantombank/search",
                        "evidence": "safe evidence",
                        "impact": "impact",
                        "recommendation": "fix it",
                        "verification": "rerun",
                        "agent": "Active Security Engine",
                        "timestamp": datetime.now(timezone.utc),
                        "parameter": "q",
                        "module": "xss",
                        "recommended_fix": "Encode output",
                    },
                )

                set_scenario_state("PATCHED")
                response = client.post(f"/api/findings/{finding_id}/verify", headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["status"], "FIX_VERIFIED")

                row = await get_finding(finding_id)
                assert row is not None
                self.assertEqual(row["verification_status"], "FIX_VERIFIED")

        asyncio.run(run_test())


class AuthorizedTestJobTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def test_create_job_persists_with_correct_defaults(self) -> None:
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss", "csrf"],
            scan_id=scan_id,
        )
        self.assertIsNotNone(job_id)
        self.assertIsInstance(job_id, str)
        self.assertEqual(len(job_id), 32)
        job = await get_authorized_test_job(job_id)
        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "QUEUED")
        self.assertEqual(job["progress_percent"], 0)
        self.assertEqual(job["scan_id"], scan_id)

    async def test_job_status_update_persists(self) -> None:
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await update_authorized_test_job(job_id, status="RUNNING", progress_percent=50)
        job = await get_authorized_test_job(job_id)
        self.assertEqual(job["status"], "RUNNING")
        self.assertEqual(job["progress_percent"], 50)

    async def test_job_completed_with_findings(self) -> None:
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await create_finding(scan_id, {
            "title": "Test finding",
            "category": "XSS",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "target": "http://localhost/lab/phantombank",
            "endpoint": "/search",
            "evidence": "evidence",
            "impact": "impact",
            "recommendation": "fix",
            "verification": "rerun",
            "agent": "Active Security Engine",
            "timestamp": datetime.now(timezone.utc),
            "module": "xss",
        })
        await update_authorized_test_job(
            job_id,
            status="COMPLETED",
            progress_percent=100,
            findings_count=1,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        job = await get_authorized_test_job(job_id)
        self.assertEqual(job["status"], "COMPLETED")
        self.assertEqual(job["findings_count"], 1)
        self.assertEqual(job["progress_percent"], 100)

    async def test_job_failed_with_structured_error(self) -> None:
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await update_authorized_test_job(
            job_id,
            status="FAILED",
            error_message="Module execution crashed",
            error_code="MODULE_EXECUTION_FAILED",
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        job = await get_authorized_test_job(job_id)
        self.assertEqual(job["status"], "FAILED")
        self.assertEqual(job["error_code"], "MODULE_EXECUTION_FAILED")
        self.assertIn("Module execution crashed", job["error_message"])

    async def test_job_reflects_module_progress(self) -> None:
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss", "csrf", "access_control"],
            scan_id=scan_id,
        )
        await update_authorized_test_job(
            job_id,
            status="RUNNING",
            current_module="xss",
            current_phase="Running xss module",
            progress_percent=33,
            surfaces_total=9,
            surfaces_completed=3,
        )
        job = await get_authorized_test_job(job_id)
        self.assertEqual(job["current_module"], "xss")
        self.assertEqual(job["progress_percent"], 33)
        self.assertEqual(job["surfaces_completed"], 3)
        self.assertEqual(job["surfaces_total"], 9)

    async def test_job_progress_never_decreases(self) -> None:
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss", "csrf"],
            scan_id=scan_id,
        )
        await update_authorized_test_job(job_id, progress_percent=50)
        await update_authorized_test_job(job_id, progress_percent=30)
        job = await get_authorized_test_job(job_id)
        self.assertEqual(job["progress_percent"], 30)

    async def test_active_run_api_returns_job_id(self) -> None:
        from main import app
        with TestClient(app, base_url="http://localhost") as client:
            headers = await create_admin_headers(client)
            response = client.post(
                "/api/active/run",
                json={
                    "target_url": "http://localhost/lab/phantombank",
                    "selected_modules": ["xss"],
                    "authorization_confirmed": True,
                },
                headers=headers,
            )
        self.assertEqual(response.status_code, 201, response.text)
        payload = response.json()
        self.assertIn("job_id", payload)
        self.assertEqual(payload["status"], "QUEUED")
        self.assertIn("message", payload)

    async def test_duplicate_run_detects_existing_job(self) -> None:
        from main import app
        with TestClient(app, base_url="http://localhost") as client:
            headers = await create_admin_headers(client)
            first = client.post(
                "/api/active/run",
                json={"target_url": "http://localhost/lab/phantombank", "selected_modules": ["xss"], "authorization_confirmed": True},
                headers=headers,
            )
            self.assertEqual(first.status_code, 201)
            first_job_id = first.json()["job_id"]
            second = client.post(
                "/api/active/run",
                json={"target_url": "http://localhost/lab/phantombank", "selected_modules": ["xss"], "authorization_confirmed": True},
                headers=headers,
            )
            self.assertEqual(second.status_code, 201)
            self.assertEqual(second.json()["job_id"], first_job_id)
            self.assertIn("already running", second.json()["message"].lower())

    async def test_job_status_endpoint_returns_correct_data(self) -> None:
        from main import app
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await update_authorized_test_job(job_id, status="RUNNING", progress_percent=42, current_module="xss", current_phase="Testing")
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get(f"/api/active/jobs/{job_id}", headers=headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["job_id"], job_id)
        self.assertEqual(payload["status"], "RUNNING")
        self.assertEqual(payload["progress_percent"], 42)
        self.assertEqual(payload["current_module"], "xss")

    async def test_job_status_404_for_nonexistent_job(self) -> None:
        from main import app
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/active/jobs/nonexistent-id", headers=headers)
        self.assertEqual(response.status_code, 404)

    async def test_job_results_endpoint_returns_findings(self) -> None:
        from main import app
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        finding_id = await create_finding(scan_id, {
            "title": "XSS finding",
            "category": "XSS",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "target": "http://localhost/lab/phantombank",
            "endpoint": "/search",
            "evidence": "evidence",
            "impact": "impact",
            "recommendation": "fix",
            "verification": "rerun",
            "agent": "Active Security Engine",
            "timestamp": datetime.now(timezone.utc),
            "module": "xss",
        })
        await update_authorized_test_job(job_id, status="COMPLETED", progress_percent=100, findings_count=1)
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get(f"/api/active/jobs/{job_id}/results", headers=headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["job_id"], job_id)
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["findings"][0]["title"], "XSS finding")

    async def test_job_results_rejected_if_still_running(self) -> None:
        from main import app
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await update_authorized_test_job(job_id, status="RUNNING")
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get(f"/api/active/jobs/{job_id}/results", headers=headers)
        self.assertEqual(response.status_code, 425)

    async def test_unverified_target_rejected(self) -> None:
        from main import app
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.post(
                "/api/active/run",
                json={"target_url": "https://example.com", "selected_modules": ["xss"], "authorization_confirmed": True},
                headers=headers,
            )
        self.assertEqual(response.status_code, 403)

    async def test_stale_job_id_returns_404(self) -> None:
        from main import app
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/active/jobs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", headers=headers)
        self.assertEqual(response.status_code, 404)

    # --- Event System Tests ---

    async def test_events_persist_in_sequence(self) -> None:
        from app.database import add_job_event, get_job_events
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await add_job_event(job_id, "JOB_STARTED", "Job started", status="RUNNING")
        await add_job_event(job_id, "MODULE_STARTED", "Module xss started", module="xss", status="RUNNING")
        await add_job_event(job_id, "JOB_COMPLETED", "Job done", status="COMPLETED", metadata={"findings": 3})

        events = await get_job_events(job_id)
        self.assertEqual(len(events), 3)
        for i, event in enumerate(events):
            self.assertEqual(event["sequence_number"], i + 1)
            self.assertEqual(event["job_id"], job_id)

    async def test_events_survive_refresh(self) -> None:
        from app.database import add_job_event, get_job_events
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await add_job_event(job_id, "JOB_STARTED", "Started")
        await add_job_event(job_id, "JOB_COMPLETED", "Completed")

        events1 = await get_job_events(job_id)
        self.assertEqual(len(events1), 2)

        events2 = await get_job_events(job_id)
        self.assertEqual(len(events2), 2)

        events3 = await get_job_events(job_id, after_sequence=1)
        self.assertEqual(len(events3), 1)
        self.assertEqual(events3[0]["sequence_number"], 2)

    async def test_events_no_duplicates_on_poll(self) -> None:
        from app.database import add_job_event, get_job_events
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await add_job_event(job_id, "JOB_STARTED", "Started")

        poll1 = await get_job_events(job_id, after_sequence=0)
        self.assertEqual(len(poll1), 1)

        poll2 = await get_job_events(job_id, after_sequence=1)
        self.assertEqual(len(poll2), 0)

        await add_job_event(job_id, "MODULE_STARTED", "Module", module="xss")
        poll3 = await get_job_events(job_id, after_sequence=1)
        self.assertEqual(len(poll3), 1)

        poll4 = await get_job_events(job_id, after_sequence=1)
        self.assertEqual(len(poll4), 1)

    async def test_findings_before_job_completion(self) -> None:
        from app.database import add_job_event, get_job_events
        from app.lab import set_scenario_state
        set_scenario_state("VULNERABLE")
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await add_job_event(job_id, "JOB_STARTED", "Started", status="RUNNING")
        await add_job_event(job_id, "FINDING_DETECTED", "XSS reflection", module="xss", status="MEDIUM")
        self.assertEqual(len(await get_job_events(job_id)), 2)

        await add_job_event(job_id, "JOB_COMPLETED", "Done", status="COMPLETED")
        self.assertEqual(len(await get_job_events(job_id)), 3)

    async def test_sensitive_fields_redacted_in_events(self) -> None:
        from app.database import add_job_event, get_job_events
        from app.services.redaction import redaction_service
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        meta = {
            "password": "super-secret-123",
            "authorization": "Bearer fake-token-xyz",
            "api_key": "sk-abc123",
            "safe_field": "hello",
        }
        safe_meta = redaction_service.redact_payload(meta)
        await add_job_event(job_id, "TEST_REQUEST_SENT", "test", metadata=safe_meta)
        events = await get_job_events(job_id)
        self.assertEqual(len(events), 1)
        md = events[0]["metadata"]
        self.assertNotIn("super-secret-123", str(md))
        self.assertNotIn("fake-token-xyz", str(md))
        self.assertNotIn("sk-abc123", str(md))
        self.assertIn("hello", str(md))

    async def test_vulnerable_lab_produces_findings(self) -> None:
        from app.lab import set_scenario_state
        set_scenario_state("VULNERABLE")
        from app.database import add_job_event, get_job_events
        from app.services.authorized_runner import run_authorized_test_job
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        import httpx
        from main import app
        transport = httpx.ASGITransport(app=app)
        await run_authorized_test_job(
            job_id=job_id,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            authorization_context={"authorization_status": "TRAINING", "is_lab": True},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id=f"test-{job_id[:8]}",
            verified_target=None,
            transport=transport,
        )
        events = await get_job_events(job_id)
        event_types = [e["event_type"] for e in events]
        self.assertIn("FINDING_DETECTED", event_types,
                       "Vulnerable lab should produce FINDING_DETECTED events")
        self.assertIn("MODULE_COMPLETED", event_types)

    async def test_patched_lab_shows_control_blocked(self) -> None:
        from app.lab import set_scenario_state
        set_scenario_state("PATCHED")
        from app.database import add_job_event, get_job_events
        from app.services.authorized_runner import run_authorized_test_job
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        import httpx
        from main import app
        transport = httpx.ASGITransport(app=app)
        await run_authorized_test_job(
            job_id=job_id,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            authorization_context={"authorization_status": "TRAINING", "is_lab": True},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id=f"test-{job_id[:8]}",
            verified_target=None,
            transport=transport,
        )
        events = await get_job_events(job_id)
        event_types = [e["event_type"] for e in events]
        self.assertNotIn("FINDING_DETECTED", event_types,
                         "Patched lab should NOT produce FINDING_DETECTED")
        self.assertIn("CONTROL_BLOCKED_TEST", event_types,
                       "Patched lab should produce CONTROL_BLOCKED_TEST events")

    async def test_events_endpoint_returns_events(self) -> None:
        from app.database import add_job_event
        from main import app
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await add_job_event(job_id, "JOB_STARTED", "Started", status="RUNNING")
        await add_job_event(job_id, "JOB_COMPLETED", "Done", status="COMPLETED")
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get(f"/api/active/jobs/{job_id}/events?after_sequence=0", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["job_id"], job_id)
        self.assertEqual(len(data["events"]), 2)
        self.assertEqual(data["latest_sequence"], 2)

    async def test_events_endpoint_404_for_nonexistent_job(self) -> None:
        from main import app
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/active/jobs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/events", headers=headers)
        self.assertEqual(response.status_code, 404)

    async def test_surface_count_fields_are_accurate(self) -> None:
        from app.database import add_job_event
        from main import app
        scan_id = await make_scan()
        job_id = await create_authorized_test_job(
            authorization_id=None,
            target_url="http://localhost/lab/phantombank",
            normalized_target_origin="http://localhost",
            selected_modules=["xss"],
            scan_id=scan_id,
        )
        await update_authorized_test_job(
            job_id,
            status="RUNNING",
            raw_surfaces_discovered=21,
            testable_surfaces=8,
            surface_groups=2,
        )
        job = await get_authorized_test_job(job_id)
        self.assertEqual(job["raw_surfaces_discovered"], 21)
        self.assertEqual(job["testable_surfaces"], 8)
        self.assertEqual(job["surface_groups"], 2)
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get(f"/api/active/jobs/{job_id}", headers=headers)
        data = response.json()
        self.assertEqual(data["raw_surfaces_discovered"], 21)
        self.assertEqual(data["testable_surfaces"], 8)
        self.assertEqual(data["surface_groups"], 2)

    async def test_external_target_remains_restricted(self) -> None:
        from main import app
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.post(
                "/api/active/run",
                json={"target_url": "https://example.com", "selected_modules": ["xss"], "authorization_confirmed": True},
                headers=headers,
            )
        self.assertEqual(response.status_code, 403,
                         "External unverified target should be rejected by the active gate")
