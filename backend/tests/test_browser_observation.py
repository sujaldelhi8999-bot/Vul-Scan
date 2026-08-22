import os
import tempfile
from unittest import IsolatedAsyncioTestCase, TestCase

_db_fd, _db_path = tempfile.mkstemp(suffix=".browser.sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("MAX_TOTAL_REQUESTS", "80")
os.environ.setdefault("MAX_REQUESTS_PER_SECOND", "100")

import httpx
from fastapi.testclient import TestClient

from app.agents.diagnostic_command import DiagnosticCommandPolicy, DiagnosticCommandPolicyError
from app.database import create_finding, create_scan, get_finding, get_scan_artifacts, initialize_database, set_scan_artifacts
from app.lab import set_scenario_state
from app.services.active_security import SecurityTestPlanner
from app.services.browser_observation import (
    BrowserObservationEngine,
    ClientDataFlowAnalyzer,
    DOMSecurityAgent,
    EvidenceCorrelationEngine,
    JavaScriptStaticAnalyzer,
    ScanSafetyPolicy,
    classify_network_request,
    infer_json_schema,
)
from app.services.execution import ExecutionBudget, ExecutionLimitError, SafetyLimits
from app.services.redaction import SecretRedactionService
from main import app
from tests.conftest import create_auth_headers


def limits(max_total_requests: int = 80) -> SafetyLimits:
    return SafetyLimits(
        max_scan_duration=10,
        max_requests_per_second=100,
        max_total_requests=max_total_requests,
        max_concurrent_scans=2,
        max_redirect_depth=0,
        max_response_size=200_000,
    )


async def make_scan() -> int:
    await initialize_database()
    return await create_scan(
        target_url="http://localhost/lab/phantombank",
        mode="defend",
        intensity="low",
        selected_tests="[]",
        user_id="local-user",
    )


class BrowserObservationTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def run_engine(self, *, max_total_requests: int = 80, patched: bool = False) -> dict:
        if patched:
            set_scenario_state("PATCHED")
        scan_id = await make_scan()
        engine = BrowserObservationEngine(
            target_url="http://localhost/lab/phantombank",
            mode="defend",
            authorization_context={"authorization_status": "TRAINING", "is_lab": True},
            limits=limits(max_total_requests),
            scan_id=scan_id,
            transport=httpx.ASGITransport(app=app),
            use_playwright=False,
        )
        return await engine.run()

    async def test_browser_observation_captures_dom_network_api_and_websocket(self) -> None:
        result = await self.run_engine()
        self.assertEqual(result["status"], "complete")
        self.assertGreaterEqual(len(result["pages"]), 1)
        self.assertGreaterEqual(len(result["network_events"]), 1)
        self.assertTrue(any(page.get("forms") for page in result["dom"]))
        self.assertTrue(any(item.get("classification") == "API" for item in result["api_inventory"]))
        self.assertTrue(result["websockets"])

    async def test_cookie_metadata_and_storage_redaction(self) -> None:
        result = await self.run_engine(patched=True)
        cookies = result["cookies"]
        self.assertTrue(any(cookie.get("httponly") and cookie.get("secure") for cookie in cookies))
        storage = SecretRedactionService().redact_payload({"localStorage": {"access_token": "eyJabc.defghi.jklmnop"}})
        self.assertEqual(storage["localStorage"]["access_token"], "[REDACTED]")

    async def test_source_map_detection_and_javascript_analysis(self) -> None:
        source = "const api='/api/profile'; localStorage.setItem('token', value); el.innerHTML=x; //# sourceMappingURL=app.js.map"
        analysis = JavaScriptStaticAnalyzer().analyze("http://localhost/app.js", source)
        self.assertIn("/api/profile", analysis["api_endpoints"])
        self.assertIn("token", analysis["storage_keys"])
        self.assertIn("HTML rendering", analysis["sink_classifications"])
        self.assertEqual(analysis["source_map_references"], ["app.js.map"])

    async def test_scope_enforcement_and_circuit_breaker(self) -> None:
        policy = ScanSafetyPolicy("http://localhost/lab/phantombank", limits(), max_pages=2)
        with self.assertRaises(ExecutionLimitError):
            policy.assert_in_scope("https://example.com/out")
        policy = ScanSafetyPolicy("http://localhost/lab/phantombank", limits(), max_pages=2)
        policy.record_response(500, 5, "http://localhost/a")
        policy.record_response(503, 5, "http://localhost/b")
        policy.record_response(502, 5, "http://localhost/c")
        self.assertTrue(policy.safety_paused)
        self.assertIn("Repeated server errors", policy.pause_reason or "")

    async def test_request_budget_and_cancellation(self) -> None:
        scan_id = await make_scan()
        budget = ExecutionBudget(limits())
        budget.cancel()
        engine = BrowserObservationEngine(
            target_url="http://localhost/lab/phantombank",
            mode="defend",
            authorization_context={"authorization_status": "TRAINING"},
            limits=limits(),
            scan_id=scan_id,
            budget=budget,
            transport=httpx.ASGITransport(app=app),
            use_playwright=False,
        )
        result = await engine.run()
        self.assertEqual(result["status"], "cancelled")

    async def test_browser_artifact_persistence(self) -> None:
        scan_id = await make_scan()
        await set_scan_artifacts(scan_id, browser_security_output={"pages": [{"url": "http://localhost"}], "network_events": []})
        artifacts = await get_scan_artifacts(scan_id)
        self.assertEqual(artifacts["browser_security_output"]["pages"][0]["url"], "http://localhost")

    async def test_browser_fix_verification_marks_patched_csp_fixed(self) -> None:
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
                scan_id = await create_scan(
                    target_url="http://localhost/lab/phantombank",
                    mode="defend",
                    intensity="low",
                    selected_tests="[]",
                    user_id=user_id,
                )
                finding_id = await create_finding(
                    scan_id,
                    {
                        "title": "CSP missing or weak with browser-observed script surfaces",
                        "category": "CSP",
                        "severity": "LOW",
                        "confidence": "HIGH",
                        "target": "http://localhost/lab/phantombank",
                        "endpoint": "http://localhost/lab/phantombank",
                        "evidence": "CSP status: missing.",
                        "impact": "impact",
                        "recommendation": "fix",
                        "verification": "rerun browser observation",
                        "agent": "Browser Security Agent",
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "module": "csp_analysis",
                    },
                )
                set_scenario_state("PATCHED")
                response = client.post(f"/api/findings/{finding_id}/verify", headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["status"], "FIX_VERIFIED")
                saved = await get_finding(finding_id)
                self.assertEqual(saved["verification_status"], "FIX_VERIFIED")

        await run_test()


class BrowserAnalysisUnitTests(TestCase):
    def test_network_classification_and_schema_inference(self) -> None:
        self.assertEqual(classify_network_request("https://app.test/api/profile", "GET", "fetch", "https://app.test"), "API")
        self.assertEqual(classify_network_request("https://app.test/graphql", "POST", "fetch", "https://app.test"), "GRAPHQL")
        self.assertEqual(classify_network_request("wss://app.test/ws", "GET", "websocket", "https://app.test"), "WEBSOCKET")
        schema = infer_json_schema({"token": "secret", "user": {"id": 1, "name": "alice"}})
        self.assertEqual(schema["token"], "redacted_secret")
        self.assertEqual(schema["user"]["id"], "integer")

    def test_dom_extraction_form_inputs_and_events(self) -> None:
        dom = DOMSecurityAgent().extract(
            "<form action='/api/login' method='post'><input name='email'><input type='password' name='password'></form><button onclick='debug()'>x</button>",
            "https://app.test/login",
        )
        self.assertEqual(len(dom["forms"]), 1)
        self.assertEqual(len(dom["auth_forms"]), 1)
        self.assertEqual(dom["event_handlers"][0]["handler"], "onclick")

    def test_dataflow_and_correlation(self) -> None:
        dataflow = ClientDataFlowAnalyzer().analyze(
            [{"forms": [{"action": "https://app.test/api/login", "inputs": [{"name": "email"}]}]}],
            [{"url": "https://app.test/api/login", "classification": "AUTH"}],
            [{"sink_classifications": ["HTML rendering"]}],
        )
        self.assertEqual(dataflow["input_to_api"][0]["api_request"], "https://app.test/api/login")
        correlation = EvidenceCorrelationEngine().correlate(
            {"dom": [{"inputs": [{"name": "q"}], "inline_script_count": 1, "scripts": []}], "network_events": [{"classification": "API"}], "console_events": [{"type": "error"}], "javascript": [{"sink_classifications": ["HTML rendering"]}]}
        )
        self.assertGreaterEqual(correlation["independent_signal_count"], 3)

    def test_secret_redaction_masks_headers_tokens_and_pii(self) -> None:
        service = SecretRedactionService()
        redacted = service.redact_payload({"Authorization": "Bearer eyJabcde12345.abcdefghi123.jklmnopqr456", "email": "alice@example.com", "password": "demo-password"})
        self.assertEqual(redacted["Authorization"], "[REDACTED]")
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertNotIn("alice@example.com", redacted["email"])

    def test_security_test_planner_uses_browser_network_evidence(self) -> None:
        plan = SecurityTestPlanner().create_verification_plan(
            attack_surface={"target_url": "https://app.test", "surfaces": []},
            network_evidence=[{"classification": "AUTH", "method": "POST", "url": "https://app.test/api/login"}],
            javascript_evidence=[{"sink_classifications": ["HTML rendering"]}],
            authorization={"authorization_status": "VERIFIED"},
        )
        modules = {item["module"] for item in plan["modules"]}
        self.assertIn("auth_session", modules)
        self.assertEqual(plan["planner_version"], "2.0")

    def test_diagnostic_command_policy_blocks_unsafe_categories(self) -> None:
        policy = DiagnosticCommandPolicy()
        with self.assertRaises(DiagnosticCommandPolicyError):
            policy.build("remote_shell", "http://localhost", limits())
        spec = policy.build("container_health", "http://localhost", limits())
        self.assertIn("python", spec.argv[0].lower())
