import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

_db_fd, _db_path = tempfile.mkstemp(suffix=".release-qa.sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("MAX_TOTAL_REQUESTS", "90")
os.environ.setdefault("MAX_REQUESTS_PER_SECOND", "100")

import httpx
from fastapi.testclient import TestClient

from app.config import get_settings

get_settings.cache_clear()

from app.database import create_finding, create_scan, get_finding, get_scan_artifacts, initialize_database, set_scan_artifacts
from app.lab import LAB_SCENARIOS, set_scenario_state
from app.agents.cve_matcher import CVEMatcherAgent
from app.routers import authorization as authorization_router
from app.security import redact_payload
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine, SecurityTestPlanner, score_findings
from app.services.authorization import TargetAuthorizationService, canonicalize_target
from app.services.browser_observation import BrowserObservationEngine, DOMSecurityAgent, JavaScriptStaticAnalyzer, ScanSafetyPolicy, classify_network_request, infer_json_schema
from app.services.execution import ExecutionLimitError, SafetyLimits
from main import app
from tests.conftest import create_auth_headers, create_admin_headers


def limits(max_total_requests: int = 90) -> SafetyLimits:
    return SafetyLimits(
        max_scan_duration=10,
        max_requests_per_second=100,
        max_total_requests=max_total_requests,
        max_concurrent_scans=2,
        max_redirect_depth=0,
        max_response_size=200_000,
    )


async def make_scan(mode: str = "defend", selected_tests: list[str] | None = None, user_id: str = "local-user") -> int:
    await initialize_database()
    return await create_scan(
        target_url="http://localhost/lab/phantombank",
        mode=mode,
        intensity="low",
        selected_tests=json.dumps(selected_tests or []),
        user_id=user_id,
    )


class BackendStartupAndContractTests(TestCase):
    def test_startup_health_routes_and_websockets(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            health = client.get("/api/health")
            self.assertEqual(health.status_code, 200, health.text)
            payload = health.json()
            self.assertEqual(payload["database"], "available")
            self.assertEqual(payload["agents"], "available")

            paths = {getattr(route, "path", "") for route in app.routes}
            for path in [
                "/api/scan/start",
                "/api/findings",
                "/api/active/map",
                "/api/authorization/challenge",
                "/api/ai/scan/{scan_id}/analysis",
                "/api/lab/status",
                "/ws/status",
                "/ws/scan/{scan_id}",
            ]:
                self.assertIn(path, paths)

            headers = create_auth_headers(client)
            with client.websocket_connect("/ws/status", headers=headers) as websocket:
                message = websocket.receive_json()
                self.assertIn(message["event"], {"status", "heartbeat"})
                self.assertEqual(message["payload"]["database"], "available")

            with client.websocket_connect("/lab/phantombank/ws/prices") as websocket:
                message = websocket.receive_text()
                self.assertIn("PHB-DEMO", message)

    def test_frontend_api_contract_endpoints_exist(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            for path in [
                "/api/scan/history",
                "/api/findings",
                "/api/logs",
                "/api/agents/status",
                "/api/self-audit/status",
                "/api/lab/status",
                "/api/lab/manifest",
            ]:
                response = client.get(path, headers=headers)
                self.assertLess(response.status_code, 500, f"{path}: {response.text}")

            lab_map = client.post("/api/active/map", json={"target_url": "http://localhost/lab/phantombank", "selected_modules": ["xss"]}, headers=headers)
            self.assertEqual(lab_map.status_code, 200, lab_map.text)
            self.assertEqual(lab_map.json()["gate"]["authorization_status"], "TRAINING")

            blocked = client.post("/api/active/map", json={"target_url": "https://example.com", "selected_modules": ["xss"]}, headers=headers)
            self.assertEqual(blocked.status_code, 403, blocked.text)

            missing_finding = client.get("/api/ai/findings/99999/explain", headers=headers)
            self.assertEqual(missing_finding.status_code, 404)

    def test_supabase_login_endpoint_contract(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            missing_token = client.post("/api/auth/supabase", json={})
            self.assertEqual(missing_token.status_code, 422, missing_token.text)

            short_token = client.post("/api/auth/supabase", json={"access_token": "x"})
            self.assertEqual(short_token.status_code, 422, short_token.text)

            # For unconfigured test, temporarily clear supabase settings
            from app.config import get_settings
            settings = get_settings()
            orig_url = settings.supabase_url
            orig_secret = settings.supabase_jwt_secret
            settings.supabase_url = ""
            settings.supabase_jwt_secret = ""
            try:
                unconfigured = client.post("/api/auth/supabase", json={"access_token": "a" * 32})
                self.assertEqual(unconfigured.status_code, 401, unconfigured.text)
            finally:
                settings.supabase_url = orig_url
                settings.supabase_jwt_secret = orig_secret


class DatabaseFindingAiAndAuthorizationTests(TestCase):
    def test_database_artifacts_risk_status_and_ai_fallback(self) -> None:
        async def setup() -> int:
            scan_id = await make_scan("defend")
            finding_id = await create_finding(
                scan_id,
                {
                    "title": "QA active risk finding",
                    "category": "QA",
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                    "target": "http://localhost/lab/phantombank",
                    "endpoint": "http://localhost/lab/phantombank/search",
                    "evidence": "controlled QA evidence",
                    "impact": "impact",
                    "recommendation": "fix",
                    "verification": "rerun",
                    "agent": "QA",
                    "timestamp": datetime.now(timezone.utc),
                    "module": "xss",
                },
            )
            await set_scan_artifacts(scan_id, browser_security_output={"pages": [{"url": "http://localhost/lab/phantombank"}], "network_events": []})
            return finding_id

        def test_database_artifacts_risk_status_and_ai_fallback(self) -> None:
            async def run_test():
                with TestClient(app, base_url="http://localhost") as client:
                    # Register and get token
                    email = f"test_{os.urandom(4).hex()}@example.com"
                    reg = client.post("/api/auth/register", json={"email": email, "password": "TestPass123!", "name": "Test User"})
                    assert reg.status_code == 201, reg.text
                    token = reg.json()["token"]
                    user_id = reg.json()["user"]["id"]
                    headers = {"Authorization": f"Bearer {token}"}

                    # Create scan with this user
                    scan_id = await make_scan("defend", user_id=user_id)
                    finding_id = await create_finding(
                        scan_id,
                        {
                            "title": "QA active risk finding",
                            "category": "QA",
                            "severity": "HIGH",
                            "confidence": "CONFIRMED",
                            "target": "http://localhost/lab/phantombank",
                            "endpoint": "http://localhost/lab/phantombank/search",
                            "evidence": "controlled QA evidence",
                            "impact": "impact",
                            "recommendation": "fix",
                            "verification": "rerun",
                            "agent": "QA",
                            "timestamp": datetime.now(timezone.utc),
                            "module": "xss",
                        },
                    )
                    await set_scan_artifacts(scan_id, browser_security_output={"pages": [{"url": "http://localhost/lab/phantombank"}], "network_events": []})

                    finding = client.patch(f"/api/findings/{finding_id}/risk", json={"risk_status": "FALSE_POSITIVE"}, headers=headers)
                    assert finding.status_code == 200, finding.text
                    assert finding.json()["risk_status"] == "FALSE_POSITIVE"

                    scan_id_resp = finding.json()["scan_id"]
                    analysis = client.get(f"/api/ai/scan/{scan_id_resp}/analysis", headers=headers)
                    assert analysis.status_code == 200, analysis.text
                    assert analysis.json()["safety"]["can_start_active_test"] == False
                    assert analysis.json()["priorities"] == []

                    answer = client.post(f"/api/ai/scan/{scan_id_resp}/ask", json={"question": "Explain finding #99999"}, headers=headers)
                    assert answer.status_code == 200, answer.text
                    assert answer.json()["can_start_active_test"] == False
                    assert "not have enough" in answer.json()["answer"].lower()

                    artifacts = await get_scan_artifacts(scan_id_resp)
                    assert artifacts is not None
                    assert artifacts["ai_analyst_output"] is not None

            with patch("app.routers.ai.call_openrouter", return_value="") as _:
                    asyncio.run(run_test())

    def test_authorization_challenge_success_failure_and_revoke_are_backend_authoritative(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            http_challenge = client.post("/api/authorization/challenge", json={"target_url": "http://localhost/lab/phantombank", "verification_method": "http"}, headers=headers)
            self.assertEqual(http_challenge.status_code, 201, http_challenge.text)
            authorization_id = http_challenge.json()["id"]

            original_http = authorization_router.authorization_service._verify_http

            async def http_missing(_origin: str, _expected_hash: str, _auth_id: int | None = None) -> tuple[bool, str | None]:
                return False, "Simulated failure"

            async def http_present(_origin: str, _expected_hash: str, _auth_id: int | None = None) -> tuple[bool, str | None]:
                return True, None

            try:
                authorization_router.authorization_service._verify_http = http_missing
                rejected = client.post(f"/api/authorization/{authorization_id}/verify", headers=headers)
                self.assertEqual(rejected.status_code, 409, rejected.text)

                authorization_router.authorization_service._verify_http = http_present
                verified = client.post(f"/api/authorization/{authorization_id}/verify", headers=headers)
                self.assertEqual(verified.status_code, 200, verified.text)
                self.assertEqual(verified.json()["status"], "VERIFIED")
            finally:
                authorization_router.authorization_service._verify_http = original_http

            revoked = client.post(f"/api/authorization/{authorization_id}/revoke", headers=headers)
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertEqual(revoked.json()["status"], "REVOKED")


class SafetyRedactionAndAnalysisUnitTests(TestCase):
    def test_target_normalization_invalid_targets_and_safety_policy(self) -> None:
        self.assertEqual(canonicalize_target("example.com").url, "https://example.com/")
        self.assertEqual(canonicalize_target("https://example.com/").url, "https://example.com/")
        with self.assertRaises(ValueError):
            canonicalize_target("ftp://example.com")
        with self.assertRaises(ValueError):
            canonicalize_target("https://user:pass@example.com")

        policy = ScanSafetyPolicy("http://localhost/lab/phantombank", limits(), max_pages=1)
        policy.reserve_page("http://localhost/lab/phantombank")
        with self.assertRaises(ExecutionLimitError):
            policy.reserve_page("http://localhost/lab/phantombank/search")
        self.assertTrue(policy.safety_paused)

    def test_secret_redaction_schema_and_network_classification(self) -> None:
        payload = redact_payload(
            {
                "Authorization": "Bearer eyJabcde12345.abcdefghi123.jklmnopqr456",
                "session_cookie": "sessionid=abc123secret",
                "api_key": "DEMO_KEY_DO_NOT_USE_123456",
                "password": "demo-password",
            }
        )
        serialized = json.dumps(payload)
        self.assertNotIn("DEMO_KEY_DO_NOT_USE_123456", serialized)
        self.assertNotIn("demo-password", serialized)
        self.assertNotIn("eyJabcde12345", serialized)
        schema = infer_json_schema({"email": "alice@example.test", "user": {"id": 1}, "items": [{"name": "x"}], "token": "secret"})
        self.assertEqual(schema["email"], "string")
        self.assertEqual(schema["user"]["id"], "integer")
        self.assertEqual(schema["items"], [{"name": "string"}])
        self.assertEqual(schema["token"], "redacted_secret")
        self.assertEqual(classify_network_request("https://app.test/graphql", "POST", "fetch", "https://app.test"), "GRAPHQL")
        self.assertEqual(classify_network_request("wss://app.test/ws", "GET", "websocket", "https://app.test"), "WEBSOCKET")
        self.assertEqual(classify_network_request("https://cdn.example/script.js", "GET", "script", "https://app.test"), "THIRD_PARTY")

    def test_dom_javascript_planner_and_score_exclusions(self) -> None:
        dom = DOMSecurityAgent().extract(
            "<form action='/api/login' method='post'><input name='email'><input type='password' name='password'><input type='hidden' name='csrf_token'></form><iframe src='/frame'></iframe><input type='file' name='statement'><script>localStorage.setItem('token','x'); el.innerHTML=x; //# sourceMappingURL=app.js.map</script>",
            "https://app.test/login",
        )
        self.assertEqual(len(dom["forms"]), 1)
        self.assertTrue(dom["auth_forms"])
        self.assertTrue(dom["file_uploads"])
        self.assertTrue(dom["hidden_inputs"])

        js = JavaScriptStaticAnalyzer().analyze("https://app.test/app.js", "const api='/api/resource/1'; const gql='/graphql'; const ws='wss://app.test/ws'; localStorage.setItem('token', value); el.innerHTML = value; //# sourceMappingURL=app.js.map")
        self.assertIn("/api/resource/1", js["api_endpoints"])
        self.assertIn("/graphql", js["graphql_endpoints"])
        self.assertIn("wss://app.test/ws", js["websocket_urls"])
        self.assertIn("token", js["storage_keys"])
        self.assertIn("app.js.map", js["source_map_references"])

        plan = SecurityTestPlanner().create_plan(
            {
                "surfaces": [
                    {"path": "/login", "module_hints": ["auth_session"], "parameters": ["username", "password"]},
                    {"path": "/upload", "module_hints": ["file_upload", "access_control"], "parameters": ["file"]},
                    {"path": "/api/resource/1", "module_hints": ["api_security", "access_control"], "parameters": ["id"]},
                    {"path": "/search", "module_hints": ["input_security", "xss"], "parameters": ["q"]},
                    {"path": "/ws", "type": "websocket", "module_hints": ["websocket"], "parameters": []},
                ]
            },
            ["auth_session", "file_upload", "access_control", "api_security", "xss", "websocket"],
        )
        modules = {item["module"] for item in plan["modules"]}
        self.assertEqual(modules, {"auth_session", "file_upload", "access_control", "api_security", "xss", "websocket"})

        base = {"severity": "HIGH", "confidence": "CONFIRMED"}
        self.assertLess(score_findings([base], 1)["score"], 100)
        self.assertEqual(score_findings([{**base, "remediation_status": "RESOLVED"}], 1)["score"], 100)
        self.assertEqual(score_findings([{**base, "verification_status": "FIX_VERIFIED"}], 1)["score"], 100)
        self.assertEqual(score_findings([{**base, "risk_status": "FALSE_POSITIVE"}], 1)["score"], 100)


class BrowserObservationAndActiveLabTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def test_http_browser_observation_captures_application_surface_without_secrets(self) -> None:
        scan_id = await make_scan("defend")
        engine = BrowserObservationEngine(
            target_url="http://localhost/lab/phantombank",
            mode="defend",
            authorization_context={"authorization_status": "TRAINING", "is_lab": True},
            limits=limits(),
            scan_id=scan_id,
            transport=httpx.ASGITransport(app=app),
            use_playwright=False,
        )
        result = await engine.run()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["browser_engine"], "http_observer")
        self.assertTrue(result["pages"])
        self.assertTrue(result["network_events"])
        self.assertTrue(any(page.get("forms") for page in result["dom"]))
        self.assertTrue(result["routes"])
        self.assertTrue(result["api_inventory"])
        self.assertTrue(result["websockets"])
        serialized = json.dumps(result, ensure_ascii=True, default=str)
        self.assertNotIn("DEMO_KEY_DO_NOT_USE_123456", serialized)
        self.assertNotIn("demo-password", serialized)

    async def test_cve_matcher_skips_external_lookup_without_api_key(self) -> None:
        scan_id = await make_scan("defend")
        result = await CVEMatcherAgent().run({"server": "uvicorn"}, scan_id)
        self.assertEqual(result["cve_matches"], [])

    async def test_active_manifest_parsing_does_not_corrupt_loopback_ip_urls(self) -> None:
        scan_id = await make_scan("pentest", ["xss"])
        engine = ActiveSecurityEngine(
            target_url="http://127.0.0.1:8012/lab/phantombank",
            attack_surface=None,
            selected_modules=["xss"],
            limits=limits(),
            authorization_context={"authorization_status": "TRAINING", "is_lab": True},
            workflow_rules={},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id="qa-loopback-ip",
            transport=httpx.ASGITransport(app=app),
        )
        result = await engine.run()
        self.assertEqual(result["status"], "complete", result)
        self.assertTrue(any(finding.get("module") == "xss" for finding in result["findings"]), result["findings"])
        self.assertNotIn("127._*", json.dumps(result["attack_surface"], ensure_ascii=True, default=str))

    async def test_every_lab_scenario_has_vulnerable_signal_and_all_patched_is_clean(self) -> None:
        for scenario, modules in LAB_SCENARIOS.items():
            with self.subTest(scenario=scenario):
                set_scenario_state("PATCHED")
                set_scenario_state("VULNERABLE", scenario)
                scan_id = await make_scan("pentest", modules)
                engine = ActiveSecurityEngine(
                    target_url="http://localhost/lab/phantombank",
                    attack_surface=None,
                    selected_modules=modules,
                    limits=limits(),
                    authorization_context={"authorization_status": "TRAINING", "is_lab": True},
                    workflow_rules={},
                    scan_id=scan_id,
                    user_id="local-user",
                    sandbox_id=f"qa-{scenario}",
                    transport=httpx.ASGITransport(app=app),
                )
                result = await engine.run()
                self.assertEqual(result["status"], "complete")
                finding_modules = {finding.get("module") for finding in result["findings"]}
                self.assertTrue(finding_modules & set(modules), f"No expected finding for {scenario}: {result['findings']}")

        set_scenario_state("PATCHED")
        scan_id = await make_scan("pentest", [module for modules in LAB_SCENARIOS.values() for module in modules])
        patched_engine = ActiveSecurityEngine(
            target_url="http://localhost/lab/phantombank",
            attack_surface=None,
            selected_modules=[module for modules in LAB_SCENARIOS.values() for module in modules],
            limits=limits(),
            authorization_context={"authorization_status": "TRAINING", "is_lab": True},
            workflow_rules={},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id="qa-patched-all",
            transport=httpx.ASGITransport(app=app),
        )
        patched = await patched_engine.run()
        self.assertEqual(patched["status"], "complete")
        self.assertEqual(patched["findings"], [])

    async def test_verify_fix_is_evidence_based_for_patched_lab(self) -> None:
        set_scenario_state("VULNERABLE")
        # Register user first to get user_id for scan ownership
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            reg = await client.post("/api/auth/register", json={"email": f"test_{os.urandom(4).hex()}@example.com", "password": "TestPass123!", "name": "Test User"})
            assert reg.status_code == 201, reg.text
            token = reg.json()["token"]
            user_id = reg.json()["user"]["id"]
            auth_headers = {"Authorization": f"Bearer {token}"}

        # Create scan with authenticated user's ID
        scan_id = await make_scan("pentest", ["xss"], user_id=user_id)
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
                "module": "xss",
            },
        )
        set_scenario_state("PATCHED")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            response = await client.post(f"/api/findings/{finding_id}/verify", headers=auth_headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "FIX_VERIFIED")
        saved = await get_finding(finding_id)
        self.assertEqual(saved["verification_status"], "FIX_VERIFIED")


class GitHubUnauthorizedFlowTests(TestCase):
    """When no OAuth token exists, GitHub endpoints must degrade gracefully instead of 401."""

    def setUp(self) -> None:
        async def purge() -> None:
            from app.database import get_connection, initialize_database
            await initialize_database()
            async with get_connection() as conn:
                await conn.execute("DELETE FROM github_oauth_tokens WHERE user_id = 'local-user'")
                await conn.execute("DELETE FROM github_app_installations WHERE user_id = 'local-user'")
                await conn.commit()

        asyncio.run(purge())

    def test_status_returns_connected_false_without_token(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/github/status", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["connected"], False)

    def test_repos_returns_200_with_empty_list_without_token(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/github/repos", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["connected"], False)
        self.assertEqual(payload["repos"], [])
        self.assertEqual(payload["total"], 0)

    def test_installations_returns_200_without_token(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.get("/api/github/installations", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["installations"], [])

    def test_disconnect_is_idempotent_without_token(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.delete("/api/github/disconnect", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "disconnected")


class GitHubOAuthFlowTests(TestCase):
    """The OAuth state->token handshake: /connect writes state, /callback stores the token."""

    def _state_row(self, state: str) -> str | None:
        async def fetch() -> str | None:
            from app.database import get_connection
            async with get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT user_id FROM github_oauth_states WHERE state = ?", (state,)
                )
                row = await cursor.fetchone()
            return row["user_id"] if row else None
        return asyncio.run(fetch())

    def test_connect_writes_state_for_authenticated_user(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            response = client.post("/api/github/connect", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertTrue(payload["authorize_url"].startswith("https://github.com/login/oauth/authorize"))
        self.assertIn(f"state={payload['state']}", payload["authorize_url"])
        self.assertIsNotNone(self._state_row(payload["state"]))

    def test_callback_stores_token_and_status_connected(self) -> None:
        from app.routers import github as github_router
        from app.models import GitHubTokenResponse, GitHubUserResponse

        async def fake_exchange(callback):
            return GitHubTokenResponse(access_token="tok-123", token_type="bearer", scope="repo")

        async def fake_user_info(token):
            return GitHubUserResponse(
                id=12345, login="octocat", name="Octo Cat", avatar_url="https://avatars/1",
                html_url="https://github.com/octocat", type="User",
            )

        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            state = client.post("/api/github/connect", headers=headers).json()["state"]

            with patch.object(github_router.github_service, "exchange_code_for_token", fake_exchange), \
                 patch.object(github_router.github_service, "get_user_info", fake_user_info):
                callback = client.get(
                    f"/api/github/callback?code=code-123&state={state}",
                    follow_redirects=False,
                )

        self.assertEqual(callback.status_code, 302, callback.text)
        self.assertIn("success=true&login=octocat", callback.headers["location"])
        self.assertIsNone(self._state_row(state), "state must be single-use")

        async def token_row() -> str | None:
            from app.database import get_connection
            async with get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT github_login FROM github_oauth_tokens WHERE github_login = 'octocat'"
                )
                row = await cursor.fetchone()
            return row["github_login"] if row else None
        self.assertEqual(asyncio.run(token_row()), "octocat")

    def test_callback_with_unknown_state_redirects_error(self) -> None:
        with TestClient(app, base_url="http://localhost") as client:
            headers = create_auth_headers(client)
            callback = client.get(
                "/api/github/callback?code=code-123&state=forged-state",
                follow_redirects=False,
            )
            status = client.get("/api/github/status", headers=headers)

        self.assertEqual(callback.status_code, 302, callback.text)
        self.assertIn("error=invalid_state", callback.headers["location"])
        self.assertEqual(status.json()["connected"], False)


class SupabaseAuthEndpointTests(TestCase):
    """POST /api/auth/supabase exchanges a Supabase access token for a session."""

    def _patch_verifier(self, user) -> None:
        import app.routers.auth as auth_router
        from app.services import supabase_auth

        async def fake_verify(access_token: str):
            if access_token == "token-invalid-12345":
                raise supabase_auth.SupabaseAuthError("Supabase rejected the token (HTTP 401)")
            return type("User", (), {"user_id": user.user_id, "email": user.email.lower(), "name": user.name})()

        self._original = supabase_auth.verify_supabase_token
        supabase_auth.verify_supabase_token = fake_verify
        auth_router.verify_supabase_token = fake_verify

    def tearDown(self) -> None:
        import app.routers.auth as auth_router
        from app.services import supabase_auth

        if hasattr(self, "_original"):
            supabase_auth.verify_supabase_token = self._original
            auth_router.verify_supabase_token = self._original

    def test_valid_token_returns_user_role(self) -> None:
        self._patch_verifier(
            type("User", (), {"user_id": "u-1", "email": "dev@example.com", "name": "Dev"})(),
        )
        with TestClient(app, base_url="http://localhost") as client:
            response = client.post("/api/auth/supabase", json={"access_token": "token-ok-123456"})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["user"]["role"], "user")
        self.assertEqual(payload["user"]["email"], "dev@example.com")
        self.assertTrue(payload["token"])

    def test_valid_token_admin_allowlist_maps_to_admin(self) -> None:
        from app.config import get_settings

        settings = get_settings()
        original = settings.supabase_admin_emails
        settings.supabase_admin_emails = "boss@example.com, other@example.com"
        try:
            self._patch_verifier(
                type("User", (), {"user_id": "u-2", "email": "BOSS@example.com", "name": "Boss"})(),
            )
            with TestClient(app, base_url="http://localhost") as client:
                response = client.post("/api/auth/supabase", json={"access_token": "token-ok-123456"})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["user"]["role"], "admin")
        finally:
            settings.supabase_admin_emails = original

    def test_invalid_token_returns_401(self) -> None:
        self._patch_verifier(
            type("User", (), {"user_id": "u-3", "email": "x@example.com", "name": "X"})(),
        )
        with TestClient(app, base_url="http://localhost") as client:
            response = client.post("/api/auth/supabase", json={"access_token": "token-invalid-12345"})
        self.assertEqual(response.status_code, 401, response.text)
