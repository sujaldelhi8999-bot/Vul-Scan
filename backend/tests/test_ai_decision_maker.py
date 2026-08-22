import json
import os
import tempfile
import time
from unittest import IsolatedAsyncioTestCase

_db_fd, _db_path = tempfile.mkstemp(suffix=".sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("MAX_TOTAL_REQUESTS", "50")
os.environ.setdefault("MAX_REQUESTS_PER_SECOND", "100")

import httpx

from app.config import get_settings

get_settings.cache_clear()

from app.database import create_scan, initialize_database
from app.lab import set_scenario_state
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine
from app.services.ai_decision_maker import AIDecisionMaker
from app.services.authorization import TargetAuthorizationService, canonicalize_target
from app.services.execution import SafetyLimits
from main import app


class FakeLLM:
    def __init__(self, response: str = "") -> None:
        self.response = response
        self.calls = 0
        self.prompts: list[tuple[str, str]] = []

    async def __call__(self, prompt: str, system_prompt: str, *, scan_id: int | None = None) -> str:
        self.calls += 1
        self.prompts.append((prompt, system_prompt))
        return self.response


class RaisingLLM:
    async def __call__(self, prompt: str, system_prompt: str, *, scan_id: int | None = None) -> str:
        raise RuntimeError("LLM provider unavailable")


def json_response(modules: list[str]) -> str:
    return json.dumps({"modules": modules, "rationale": "test"})


class AIDecisionMakerUnitTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.target = "http://localhost/lab/phantombank"

    async def test_recommends_valid_modules_in_priority_order(self) -> None:
        llm = FakeLLM(json_response(["xss", "authentication", "bogus_module", "cors", "xss"]))
        dm = AIDecisionMaker(llm=llm)
        result = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(result, ["xss", "auth_session", "cors"])

    async def test_accepts_object_form(self) -> None:
        llm = FakeLLM(json.dumps({"modules": [{"module": "ssrf", "priority": 1}], "rationale": "ok"}))
        dm = AIDecisionMaker(llm=llm)
        result = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(result, ["ssrf"])

    async def test_empty_llm_response_falls_back(self) -> None:
        dm = AIDecisionMaker(llm=FakeLLM(""))
        result = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(result, [])

    async def test_malformed_json_falls_back(self) -> None:
        dm = AIDecisionMaker(llm=FakeLLM("not json at all"))
        result = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(result, [])

    async def test_missing_modules_key_falls_back(self) -> None:
        dm = AIDecisionMaker(llm=FakeLLM(json.dumps({"rationale": "no plan"})))
        result = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(result, [])

    async def test_llm_error_falls_back(self) -> None:
        dm = AIDecisionMaker(llm=RaisingLLM())
        result = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(result, [])

    async def test_cap_applied(self) -> None:
        llm = FakeLLM(json_response(["xss", "injection", "cors", "ssrf", "xxe"]))
        dm = AIDecisionMaker(llm=llm, max_modules=3)
        result = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(result, ["xss", "injection", "cors"])

    async def test_cache_hits_within_ttl(self) -> None:
        llm = FakeLLM(json_response(["xss", "cors"]))
        dm = AIDecisionMaker(llm=llm)
        first = await dm.recommend_modules(self.target, {"technologies": []})
        second = await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(first, ["xss", "cors"])
        self.assertEqual(second, ["xss", "cors"])
        self.assertEqual(llm.calls, 1)
        self.assertEqual(dm.cached_targets(), [canonicalize_target(self.target).url])

    async def test_cache_expired_recalls_llm(self) -> None:
        llm = FakeLLM(json_response(["xss"]))
        dm = AIDecisionMaker(llm=llm)
        await dm.recommend_modules(self.target, {"technologies": []})
        key = canonicalize_target(self.target).url
        dm._cache[key] = (time.monotonic() - 1.0, ["xss"])
        await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(llm.calls, 2)

    async def test_cache_keyed_per_target(self) -> None:
        llm = FakeLLM(json_response(["xss"]))
        dm = AIDecisionMaker(llm=llm)
        await dm.recommend_modules("http://localhost/lab/phantombank", {"technologies": []})
        await dm.recommend_modules("http://localhost/lab/other", {"technologies": []})
        self.assertEqual(llm.calls, 2)

    async def test_empty_recommendation_not_cached(self) -> None:
        llm = FakeLLM(json_response([]))
        dm = AIDecisionMaker(llm=llm)
        await dm.recommend_modules(self.target, {"technologies": []})
        await dm.recommend_modules(self.target, {"technologies": []})
        self.assertEqual(llm.calls, 2)

    async def test_manual_selection_always_kept(self) -> None:
        llm = FakeLLM(json_response(["xss", "graphql"]))
        dm = AIDecisionMaker(llm=llm)
        result = await dm.recommend_modules(
            self.target,
            {"technologies": []},
            manual_selection=["graphql", "jwt"],
        )
        self.assertEqual(result, ["graphql", "jwt", "xss"])

    async def test_manual_selection_fills_up_to_cap(self) -> None:
        llm = FakeLLM(json_response(["cors", "security_headers", "ssrf"]))
        dm = AIDecisionMaker(llm=llm, max_modules=3)
        result = await dm.recommend_modules(
            self.target,
            {"technologies": []},
            manual_selection=["xss"],
        )
        self.assertEqual(result, ["xss", "cors", "security_headers"])

    async def test_manual_selection_uses_cache_hit(self) -> None:
        llm = FakeLLM(json_response(["cors"]))
        dm = AIDecisionMaker(llm=llm)
        await dm.recommend_modules(self.target, {"technologies": []})
        result = await dm.recommend_modules(
            self.target,
            {"technologies": []},
            manual_selection=["jwt"],
        )
        self.assertEqual(llm.calls, 1)
        self.assertEqual(result, ["jwt", "cors"])

    async def test_provided_recon_used_in_prompt(self) -> None:
        llm = FakeLLM(json_response(["xss"]))
        dm = AIDecisionMaker(llm=llm)
        await dm.recommend_modules(self.target, {"technologies": ["wordpress"], "hints": ["login_form"]})
        prompt = llm.prompts[0][0]
        self.assertIn("wordpress", prompt)
        self.assertIn("login_form", prompt)


class AIDecisionMakerReconTests(IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    async def test_light_recon_extracts_fingerprint(self) -> None:
        dm = AIDecisionMaker(llm=FakeLLM(), transport=httpx.ASGITransport(app=app))
        recon = await dm._light_recon("http://localhost/lab/phantombank")
        self.assertEqual(recon["status"], 200)
        self.assertIsInstance(recon["headers"], dict)
        self.assertIsInstance(recon["technologies"], list)
        self.assertIsInstance(recon["hints"], list)
        self.assertEqual(recon["url"], "http://localhost/lab/phantombank")

    async def test_light_recon_failure_graceful(self) -> None:
        class BoomTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("connection refused")

        dm = AIDecisionMaker(llm=FakeLLM(), transport=BoomTransport())
        recon = await dm._light_recon("http://localhost/lab/phantombank")
        self.assertIn("error", recon)
        self.assertEqual(recon["status"], None)

    async def test_recommend_falls_back_when_recon_fails(self) -> None:
        class BoomTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.ConnectError("connection refused")

        llm = FakeLLM(json_response(["xss"]))
        dm = AIDecisionMaker(llm=llm, transport=BoomTransport())
        result = await dm.recommend_modules("http://localhost/lab/phantombank")
        self.assertEqual(result, ["xss"])
        self.assertIn("error", llm.prompts[0][0])


class AIDecisionReducedScanTimeTests(IsolatedAsyncioTestCase):
    """Demonstrates the core value: AI selection runs fewer modules/requests.

    Measured against the PhantomBank lab: the planner-derived baseline selects
    18 modules (~24 requests); an AI-narrowed subset (single module) runs
    1 module (~2 requests).
    """

    async def asyncSetUp(self) -> None:
        await initialize_database()
        set_scenario_state("VULNERABLE")

    def limits(self, max_total_requests: int = 50) -> SafetyLimits:
        return SafetyLimits(
            max_scan_duration=30,
            max_requests_per_second=100,
            max_total_requests=max_total_requests,
            max_concurrent_scans=2,
            max_redirect_depth=0,
            max_response_size=200_000,
        )

    async def run_engine(self, selected_modules: list[str]) -> dict:
        scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="pentest",
            intensity="low",
            selected_tests=json.dumps(selected_modules),
            user_id="local-user",
            authorization_confirmed=False,
        )
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit(
            "http://localhost/lab/phantombank", "local-user"
        )
        engine = ActiveSecurityEngine(
            target_url=decision.target_url,
            attack_surface=None,
            selected_modules=selected_modules,
            limits=self.limits(),
            authorization_context=decision.to_context(),
            workflow_rules={},
            scan_id=scan_id,
            user_id="local-user",
            sandbox_id="ai-decision-test",
            transport=httpx.ASGITransport(app=app),
        )
        return await engine.run()

    @staticmethod
    def started_modules(result: dict) -> list[str]:
        return [
            str(event.get("selected_module") or "")
            for event in result.get("events", [])
            if event.get("event") == "module_started"
        ]

    async def test_ai_selection_reduces_modules_and_requests(self) -> None:
        baseline = await self.run_engine([])
        narrowed = await self.run_engine(["xss"])

        baseline_modules = self.started_modules(baseline)
        narrowed_modules = self.started_modules(narrowed)

        self.assertEqual(baseline["status"], "complete")
        self.assertEqual(narrowed["status"], "complete")
        self.assertGreater(len(baseline_modules), 1)
        self.assertLess(len(narrowed_modules), len(baseline_modules))
        self.assertLess(narrowed["request_count"], baseline["request_count"])

    async def test_ai_recommendation_drives_engine_selection(self) -> None:
        llm = FakeLLM(json_response(["xss", "cors"]))
        dm = AIDecisionMaker(llm=llm)
        recommended = await dm.recommend_modules(
            "http://localhost/lab/phantombank", {"technologies": [], "hints": ["login_form"]}
        )
        result = await self.run_engine(recommended)
        started = self.started_modules(result)
        self.assertEqual(started, ["xss", "cors"])
        self.assertGreaterEqual(result["request_count"], 0)
        self.assertEqual(result["status"], "complete")
