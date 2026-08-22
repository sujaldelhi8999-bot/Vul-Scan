import json
import os
import tempfile
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

_db_fd, _db_path = tempfile.mkstemp(suffix=".sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")

from app.database import (  # noqa: E402
    create_finding,
    create_scan,
    initialize_database,
)
from app.models import FindingCreate  # noqa: E402
from app.services.learning_engine import (  # noqa: E402
    ContinuousLearningEngine,
    aggregate_findings,
    classify_finding,
    heuristic_recommendation,
)

FINDING_BASE = {
    "title": "Test finding",
    "category": "injection",
    "severity": "HIGH",
    "confidence": "CONFIRMED",
    "target": "http://localhost/lab/phantombank",
    "agent": "Test Agent",
    "timestamp": "2026-01-01T00:00:00Z",
}


def make_finding(**overrides) -> dict:
    values = dict(FINDING_BASE)
    values.update(overrides)
    return values


async def seed_findings(scan_id: int, rows: list[dict]) -> None:
    for row in rows:
        await create_finding(scan_id, FindingCreate(**make_finding(**row)))


class ClassificationTests(IsolatedAsyncioTestCase):
    def test_classify_risk_and_verification_statuses(self) -> None:
        self.assertEqual(classify_finding({"risk_status": "ACTIVE"}), "tp")
        self.assertEqual(classify_finding({"risk_status": "ACCEPTED_RISK"}), "tp")
        self.assertEqual(classify_finding({"risk_status": "FALSE_POSITIVE"}), "fp")
        self.assertEqual(classify_finding({"verification_status": "FIX_VERIFIED"}), "tp")
        self.assertEqual(classify_finding({"verification_status": "ISSUE_STILL_PRESENT"}), "tp")
        self.assertEqual(classify_finding({"risk_status": "ACTIVE", "verification_status": "FALSE_POSITIVE"}), "tp")
        self.assertEqual(classify_finding({"risk_status": "UNRATED"}), "unrated")

    def test_aggregate_findings_per_module(self) -> None:
        rows = aggregate_findings(
            [
                {"module": "xss", "risk_status": "ACTIVE"},
                {"module": "xss", "risk_status": "FALSE_POSITIVE"},
                {"module": "xss", "risk_status": "FALSE_POSITIVE"},
                {"module": "jwt", "risk_status": "ACTIVE"},
                {"module": None, "risk_status": "FALSE_POSITIVE"},
            ]
        )
        by_module = {row["module"]: row for row in rows}
        self.assertEqual(by_module["xss"]["true_positives"], 1)
        self.assertEqual(by_module["xss"]["false_positives"], 2)
        self.assertEqual(by_module["xss"]["false_positive_rate"], round(2 / 3, 3))
        self.assertEqual(by_module["jwt"]["true_positive_rate"], 1.0)
        self.assertEqual(by_module["unmapped"]["false_positives"], 1)

    def test_heuristic_recommendations(self) -> None:
        action, _ = heuristic_recommendation({"false_positive_rate": 0.9, "true_positive_rate": 0.0, "total_count": 10})
        self.assertEqual(action, "disable")
        action, _ = heuristic_recommendation({"false_positive_rate": 0.6, "true_positive_rate": 0.4, "total_count": 10})
        self.assertEqual(action, "tune")
        action, _ = heuristic_recommendation({"false_positive_rate": 0.1, "true_positive_rate": 0.0, "total_count": 10})
        self.assertEqual(action, "review")
        action, _ = heuristic_recommendation({"false_positive_rate": 0.1, "true_positive_rate": 0.9, "total_count": 10})
        self.assertEqual(action, "keep")


class LearningEngineTests(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._cache_patcher = patch(
            "app.services.learning_engine.get_ai_cache", new=AsyncMock(return_value=None)
        )
        self._cache_patcher.start()
        self._set_cache_patcher = patch(
            "app.services.learning_engine.set_ai_cache", new=AsyncMock()
        )
        self._set_cache_patcher.start()

    def tearDown(self) -> None:
        self._set_cache_patcher.stop()
        self._cache_patcher.stop()

    async def asyncSetUp(self) -> None:
        await initialize_database()
        self.scan_id = await create_scan(
            target_url="http://localhost/lab/phantombank",
            mode="pentest",
            intensity="medium",
            selected_tests=json.dumps(["xss", "jwt"]),
        )
        await seed_findings(
            self.scan_id,
            [
                {"module": "xss", "risk_status": "FALSE_POSITIVE"},
                {"module": "xss", "risk_status": "FALSE_POSITIVE"},
                {"module": "xss", "risk_status": "FALSE_POSITIVE"},
                {"module": "xss", "risk_status": "ACTIVE"},
                {"module": "jwt", "risk_status": "ACTIVE"},
            ],
        )

    async def test_process_scan_heuristic_fallback_disables_noisy_module(self) -> None:
        with patch("app.services.learning_engine.call_openrouter", return_value=""):
            rows = await ContinuousLearningEngine().process_scan(self.scan_id)
        by_module = {row["module"]: row for row in rows if row["kind"] == "module"}
        self.assertIn("xss", by_module)
        self.assertEqual(by_module["xss"]["false_positive_rate"], 0.75)
        self.assertEqual(by_module["xss"]["recommendation_data"]["action"], "tune")
        self.assertEqual(by_module["jwt"]["recommendation_data"]["action"], "keep")
        kinds = {row["kind"] for row in rows}
        self.assertEqual(kinds, {"module", "scan"})

    async def test_llm_recommendation_disables_when_requested(self) -> None:
        async def fake_llm(user_prompt: str, system_prompt: str, scan_id: int | None = None) -> str:
            payload = json.loads(user_prompt)
            if payload["module"] == "xss":
                return json.dumps({"action": "disable", "rationale": "noise source"})
            return json.dumps({"action": "keep", "rationale": "fine"})

        rows = await ContinuousLearningEngine(llm=fake_llm).process_scan(self.scan_id)
        by_module = {row["module"]: row for row in rows if row["kind"] == "module"}
        self.assertEqual(by_module["xss"]["recommendation_data"]["action"], "disable")
        self.assertEqual(by_module["jwt"]["recommendation_data"]["action"], "keep")

    async def test_apply_and_dismiss_insight(self) -> None:
        engine = ContinuousLearningEngine()
        with patch("app.services.learning_engine.call_openrouter", return_value=""):
            await engine.process_scan(self.scan_id)
        insights = await engine.list_insights(self.scan_id)
        self.assertTrue(insights)
        xss_insight = next(row for row in insights if row["module"] == "xss")
        applied = await engine.apply_insight(xss_insight["id"])
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(applied["applied_settings"]["action"], "tune")
        dismissed = await engine.dismiss_insight(xss_insight["id"])
        self.assertEqual(dismissed["status"], "dismissed")

    async def test_applied_tunings_consumed_by_planner(self) -> None:
        engine = ContinuousLearningEngine()
        with patch("app.services.learning_engine.call_openrouter", return_value=""):
            await engine.process_scan(self.scan_id)
        insights = await engine.list_insights(self.scan_id)
        xss_insight = next(row for row in insights if row["module"] == "xss")
        await engine.apply_insight(xss_insight["id"])
        tunings = await engine.tunings()
        self.assertIn("xss", tunings)
        self.assertEqual(tunings["xss"]["action"], "tune")

    async def test_quality_summary_shapes(self) -> None:
        with patch("app.services.learning_engine.call_openrouter", return_value=""):
            await ContinuousLearningEngine().process_scan(self.scan_id)
        summary = await ContinuousLearningEngine().quality_summary()
        self.assertIn("modules", summary)
        self.assertIn("scans", summary)
        modules = {row["module"]: row for row in summary["modules"]}
        self.assertIn("xss", modules)
        self.assertGreaterEqual(modules["xss"]["total_count"], 4)
