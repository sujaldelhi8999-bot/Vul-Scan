import asyncio
import os
import tempfile
from unittest import IsolatedAsyncioTestCase

_db_fd, _db_path = tempfile.mkstemp(suffix=".sqlite3")
os.close(_db_fd)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("MAX_REQUESTS_PER_SECOND", "3.0")

from app.models import ScanRequest  # noqa: E402
from app.services.adaptive_scan_planner import (  # noqa: E402
    ESSENTIAL_MODULES,
    FULL_MODULE_LIST,
    AdaptiveScanPlanner,
)
from app.services.execution import SafetyLimits  # noqa: E402
from app.services.tci import (  # noqa: E402
    BAND_COMPLEX,
    BAND_CRITICAL,
    BAND_MEDIUM,
    BAND_SIMPLE,
    TargetComplexityIndex,
    band_for_score,
)


def make_request(**overrides) -> ScanRequest:
    values = {
        "target_url": "http://localhost/lab/phantombank",
        "mode": "pentest",
        "intensity": "medium",
        "selected_tests": [],
    }
    values.update(overrides)
    return ScanRequest(**values)


def make_limits(req_per_second: float = 100.0) -> SafetyLimits:
    return SafetyLimits(
        max_scan_duration=120,
        max_requests_per_second=req_per_second,
        max_total_requests=500,
        max_concurrent_scans=1,
        max_redirect_depth=5,
        max_response_size=4096,
    )


class TciScoringTests(IsolatedAsyncioTestCase):
    def test_band_for_score_edges(self) -> None:
        self.assertEqual(band_for_score(0), BAND_SIMPLE)
        self.assertEqual(band_for_score(25), BAND_SIMPLE)
        self.assertEqual(band_for_score(26), BAND_MEDIUM)
        self.assertEqual(band_for_score(50), BAND_MEDIUM)
        self.assertEqual(band_for_score(51), BAND_COMPLEX)
        self.assertEqual(band_for_score(75), BAND_COMPLEX)
        self.assertEqual(band_for_score(76), BAND_CRITICAL)
        self.assertEqual(band_for_score(100), BAND_CRITICAL)

    def test_empty_signals_score_zero(self) -> None:
        result = TargetComplexityIndex().analyze({})
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], BAND_SIMPLE)

    def test_ports_and_db_score(self) -> None:
        result = TargetComplexityIndex().analyze({"ports": [80, 443, 3306, 5432, 22, 6379]})
        self.assertEqual(result["breakdown"]["ports"]["database_ports"], [3306, 5432, 6379])
        self.assertEqual(result["breakdown"]["ports"]["admin_ports"], [22])
        self.assertEqual(result["score"], 18)

    def test_auth_api_waf_headers_and_scale_raise_score(self) -> None:
        result = TargetComplexityIndex().analyze(
            {
                "ports": [80, 443, 3000, 8080],
                "tech_stack": ["django", "react", "graphql"],
                "versions": ["4.2"],
                "auth_mechanisms": ["basic", "bearer/token"],
                "has_admin_surface": True,
                "api_endpoints": 6,
                "has_graphql": True,
                "has_openapi": True,
                "waf": False,
                "security_headers": {},
                "endpoints": 30,
                "subdomains": 2,
            }
        )
        self.assertEqual(result["band"], BAND_CRITICAL)
        self.assertGreaterEqual(result["score"], 76)
        self.assertGreater(result["breakdown"]["authentication"]["points"], 0)

    def test_waf_and_headers_reduce_header_points(self) -> None:
        with_headers = TargetComplexityIndex().analyze(
            {"security_headers": {"strict-transport-security": "1", "x-frame-options": "DENY"}, "waf": True}
        )
        without = TargetComplexityIndex().analyze({"security_headers": {}, "waf": False})
        self.assertLess(with_headers["breakdown"]["security_headers"]["points"], without["breakdown"]["security_headers"]["points"])

    def test_analyze_recon_from_scanner_output(self) -> None:
        result = TargetComplexityIndex().analyze_recon(
            {
                "open_ports": [80, 443],
                "tech_stack": {"technologies": ["nginx", "django"], "server": "nginx/1.24"},
                "technologies_detailed": [{"name": "django", "version": "4.2"}],
                "http_headers": {"server": "nginx", "content-security-policy": "default-src 'self'"},
                "waf_detected": False,
                "endpoints": ["/", "/api/users", "/login", "/graphql"],
            }
        )
        self.assertIn("django", result["breakdown"]["tech_stack"]["detected"])
        self.assertEqual(result["breakdown"]["api_surface"]["endpoints"], 2)
        self.assertTrue(result["breakdown"]["api_surface"]["graphql"])
        self.assertGreaterEqual(result["score"], 20)

    async def test_analyze_live_collects_probes(self) -> None:
        tci = TargetComplexityIndex()

        async def fake_fetch(url: str):
            if url.endswith("/robots.txt"):
                return type("P", (), {"status_code": 200, "body": "Disallow: /admin", "headers": {}})
            if url.endswith("/openapi.json"):
                return type("P", (), {"status_code": 200, "body": "{}", "headers": {}})
            return type(
                "P",
                (),
                {
                    "status_code": 200,
                    "headers": {"server": "nginx", "www-authenticate": "Basic"},
                    "body": '<html><a href="/api/users">users</a><a href="/api/v1/accounts">accounts</a><a href="/login">login</a></html>',
                },
            )

        async def fake_sweep(_origin: str):
            return [80, 443, 3306]

        tci._fetch = fake_fetch
        tci._sweep_ports = fake_sweep
        result = await tci.analyze_live("http://localhost/lab/phantombank")
        self.assertIn("basic", result["breakdown"]["authentication"]["mechanisms"])
        self.assertGreaterEqual(result["breakdown"]["api_surface"]["endpoints"], 2)
        self.assertTrue(result["breakdown"]["api_surface"]["openapi"])
        self.assertIn("nginx", result["breakdown"]["tech_stack"]["detected"])


class AdaptivePlannerTests(IsolatedAsyncioTestCase):
    def test_simple_band_essential_modules_low_rate(self) -> None:
        plan = AdaptiveScanPlanner().plan(
            {"band": BAND_SIMPLE, "score": 10},
            make_request(),
            make_limits(),
        )
        self.assertEqual(plan["modules"], ESSENTIAL_MODULES)
        self.assertEqual(plan["requests_per_second"], 2.0)
        self.assertEqual(plan["intensity"], "low")

    def test_medium_band_all_modules(self) -> None:
        plan = AdaptiveScanPlanner().plan(
            {"band": BAND_MEDIUM, "score": 40},
            make_request(),
            make_limits(),
        )
        self.assertEqual(plan["modules"], FULL_MODULE_LIST)
        self.assertEqual(plan["requests_per_second"], 5.0)

    def test_complex_band_deepens_budget(self) -> None:
        plan = AdaptiveScanPlanner().plan(
            {"band": BAND_COMPLEX, "score": 60},
            make_request(),
            make_limits(),
        )
        self.assertTrue(plan["deeper"])
        self.assertEqual(plan["limits"]["max_total_requests"], 1000)

    def test_critical_band_capped_by_safety_limit(self) -> None:
        plan = AdaptiveScanPlanner().plan(
            {"band": BAND_CRITICAL, "score": 90},
            make_request(),
            make_limits(req_per_second=3.0),
        )
        self.assertEqual(plan["requests_per_second"], 3.0)
        self.assertTrue(any("capped" in line for line in plan["rationale"]))

    def test_explicit_selection_overrides_band_defaults(self) -> None:
        plan = AdaptiveScanPlanner().plan(
            {"band": BAND_CRITICAL, "score": 90},
            make_request(selected_tests=["xss", "jwt"]),
            make_limits(),
        )
        self.assertEqual(plan["modules"], ["xss", "jwt"])
        self.assertTrue(any("explicitly selected" in line for line in plan["rationale"]))

    def test_learning_tunings_disable_and_deprioritize(self) -> None:
        plan = AdaptiveScanPlanner().plan(
            {"band": BAND_MEDIUM, "score": 40},
            make_request(),
            make_limits(),
            tunings={
                "xss": {"action": "disable", "fp_rate": 0.9, "sample_count": 20},
                "jwt": {"action": "reduce_priority", "fp_rate": 0.6, "sample_count": 5},
            },
        )
        self.assertNotIn("xss", plan["modules"])
        self.assertIn("xss", plan["excluded_modules"])
        self.assertIn("learning", plan["excluded_reasons"]["xss"])
        self.assertIn("jwt", plan["modules"])

    def test_explicit_selection_ignores_tunings(self) -> None:
        plan = AdaptiveScanPlanner().plan(
            {"band": BAND_MEDIUM, "score": 40},
            make_request(selected_tests=["xss"]),
            make_limits(),
            tunings={"xss": {"action": "disable", "fp_rate": 0.9, "sample_count": 20}},
        )
        self.assertEqual(plan["modules"], ["xss"])
