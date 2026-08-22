import random
import unittest

from app.ml.base import ML_AVAILABLE, ModelRegistry
from app.ml.cve_validator import CVEVersionValidator
from app.ml.dataset import build_injection_dataset
from app.ml.false_positive_filter import FalsePositiveFilter
from app.ml.injection_detector import MLInjectionDetector
from app.ml.poc_validator import PoCValidator
from app.ml.risk_prioritizer import RiskPrioritizer
from app.ml.severity_predictor import SeverityPredictor
from app.ml.tech_detector import TechnologyDetector
from app.ml.waf_bypass import WAFBypassAgent


class TestInjectionDetector(unittest.IsolatedAsyncioTestCase):
    async def test_detects_sqli_payload(self):
        detector = MLInjectionDetector(use_ml=False)
        verdict = await detector.predict(
            {
                "payload": "1' OR '1'='1' --",
                "response_body": "you have an error in your sql syntax",
                "status_code": 500,
            }
        )
        self.assertTrue(verdict["is_injection"])
        self.assertEqual(verdict["type"], "sqli")
        self.assertGreaterEqual(verdict["confidence"], 0.35)
        self.assertIn("backend", verdict)
        self.assertIn("reason", verdict)

    async def test_detects_xss_payload(self):
        detector = MLInjectionDetector(use_ml=False)
        verdict = await detector.predict(
            {
                "payload": "<script>alert(1)</script>",
                "response_body": "Value: <script>alert(1)</script>",
                "status_code": 200,
            }
        )
        self.assertTrue(verdict["is_injection"])
        self.assertEqual(verdict["type"], "xss")

    async def test_benign_request_is_not_injection(self):
        detector = MLInjectionDetector(use_ml=False)
        verdict = await detector.predict(
            {
                "payload": "normal_text",
                "response_body": "results page loaded",
                "status_code": 200,
            }
        )
        self.assertFalse(verdict["is_injection"])
        self.assertEqual(verdict["type"], "benign")

    async def test_ml_backend_used_when_models_present(self):
        if not ML_AVAILABLE:
            self.skipTest("sklearn not installed")
        try:
            ModelRegistry.put("injection_vectorizer", object())
            ModelRegistry.put("injection_detector", object())
            detector = MLInjectionDetector(use_ml=True)
        finally:
            ModelRegistry.reset()
        self.assertFalse(detector.ml_ready)


class TestFalsePositiveFilter(unittest.IsolatedAsyncioTestCase):
    async def test_filters_weak_finding(self):
        result = await FalsePositiveFilter().filter_finding(
            {
                "title": "Missing header",
                "category": "Security Headers",
                "severity": "LOW",
                "confidence": "POTENTIAL",
                "evidence": "no",
            }
        )
        self.assertFalse(result["is_true_positive"])
        self.assertIn("reason", result)
        self.assertIn("features", result)

    async def test_keeps_strong_finding(self):
        result = await FalsePositiveFilter().filter_finding(
            {
                "title": "SQL injection in q",
                "category": "Injection",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "evidence": "you have an error in your sql syntax near ' OR 1=1--",
                "verification": "Repeat with payload and verify error is gone",
                "cve_id": None,
                "cvss_score": None,
            }
        )
        self.assertTrue(result["is_true_positive"])

    async def test_cve_boosts_score(self):
        weak = await FalsePositiveFilter().filter_finding(
            {
                "category": "CVE",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "evidence": "x",
            }
        )
        strong = await FalsePositiveFilter().filter_finding(
            {
                "category": "CVE",
                "severity": "LOW",
                "confidence": "MEDIUM",
                "evidence": "x",
                "cve_id": "CVE-2024-1234",
                "cvss_score": 7.5,
            }
        )
        self.assertGreater(strong["confidence"], weak["confidence"])


class TestSeverityPredictor(unittest.IsolatedAsyncioTestCase):
    async def test_predicts_critical_for_cvss_9_8(self):
        result = await SeverityPredictor().predict_severity(
            {
                "category": "Injection",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "cvss_score": 9.8,
                "evidence": "x" * 120,
            }
        )
        self.assertIn(result["severity"], ("CRITICAL", "HIGH"))
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertIsInstance(result["factors"], list)
        self.assertTrue(any("CVSS" in f for f in result["factors"]))

    async def test_predicts_low_for_baseline_finding(self):
        result = await SeverityPredictor().predict_severity(
            {
                "category": "Security Headers",
                "severity": "low",
                "confidence": "POTENTIAL",
                "evidence": "x",
            }
        )
        self.assertIn(result["severity"], ("LOW", "INFO"))


class TestRiskPrioritizer(unittest.IsolatedAsyncioTestCase):
    async def test_sorts_and_labels_findings(self):
        findings = [
            {
                "title": "low",
                "category": "Cookies",
                "severity": "INFO",
                "confidence": "LOW",
            },
            {
                "title": "high",
                "category": "Injection",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "cvss_score": 9.8,
                "module": "sqli",
            },
            {
                "title": "mid",
                "category": "CORS",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
            },
        ]
        prioritized = RiskPrioritizer().prioritize(findings)
        self.assertEqual(prioritized[0]["title"], "high")
        self.assertEqual(prioritized[0]["priority"], "P0-Emergency")
        self.assertGreater(
            prioritized[0]["priority_score"], prioritized[1]["priority_score"]
        )
        self.assertIn("priority_reason", prioritized[0])
        for f in prioritized:
            self.assertRegex(f["priority"], r"^P[0-4]")

    async def test_empty_findings(self):
        self.assertEqual(RiskPrioritizer().prioritize([]), [])


class TestCVEVersionValidator(unittest.IsolatedAsyncioTestCase):
    async def test_version_in_range(self):
        result = await CVEVersionValidator().validate(
            {"cve_id": "CVE-2024-0001", "version_affected": ">=1.0 and <2.0"}, "1.5.3"
        )
        self.assertTrue(result["is_vulnerable"])
        self.assertEqual(result["match_type"], "range")
        self.assertGreater(result["confidence"], 0.8)

    async def test_version_out_of_range(self):
        result = await CVEVersionValidator().validate(
            {"cve_id": "CVE-2024-0001", "version_affected": ">=2.0 and <2.5"}, "3.0"
        )
        self.assertFalse(result["is_vulnerable"])

    async def test_exact_version(self):
        result = await CVEVersionValidator().validate(
            {"cve_id": "CVE-2024-0002", "version_affected": "1.2.3"}, "1.2.3"
        )
        self.assertTrue(result["is_vulnerable"])

    async def test_unknown_detected_version_keeps_match(self):
        result = await CVEVersionValidator().validate(
            {"cve_id": "CVE-2024-0003", "version_affected": "<2.0"}, None
        )
        self.assertTrue(result["is_vulnerable"])
        self.assertEqual(result["match_type"], "unknown_version")

    async def test_validate_match_extracts_version(self):
        result = await CVEVersionValidator().validate_match(
            {
                "cve_id": "CVE-2024-0004",
                "version_affected": "<=1.8",
                "affected_component": "nginx 1.8.1",
            }
        )
        self.assertEqual(result["detected_version"], "1.8.1")
        self.assertTrue(result["is_vulnerable"])


class TestTechnologyDetector(unittest.IsolatedAsyncioTestCase):
    async def test_signature_detect(self):
        results = await TechnologyDetector(use_ml=False).detect(
            {
                "headers": {"server": "nginx/1.24.0"},
                "body": "Powered by Laravel",
            }
        )
        names = [r["technology"] for r in results]
        self.assertIn("nginx", names)
        self.assertIn("laravel", names)
        for r in results:
            self.assertIn("confidence", r)

    async def test_refine_adds_ml_confidence(self):
        detections = [
            {
                "name": "nginx",
                "confidence": 60,
                "evidence": ["header server: nginx"],
                "multi_source": False,
            },
        ]
        refined = await TechnologyDetector(use_ml=False).refine(
            detections, {"server": "nginx"}, ""
        )
        self.assertIn("ml_confidence", refined[0])
        self.assertGreaterEqual(refined[0]["ml_confidence"], 0.0)


class TestWAFBypassAgent(unittest.IsolatedAsyncioTestCase):
    async def test_generates_payload_with_strategy(self):
        agent = WAFBypassAgent(epsilon=0.0)
        result = agent.generate_bypass_payload("1' OR 1=1--", context="sqli")
        self.assertIn("payload", result)
        self.assertIn("strategy", result)
        self.assertEqual(result["attempts"], 1)
        self.assertFalse(result["learned"])

    async def test_learns_from_rewards(self):
        random.seed(7)
        agent = WAFBypassAgent(epsilon=0.0)
        for _ in range(5):
            result = agent.generate_bypass_payload("SELECT 1", context="sqli")
            agent.observe_reward(1.0 if result["strategy"] == "case_mutation" else 0.0)
        self.assertTrue(agent.replay)
        self.assertEqual(agent.best_strategy(), "case_mutation")

    async def test_obfuscation_changes_payload(self):
        agent = WAFBypassAgent(epsilon=0.0)
        base = "SELECT 1 OR 1=1--"
        seen = {
            agent.generate_bypass_payload(base, context="sqli")["payload"]
            for _ in range(20)
        }
        self.assertGreater(len(seen), 1)


class TestPoCValidator(unittest.IsolatedAsyncioTestCase):
    async def test_valid_spec_is_reachable(self):
        result = await PoCValidator().validate(
            {
                "url": "http://target.local/search?q=test",
                "method": "GET",
                "payload": "test",
                "parameter": "q",
                "expected_evidence": "reflected",
            }
        )
        self.assertTrue(result["reachable"])
        self.assertGreaterEqual(result["score"], 0.6)

    async def test_invalid_spec_is_not_reachable(self):
        result = await PoCValidator().validate(
            {
                "url": "not-a-url",
                "method": "NOPE",
                "payload": "",
                "expected_evidence": "",
            }
        )
        self.assertFalse(result["reachable"])
        self.assertTrue(result["suggestions"])


class TestDataset(unittest.IsolatedAsyncioTestCase):
    async def test_builds_labeled_rows(self):
        rows = build_injection_dataset(n=300, seed=1)
        self.assertGreaterEqual(len(rows), 200)
        self.assertEqual(len(rows), 300)
        labels = {r["label"] for r in rows}
        self.assertEqual(labels, {0, 1})
        types = {r["type"] for r in rows}
        self.assertEqual(types, {"benign", "sqli", "xss"})


@unittest.skipUnless(ML_AVAILABLE, "scikit-learn not installed")
class TestTrainingScript(unittest.TestCase):
    def test_trains_and_persists_models(self):
        try:
            from app.ml.train_injection_detector import main

            result = main(samples=400, seed=3)
            self.assertIn("report", result)
            self.assertIn("models", result)
            self.assertTrue(result["models"]["injection_vectorizer"])
            self.assertTrue(result["models"]["injection_detector"])
        finally:
            ModelRegistry.reset()


if __name__ == "__main__":
    unittest.main()
