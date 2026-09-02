import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app.config import get_settings
from app.services.openrouter_client import call_openrouter, get_ai_status, ai_usage_logger


class TestOpenRouterClient(unittest.TestCase):
    def setUp(self):
        ai_usage_logger.clear()

    def test_ai_status_when_not_configured(self):
        with patch("app.services.openrouter_client.get_settings") as mock_settings:
            mock_settings.return_value.openrouter_api_key = ""
            mock_settings.return_value.openrouter_model = "openrouter/free"
            status = get_ai_status()
            self.assertEqual(status["provider"], "OpenRouter")
            self.assertEqual(status["model"], "openrouter/free")
            self.assertFalse(status["configured"])

    def test_ai_status_when_configured(self):
        with patch("app.services.openrouter_client.get_settings") as mock_settings:
            mock_settings.return_value.openrouter_api_key = "sk-test-key"
            mock_settings.return_value.openrouter_model = "openrouter/free"
            status = get_ai_status()
            self.assertEqual(status["provider"], "OpenRouter")
            self.assertEqual(status["model"], "openrouter/free")
            self.assertTrue(status["configured"])

    def test_call_openrouter_returns_empty_when_no_key(self):
        with patch("app.services.openrouter_client.get_settings") as mock_settings:
            mock_settings.return_value.openrouter_api_key = ""
            mock_settings.return_value.openrouter_model = "openrouter/free"
            result = asyncio.run(call_openrouter("test prompt"))
            self.assertEqual(result, "")

    def test_call_openrouter_returns_empty_on_http_error(self):
        async def run_test():
            with (
                patch("app.services.openrouter_client.get_settings") as mock_settings,
                patch("httpx.AsyncClient") as mock_client,
            ):
                mock_settings.return_value.openrouter_api_key = "sk-test-key"
                mock_settings.return_value.openrouter_model = "openrouter/free"
                mock_instance = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_instance
                mock_instance.post.side_effect = httpx.HTTPError("Connection error")
                result = await call_openrouter("test prompt")
                self.assertEqual(result, "")
        asyncio.run(run_test())

    def test_ai_usage_logging(self):
        ai_usage_logger.log(
            model="openrouter/free",
            scan_id=1,
            response_status="success",
            token_usage={"prompt_tokens": 50, "completion_tokens": 100},
        )
        logs = ai_usage_logger.get_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["model"], "openrouter/free")
        self.assertEqual(logs[0]["scan_id"], 1)
        self.assertEqual(logs[0]["response_status"], "success")
        self.assertEqual(logs[0]["token_usage"]["prompt_tokens"], 50)

    def test_ai_usage_logging_no_keys(self):
        ai_usage_logger.log(
            model="openrouter/free",
            response_status="skipped",
            error="OPENROUTER_API_KEY is not configured",
        )
        logs = ai_usage_logger.get_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["response_status"], "skipped")
        self.assertIn("error", logs[0])

    def test_call_openrouter_fallback_on_failure(self):
        async def run_test():
            with (
                patch("app.services.openrouter_client.get_settings") as mock_settings,
                patch("httpx.AsyncClient") as mock_client,
            ):
                mock_settings.return_value.openrouter_api_key = "sk-test-key"
                mock_settings.return_value.openrouter_model = "openrouter/free"
                mock_instance = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_instance
                mock_instance.post.side_effect = httpx.HTTPError("API failure")
                ai_usage_logger.clear()
                result = await call_openrouter("test prompt")
                self.assertEqual(result, "")
                logs = ai_usage_logger.get_logs()
                self.assertTrue(any(log["response_status"] == "failed" for log in logs))
        asyncio.run(run_test())

    def test_call_openrouter_retries_429_and_caches_success(self):
        async def run_test():
            request = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
            responses = [
                httpx.Response(429, request=request),
                httpx.Response(200, request=request, json={"choices": [{"message": {"content": "cached answer"}}]}),
            ]

            class FakeClient:
                def __init__(self, *_args, **_kwargs):
                    pass

                async def __aenter__(self):
                    return self

                async def __aexit__(self, *_args):
                    return None

                async def post(self, *_args, **_kwargs):
                    return responses.pop(0)

            with (
                patch("app.services.openrouter_client.get_settings") as mock_settings,
                patch("app.services.openrouter_client.httpx.AsyncClient", FakeClient),
                patch("app.services.openrouter_client.asyncio.sleep", new=AsyncMock()) as sleep_mock,
            ):
                mock_settings.return_value.openrouter_api_key = "sk-test-key"
                mock_settings.return_value.openrouter_model = "openrouter/free"
                ai_usage_logger.clear()
                first = await call_openrouter("cacheable prompt", retry_limit=2)
                second = await call_openrouter("cacheable prompt", retry_limit=2)

            self.assertEqual(first, "cached answer")
            self.assertEqual(second, "cached answer")
            self.assertEqual(responses, [])
            sleep_mock.assert_awaited_once()
            self.assertTrue(any(log["response_status"] == "rate_limited_retry" for log in ai_usage_logger.get_logs()))
            self.assertTrue(any(log["response_status"] == "cached" for log in ai_usage_logger.get_logs()))

        asyncio.run(run_test())


class TestAIAnalystFallback(unittest.TestCase):
    def test_ai_unavailable_response_format(self):
        fallback = {
            "ai_status": "unavailable",
            "message": "AI analysis temporarily unavailable",
            "basic_analysis": True,
        }
        self.assertEqual(fallback["ai_status"], "unavailable")
        self.assertTrue(fallback["basic_analysis"])

    def test_explain_finding_fallback(self):
        finding = {"title": "Missing Content Security Policy header", "severity": "MEDIUM", "confidence": "HIGH"}
        explanation = self._mock_explain_finding(finding)
        self.assertIn("explanation", explanation)
        self.assertIn("severity_reasoning", explanation)
        self.assertIn("remediation_advice", explanation)

    def _mock_explain_finding(self, finding: dict) -> dict:
        title = str(finding.get("title", ""))
        severity = str(finding.get("severity", "MEDIUM"))
        return {
            "explanation": f"{title} allows an attacker to inject malicious scripts or exfiltrate data.",
            "severity_reasoning": f"Rated {severity} because missing CSP increases risk of XSS attacks.",
            "remediation_advice": "Add a Content-Security-Policy header with appropriate directives.",
        }

    def test_vulnerability_analysis_format(self):
        analysis = self._mock_vulnerability_analysis("Missing Content Security Policy header")
        required_keys = [
            "vulnerability_summary",
            "risk_explanation",
            "real_world_impact",
            "recommended_fix",
            "verification_steps",
            "confidence_score",
        ]
        for key in required_keys:
            self.assertIn(key, analysis, f"Missing key: {key}")

    def _mock_vulnerability_analysis(self, vuln_name: str) -> dict:
        return {
            "vulnerability_summary": f"{vuln_name} detected on the target application.",
            "risk_explanation": "Missing CSP headers allow XSS, data injection, and clickjacking attacks.",
            "real_world_impact": "Attackers can steal user data, perform phishing, or deface the site.",
            "recommended_fix": "Implement Content-Security-Policy header with strict directives.",
            "verification_steps": "1. Add CSP header. 2. Scan again. 3. Verify no violations.",
            "confidence_score": "HIGH",
        }


if __name__ == "__main__":
    unittest.main()
