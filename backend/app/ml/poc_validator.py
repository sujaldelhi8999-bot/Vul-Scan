from __future__ import annotations

from typing import Any

VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

SECRET_HINTS = ("api_key=", "secret=", "password=", "token=", "authorization:")


class PoCValidator:
    """Static validation of PoC specs before they reach the sandbox.

    Checks reachability (URL/method), payload attachment, expected-evidence
    quality and secret hygiene, mirroring path-sensitive taint checks so
    hallucinated or unreachable PoCs are rejected early.
    """

    async def validate(self, spec: dict[str, Any]) -> dict[str, Any]:
        url = str(spec.get("url") or "")
        method = str(spec.get("method") or "GET").upper()
        payload = str(spec.get("payload") or "")
        parameter = str(spec.get("parameter") or "")
        headers = spec.get("headers") or {}
        evidence = str(spec.get("expected_evidence") or "")

        checks = {
            "valid_url": url.startswith(("http://", "https://")),
            "valid_method": method in VALID_METHODS,
            "has_payload": bool(payload),
            "has_evidence": bool(evidence),
            "evidence_plausible": self._evidence_plausible(evidence, payload),
            "payload_attached": self._payload_attached(
                url, payload, parameter, headers
            ),
            "no_secret_leak": not any(
                hint in (payload + evidence).lower() for hint in SECRET_HINTS
            ),
        }

        score = sum(1 for ok in checks.values() if ok) / max(1, len(checks))
        reachable = (
            checks["valid_url"]
            and checks["valid_method"]
            and checks["has_evidence"]
            and score >= 0.6
        )

        return {
            "reachable": reachable,
            "score": round(score, 3),
            "checks": checks,
            "suggestions": self._suggestions(checks),
        }

    def _evidence_plausible(self, evidence: str, payload: str) -> bool:
        lowered = evidence.lower()
        if any(
            kw in lowered for kw in ("error", "reflected", "status", "found", "200")
        ):
            return True
        if len(payload) >= 8 and payload[:8].lower() in lowered:
            return True
        return False

    def _payload_attached(
        self, url: str, payload: str, parameter: str, headers: dict[str, Any]
    ) -> bool:
        if parameter and payload:
            return True
        if payload and payload in url:
            return True
        if headers:
            return True
        return False

    def _suggestions(self, checks: dict[str, bool]) -> list[str]:
        suggestions: list[str] = []
        mapping = {
            "valid_url": "Provide an absolute http(s) URL",
            "valid_method": "Use a supported HTTP method",
            "has_payload": "Specify a payload to send",
            "has_evidence": "Define expected_evidence to assert on",
            "evidence_plausible": "expected_evidence should reference a reflection, error or status signal",
            "payload_attached": "Attach the payload to a parameter, URL or headers",
            "no_secret_leak": "Remove secrets from payload and evidence",
        }
        for check, ok in checks.items():
            if not ok and check in mapping:
                suggestions.append(mapping[check])
        return suggestions
