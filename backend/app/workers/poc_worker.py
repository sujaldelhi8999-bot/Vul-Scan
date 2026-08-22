"""Sandboxed Proof-of-Concept validator worker.

Executes a single HTTP request for a PoC payload and checks the response
against expected evidence. Runs inside a restricted sandbox (resource-limited
subprocess or Docker container); must remain stdlib-only so it works in a
bare ``python:3.12-slim`` image without installing dependencies.

Protocol: read a JSON spec from stdin, write a JSON result to stdout.
"""

import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any

MAX_RESPONSE_BYTES = 500_000
MAX_SPEC_BYTES = 20_000

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]{12,})"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*[\"']?)([^\s\"']{6,})"),
    re.compile(r"(?i)(password\s*[:=]\s*[\"']?)([^\s\"']{4,})"),
    re.compile(r"(?i)(token\s*[:=]\s*[\"']?)([^\s\"']{8,})"),
    re.compile(r"(?i)(secret\s*[:=]\s*[\"']?)([^\s\"']{8,})"),
    re.compile(r"(?i)(session(?:id)?\s*[:=]\s*[\"']?)([^\s\"']{8,})"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]
_PII_PATTERNS = [
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\+?\d[\d\s().-]{7,}\d)\b"),
]


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}_{'*' * min(12, len(value) - 8)}{value[-4:]}"


def redact_text(text: str, limit: int = 4000) -> str:
    redacted = str(text)[:limit]
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(lambda match: f"{match.group(1)}{_mask(match.group(2))}", redacted)
        else:
            redacted = pattern.sub(lambda match: _mask(match.group(0)), redacted)
    for pattern in _PII_PATTERNS:
        redacted = pattern.sub(lambda match: _mask(match.group(0)), redacted)
    return redacted


def _evidence_found(expected: list[str], body: str, headers: dict[str, str]) -> tuple[bool, str]:
    """Return (found, snippet) - snippet shows where the evidence matched."""
    body_lower = body.lower()
    for needle in expected:
        needle_lower = needle.lower()
        if needle_lower in body_lower:
            return True, body[:500]
    for key, value in headers.items():
        header_line = f"{key}: {value}"
        if any(needle.lower() in header_line.lower() for needle in expected):
            return True, redact_text(header_line, 500)
    return False, ""


def execute(spec: dict[str, Any]) -> dict[str, Any]:
    url = str(spec.get("url") or "")
    if not url:
        return {"status": "failed", "error": "no url in spec"}
    method = str(spec.get("method") or "GET").upper()
    headers = {str(k): str(v) for k, v in (spec.get("headers") or {}).items() if k and v}
    expected = [str(item) for item in (spec.get("expected_evidence") or []) if str(item).strip()]
    timeout = float(spec.get("timeout") or 15.0)
    max_bytes = int(spec.get("max_response_size") or MAX_RESPONSE_BYTES)
    follow_redirects = bool(spec.get("follow_redirects", True))

    data = None
    body = spec.get("body")
    if body is not None and method in ("POST", "PUT", "PATCH", "DELETE"):
        data = str(body).encode("utf-8")
        if not any(name.lower() == "content-type" for name in headers):
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            raw_headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
            data = response.read(max_bytes + 1)
            truncated = len(data) > max_bytes
            body = data[:max_bytes].decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw_headers = {str(key).lower(): str(value) for key, value in exc.headers.items()}
        data = exc.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        body = data[:max_bytes].decode("utf-8", errors="replace")
    except Exception as exc:
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}

    if not follow_redirects and status in (301, 302, 303, 307, 308):
        found, snippet = _evidence_found(expected, body, raw_headers)
        return {
            "status": "validated" if found else "failed",
            "status_code": status,
            "evidence_found": found,
            "evidence_snippet": snippet,
            "response_preview": redact_text(f"Redirect to: {raw_headers.get('location', '')}", 500),
            "truncated": False,
        }

    found, snippet = _evidence_found(expected, body, raw_headers)
    return {
        "status": "validated" if found else "failed",
        "status_code": status,
        "evidence_found": found,
        "evidence_snippet": snippet[:500],
        "response_preview": redact_text(body[:300]),
        "truncated": truncated,
    }


def main() -> int:
    raw = sys.stdin.read(MAX_SPEC_BYTES + 1)
    try:
        spec = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        sys.stdout.write(json.dumps({"status": "failed", "error": f"invalid spec: {exc}"}))
        return 1
    try:
        result = execute(spec if isinstance(spec, dict) else {})
    except Exception as exc:
        result = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
