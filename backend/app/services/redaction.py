import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class SecretRedactionService:
    SECRET_PATTERNS = [
        re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]{12,})"),
        re.compile(r"(?i)(api[_-]?key\s*[:=]\s*[\"']?)([^\s\"']{6,})"),
        re.compile(r"(?i)(password\s*[:=]\s*[\"']?)([^\s\"']{4,})"),
        re.compile(r"(?i)(token\s*[:=]\s*[\"']?)([^\s\"']{8,})"),
        re.compile(r"(?i)(secret\s*[:=]\s*[\"']?)([^\s\"']{8,})"),
        re.compile(r"(?i)(csrf[_-]?token\s*[:=]\s*[\"']?)([^\s\"']{6,})"),
        re.compile(r"(?i)(session(?:id)?\s*[:=]\s*[\"']?)([^\s\"']{8,})"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    ]
    SENSITIVE_KEYS = {
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "secret",
        "client_secret",
        "csrf",
        "csrf_token",
        "xsrf_token",
        "session",
        "sessionid",
    }
    PII_PATTERNS = [
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        re.compile(r"\b(?:\+?\d[\d\s().-]{7,}\d)\b"),
    ]

    def __init__(self, limit: int = 12000) -> None:
        self.limit = limit

    def mask_value(self, value: str) -> str:
        if len(value) <= 8:
            return "********"
        return f"{value[:4]}_{'*' * min(12, len(value) - 8)}{value[-4:]}"

    def redact_text(self, text: str, limit: int | None = None) -> str:
        redacted = str(text)[: limit or self.limit]
        for pattern in self.SECRET_PATTERNS:
            if pattern.groups >= 2:
                redacted = pattern.sub(lambda match: f"{match.group(1)}{self.mask_value(match.group(2))}", redacted)
            else:
                redacted = pattern.sub(lambda match: self.mask_value(match.group(0)), redacted)
        for pattern in self.PII_PATTERNS:
            redacted = pattern.sub(lambda match: self.mask_value(match.group(0)), redacted)
        return redacted

    def redact_url(self, url: str) -> str:
        parsed = urlsplit(str(url))
        query = urlencode(
            [
                (key, self.mask_value(value) if value or key.lower() in self.SENSITIVE_KEYS else "")
                for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            ]
        )
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))

    def redact_headers(self, headers: dict[str, Any]) -> dict[str, Any]:
        safe: dict[str, Any] = {}
        for key, value in headers.items():
            name = str(key).lower()
            if name in self.SENSITIVE_KEYS or "token" in name or "secret" in name:
                safe[str(key)] = "[REDACTED]"
            else:
                safe[str(key)] = self.redact_text(str(value), 1000)
        return safe

    def redact_payload(self, value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return "[REDACTED_DEPTH_LIMIT]"
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, bytes):
            return self.redact_text(value.decode("utf-8", errors="replace"))
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                normalized = key_text.lower().replace("-", "_")
                if normalized in self.SENSITIVE_KEYS or "token" in normalized or "secret" in normalized or "password" in normalized:
                    redacted[key_text] = "[REDACTED]"
                else:
                    redacted[key_text] = self.redact_payload(item, depth + 1)
            return redacted
        if isinstance(value, list):
            return [self.redact_payload(item, depth + 1) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_payload(item, depth + 1) for item in value)
        return value


redaction_service = SecretRedactionService()
