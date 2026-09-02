import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.config import get_settings

OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"
OPENROUTER_CACHE_TTL = timedelta(hours=1)
_response_cache: dict[str, tuple[datetime, str]] = {}
_rate_limited_until: datetime | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cache_key(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def clear_openrouter_cache() -> None:
    global _rate_limited_until
    _response_cache.clear()
    _rate_limited_until = None


class AIUsageLogger:
    def __init__(self) -> None:
        self._logs: list[dict[str, Any]] = []

    def log(
        self,
        *,
        model: str,
        scan_id: int | None = None,
        response_status: str,
        token_usage: dict[str, Any] | None = None,
        error: str | None = None,
        response_body: dict[str, Any] | None = None,
    ) -> None:
        self._logs.append(
            {
                "model": model,
                "request_timestamp": utc_now(),
                "scan_id": scan_id,
                "response_status": response_status,
                "token_usage": token_usage or {},
                "error": error,
                "response_body": response_body,
            }
        )

    def get_logs(self) -> list[dict[str, Any]]:
        return list(self._logs)

    def clear(self) -> None:
        self._logs.clear()
        clear_openrouter_cache()


ai_usage_logger = AIUsageLogger()


def get_ai_status() -> dict[str, Any]:
    settings = get_settings()
    return {
        "provider": "OpenRouter",
        "model": settings.openrouter_model,
        "configured": bool(settings.openrouter_api_key),
    }


async def call_openrouter(
    prompt: str,
    system_prompt: str = "",
    *,
    model: str | None = None,
    max_tokens: int = 500,
    timeout: float = 15.0,
    retry_limit: int = 2,
    scan_id: int | None = None,
    json_response: bool = False,
) -> str:
    global _rate_limited_until
    settings = get_settings()
    api_key = settings.openrouter_api_key
    active_model = model or settings.openrouter_model

    if not api_key:
        ai_usage_logger.log(
            model=active_model,
            scan_id=scan_id,
            response_status="skipped",
            error="OPENROUTER_API_KEY is not configured",
        )
        return ""

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload: dict[str, Any] = {
        "model": active_model,
        "max_tokens": max_tokens,
        "messages": messages,
    }
    if json_response:
        payload["response_format"] = {"type": "json_object"}

    key = _cache_key(payload)
    now = datetime.now(timezone.utc)
    cached = _response_cache.get(key)
    if cached and cached[0] > now:
        ai_usage_logger.log(
            model=active_model,
            scan_id=scan_id,
            response_status="cached",
        )
        return cached[1]
    if cached:
        _response_cache.pop(key, None)
    if _rate_limited_until and _rate_limited_until > now:
        ai_usage_logger.log(
            model=active_model,
            scan_id=scan_id,
            response_status="rate_limited_cooldown",
            error="OpenRouter recently returned 429; skipping AI call",
        )
        return ""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://phantomscan.app",
        "X-Title": "PhantomScan",
    }

    last_error: str | None = None
    for attempt in range(max(1, retry_limit)):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{OPENROUTER_API_BASE}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
        except httpx.TimeoutException as exc:
            last_error = f"OpenRouter timeout: {exc}"
            if attempt < retry_limit - 1:
                await asyncio.sleep(2 ** attempt)
            continue
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            last_error = f"OpenRouter HTTP {status_code}: {exc}"
            if status_code == 429 and attempt < retry_limit - 1:
                retry_after = exc.response.headers.get("retry-after")
                try:
                    delay = min(float(retry_after), 8.0) if retry_after else float(2 ** attempt)
                except (TypeError, ValueError):
                    delay = float(2 ** attempt)
                ai_usage_logger.log(
                    model=active_model,
                    scan_id=scan_id,
                    response_status="rate_limited_retry",
                    error=last_error,
                )
                await asyncio.sleep(delay)
                continue
            if status_code == 429:
                retry_after = exc.response.headers.get("retry-after")
                try:
                    cooldown = min(max(float(retry_after), 15.0), 120.0) if retry_after else 60.0
                except (TypeError, ValueError):
                    cooldown = 60.0
                _rate_limited_until = datetime.now(timezone.utc) + timedelta(seconds=cooldown)
            ai_usage_logger.log(
                model=active_model,
                scan_id=scan_id,
                response_status=f"error_{status_code}",
                error=last_error,
            )
            return ""
        except httpx.HTTPError as exc:
            last_error = f"OpenRouter request failed: {exc}"
            if attempt < retry_limit - 1:
                await asyncio.sleep(2 ** attempt)
            continue

        try:
            data = response.json()
        except ValueError as exc:
            ai_usage_logger.log(
                model=active_model,
                scan_id=scan_id,
                response_status="malformed",
                error=f"OpenRouter returned malformed JSON: {exc}",
            )
            return ""
        token_usage = data.get("usage", {})

        choices = data.get("choices", [])
        if not isinstance(choices, list) or not choices:
            ai_usage_logger.log(
                model=active_model,
                scan_id=scan_id,
                response_status="success",
                token_usage=token_usage,
                response_body=data,
            )
            return ""
        choice = choices[0] if isinstance(choices[0], dict) else {}
        message = choice.get("message", {}) if isinstance(choice.get("message", {}), dict) else {}
        content = message.get("content", "")
        if not content or not content.strip():
            ai_usage_logger.log(
                model=active_model,
                scan_id=scan_id,
                response_status="success",
                token_usage=token_usage,
                response_body=data,
            )
            return ""
        ai_usage_logger.log(
            model=active_model,
            scan_id=scan_id,
            response_status="success",
            token_usage=token_usage,
        )
        content = content.strip()
        _response_cache[key] = (datetime.now(timezone.utc) + OPENROUTER_CACHE_TTL, content)
        return content

    ai_usage_logger.log(
        model=active_model,
        scan_id=scan_id,
        response_status="failed",
        error=last_error or "Unknown OpenRouter error",
    )
    return ""
