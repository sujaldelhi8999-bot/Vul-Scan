import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from app.config import get_settings

OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    timeout: float = 30.0,
    retry_limit: int = 2,
    scan_id: int | None = None,
    json_response: bool = False,
) -> str:
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
                await asyncio.sleep(1 * (attempt + 1))
            continue
        except httpx.HTTPStatusError as exc:
            last_error = f"OpenRouter HTTP {exc.response.status_code}: {exc}"
            ai_usage_logger.log(
                model=active_model,
                scan_id=scan_id,
                response_status=f"error_{exc.response.status_code}",
                error=last_error,
            )
            return ""
        except httpx.HTTPError as exc:
            last_error = f"OpenRouter request failed: {exc}"
            if attempt < retry_limit - 1:
                await asyncio.sleep(1 * (attempt + 1))
            continue

        data = response.json()
        token_usage = data.get("usage", {})

        choices = data.get("choices", [])
        if not choices:
            ai_usage_logger.log(
                model=active_model,
                scan_id=scan_id,
                response_status="success",
                token_usage=token_usage,
                response_body=data,
            )
            return ""
        content = choices[0].get("message", {}).get("content", "")
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
        return content.strip()

    ai_usage_logger.log(
        model=active_model,
        scan_id=scan_id,
        response_status="failed",
        error=last_error or "Unknown OpenRouter error",
    )
    return ""
