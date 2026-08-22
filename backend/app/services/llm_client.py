"""Multi-provider LLM client via LiteLLM.

Falls back to the existing OpenRouter client when LiteLLM is unavailable or
the configured provider fails.  Configure via env vars:

    LLM_PROVIDER  – e.g. "openai", "anthropic", "gemini", "openrouter" (default: openrouter)
    LLM_MODEL     – model override, e.g. "gpt-4o" (default: per-provider default)
    LLM_API_KEY   – API key for the chosen provider (falls back to OPENROUTER_API_KEY)
"""

import logging
from typing import Any

from app.config import get_settings

logger = logging.getLogger("phantomscan.llm_client")


async def call_llm(
    prompt: str,
    system_prompt: str = "",
    *,
    model: str | None = None,
    max_tokens: int = 500,
    json_response: bool = False,
    scan_id: int | None = None,
) -> str:
    """Call an LLM via LiteLLM, falling back to call_openrouter on failure."""
    settings = get_settings()
    provider = getattr(settings, "llm_provider", "openrouter")
    llm_model = model or getattr(settings, "llm_model", "") or settings.openrouter_model
    api_key = getattr(settings, "llm_api_key", "") or settings.openrouter_api_key

    if not api_key:
        logger.debug("No LLM API key configured, skipping")
        return ""

    try:
        import litellm
        litellm.drop_params = True

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await litellm.acompletion(
            model=f"{provider}/{llm_model}" if "/" not in llm_model else llm_model,
            messages=messages,
            max_tokens=max_tokens,
            api_key=api_key,
            temperature=0.3,
        )
        content = response.choices[0].message.content or ""
        if json_response:
            return content.strip()
        return content.strip()
    except ImportError:
        logger.debug("LiteLLM not installed, falling back to call_openrouter")
    except Exception as exc:
        logger.warning("LiteLLM call failed (%s/%s): %s", provider, llm_model, exc)

    from app.services.openrouter_client import call_openrouter
    return await call_openrouter(
        prompt, system_prompt,
        model=model, max_tokens=max_tokens,
        scan_id=scan_id, json_response=json_response,
    )
