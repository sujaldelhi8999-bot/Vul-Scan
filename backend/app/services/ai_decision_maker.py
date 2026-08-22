"""AI Decision Maker: context-aware module selection for active scans.

Learns from Strix's TCI/ScanPlanner direction: perform lightweight
reconnaissance on the target (technologies, headers, frameworks), let an
LLM threat-model the fingerprint, and return a prioritized module plan.
Recommendations are cached per target for one hour.

Fallback contract: ``recommend_modules`` returns ``[]`` whenever the LLM is
unavailable, unconfigured, or returns something unusable - callers then run
their existing (full) module set.
"""

import asyncio
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

from app.config import get_settings
from app.services.active_security import CANONICAL_MODULES, normalize_modules
from app.services.authorization import canonicalize_target
from app.services.openrouter_client import call_openrouter

logger = logging.getLogger("phantomscan.ai_decision")

DEFAULT_CACHE_TTL_SECONDS = 3600.0
DEFAULT_MAX_MODULES = 10
MAX_CACHE_ENTRIES = 256
MAX_RECON_BODY_BYTES = 200_000
RECON_TIMEOUT_SECONDS = 8.0

MODULE_DESCRIPTIONS = {
    "input_security": "Client-side input handling, DOM sinks and user-supplied value flows",
    "injection": "Generic injection vectors across parameters (SQL, NoSQL, LDAP, XPath, OS)",
    "xss": "Cross-site scripting: reflected, stored and DOM-based payloads",
    "auth_session": "Authentication and session management: login flows, cookies, session fixation",
    "access_control": "Broken access control: IDOR, privilege escalation, forced browsing",
    "csrf": "Cross-site request forgery on state-changing endpoints",
    "file_upload": "Unrestricted file upload and content-type bypasses",
    "path_handling": "Path traversal and file-handling abuse",
    "api_security": "REST/API surface: mass assignment, verb tampering, schema exposure",
    "graphql": "GraphQL introspection, batching and nested-query abuse",
    "websocket": "WebSocket endpoint authentication and message-level flaws",
    "jwt": "JWT algorithm confusion, weak secrets and claims tampering",
    "redirect": "Open redirect and header-injection redirects",
    "cors": "Permissive CORS policies and origin reflection",
    "security_headers": "Missing or misconfigured security headers (CSP, HSTS, X-Frame-Options)",
    "tls_https": "TLS configuration, protocol/cipher weaknesses, certificate issues",
    "sensitive_exposure": "Exposed secrets, source maps, backup files and debug endpoints",
    "business_logic": "Workflow bypass, race conditions and transactional flaws",
    "rate_limiting": "Missing rate limiting, credential stuffing and brute-force resistance",
    "command_injection": "OS command injection through parameters and headers",
    "ssti": "Server-side template injection (Jinja2, Twig, Velocity, etc.)",
    "xxe": "XML external entity injection through XML parsers",
    "ssrf": "Server-side request forgery to internal resources",
    "dependency_security": "Known vulnerable dependencies and CVE exposure",
    "info_disclosure": "Information disclosure via errors, headers and verbose responses",
}

_TECH_HEADER_SIGNATURES = [
    ("nginx", ("server", "nginx")),
    ("apache", ("server", "apache")),
    ("iis", ("server", "iis")),
    ("cloudflare", ("server", "cloudflare")),
    ("openresty", ("server", "openresty")),
    ("php", ("x-powered-by", "php")),
    ("asp.net", ("x-powered-by", "asp.net")),
    ("express", ("x-powered-by", "express")),
    ("gunicorn", ("server", "gunicorn")),
    ("uvicorn", ("server", "uvicorn")),
]

_TECH_BODY_SIGNATURES = [
    ("wordpress", "wp-content"),
    ("wordpress", "wp-includes"),
    ("laravel", "laravel_session"),
    ("laravel", "xsrf-token"),
    ("django", "csrftoken"),
    ("django", "django"),
    ("flask", "flask"),
    ("next.js", "__next_data__"),
    ("next.js", "_next/static"),
    ("react", "react"),
    ("vue.js", "__nuxt__"),
    ("vue.js", "vue"),
    ("angular", "ng-version"),
    ("spring", "spring"),
    ("graphql", "graphql"),
    ("websocket", "websocket"),
    ("php", "php"),
    ("asp.net", "viewstate"),
]

_HINT_BODY_SIGNATURES = [
    ("login_form", "password"),
    ("login_form", "type=\"password\""),
    ("api_surface", "\"/api/"),
    ("api_surface", "'/api/"),
    ("oauth", "oauth"),
    ("jwt", "authorization: bearer"),
    ("graphql", "graphql"),
    ("file_upload", "type=\"file\""),
    ("websocket", "websocket"),
]


class AIDecisionMaker:
    """Recommends a prioritized active-testing module list for a target.

    The recommendation is cached per canonical target URL for one hour;
    cache hits skip both recon and the LLM call.
    """

    def __init__(
        self,
        *,
        llm: Callable[..., Any] | None = None,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        max_modules: int | None = None,
        timeout: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        settings = get_settings()
        self._llm = llm
        self._cache_ttl_seconds = float(cache_ttl_seconds)
        configured_cap = settings.ai_max_modules if max_modules is None else max_modules
        self._max_modules = int(configured_cap) if configured_cap and int(configured_cap) > 0 else DEFAULT_MAX_MODULES
        self._timeout = float(timeout)
        self._transport = transport
        self._cache: dict[str, tuple[float, list[str]]] = {}
        self._lock = asyncio.Lock()

    async def recommend_modules(
        self,
        target_url: str,
        recon: dict[str, Any] | None = None,
        *,
        scan_id: int | None = None,
        manual_selection: list[str] | None = None,
    ) -> list[str]:
        """Return a prioritized module list, or ``[]`` to fall back to all modules.

        ``recon``: optional pre-collected fingerprint (scanner output) to
        avoid duplicate HTTP work. ``manual_selection``: user-chosen modules
        are always kept; AI picks fill remaining capacity.
        """
        target = canonicalize_target(target_url)
        key = target.url

        cached = await self._cached(key)
        if cached is not None:
            logger.info("AI decision cache hit for %s (%d modules)", key, len(cached))
            return self._apply_manual(cached, manual_selection)

        fingerprint = recon if recon else await self._light_recon(target.url)
        try:
            content = await self._ask_llm(target.url, fingerprint, scan_id=scan_id)
        except Exception as exc:
            logger.warning("AI decision LLM call failed for %s: %s", key, exc)
            return []
        modules = self._parse(content)
        if modules is None:
            logger.info("AI decision unavailable for %s; caller falls back to full module set", key)
            return []

        result = self._apply_manual(modules, manual_selection)
        if result:
            await self._store(key, result)
            logger.info("AI decision for %s: %d modules %s", key, len(result), result[:12])
        return result

    def clear_cache(self) -> None:
        self._cache.clear()

    def cached_targets(self) -> list[str]:
        return list(self._cache)

    async def _cached(self, key: str) -> list[str] | None:
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            expires_at, modules = entry
            if expires_at <= time.monotonic():
                self._cache.pop(key, None)
                return None
            return modules

    async def _store(self, key: str, modules: list[str]) -> None:
        async with self._lock:
            self._cache[key] = (time.monotonic() + self._cache_ttl_seconds, list(modules))
            if len(self._cache) > MAX_CACHE_ENTRIES:
                oldest_key = next(iter(self._cache))
                self._cache.pop(oldest_key, None)

    def _apply_manual(
        self,
        recommended: list[str],
        manual_selection: list[str] | None,
    ) -> list[str]:
        manual = normalize_modules(manual_selection)
        if not manual:
            return list(recommended[: self._max_modules])
        extras = recommended[: max(0, self._max_modules - len(manual))]
        for module in extras:
            if module not in manual:
                manual.append(module)
        return manual

    async def _ask_llm(
        self,
        target_url: str,
        fingerprint: dict[str, Any],
        *,
        scan_id: int | None = None,
    ) -> str:
        catalog = [
            {"module": module, "description": MODULE_DESCRIPTIONS.get(module, "")}
            for module in CANONICAL_MODULES
        ]
        user_prompt = json.dumps(
            {
                "target": target_url,
                "fingerprint": fingerprint,
                "module_catalog": catalog,
                "max_modules": self._max_modules,
            },
            ensure_ascii=False,
            default=str,
        )
        system_prompt = (
            "You are PhantomScan's AI Decision Maker. Analyze the target fingerprint "
            "and select the most likely applicable security testing modules. Choose "
            "modules whose attack surface is suggested by the observed technologies, "
            "headers, and behavior. Prefer fewer, higher-confidence modules over "
            "spraying everything. Respond ONLY with JSON in this exact shape: "
            '{"modules": ["module_name", ...], "rationale": "one sentence"}. '
            "Use only module names from the catalog. Omit modules with no evident "
            "attack surface. Empty modules list is acceptable when nothing applies."
        )
        if self._llm is not None:
            response = await self._llm(user_prompt, system_prompt, scan_id=scan_id)
            return str(response or "")
        return await call_openrouter(
            user_prompt,
            system_prompt,
            max_tokens=400,
            timeout=self._timeout,
            retry_limit=1,
            scan_id=scan_id,
            json_response=True,
        )

    @staticmethod
    def _parse(content: str) -> list[str] | None:
        """Parse the LLM response into normalized modules.

        Returns None when the response is unusable (empty, malformed, or
        missing the modules key) so callers fall back to the full set.
        """
        if not content or not content.strip():
            return None
        payload: Any = None
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            stripped = content.strip()
            start = stripped.find("{")
            end = stripped.rfind("}")
            if start < 0 or end < start:
                return None
            try:
                payload = json.loads(stripped[start : end + 1])
            except json.JSONDecodeError:
                return None
        if not isinstance(payload, dict):
            return None
        modules = payload.get("modules")
        if not isinstance(modules, list):
            return None
        names: list[str] = []
        for item in modules:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                name = item.get("module") or item.get("name")
                if isinstance(name, str):
                    names.append(name)
        return normalize_modules(names)

    async def _light_recon(self, target_url: str) -> dict[str, Any]:
        """Minimal fingerprint: homepage headers + body tech/hint sniffing."""
        try:
            async with httpx.AsyncClient(
                timeout=RECON_TIMEOUT_SECONDS,
                follow_redirects=True,
                transport=self._transport,
                headers={
                    "User-Agent": "PhantomScan-DecisionMaker/1.0",
                    "Accept": "text/html,application/json,application/xml",
                },
            ) as client:
                response = await client.get(target_url)
                status = response.status_code
                raw_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
                body = ""
                try:
                    body = response.text[:MAX_RECON_BODY_BYTES]
                except Exception:
                    body = ""
        except Exception as exc:
            logger.warning("AI decision light recon failed for %s: %s", target_url, exc)
            return {
                "url": target_url,
                "status": None,
                "headers": {},
                "technologies": [],
                "hints": [],
                "error": str(exc)[:200],
            }

        relevant_headers = {
            name: raw_headers[name]
            for name in ("server", "x-powered-by", "x-aspnet-version", "via", "set-cookie")
            if name in raw_headers
        }
        technologies: list[str] = []
        for tech, (header_name, needle) in _TECH_HEADER_SIGNATURES:
            header_value = raw_headers.get(header_name, "")
            if needle in header_value.lower() and tech not in technologies:
                technologies.append(tech)
        body_lower = body.lower()
        for tech, needle in _TECH_BODY_SIGNATURES:
            if needle in body_lower and tech not in technologies:
                technologies.append(tech)
        hints: list[str] = []
        for hint, needle in _HINT_BODY_SIGNATURES:
            if needle in body_lower and hint not in hints:
                hints.append(hint)
        title = ""
        title_match_start = body_lower.find("<title>")
        if title_match_start >= 0:
            title_end = body.find("</title>", title_match_start)
            if title_end > title_match_start:
                title = body[title_match_start + 7 : title_end].strip()[:200]
        return {
            "url": target_url,
            "status": status,
            "headers": relevant_headers,
            "technologies": technologies,
            "hints": hints,
            "title": title,
            "body_snippet_length": len(body),
        }
