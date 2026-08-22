"""Target Complexity Index (TCI).

Scores a target's complexity from 0-100 across four bands (simple, medium,
complex, critical) using recon signals (ports, technology stack, authentication
mechanisms, API surface, WAF/security headers). Two entry points:

- ``analyze_recon`` consumes the scanner's rich output in-scan (no probes).
- ``analyze_live`` performs bounded lightweight probes for pre-scan threat
  modeling from the scan configuration UI.
"""

import asyncio
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.config import get_settings
from app.services.authorization import canonicalize_target
from app.services.execution import SafetyLimits

BAND_SIMPLE = "simple"
BAND_MEDIUM = "medium"
BAND_COMPLEX = "complex"
BAND_CRITICAL = "critical"

BAND_LABELS = {
    BAND_SIMPLE: "Simple (static site, no auth)",
    BAND_MEDIUM: "Medium (dynamic, basic auth)",
    BAND_COMPLEX: "Complex (API, multi-auth)",
    BAND_CRITICAL: "Critical (enterprise, multiple subdomains)",
}

DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
ADMIN_PORTS = {21, 22, 23, 11211, 5601, 8009, 8500, 9090, 3389}
WEB_PORTS = {80, 443, 8080, 8443}
EXTRA_WEB_PORTS = {3000, 5000, 8000, 8081, 8888, 9000}

COMMON_SCAN_PORTS = sorted(
    {21, 22, 23, 80, 443, 3000, 3306, 5432, 6379, 5601, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 11211, 27017}
)

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

WAF_HEADER_HINTS = [
    ("cf-ray", "cloudflare"),
    ("x-amz-cf-id", "cloudfront"),
    ("x-azure-ref", "azure"),
    ("akamai", "akamai"),
    ("x-sucuri-id", "sucuri"),
    ("x-powered-by-anquanbao", "anquanbao"),
    ("x-waf", "generic"),
]

TECH_HEADER_SIGNATURES = [
    ("server", "nginx", "nginx"),
    ("server", "apache", "apache"),
    ("server", "iis", "iis"),
    ("server", "cloudflare", "cloudflare"),
    ("server", "openresty", "openresty"),
    ("server", "gunicorn", "gunicorn"),
    ("server", "uvicorn", "uvicorn"),
    ("x-powered-by", "flask", "flask"),
    ("x-powered-by", "django", "django"),
    ("x-powered-by", "express", "express"),
    ("x-powered-by", "php", "php"),
    ("x-powered-by", "asp.net", "asp.net"),
    ("x-aspnet-version", "asp.net", "asp.net"),
    ("x-drupal-cache", "drupal", "drupal"),
]

TECH_BODY_SIGNATURES = [
    ("django", "django"),
    ("csrftoken", "django"),
    ("wordpress", "wordpress"),
    ("wp-content", "wordpress"),
    ("wp-json", "wordpress"),
    ("laravel", "laravel"),
    ("__laravel_session", "laravel"),
    ("rails", "rails"),
    ("react", "react"),
    ("next.js", "next.js"),
    ("__next", "next.js"),
    ("angular", "angular"),
    ("vue.js", "vue"),
    ("graphql", "graphql"),
    ("spring", "spring"),
]

AUTH_PATH_HINTS = [
    "/login",
    "/signin",
    "/sign-in",
    "/wp-login.php",
    "/admin",
    "/auth",
    "/oauth",
    "/api/auth",
]

AUTH_BODY_HINTS = ["password", "sign in", "log in", "login", "authenticate", "username"]
API_LINK_PATTERN = re.compile(r"/(?:api|graphql|rest|swagger|openapi|v\d+)(?:/|$)", re.IGNORECASE)

FRAMEWORK_HINTS = [
    "django",
    "flask",
    "fastapi",
    "rails",
    "laravel",
    "spring",
    "express",
    "next.js",
    "asp.net",
    "drupal",
    "wordpress",
    "react",
    "angular",
    "vue",
    "graphql",
]


def band_for_score(score: int) -> str:
    if score <= 25:
        return BAND_SIMPLE
    if score <= 50:
        return BAND_MEDIUM
    if score <= 75:
        return BAND_COMPLEX
    return BAND_CRITICAL


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"a", "link", "script", "iframe", "form", "img"}:
            return
        for key, value in attrs:
            if key in {"href", "src", "action"} and value:
                self.links.append(value)


@dataclass
class ProbeResult:
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


class TargetComplexityIndex:
    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        limits: SafetyLimits | None = None,
    ) -> None:
        self.transport = transport
        self.limits = limits or SafetyLimits.from_settings()

    # ------------------------------------------------------------------ scoring

    def analyze(self, signals: dict[str, Any]) -> dict[str, Any]:
        ports = [int(port) for port in (signals.get("ports") or [])]
        web_ports = sorted(set(ports) & WEB_PORTS)
        extra_web = sorted(set(ports) & EXTRA_WEB_PORTS)
        database_ports = sorted(set(ports) & DATABASE_PORTS)
        admin_ports = sorted(set(ports) & ADMIN_PORTS)

        port_points = min(
            20,
            len(web_ports) * 2 + len(extra_web) * 2 + len(database_ports) * 4 + len(admin_ports) * 2,
        )

        tech_stack = list(dict.fromkeys(str(item).lower() for item in (signals.get("tech_stack") or [])))
        framework_matches = [tech for tech in tech_stack if tech in FRAMEWORK_HINTS]
        if framework_matches:
            tech_points = min(15, len(framework_matches) * 4 + (2 if signals.get("versions") else 0))
        else:
            tech_points = 0

        auth_mechanisms = list(dict.fromkeys(str(item).lower() for item in (signals.get("auth_mechanisms") or [])))
        if auth_mechanisms:
            auth_points = 8 + min(12, (len(auth_mechanisms) - 1) * 4)
            if signals.get("has_admin_surface"):
                auth_points = min(20, auth_points + 4)
        else:
            auth_points = 0

        api_endpoints = max(0, int(signals.get("api_endpoints") or 0))
        api_points = min(15, api_endpoints * 2)
        if signals.get("has_graphql"):
            api_points = min(15, api_points + 3)
        if signals.get("has_openapi"):
            api_points = min(15, api_points + 3)

        security_headers = signals.get("security_headers")
        if security_headers is None:
            missing_headers: list[str] = []
            header_points = 0
        else:
            missing_headers = sorted(
                name
                for name in SECURITY_HEADERS
                if not str(security_headers.get(name) or "").strip()
            )
            header_points = min(15, len(missing_headers) * 3)
        waf = bool(signals.get("waf"))
        if waf:
            header_points = max(0, header_points - 3)

        endpoints = max(0, int(signals.get("endpoints") or 0))
        subdomains = max(0, int(signals.get("subdomains") or 0))
        scale_points = min(10, endpoints // 4 + subdomains * 2)

        score = max(0, min(100, port_points + tech_points + auth_points + api_points + header_points + scale_points))
        band = band_for_score(score)
        return {
            "score": score,
            "band": band,
            "band_label": BAND_LABELS[band],
            "breakdown": {
                "ports": {
                    "web_ports": web_ports,
                    "extra_web_ports": extra_web,
                    "database_ports": database_ports,
                    "admin_ports": admin_ports,
                    "points": port_points,
                },
                "tech_stack": {"detected": tech_stack, "points": tech_points},
                "authentication": {"mechanisms": auth_mechanisms, "has_admin_surface": bool(signals.get("has_admin_surface")), "points": auth_points},
                "api_surface": {"endpoints": api_endpoints, "graphql": bool(signals.get("has_graphql")), "openapi": bool(signals.get("has_openapi")), "points": api_points},
                "waf": waf,
                "security_headers": {"present": sorted(name for name in SECURITY_HEADERS if str((security_headers or {}).get(name) or "").strip()), "missing": missing_headers, "points": header_points},
                "scale": {"endpoints": endpoints, "subdomains": subdomains, "points": scale_points},
            },
        }

    # ------------------------------------------------------------- in-scan recon

    def analyze_recon(self, scanner_output: dict[str, Any]) -> dict[str, Any]:
        tech_stack_obj = scanner_output.get("tech_stack") or {}
        technologies = tech_stack_obj.get("technologies") or []
        if isinstance(technologies, str):
            technologies = [technologies]
        server = tech_stack_obj.get("server")
        if server and str(server).lower() not in {str(t).lower() for t in technologies}:
            technologies = [*technologies, str(server)]
        technologies_detailed = scanner_output.get("technologies_detailed") or []
        versions = [
            str(item.get("version"))
            for item in technologies_detailed
            if isinstance(item, dict) and item.get("version")
        ]
        headers = {str(key).lower(): str(value) for key, value in (scanner_output.get("http_headers") or {}).items()}
        open_ports = [int(port) for port in (scanner_output.get("open_ports") or [])]
        endpoints = scanner_output.get("endpoints") or []
        if not endpoints and scanner_output.get("discovered_urls"):
            endpoints = scanner_output["discovered_urls"]
        subdomains = scanner_output.get("subdomains") or []
        signals = {
            "ports": open_ports,
            "tech_stack": technologies,
            "versions": versions,
            "auth_mechanisms": scanner_output.get("auth_mechanisms") or self._detect_auth_from_headers(headers, ""),
            "has_admin_surface": bool(
                any("/admin" in str(path).lower() for path in endpoints)
                or any("admin" in str(item).lower() for item in (scanner_output.get("tech_stack") or {}).get("technologies", []))
            ),
            "api_endpoints": sum(1 for path in endpoints if API_LINK_PATTERN.search(str(path))),
            "has_graphql": any("graphql" in str(item).lower() for item in technologies)
            or any("graphql" in str(path).lower() for path in endpoints),
            "has_openapi": any("openapi" in str(path).lower() or "swagger" in str(path).lower() for path in endpoints),
            "waf": bool(scanner_output.get("waf_detected") or scanner_output.get("cdn_detected")),
            "security_headers": headers,
            "endpoints": len(endpoints),
            "subdomains": len(subdomains),
        }
        return self.analyze(signals)

    # ------------------------------------------------------------- live probes

    async def analyze_live(self, target_url: str) -> dict[str, Any]:
        target = canonicalize_target(target_url)
        is_lab = "/lab/" in target.url
        homepage = await self._fetch(target.url)

        headers = {str(key).lower(): str(value) for key, value in homepage.headers.items()}
        waf = self._detect_waf(headers)
        technologies = self._detect_tech(headers, homepage.body)
        auth_mechanisms = self._detect_auth_from_headers(headers, homepage.body)

        robots_text = ""
        robots_url = urljoin(f"{target.origin}/", "/robots.txt")
        robots = await self._fetch(robots_url)
        if robots.status_code == 200:
            robots_text = robots.body

        links: list[str] = []
        if homepage.status_code == 200 and homepage.body:
            parser = _LinkParser()
            parser.feed(homepage.body[:200_000])
            links = parser.links

        openapi_url = urljoin(f"{target.origin}/", "/openapi.json")
        openapi_probe = await self._fetch(openapi_url)
        has_openapi = openapi_probe.status_code == 200

        if is_lab:
            ports = [80, 443]
        else:
            ports = await self._sweep_ports(target.origin)

        auth_paths_seen: list[str] = []
        if not auth_mechanisms:
            for path in AUTH_PATH_HINTS:
                response = await self._fetch(urljoin(f"{target.origin}/", path))
                if response.status_code in {200, 301, 302, 401, 403}:
                    hint_body = (response.body or "").lower()
                    if response.status_code == 401 or any(hint in hint_body for hint in AUTH_BODY_HINTS):
                        auth_paths_seen.append(path)
                        break

        unique_paths = sorted(
            {
                (urlsplit(urljoin(target.url, link)).path or "/")
                for link in links
            }
        )
        api_endpoints = sum(1 for path in unique_paths if API_LINK_PATTERN.search(path))
        robots_paths = [
            line.strip().split(":", 1)[1].strip()
            for line in robots_text.splitlines()
            if line.strip().lower().startswith(("allow:", "disallow:"))
        ]
        api_endpoints += sum(1 for path in robots_paths if API_LINK_PATTERN.search(path))
        if has_openapi:
            api_endpoints = max(api_endpoints, 1)

        signals = {
            "ports": ports,
            "tech_stack": technologies,
            "versions": [],
            "auth_mechanisms": auth_mechanisms + auth_paths_seen,
            "has_admin_surface": any("/admin" in path for path in unique_paths)
            or any("admin" in path for path in robots_paths)
            or "/admin" in auth_paths_seen,
            "api_endpoints": api_endpoints,
            "has_graphql": any("graphql" in str(item).lower() for item in technologies)
            or any("graphql" in path for path in unique_paths + robots_paths),
            "has_openapi": has_openapi,
            "waf": waf,
            "security_headers": headers,
            "endpoints": len(unique_paths),
            "subdomains": 0,
        }
        return self.analyze(signals)

    async def _fetch(self, url: str) -> ProbeResult:
        timeout = min(6.0, max(1.0, self.limits.max_scan_duration / 4))
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
                headers={"User-Agent": "PhantomScan-TCI/1.0"},
            ) as client:
                response = await client.get(url)
                return ProbeResult(
                    status_code=response.status_code,
                    headers={str(key).lower(): str(value) for key, value in response.headers.items()},
                    body=response.text[: min(self.limits.max_response_size, 200_000)],
                )
        except httpx.HTTPError:
            return ProbeResult()

    async def _sweep_ports(self, origin: str) -> list[int]:
        hostname = urlsplit(origin).hostname or ""
        semaphore = asyncio.Semaphore(10)

        async def check(port: int) -> int | None:
            async with semaphore:
                try:
                    reader, _writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port), timeout=1.2
                    )
                    _writer.close()
                    return port
                except (OSError, asyncio.TimeoutError, ValueError):
                    return None

        results = await asyncio.gather(*(check(port) for port in COMMON_SCAN_PORTS))
        return sorted(port for port in results if port is not None)

    @staticmethod
    def _detect_waf(headers: dict[str, str]) -> bool:
        server = headers.get("server", "")
        if "cloudflare" in server.lower():
            return True
        for header, _name in WAF_HEADER_HINTS:
            if header in headers:
                return True
        return False

    @staticmethod
    def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
        detected: list[str] = []
        for header_name, needle, tech in TECH_HEADER_SIGNATURES:
            value = str(headers.get(header_name) or "").lower()
            if needle in value:
                detected.append(tech)
        body_lower = (body or "").lower()
        for needle, tech in TECH_BODY_SIGNATURES:
            if needle in body_lower and tech not in detected:
                detected.append(tech)
        return list(dict.fromkeys(detected))

    @staticmethod
    def _detect_auth_from_headers(headers: dict[str, str], body: str) -> list[str]:
        mechanisms: list[str] = []
        www_auth = str(headers.get("www-authenticate") or "").lower()
        if www_auth:
            if "basic" in www_auth:
                mechanisms.append("basic")
            if "bearer" in www_auth or "token" in www_auth:
                mechanisms.append("bearer/token")
            if "digest" in www_auth:
                mechanisms.append("digest")
        body_lower = (body or "").lower()
        if any(hint in body_lower for hint in ("csrftoken", "django admin", "__laravel_session")):
            mechanisms.append("session-cookie")
        if "oauth" in body_lower:
            mechanisms.append("oauth")
        return list(dict.fromkeys(mechanisms))
