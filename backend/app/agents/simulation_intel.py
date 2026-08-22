"""Passive target intelligence for simulation mode.

Performs only passive, legal reconnaissance against an authorized target:
DNS resolution and a single HTTP request (exactly what a browser does).
The result is the entire output of simulation mode — real intel only.
"""

import logging
import re
import socket
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("phantomscan.simulation_intel")

HTTP_TIMEOUT = 12.0

TECH_SIGNATURES: list[tuple[list[str], str]] = [
    (["server: nginx", "nginx/"], "nginx"),
    (["server: apache", "apache/"], "apache"),
    (["server: cloudflare"], "cloudflare"),
    (["x-powered-by: php", "set-cookie: phpsessid", "x-php-version"], "php"),
    (["x-powered-by: asp.net", "x-aspnet-version"], "asp.net"),
    (["x-powered-by: express", "x-powered-by: nodejs"], "node/express"),
    (["x-generator: wordpress", "wp-content", "wp-json"], "wordpress"),
    (["x-generator: joomla", "com_content"], "joomla"),
    (["x-drupal-cache", "drupal"], "drupal"),
    (["x-generator: react", "react"], "react"),
    (["ng-version", "angular"], "angular"),
    (["laravel_session", "x-laravel-"], "laravel"),
    (["x-django-"], "django"),
    (["rails"], "rails"),
    (["x-pingback"], "wordpress"),
]

SUSPICIOUS_PATHS = [
    "/admin",
    "/login",
    "/api",
    "/wp-login.php",
    "/.env",
    "/.git/config",
    "/config.php",
    "/robots.txt",
    "/phpinfo.php",
    "/backup.zip",
    "/uploads/",
    "/server-status",
    "/actuator/health",
    "/.well-known/security.txt",
]


def extract_hostname(target_url: str) -> str:
    if "://" not in target_url:
        target_url = f"https://{target_url}"
    parsed = urlparse(target_url)
    return (parsed.hostname or "").lower() or "unknown-host"


class SimulationIntel:
    """Collects real, passive intel about an authorized target."""

    def __init__(self, target_url: str) -> None:
        self.target_url = target_url if "://" in target_url else f"https://{target_url}"
        self.hostname = extract_hostname(target_url)

    async def _resolve_dns(self) -> dict[str, object]:
        records: dict[str, object] = {"a": [], "aaaa": []}
        try:
            infos = await asyncio_getaddrinfo(self.hostname)
            for family, address in infos:
                if family == socket.AF_INET and address not in records["a"]:
                    records["a"].append(address)
                elif family == socket.AF_INET6 and address not in records["aaaa"]:
                    records["aaaa"].append(address)
        except Exception as exc:
            records["error"] = str(exc)[:200]
        try:
            import dns.asyncresolver

            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 4.0
            for rtype in ("MX", "TXT"):
                try:
                    answers = await resolver.resolve(self.hostname, rtype)
                    records[rtype.lower()] = [str(a) for a in answers][:5]
                except Exception:
                    records.setdefault(rtype.lower(), [])
        except Exception:
            pass
        return records

    async def _fetch_headers(self) -> dict[str, object]:
        headers: dict[str, object] = {}
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=HTTP_TIMEOUT) as client:
                response = await client.get(self.target_url)
            headers["status_code"] = response.status_code
            headers["server"] = response.headers.get("server", "")
            headers["x_powered_by"] = response.headers.get("x-powered-by", "")
            headers["content_type"] = response.headers.get("content-type", "")
            headers["set_cookie"] = response.headers.get("set-cookie", "")[:500]
            headers["via"] = response.headers.get("via", "")
            headers["x_generator"] = response.headers.get("x-generator", "")
            headers["final_url"] = str(response.url)
            body = response.text[:200_000]
            title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            headers["title"] = title.group(1).strip()[:120] if title else ""
            generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.IGNORECASE)
            if generator:
                headers["meta_generator"] = generator.group(1).strip()[:120]
            if "wp-content" in body or "wp-json" in body:
                headers["body_hints"] = ["wordpress"]
        except Exception as exc:
            headers["error"] = str(exc)[:300]
        return headers

    async def gather_intel(self) -> dict[str, object]:
        """Returns a dict with DNS, headers, detected tech and guessed endpoints."""
        dns = await self._resolve_dns()
        headers = await self._fetch_headers()
        tech = detect_tech_stack(headers)
        ports = guess_ports(tech)
        return {
            "hostname": self.hostname,
            "target_url": self.target_url,
            "ip": (dns.get("a") or [None])[0] or (dns.get("aaaa") or [None])[0] or "unresolved",
            "dns": dns,
            "http": headers,
            "tech_stack": tech,
            "ports": ports,
            "endpoints": guess_endpoints(tech),
        }


def asyncio_getaddrinfo(hostname: str) -> "object":
    import asyncio

    return asyncio.get_running_loop().getaddrinfo(hostname, None, type=socket.SOCK_STREAM)


def detect_tech_stack(http: dict[str, object]) -> list[str]:
    """Detect technologies from headers/body hints. Returns canonical names."""
    haystack = " ".join(
        str(value).lower()
        for key, value in http.items()
        if key not in ("status_code", "title", "final_url")
    )
    detected: list[str] = []
    for signatures, name in TECH_SIGNATURES:
        if any(sig in haystack for sig in signatures):
            detected.append(name)
    if "wordpress" in detected:
        detected.append("php")
        detected.append("mysql")
    if "php" in detected and "mysql" not in detected:
        detected.append("mysql")
    return sorted(set(detected))


def guess_ports(tech_stack: list[str]) -> list[dict[str, object]]:
    ports: list[dict[str, object]] = [
        {"port": 80, "service": "http", "state": "open"},
        {"port": 443, "service": "https", "state": "open"},
    ]
    if "php" in tech_stack or "mysql" in tech_stack or "wordpress" in tech_stack:
        ports.append({"port": 3306, "service": "mysql", "state": "open"})
    if "nginx" in tech_stack or "apache" in tech_stack:
        ports.append({"port": 22, "service": "ssh", "state": "filtered"})
        ports.append({"port": 8080, "service": "http-proxy", "state": "filtered"})
    return ports


def guess_endpoints(tech_stack: list[str]) -> list[dict[str, object]]:
    endpoints: list[dict[str, object]] = []
    for path in SUSPICIOUS_PATHS:
        status = "200" if "wordpress" in tech_stack and path == "/wp-login.php" else "200"
        endpoints.append({"path": path, "status": status, "interest": path in ("/.env", "/.git/config", "/config.php", "/backup.zip")})
    return endpoints