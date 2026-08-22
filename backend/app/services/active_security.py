import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from app.config import get_settings
from app.database import add_audit_log, create_evidence_record, update_evidence_finding
from app.security import build_finding, redact_sensitive, redact_url
from app.services.active_gate import ActiveTargetGate
from app.services.authorization import TargetAuthorizationService, canonicalize_target
from app.services.execution import ExecutionBudget, ExecutionLimitError, SafetyLimits, ScanCancelled
from app.services.tci import TargetComplexityIndex, band_for_score

logger = logging.getLogger("phantomscan.active_security")

CANONICAL_MODULES = [
    "input_security",
    "injection",
    "xss",
    "auth_session",
    "access_control",
    "csrf",
    "file_upload",
    "path_handling",
    "api_security",
    "graphql",
    "websocket",
    "jwt",
    "redirect",
    "cors",
    "security_headers",
    "tls_https",
    "sensitive_exposure",
    "business_logic",
    "rate_limiting",
    "command_injection",
    "ssti",
    "xxe",
    "ssrf",
    "dependency_security",
    "info_disclosure",
]

MODULE_ALIASES = {
    "authentication": "auth_session",
    "authorization": "access_control",
    "rate_limits": "rate_limiting",
    "session_security": "auth_session",
    "websockets": "websocket",
    "redirect_security": "redirect",
    "security_headers_cors": "security_headers",
    "sensitive": "sensitive_exposure",
    "tls": "tls_https",
    "https": "tls_https",
    "sql_injection": "injection",
    "xss_reflection": "xss",
    "path_traversal": "path_handling",
    "jwt_attacks": "jwt",
    "command_injection": "command_injection",
    "ssti": "ssti",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "dependency_security": "dependency_security",
    "info_disclosure": "info_disclosure",
    "file_upload": "file_upload",
    "open_redirect": "redirect",
    "rate_limiting": "rate_limiting",
    "business_logic": "business_logic",
    "access_control": "access_control",
    "api_security": "api_security",
    "sensitive_exposure": "sensitive_exposure",
    "cors": "cors",
    "security_headers": "security_headers",
    "tls_https": "tls_https",
    "websocket": "websocket",
    "graphql": "graphql",
    "jwt": "jwt",
    "auth_session": "auth_session",
    "csrf": "csrf",
}

FetchCallable = Callable[[str, str, str, dict[str, str] | None, dict[str, Any] | None], Awaitable[dict[str, Any]]]


def normalize_module(module: str) -> str:
    normalized = module.strip().lower().replace("-", "_")
    return MODULE_ALIASES.get(normalized, normalized)


def normalize_modules(modules: list[str] | None) -> list[str]:
    selected: list[str] = []
    for module in modules or []:
        normalized = normalize_module(str(module))
        if normalized in CANONICAL_MODULES and normalized not in selected:
            selected.append(normalized)
    return selected


# Module priority tiers for TCI-driven planning
MODULE_PRIORITY = {
    # Tier 1: Always run (high confidence, low risk)
    "security_headers": 1,
    "cors": 1,
    "tls_https": 1,
    "info_disclosure": 1,
    # Tier 2: High priority - auth/access control
    "auth_session": 2,
    "access_control": 2,
    "csrf": 2,
    "jwt": 2,
    # Tier 3: Injection/XSS - medium risk, high value
    "injection": 3,
    "xss": 3,
    "input_security": 3,
    # Tier 4: SSRF/XXE/SSTI - higher risk, targeted
    "ssrf": 4,
    "xxe": 4,
    "ssti": 4,
    # Tier 5: Specialized - run based on surface hints
    "command_injection": 5,
    "file_upload": 5,
    "path_handling": 5,
    "rate_limiting": 5,
    "redirect": 5,
    "graphql": 5,
    "websocket": 5,
    "api_security": 5,
    "dependency_security": 5,
    "sensitive_exposure": 5,
    "business_logic": 5,
}

# Safe mode hints per module (TCI-driven)
MODULE_SAFE_MODE = {
    "injection": True,
    "xss": True,
    "input_security": True,
    "command_injection": True,
    "file_upload": True,
    "path_handling": True,
    "ssrf": True,
    "xxe": True,
    "ssti": True,
    "auth_session": False,
    "access_control": False,
    "csrf": False,
    "jwt": False,
    "rate_limiting": False,
    "security_headers": False,
    "cors": False,
    "tls_https": False,
    "dependency_security": False,
    "info_disclosure": False,
    "redirect": False,
    "graphql": False,
    "websocket": False,
    "api_security": False,
    "sensitive_exposure": False,
    "business_logic": False,
}


def compute_tci_from_attack_surface(attack_surface: dict[str, Any]) -> dict[str, Any]:
    """
    Compute Target Complexity Index (0-100) from attack surface data.
    
    Uses the same signals as TargetComplexityIndex.analyze() but derives them
    from the AttackSurfaceMapper output instead of live probes.
    """
    surfaces = attack_surface.get("surfaces", [])
    
    # Extract signals from surfaces
    ports = set()
    tech_stack = set()
    auth_mechanisms = set()
    has_admin_surface = False
    api_endpoints = 0
    has_graphql = False
    has_openapi = False
    waf = False
    security_headers = {}
    endpoints = set()
    subdomains = set()
    
    for surface in surfaces:
        if not isinstance(surface, dict):
            continue
            
        # Track endpoints
        path = surface.get("path") or surface.get("url", "")
        if path:
            endpoints.add(path)
            if "/admin" in path.lower():
                has_admin_surface = True
            if "graphql" in path.lower():
                has_graphql = True
            if "openapi" in path.lower() or "swagger" in path.lower():
                has_openapi = True
        
        # Extract module hints as tech indicators
        for hint in surface.get("module_hints", []):
            if hint in {"auth_session", "jwt"}:
                auth_mechanisms.add(hint)
            if hint in {"api_security", "graphql", "websocket"}:
                api_endpoints += 1
    
    # Derive from target URL and surface characteristics
    target_url = attack_surface.get("target_url", "")
    if target_url:
        parsed = urlsplit(target_url)
        # Add web ports
        if parsed.scheme == "https":
            ports.add(443)
        elif parsed.scheme == "http":
            ports.add(80)
        
        # Check for common web ports in URL
        if ":" in parsed.netloc:
            try:
                port = int(parsed.netloc.split(":")[-1])
                ports.add(port)
            except ValueError:
                pass
    
    # Build signals dict for TCI analysis
    signals = {
        "ports": sorted(ports),
        "tech_stack": sorted(tech_stack) if tech_stack else [],
        "versions": [],
        "auth_mechanisms": sorted(auth_mechanisms),
        "has_admin_surface": has_admin_surface,
        "api_endpoints": api_endpoints,
        "has_graphql": has_graphql,
        "has_openapi": has_openapi,
        "waf": waf,
        "security_headers": security_headers,
        "endpoints": len(endpoints),
        "subdomains": len(subdomains),
    }
    
    # Use TCI analyzer
    tci = TargetComplexityIndex()
    return tci.analyze(signals)


@dataclass(frozen=True)
class PlannedModule:
    module: str
    surfaces: list[dict[str, Any]]


@dataclass(frozen=True)
class WorkflowRules:
    business_logic_tests: list[dict[str, Any]]

    @classmethod
    def from_payload(cls, payload: dict[str, Any] | None) -> "WorkflowRules":
        rules = payload or {}
        business_logic_tests = rules.get("business_logic_tests", [])
        if not isinstance(business_logic_tests, list):
            business_logic_tests = []
        return cls(business_logic_tests=[item for item in business_logic_tests if isinstance(item, dict)])


class SurfaceHTMLParser(HTMLParser):
    def __init__(self, target_url: str) -> None:
        super().__init__()
        self.target_url = target_url
        self.forms: list[dict[str, Any]] = []
        self.links: list[dict[str, Any]] = []
        self.websocket_refs: list[str] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        if tag == "form":
            action = values.get("action") or self.target_url
            method = (values.get("method") or "GET").upper()
            self._current_form = {
                "id": f"form_{len(self.forms) + 1}",
                "type": "form",
                "method": method,
                "path": action,
                "url": urljoin(self.target_url, action),
                "parameters": [],
                "module_hints": self.hints_for_url(action),
                "description": "HTML form discovered on target page.",
            }
        elif tag == "input" and self._current_form is not None:
            name = values.get("name")
            input_type = values.get("type", "text").lower()
            if name:
                self._current_form["parameters"].append(name)
            if input_type == "file" and "file_upload" not in self._current_form["module_hints"]:
                self._current_form["module_hints"].append("file_upload")
        elif tag in {"a", "script"}:
            href = values.get("href") or values.get("src")
            if href:
                absolute = urljoin(self.target_url, href)
                if absolute.startswith("ws://") or absolute.startswith("wss://"):
                    self.websocket_refs.append(absolute)
                else:
                    self.links.append(
                        {
                            "id": f"link_{len(self.links) + 1}",
                            "type": "link",
                            "method": "GET",
                            "path": urlsplit(absolute).path or "/",
                            "url": absolute,
                            "parameters": [name for name, _ in parse_qsl(urlsplit(absolute).query, keep_blank_values=True)],
                            "module_hints": self.hints_for_url(absolute),
                            "description": "Link discovered on target page.",
                        }
                    )

    def handle_data(self, data: str) -> None:
        for match in re.findall(r"wss?://[^\s'\"<>]+", data):
            self.websocket_refs.append(match)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self._current_form["module_hints"] = self.hints_for_parameters(
                self._current_form["parameters"],
                self._current_form["module_hints"],
            )
            self.forms.append(self._current_form)
            self._current_form = None

    @staticmethod
    def hints_for_url(url: str) -> list[str]:
        parsed = urlsplit(url)
        path = parsed.path.lower()
        params = [name.lower() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        hints: list[str] = []
        if any(name in params for name in ["q", "query", "search", "name", "message"]):
            hints.extend(["input_security", "xss", "injection"])
        if any(name in params for name in ["url", "next", "redirect", "return_to"]):
            hints.append("redirect")
        if any(name in params for name in ["file", "path", "download"]):
            hints.append("path_handling")
        if "login" in path or "signin" in path:
            hints.append("auth_session")
        if "admin" in path:
            hints.append("access_control")
        if "graphql" in path:
            hints.append("graphql")
        if "/api/" in path:
            hints.append("api_security")
        return list(dict.fromkeys(hints))

    @staticmethod
    def hints_for_parameters(parameters: list[str], existing: list[str]) -> list[str]:
        hints = list(existing)
        names = {name.lower() for name in parameters}
        if names & {"q", "query", "search", "name", "message", "display_name"}:
            hints.extend(["input_security", "xss", "injection"])
        if names & {"username", "password", "email"}:
            hints.append("auth_session")
        if names & {"csrf", "csrf_token", "xsrf", "authenticity_token"}:
            hints.append("csrf")
        if names & {"amount", "from_account", "to_account", "quantity"}:
            hints.extend(["csrf", "business_logic"])
        if names & {"file", "path", "filename"}:
            hints.extend(["file_upload", "path_handling"])
        return list(dict.fromkeys(hints))


class AttackSurfaceMapper:
    def __init__(
        self,
        *,
        fetch: FetchCallable | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        limits: SafetyLimits | None = None,
    ) -> None:
        self.fetch = fetch
        self.transport = transport
        self.limits = limits or SafetyLimits.from_settings()

    async def map(self, target_url: str) -> dict[str, Any]:
        target = canonicalize_target(target_url)
        if target.url.rstrip("/").endswith("/lab/phantombank") or "/lab/phantombank/" in target.url:
            manifest_url = urljoin(f"{target.origin}/", "/lab/phantombank/manifest")
            manifest_response = await self.fetch_url("mapper", "GET", manifest_url)
            if manifest_response.get("status_code") == 200:
                try:
                    data = json.loads(str(manifest_response.get("raw_body") or manifest_response.get("body") or "{}"))
                except json.JSONDecodeError:
                    data = {}
                if isinstance(data, dict) and isinstance(data.get("surfaces"), list):
                    return {
                        "target_url": target.url,
                        "target_origin": target.origin,
                        "source": "lab_manifest",
                        "surfaces": data["surfaces"],
                        "manifest": data,
                    }

        response = await self.fetch_url("mapper", "GET", target.url)
        surfaces = self.root_surfaces(target.url)
        if response.get("status_code") == 200:
            parser = SurfaceHTMLParser(target.url)
            parser.feed(str(response.get("body") or ""))
            surfaces.extend(parser.forms)
            surfaces.extend(parser.links)
            for index, websocket_url in enumerate(parser.websocket_refs, start=1):
                surfaces.append(
                    {
                        "id": f"websocket_ref_{index}",
                        "type": "websocket",
                        "method": "WEBSOCKET",
                        "url": websocket_url,
                        "path": urlsplit(websocket_url).path or "/",
                        "parameters": [],
                        "module_hints": ["websocket"],
                        "auth_required": None,
                        "description": "WebSocket reference discovered in page content.",
                    }
                )
        parsed = urlsplit(target.url)
        query_params = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        if query_params:
            surfaces.append(
                {
                    "id": "target_query",
                    "type": "query",
                    "method": "GET",
                    "path": parsed.path or "/",
                    "url": target.url,
                    "parameters": query_params,
                    "module_hints": SurfaceHTMLParser.hints_for_parameters(query_params, ["input_security", "xss", "injection"]),
                    "description": "Query parameters from the target URL.",
                }
            )
        return {
            "target_url": target.url,
            "target_origin": target.origin,
            "source": "html_conservative",
            "surfaces": self.dedupe_surfaces(surfaces),
        }

    async def fetch_url(
        self,
        module: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.fetch is not None:
            return await self.fetch(module, method, url, headers, json_body)
        timeout = min(8.0, max(1.0, self.limits.max_scan_duration / 4))
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
                headers={"User-Agent": "PhantomScan-Active-Mapper/1.0"},
            ) as client:
                response = await client.request(method, url, headers=headers, json=json_body)
                return {
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "raw_body": response.text[: self.limits.max_response_size],
                    "body": redact_sensitive(response.text, self.limits.max_response_size),
                    "truncated": len(response.content) > self.limits.max_response_size,
                }
        except httpx.HTTPError as exc:
            return {"url": url, "status_code": None, "headers": {}, "body": "", "error": str(exc), "truncated": False}

    @staticmethod
    def root_surfaces(target_url: str) -> list[dict[str, Any]]:
        parsed = urlsplit(target_url)
        return [
            {
                "id": "root_page",
                "type": "page",
                "method": "GET",
                "path": parsed.path or "/",
                "url": target_url,
                "parameters": [],
                "module_hints": ["security_headers", "cors", "tls_https"],
                "description": "Target landing page.",
            }
        ]

    @staticmethod
    def dedupe_surfaces(surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str]] = set()
        unique: list[dict[str, Any]] = []
        for surface in surfaces:
            key = (str(surface.get("method", "GET")), str(surface.get("url") or surface.get("path")), ",".join(surface.get("parameters") or []))
            if key in seen:
                continue
            seen.add(key)
            unique.append(surface)
        return unique


class SecurityTestPlanner:
    def create_plan(self, attack_surface: dict[str, Any], selected_modules: list[str] | None = None) -> dict[str, Any]:
        surfaces = [surface for surface in attack_surface.get("surfaces", []) if isinstance(surface, dict)]
        selected = normalize_modules(selected_modules)
        relevant_modules = selected or self.modules_from_surfaces(surfaces)
        
        # Compute TCI from attack surface
        tci = compute_tci_from_attack_surface(attack_surface)
        tci_score = tci.get("score", 0)
        tci_band = tci.get("band", "simple")
        
        # Determine which priority tiers to include based on TCI
        # Higher TCI = more thorough testing (include more tiers)
        if tci_score >= 75:  # Critical/Complex
            max_priority_tier = 5  # All modules
        elif tci_score >= 50:  # Medium
            max_priority_tier = 4  # Up to tier 4
        elif tci_score >= 25:  # Simple
            max_priority_tier = 3  # Up to tier 3
        else:  # Very simple
            max_priority_tier = 2  # Only tier 1-2
        
        # Filter modules by priority tier
        if not selected:  # Only auto-filter if not explicitly selected
            filtered_modules = [
                m for m in relevant_modules 
                if MODULE_PRIORITY.get(m, 5) <= max_priority_tier
            ]
        else:
            filtered_modules = relevant_modules
        
        modules: list[dict[str, Any]] = []
        for module in filtered_modules:
            module_surfaces = self.surfaces_for_module(surfaces, module)
            if module_surfaces:
                modules.append({
                    "module": module, 
                    "surfaces": module_surfaces,
                    "priority": MODULE_PRIORITY.get(module, 5),
                    "safe_mode": MODULE_SAFE_MODE.get(module, False),
                })
        
        return {
            "target_url": attack_surface.get("target_url"),
            "source": attack_surface.get("source", "unknown"),
            "selected_modules": filtered_modules,
            "modules": modules,
            "surface_count": len(surfaces),
            "tci": {
                "score": tci_score,
                "band": tci_band,
                "band_label": tci.get("band_label", ""),
                "breakdown": tci.get("breakdown", {}),
            },
            "planner_config": {
                "max_priority_tier": max_priority_tier,
                "auto_filtered": not selected,
            },
        }

    def create_verification_plan(
        self,
        *,
        attack_surface: dict[str, Any],
        browser_evidence: dict[str, Any] | None = None,
        network_evidence: list[dict[str, Any]] | None = None,
        javascript_evidence: list[dict[str, Any]] | None = None,
        target_technology: dict[str, Any] | None = None,
        authorization: dict[str, Any] | None = None,
        previous_findings: list[dict[str, Any]] | None = None,
        selected_modules: list[str] | None = None,
    ) -> dict[str, Any]:
        surfaces = [surface for surface in attack_surface.get("surfaces", []) if isinstance(surface, dict)]
        surfaces.extend(self.surfaces_from_network(network_evidence or []))
        surfaces.extend(self.surfaces_from_browser(browser_evidence or {}))
        surfaces = AttackSurfaceMapper.dedupe_surfaces(surfaces)
        enriched_surface = {**attack_surface, "surfaces": surfaces}
        plan = self.create_plan(enriched_surface, selected_modules)
        evidence_notes: list[dict[str, Any]] = []
        modules = {item["module"]: item for item in plan["modules"]}
        for finding in previous_findings or []:
            module = normalize_module(str(finding.get("module") or ""))
            if module in CANONICAL_MODULES and module in modules:
                evidence_notes.append({"module": module, "reason": "previous finding consistency", "finding": finding.get("title")})
        for js in javascript_evidence or []:
            sinks = js.get("sink_classifications") or []
            if sinks and "xss" in modules:
                evidence_notes.append({"module": "xss", "reason": "client-side rendering sinks", "sinks": sinks})
        for event in network_evidence or []:
            classification = str(event.get("classification") or "")
            if classification == "AUTH" and "auth_session" in modules:
                evidence_notes.append({"module": "auth_session", "reason": "browser-observed authentication endpoint", "endpoint": event.get("url")})
            if classification == "GRAPHQL" and "graphql" in modules:
                evidence_notes.append({"module": "graphql", "reason": "browser-observed GraphQL traffic", "endpoint": event.get("url")})
        plan["planner_version"] = "2.0"
        plan["evidence_notes"] = evidence_notes
        plan["authorization"] = authorization or {}
        plan["target_technology"] = target_technology or {}
        return plan

    @staticmethod
    def surfaces_from_network(network_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        surfaces = []
        for index, event in enumerate(network_events, start=1):
            classification = str(event.get("classification") or "")
            if classification not in {"API", "AUTH", "GRAPHQL", "WEBSOCKET"}:
                continue
            url = str(event.get("url") or "")
            parsed = urlsplit(url)
            hints = ["api_security"]
            if classification == "AUTH":
                hints.extend(["auth_session", "jwt"])
            if classification == "GRAPHQL":
                hints.append("graphql")
            if classification == "WEBSOCKET":
                hints = ["websocket"]
            surfaces.append(
                {
                    "id": f"observed_network_{index}",
                    "type": classification.lower(),
                    "method": event.get("method") or "GET",
                    "path": parsed.path or "/",
                    "url": url,
                    "parameters": [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)],
                    "module_hints": list(dict.fromkeys(hints)),
                    "description": "Endpoint observed from browser network traffic.",
                }
            )
        return surfaces

    @staticmethod
    def surfaces_from_browser(browser_evidence: dict[str, Any]) -> list[dict[str, Any]]:
        surfaces = []
        for index, dom in enumerate(browser_evidence.get("dom", []) if isinstance(browser_evidence, dict) else [], start=1):
            for form_index, form in enumerate(dom.get("forms", []), start=1):
                names = [str(item.get("name")) for item in form.get("inputs", []) if item.get("name")]
                hints = SurfaceHTMLParser.hints_for_parameters(names, [])
                surfaces.append(
                    {
                        "id": f"observed_form_{index}_{form_index}",
                        "type": "form",
                        "method": form.get("method") or "GET",
                        "path": urlsplit(str(form.get("action") or "/")).path or "/",
                        "url": form.get("action"),
                        "parameters": names,
                        "module_hints": hints,
                        "description": "Form observed from browser DOM extraction.",
                    }
                )
        return surfaces

    @staticmethod
    def modules_from_surfaces(surfaces: list[dict[str, Any]]) -> list[str]:
        modules: list[str] = []
        for surface in surfaces:
            for hint in surface.get("module_hints") or []:
                module = normalize_module(str(hint))
                if module in CANONICAL_MODULES and module not in modules:
                    modules.append(module)
        return modules

    @staticmethod
    def surfaces_for_module(surfaces: list[dict[str, Any]], module: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for surface in surfaces:
            hints = {normalize_module(str(hint)) for hint in surface.get("module_hints") or []}
            if module in hints:
                matches.append(surface)
        return matches


class ActiveTargetClient:
    def __init__(
        self,
        *,
        scan_id: int,
        user_id: str,
        target_url: str,
        sandbox_id: str,
        authorization_context: dict[str, Any],
        budget: ExecutionBudget,
        authorization_service: TargetAuthorizationService | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        emit_event: Any = None,
        job_id: str | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.user_id = user_id
        self.target = canonicalize_target(target_url)
        self.sandbox_id = sandbox_id
        self.authorization_context = authorization_context
        self.authorization_service = authorization_service or TargetAuthorizationService()
        self.budget = budget
        self.transport = transport
        self.emit_event = emit_event
        self.job_id = job_id

    async def request(
        self,
        module: str,
        method: str,
        url_or_path: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        *,
        surface: str = "",
        safe_test_marker: str = "",
    ) -> dict[str, Any]:
        self.budget.check()
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            raise ExecutionLimitError(f"HTTP method {method} is not allowed by the active-test engine")
        url = urljoin(f"{self.target.origin}/", url_or_path) if url_or_path.startswith("/") else url_or_path
        candidate = canonicalize_target(url)
        if candidate.origin != self.target.origin:
            raise ExecutionLimitError("Active requests cannot leave the admitted target origin")
        if self.authorization_context.get("authorization_status") == "VERIFIED":
            authorization_id = self.authorization_context.get("authorization_id")
            await self.authorization_service.require_verified(candidate.url, self.user_id, int(authorization_id))
        request_id = uuid.uuid4().hex[:16]
        request_number = await self.budget.reserve_request()
        safe_headers_summary = {k: "[REDACTED]" if k.lower() in {"authorization", "cookie", "x-api-key", "set-cookie"} else v for k, v in (headers or {}).items()}
        body_shape = None
        if json_body:
            body_shape = f"{len(json_body)} keys: {', '.join(list(json_body.keys())[:8])}" if isinstance(json_body, dict) else "non-dict body"
        start_ts = datetime.now(timezone.utc).isoformat()
        await add_audit_log(
            self.scan_id,
            "Active Security Engine",
            "active_request",
            f"{method} {redact_url(candidate.url)}",
            user_id=self.user_id,
            target=self.target.origin,
            authorization_status=str(self.authorization_context.get("authorization_status") or "UNKNOWN"),
            selected_module=module,
            request_count=request_number,
            sandbox_id=self.sandbox_id,
        )
        request_path = urlsplit(candidate.url).path or "/"
        if self.emit_event:
            await self.emit_event(
                "TEST_REQUEST_SENT",
                f"{method} {request_path}",
                module=module,
                status="SENT",
                metadata={
                    "request_id": request_id,
                    "method": method,
                    "route": request_path,
                    "safe_headers": safe_headers_summary,
                    "body_shape": body_shape,
                    "content_type": (headers or {}).get("Content-Type") or (headers or {}).get("content-type"),
                },
            )
        timeout = min(8.0, max(1.0, self.budget.limits.max_scan_duration / 4))
        evidence = {
            "request_id": request_id,
            "job_id": self.job_id,
            "scan_id": self.scan_id,
            "module": module,
            "surface": surface,
            "method": method,
            "request_url": candidate.url,
            "safe_test_marker": safe_test_marker,
            "request_timestamp": start_ts,
            "response_status": None,
            "response_time_ms": None,
            "response_observed": False,
            "detection_result": "INCONCLUSIVE",
            "evidence_summary": "",
            "finding_id": None,
            "error": None,
        }
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
                headers={"User-Agent": "PhantomScan-ActiveSecurity/1.0"},
            ) as client:
                async with client.stream(method, candidate.url, headers=headers, json=json_body) as response:
                    body = bytearray()
                    truncated = False
                    async for chunk in response.aiter_bytes():
                        remaining = self.budget.limits.max_response_size - len(body)
                        if remaining <= 0:
                            truncated = True
                            break
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break
                    decoded = body.decode(response.encoding or "utf-8", errors="replace")
                    end_ts = datetime.now(timezone.utc).isoformat()
                    duration_ms = round((datetime.now(timezone.utc) - datetime.fromisoformat(start_ts)).total_seconds() * 1000)
                    safe_resp_headers = {k: "[REDACTED]" if k.lower() in {"set-cookie", "authorization"} else v for k, v in response.headers.items()}
                    resp_summary = decoded[:300] if decoded else ""
                    evidence["response_status"] = response.status_code
                    evidence["response_time_ms"] = duration_ms
                    evidence["response_observed"] = True
                    if self.emit_event:
                        await self.emit_event(
                            "RESPONSE_RECEIVED",
                            f"HTTP {response.status_code} from {request_path}",
                            module=module,
                            status=str(response.status_code),
                            metadata={
                                "request_id": request_id,
                                "method": method,
                                "route": request_path,
                                "status_code": response.status_code,
                                "response_headers": safe_resp_headers,
                                "response_summary": resp_summary,
                                "truncated": truncated,
                                "duration_ms": duration_ms,
                            },
                        )
                    ev_result = {
                        "url": candidate.url,
                        "status_code": response.status_code,
                        "headers": {key.lower(): value for key, value in response.headers.items()},
                        "raw_body": decoded,
                        "body": redact_sensitive(decoded, self.budget.limits.max_response_size),
                        "truncated": truncated,
                        "_request_id": request_id,
                        "_evidence": evidence,
                    }
                    evidence_id = await create_evidence_record(evidence)
                    ev_result["_evidence_id"] = evidence_id
                    return ev_result
        except httpx.HTTPError as exc:
            error_msg = str(exc)[:500]
            evidence["error"] = error_msg
            if self.emit_event:
                await self.emit_event(
                    "RESPONSE_RECEIVED",
                    f"HTTP error for {request_path}: {str(exc)[:100]}",
                    module=module,
                    status="ERROR",
                    metadata={
                        "request_id": request_id,
                        "method": method,
                        "route": request_path,
                        "error": str(exc)[:300],
                    },
                )
            evidence_id = await create_evidence_record(evidence)
            return {
                "url": candidate.url,
                "status_code": None,
                "headers": {},
                "body": "",
                "error": str(exc),
                "truncated": False,
                "_request_id": request_id,
                "_evidence": evidence,
                "_evidence_id": evidence_id,
            }


class ActiveSecurityEngine:
    def __init__(
        self,
        *,
        target_url: str,
        attack_surface: dict[str, Any] | None,
        selected_modules: list[str],
        limits: SafetyLimits,
        authorization_context: dict[str, Any],
        workflow_rules: dict[str, Any] | None,
        scan_id: int,
        user_id: str,
        sandbox_id: str,
        budget: ExecutionBudget | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        emit_event: Any = None,
        job_id: str | None = None,
    ) -> None:
        self.target = canonicalize_target(target_url)
        self.attack_surface = attack_surface or {}
        self.selected_modules = normalize_modules(selected_modules)
        self.limits = limits
        self.authorization_context = authorization_context
        self.workflow_rules = WorkflowRules.from_payload(workflow_rules)
        self.scan_id = scan_id
        self.user_id = user_id
        self.sandbox_id = sandbox_id
        self.budget = budget or ExecutionBudget(limits)
        self.emit_event = emit_event
        self.client = ActiveTargetClient(
            scan_id=scan_id,
            user_id=user_id,
            target_url=target_url,
            sandbox_id=sandbox_id,
            authorization_context=authorization_context,
            budget=self.budget,
            transport=transport,
            emit_event=emit_event,
            job_id=job_id,
        )
        self.mapper = AttackSurfaceMapper(fetch=self.client.request, transport=transport, limits=limits)
        self.planner = SecurityTestPlanner()
        self.events: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.timed_out_modules: list[str] = []
        self.module_timeout = get_settings().module_timeout

    async def run(self) -> dict[str, Any]:
        await self.emit("test_started", f"Active security test started for {self.target.url}")
        status = "complete"
        error: str | None = None
        try:
            if not self.attack_surface.get("surfaces"):
                self.attack_surface = await self.mapper.map(self.target.url)
            plan = self.planner.create_plan(self.attack_surface, self.selected_modules)
            await self.emit("plan_created", f"Planned {len(plan['modules'])} active modules", result=json.dumps(self.plan_summary(plan)))
            for index, module_plan in enumerate(plan["modules"], start=1):
                module = str(module_plan["module"])
                await self.emit("module_started", module, selected_module=module)
                module_findings = await self.run_module(module, module_plan["surfaces"])
                for finding in module_findings:
                    self.findings.append(finding)
                    await self.emit("finding_created", finding["title"], selected_module=module, result=finding["severity"])
                progress = int(10 + (index / max(1, len(plan["modules"]))) * 85)
                was_timeout = module in self.timed_out_modules
                status_label = f"{module}: {len(module_findings)} findings" + (" (TIMEOUT)" if was_timeout else "")
                await self.emit("module_completed", status_label, selected_module=module)
                await self.emit("progress", f"Active security progress {progress}%", selected_module=module, request_count=self.budget.request_count)
            await self.emit("test_completed", f"Active security test completed with {len(self.findings)} findings")
        except ScanCancelled as exc:
            status = "cancelled"
            error = str(exc)
            await self.emit("test_cancelled", error)
        except ExecutionLimitError as exc:
            status = "limited"
            error = str(exc)
            await self.emit("test_failed", error)
        except Exception as exc:
            status = "error"
            error = str(exc)
            await self.emit("test_failed", error[:2000])
        report = self.final_report(status, error)
        return {
            "status": status,
            "target_url": self.target.url,
            "attack_surface": self.attack_surface,
            "test_plan": self.planner.create_plan(self.attack_surface, self.selected_modules),
            "events": self.events,
            "evidence": self.safe_evidence(),
            "findings": self.findings,
            "final_report": report,
            "score": score_findings(self.findings, len(self.attack_surface.get("surfaces", []))),
            "request_count": self.budget.request_count,
            "sandbox_id": self.sandbox_id,
            "timed_out_modules": self.timed_out_modules,
        }

    async def run_module(self, module: str, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        handlers = {
            "input_security": self.check_input_security,
            "injection": self.check_injection,
            "xss": self.check_xss,
            "auth_session": self.check_auth_session,
            "access_control": self.check_access_control,
            "csrf": self.check_csrf,
            "file_upload": self.check_file_upload,
            "path_handling": self.check_path_handling,
            "api_security": self.check_api_security,
            "graphql": self.check_graphql,
            "websocket": self.check_websocket,
            "jwt": self.check_jwt,
            "redirect": self.check_redirect,
            "cors": self.check_cors,
            "security_headers": self.check_security_headers,
            "tls_https": self.check_tls_https,
            "sensitive_exposure": self.check_sensitive_exposure,
            "business_logic": self.check_business_logic,
            "rate_limiting": self.check_rate_limiting,
            "command_injection": self.check_command_injection,
            "ssti": self.check_ssti,
            "xxe": self.check_xxe,
            "ssrf": self.check_ssrf,
            "dependency_security": self.check_dependency_security,
            "info_disclosure": self.check_info_disclosure,
        }
        handler = handlers.get(module)
        if handler is None:
            return []
        await self.emit("check_started", f"{module} checks started", selected_module=module)
        try:
            results = await asyncio.wait_for(handler(surfaces[:3]), timeout=self.module_timeout)
        except asyncio.TimeoutError:
            logger.warning("Module %s timed out after %ds", module, self.module_timeout)
            await self.emit("module_timeout", f"{module} timed out after {self.module_timeout}s", selected_module=module)
            self.timed_out_modules.append(module)
            return []
        for surface in surfaces[:3]:
            await self.emit("surface_tested", str(surface.get("id") or surface.get("path") or module), selected_module=module)
        for finding in results:
            if self.emit_event:
                await self.emit_event(
                    "SECURITY_CONTROL_EVALUATED",
                    f"Control evaluated for {module}: {finding.get('severity', 'INFO')} - {finding.get('title', 'No title')[:100]}",
                    module=module,
                    status=finding.get("severity", "INFO"),
                    metadata={
                        "finding_title": finding.get("title"),
                        "severity": finding.get("severity"),
                        "confidence": finding.get("confidence"),
                        "endpoint": finding.get("endpoint"),
                    },
                )
        return results

    async def check_input_security(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            sid = str(surface.get("id", ""))
            if str(surface.get("method", "GET")).upper() == "POST":
                response = await self.client.request(
                    "input_security",
                    "POST",
                    self.surface_target(surface),
                    json_body={"display_name": "PHANTOMSCAN_INPUT_PROBE", "age": "not-a-number"},
                    surface=sid,
                    safe_test_marker="PHANTOMSCAN_INPUT_PROBE",
                )
            else:
                response = await self.client.request(
                    "input_security", "GET", self.with_parameter(surface, "q", "PHANTOMSCAN_INPUT_PROBE"),
                    surface=sid,
                    safe_test_marker="PHANTOMSCAN_INPUT_PROBE",
                )
            body = str(response.get("body", "")).lower()
            if response.get("status_code") == 200 and "accepted invalid input" in body:
                findings.append(
                    self.make_finding(
                        "Input validation accepted a controlled invalid value",
                        "Input Security",
                        "MEDIUM",
                        "HIGH",
                        "input_security",
                        surface,
                        response,
                        "A harmless invalid marker was accepted or reflected without normalization.",
                        "Invalid or unexpected input can reach business logic and downstream interpreters.",
                        "Validate types, lengths, and allowed values at the server boundary and encode reflected values.",
                        "Rerun the input-security check and confirm invalid markers are rejected or normalized.",
                    )
                )
        return findings

    async def check_injection(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            parameter = self.first_parameter(surface, "customer")
            response = await self.client.request(
                "injection", "GET", self.with_parameter(surface, parameter, "PHANTOMSCAN_DATA_PROBE"),
                surface=str(surface.get("id", "")),
                safe_test_marker="PHANTOMSCAN_DATA_PROBE",
            )
            body = str(response.get("body", "")).lower()
            if response.get("status_code") and int(response["status_code"]) >= 500 and any(token in body for token in ["data layer error", "sql", "sqlite", "odbc"]):
                findings.append(
                    self.make_finding(
                        "Controlled data-layer probe caused an error response",
                        "Data-Layer Handling",
                        "HIGH",
                        "HIGH",
                        "injection",
                        surface,
                        response,
                        "A benign data-layer marker produced a server error indicator.",
                        "Untrusted input may be reaching query construction or interpreter boundaries unsafely.",
                        "Use parameterized data access APIs, strict allowlists, and uniform error handling.",
                        "Repeat the controlled data-layer probe and confirm no interpreter error or marker-specific behavior occurs.",
                        parameter=parameter,
                    )
                )
        return findings

    async def check_xss(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        marker = '<span data-phantomscan-probe="1">probe</span>'
        for surface in surfaces:
            response = await self.client.request(
                "xss", "GET", self.with_parameter(surface, self.first_parameter(surface, "q"), marker),
                surface=str(surface.get("id", "")),
                safe_test_marker="PHANTOMSCAN_XSS_PROBE",
            )
            if marker.lower() in str(response.get("body", "")).lower():
                findings.append(
                    self.make_finding(
                        "HTML-like input marker reflected without encoding",
                        "Output Encoding",
                        "MEDIUM",
                        "HIGH",
                        "xss",
                        surface,
                        response,
                        "A harmless HTML-like marker was returned as markup instead of encoded text.",
                        "Executable markup could run in a browser if attacker-controlled input reaches the same context.",
                        "Apply context-aware output encoding and deploy a restrictive Content Security Policy.",
                        "Rerun the output-encoding check and confirm the marker is HTML-encoded.",
                    )
                )
        return findings

    async def check_auth_session(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            response = await self.client.request(
                "auth_session", "GET", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="auth_session_probe",
            )
            headers = response.get("headers", {})
            if self.is_login_surface(surface) and response.get("status_code") in {200, 401, 403} and not self.has_rate_limit_headers(headers):
                findings.append(
                    self.make_finding(
                        "Authentication surface lacks visible throttling signals",
                        "Authentication and Session",
                        "LOW",
                        "POTENTIAL",
                        "auth_session",
                        surface,
                        response,
                        "No standard rate-limit headers were observed on the authentication surface.",
                        "Sensitive endpoints without throttling may permit automated guessing or abuse.",
                        "Add per-account and per-source throttling with monitoring and documented limits.",
                        "Repeat a conservative request sequence and confirm 429 responses or rate-limit headers appear.",
                    )
                )
            cookie = str(headers.get("set-cookie", "")).lower()
            if cookie and ("httponly" not in cookie or "samesite" not in cookie or "secure" not in cookie):
                findings.append(
                    self.make_finding(
                        "Session cookie missing hardened attributes",
                        "Authentication and Session",
                        "MEDIUM",
                        "HIGH",
                        "auth_session",
                        surface,
                        response,
                        "A session-like cookie was set without all expected security attributes.",
                        "Client-side script access or cross-site request contexts may expose sessions.",
                        "Set HttpOnly, Secure, and SameSite attributes on session cookies.",
                        "Repeat login and inspect Set-Cookie attributes.",
                    )
                )
        return findings

    async def check_access_control(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            response = await self.client.request(
                "access_control", "GET", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="access_control_probe",
            )
            body = str(response.get("body", "")).lower()
            if response.get("status_code") == 200 and ("fake admin data" in body or "admin demo" in body or "users" in body):
                findings.append(
                    self.make_finding(
                        "Unauthenticated request reached an admin data surface",
                        "Access Control",
                        "HIGH",
                        "CONFIRMED",
                        "access_control",
                        surface,
                        response,
                        "A no-credential request returned fake admin-user data from the lab surface.",
                        "Missing server-side authorization can expose privileged functions or tenant data.",
                        "Enforce authentication, role checks, and object-level authorization on every privileged API.",
                        "Repeat the no-credential request and confirm HTTP 401 or 403.",
                    )
                )
        return findings

    async def check_csrf(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            page = "/lab/phantombank/transfer" if str(surface.get("path", "")).startswith("/lab/phantombank") else self.target.url
            response = await self.client.request(
                "csrf", "GET", page,
                surface=str(surface.get("id", "")),
                safe_test_marker="csrf_probe",
            )
            body = str(response.get("body", "")).lower()
            if "<form" in body and "method=\"post\"" in body and not any(token in body for token in ["csrf", "xsrf", "authenticity_token"]):
                findings.append(
                    self.make_finding(
                        "State-changing form lacks an anti-CSRF token",
                        "CSRF",
                        "MEDIUM",
                        "MEDIUM",
                        "csrf",
                        surface,
                        response,
                        "A POST form was observed without a recognizable anti-CSRF token field.",
                        "A cross-origin page may submit authenticated state-changing requests.",
                        "Require a server-validated anti-CSRF token and review SameSite cookie policy.",
                        "Submit the workflow without a token and confirm the server rejects it.",
                    )
                )
        return findings

    async def check_file_upload(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            sid = str(surface.get("id", ""))
            upload_url = self.surface_target(surface)
            get_response = await self.client.request(
                "file_upload", "GET", upload_url,
                surface=sid,
                safe_test_marker="file_upload_get",
            )
            body = str(get_response.get("body", "")).lower()
            if "type=\"file\"" not in body:
                continue
            upload_post_url = urljoin(upload_url, "/lab/phantombank/upload") if "/upload" not in upload_url else upload_url
            post_response = await self.client.request(
                "file_upload", "POST", upload_post_url,
                json_body={"filename": "PHANTOMSCAN_TEST_FILE.txt", "content": "harmless test content"},
                surface=sid,
                safe_test_marker="PHANTOMSCAN_TEST_FILE.txt",
            )
            post_body = str(post_response.get("body", "")).lower()
            post_status = post_response.get("status_code")
            if surface.get("vulnerable") and post_status == 200 and "stored_as" in post_body:
                findings.append(
                    self.make_finding(
                        "File upload accepted a test filename without validation",
                        "File Upload Security",
                        "MEDIUM",
                        "HIGH",
                        "file_upload",
                        surface,
                        post_response,
                        "A harmless test filename was accepted by the upload endpoint.",
                        "Weak filename, type, and storage controls can expose uploaded content or overwrite paths.",
                        "Validate type and extension, rename files, store outside the web root, and isolate processing.",
                        "Use benign fixtures to confirm unsafe filenames and content types are rejected.",
                        evidence_records=[post_response.get("_evidence_id"), get_response.get("_evidence_id")],
                    )
                )
        return findings

    async def check_path_handling(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            response = await self.client.request(
                "path_handling", "GET", self.with_parameter(surface, "file", "../private/demo-statement.txt"),
                surface=str(surface.get("id", "")),
                safe_test_marker="../private/demo-statement.txt",
            )
            if response.get("status_code") == 200 and "phantombank internal demo statement" in str(response.get("body", "")).lower():
                findings.append(
                    self.make_finding(
                        "Path handling probe returned internal demo content",
                        "Path Handling",
                        "HIGH",
                        "CONFIRMED",
                        "path_handling",
                        surface,
                        response,
                        "A controlled path probe returned the hardcoded internal demo statement marker.",
                        "User-controlled paths may read unintended application-managed content.",
                        "Resolve paths against a fixed base directory and reject traversal or absolute path input.",
                        "Repeat the controlled path probe and confirm it is rejected without content disclosure.",
                        parameter="file",
                    )
                )
        return findings

    async def check_api_security(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            response = await self.client.request(
                "api_security", "OPTIONS", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="api_options_probe",
            )
            allow = str(response.get("headers", {}).get("allow", "")).upper()
            dangerous = sorted({method for method in ["PUT", "DELETE", "PATCH", "TRACE"] if method in allow})
            if dangerous:
                findings.append(
                    self.make_finding(
                        "API advertises unnecessary sensitive HTTP methods",
                        "API Security",
                        "MEDIUM",
                        "MEDIUM",
                        "api_security",
                        surface,
                        response,
                        f"The Allow header advertises sensitive methods: {', '.join(dangerous)}.",
                        "Unneeded methods increase the reachable attack surface and authorization burden.",
                        "Disable unused methods and enforce authentication and authorization for state-changing routes.",
                        "Repeat OPTIONS and verify only required methods are advertised.",
                    )
                )
        return findings

    async def check_graphql(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            response = await self.client.request(
                "graphql",
                "POST",
                self.surface_target(surface),
                json_body={"query": "query PhantomScanIntrospection { __schema { queryType { name } } }"},
                surface=str(surface.get("id", "")),
                safe_test_marker="graphql_introspection_probe",
            )
            if response.get("status_code") == 200 and "__schema" in str(response.get("body", "")):
                findings.append(
                    self.make_finding(
                        "GraphQL schema introspection is exposed",
                        "GraphQL Security",
                        "LOW",
                        "HIGH",
                        "graphql",
                        surface,
                        response,
                        "The endpoint returned schema introspection data to an unauthenticated lab request.",
                        "Schema discovery can reveal operations and types that simplify targeted abuse.",
                        "Restrict introspection where practical and enforce authorization inside every resolver.",
                        "Repeat the introspection query without credentials and confirm it is rejected or limited.",
                    )
                )
        return findings

    async def check_websocket(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            sid = str(surface.get("id", ""))
            ws_url = str(surface.get("url") or surface.get("path") or "")
            http_url = ws_url.replace("ws://", "http://").replace("wss://", "https://")
            response = await self.client.request(
                "websocket", "GET", http_url,
                surface=sid,
                safe_test_marker="websocket_http_probe",
            )
            status = response.get("status_code")
            body_lower = str(response.get("body", "")).lower()
            if status == 426:
                continue
            auth_required = surface.get("auth_required")
            vulnerable = surface.get("vulnerable", True)
            if auth_required is False and vulnerable and status in (200, 404, 405):
                findings.append(
                    self.make_finding(
                        "WebSocket channel reachable via HTTP endpoint without visible auth",
                        "WebSocket Security",
                        "LOW",
                        "MEDIUM",
                        "websocket",
                        surface,
                        response,
                        f"HTTP probe of WebSocket surface returned HTTP {status} without authentication.",
                        "Unauthenticated real-time channels may expose events or permit message abuse.",
                        "Require authenticated handshakes, validate Origin, and authorize every message.",
                        "Attempt an unauthenticated handshake and confirm it is rejected before messages are exchanged.",
                        evidence_records=[response.get("_evidence_id")],
                    )
                )
        return findings

    async def check_jwt(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            response = await self.client.request(
                "jwt", "GET", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="jwt_probe",
            )
            body = str(response.get("body", ""))
            lowered = body.lower()
            if '"alg":"none"' in lowered.replace(" ", "") or "localstorage" in lowered or re.search(r"eyJ[A-Za-z0-9_-]{8,}", body):
                findings.append(
                    self.make_finding(
                        "Token configuration is exposed or weak in response content",
                        "JWT and Token Security",
                        "MEDIUM",
                        "HIGH",
                        "jwt",
                        surface,
                        response,
                        "A token-shaped value or weak token configuration was observed in response content; token text was masked.",
                        "Tokens in script-readable content or weak algorithms can enable session theft or forgery.",
                        "Use HttpOnly cookies where appropriate and enforce issuer, audience, algorithm, expiry, and rotation.",
                        "Confirm tokens are absent from page content and decoded test tokens have approved claims and algorithms.",
                    )
                )
        return findings

    async def check_redirect(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            parameter = self.first_parameter(surface, "next")
            response = await self.client.request(
                "redirect", "GET", self.with_parameter(surface, parameter, "https://example.invalid/phantomscan"),
                surface=str(surface.get("id", "")),
                safe_test_marker="https://example.invalid/phantomscan",
            )
            location = str(response.get("headers", {}).get("location", ""))
            if response.get("status_code") in {301, 302, 303, 307, 308} and location.startswith("https://example.invalid"):
                findings.append(
                    self.make_finding(
                        "External redirect destination is accepted",
                        "Redirect Security",
                        "MEDIUM",
                        "CONFIRMED",
                        "redirect",
                        surface,
                        response,
                        f"The server redirected to an unapproved external destination: {location}.",
                        "Trusted links can be abused for phishing or authentication-flow manipulation.",
                        "Use relative redirects or a strict allowlist and bind redirect state to the authenticated flow.",
                        "Repeat with an unapproved external destination and confirm it is rejected or normalized.",
                        parameter=parameter,
                    )
                )
        return findings

    async def check_cors(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            response = await self.client.request(
                "cors", "GET", self.surface_target(surface), headers={"Origin": "https://attacker.invalid"},
                surface=str(surface.get("id", "")),
                safe_test_marker="cors_origin_probe",
            )
            headers = response.get("headers", {})
            acao = str(headers.get("access-control-allow-origin", ""))
            acac = str(headers.get("access-control-allow-credentials", "")).lower()
            if acao == "*" or (acao == "https://attacker.invalid" and acac == "true"):
                findings.append(
                    self.make_finding(
                        "CORS policy trusts an unapproved origin",
                        "CORS",
                        "MEDIUM",
                        "HIGH",
                        "cors",
                        surface,
                        response,
                        "A request with an untrusted Origin received a permissive CORS response.",
                        "Browser clients may expose authenticated API responses to unauthorized origins.",
                        "Return CORS headers only for explicit trusted origins and avoid wildcard credentials.",
                        "Repeat with an untrusted Origin and confirm no permissive CORS headers are returned.",
                    )
                )
        return findings

    async def check_security_headers(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            response = await self.client.request(
                "security_headers", "GET", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="security_headers_probe",
            )
            headers = response.get("headers", {})
            missing = [
                name
                for name in ["content-security-policy", "x-content-type-options", "referrer-policy"]
                if name not in headers
            ]
            has_frame_control = "x-frame-options" in headers or "frame-ancestors" in str(headers.get("content-security-policy", ""))
            if not has_frame_control:
                missing.append("frame-ancestors/x-frame-options")
            if len(missing) >= 2:
                findings.append(
                    self.make_finding(
                        "Important browser security headers are missing",
                        "Security Headers",
                        "LOW",
                        "MEDIUM",
                        "security_headers",
                        surface,
                        response,
                        f"Missing or incomplete headers: {', '.join(missing)}.",
                        "Missing browser controls can increase impact from content injection, clickjacking, or data leakage.",
                        "Set a restrictive CSP, X-Content-Type-Options, Referrer-Policy, and frame protection.",
                        "Repeat the header check and confirm required headers are present on HTML responses.",
                    )
                )
        return findings

    async def check_tls_https(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        parsed = urlsplit(self.target.url)
        hostname = parsed.hostname or ""
        origin_is_http = parsed.scheme == "http"
        is_lab_target = ActiveTargetGate.is_builtin_lab_target(self.target.url) or ActiveTargetGate.is_loopback_host(hostname)
        surface = surfaces[0] if surfaces else {"id": "root", "url": self.target.url, "path": parsed.path or "/", "parameters": []}
        sid = str(surface.get("id", "root"))
        response_observed = False
        status = None
        ev_id = None
        if not is_lab_target:
            https_url = self.target.url.replace("http://", "https://", 1)
            response = await self.client.request(
                "tls_https", "GET", https_url,
                surface=sid,
                safe_test_marker="tls_https_probe",
            )
            status = response.get("status_code")
            response_observed = status is not None
            ev_id = response.get("_evidence_id")
            if response_observed and status < 500:
                return []
        lab_vulnerable = any(surface.get("vulnerable") for surface in surfaces) and self.authorization_context.get("authorization_status") == "TRAINING"
        external_http = origin_is_http and not is_lab_target and not response_observed
        if lab_vulnerable or external_http:
            fake_resp = {"url": self.target.url, "status_code": None, "headers": {}, "body": "", "_evidence_id": ev_id}
            return [
                self.make_finding(
                    "HTTPS transport enforcement is not demonstrated",
                    "TLS and HTTPS",
                    "LOW",
                    "MEDIUM" if external_http else "POTENTIAL",
                    "tls_https",
                    surface,
                    fake_resp,
                    f"HTTPS check: scheme={parsed.scheme}. "
                    f"{'Lab marks scenario as vulnerable.' if lab_vulnerable else 'External HTTP target could not be reached via HTTPS.'}",
                    "Credentials and session data should not be sent over cleartext transport outside local training.",
                    "Serve production targets over HTTPS and deploy HSTS after confirming all subresources use HTTPS.",
                    "Repeat the scan using the HTTPS origin and confirm HSTS is present where applicable.",
                    evidence_records=[ev_id] if ev_id else None,
                )
            ]
        return []

    async def check_sensitive_exposure(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            response = await self.client.request(
                "sensitive_exposure", "GET", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="sensitive_exposure_probe",
            )
            body = str(response.get("body", "")).lower()
            if response.get("status_code") == 200 and any(token in body for token in ["api_key", "debug", "demo_key"]):
                findings.append(
                    self.make_finding(
                        "Diagnostic endpoint exposes sensitive-looking demo data",
                        "Sensitive Exposure",
                        "MEDIUM",
                        "HIGH",
                        "sensitive_exposure",
                        surface,
                        response,
                        "A diagnostic endpoint returned debug metadata and a fake key-like value; captured values were masked.",
                        "Real debug or secret material in responses can aid account takeover or infrastructure abuse.",
                        "Disable diagnostics in production and remove secrets from responses, logs, and client-visible config.",
                        "Repeat the endpoint request and confirm debug metadata and key-like values are absent.",
                    )
                )
        return findings

    async def check_business_logic(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for rule in self.workflow_rules.business_logic_tests:
            path = str(rule.get("path", "/"))
            method = str(rule.get("method", "GET"))
            expected_status = int(rule.get("expected_status", 200))
            response = await self.client.request(
                "business_logic", method, path,
                surface="workflow_rule",
                safe_test_marker=f"business_logic_{rule.get('name', 'rule')}",
            )
            if response.get("status_code") != expected_status:
                findings.append(
                    self.make_finding(
                        f"Unexpected workflow response: {rule.get('name', 'business rule')}",
                        "Business Logic",
                        "MEDIUM",
                        "HIGH",
                        "business_logic",
                        {"url": path, "path": path, "parameters": []},
                        response,
                        f"Expected HTTP {expected_status}, received {response.get('status_code')}.",
                        "An invalid state transition or trust-boundary assumption may be accepted.",
                        "Enforce workflow state and authorization server-side and add a regression test for the rule.",
                        f"Repeat {method} {path} and confirm HTTP {expected_status}.",
                    )
                )
        for surface in surfaces:
            response = await self.client.request(
                "business_logic",
                "POST",
                self.surface_target(surface),
                json_body={"from_account": "alice", "to_account": "bob", "amount": -10},
                surface=str(surface.get("id", "")),
                safe_test_marker="negative_amount_probe",
            )
            body = str(response.get("body", "")).lower()
            if response.get("status_code") == 200 and "accepted" in body and "invalid amount" in body:
                findings.append(
                    self.make_finding(
                        "Transfer workflow accepted an invalid amount",
                        "Business Logic",
                        "HIGH",
                        "CONFIRMED",
                        "business_logic",
                        surface,
                        response,
                        "A controlled transfer request with an invalid amount was accepted by the demo workflow.",
                        "Invalid state transitions can alter balances or bypass intended business rules.",
                        "Validate amount, account ownership, balance, and workflow state on the server.",
                        "Repeat the invalid transfer request and confirm it is rejected with HTTP 400 or 403.",
                        parameter="amount",
                    )
                )
        return findings

    async def check_rate_limiting(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            try:
                rate_limit_payload = "PHANTOMSCAN_RATE_LIMIT_TEST_1"
                response = await self.client.request(
                    "rate_limiting", "GET", self.with_parameter(surface, "user", rate_limit_payload),
                    surface=str(surface.get("id", "")),
                    safe_test_marker="rate_limiting_probe",
                )
                headers = response.get("headers", {})
                status = response.get("status_code")
                body = str(response.get("body", "")).lower()

                rate_limit_indicators = []
                if status == 429:
                    rate_limit_indicators.append("HTTP 429")
                if "retry-after" in headers:
                    rate_limit_indicators.append("Retry-After")
                if "x-ratelimit-limit" in headers:
                    rate_limit_indicators.append("RateLimit-Limit")
                if "x-ratelimit-remaining" in headers:
                    rate_limit_indicators.append("RateLimit-Remaining")

                if rate_limit_indicators:
                    findings.append(
                        self.make_finding(
                            "Rate limiting is implemented",
                            "Rate Limiting",
                            "MEDIUM",
                            "CONFIRMED",
                            "rate_limiting",
                            surface,
                            response,
                            f"Rate limiting indicators: {', '.join(rate_limit_indicators)}",
                            "Rate limiting prevents brute force and DoS attacks.",
                            "Implement rate limiting per account and per source with documented limits.",
                            "Repeat the request rapidly and confirm rate limiting triggers.",
                        )
                    )
                elif status in {200, 401, 403}:
                    findings.append(
                        self.make_finding(
                            "Rate limiting appears not implemented",
                            "Rate Limiting",
                            "MEDIUM",
                            "HIGH",
                            "rate_limiting",
                            surface,
                            response,
                            "No rate limiting headers observed and no 429 responses.",
                            "Brute force attacks on login/authentication endpoints are possible.",
                            "Implement rate limiting (e.g., 5 attempts per minute, account lockout after X failures).",
                            "Repeat the rate limiting test and confirm rate limiting triggers.",
                        )
                    )
            except Exception as exc:
                logger.warning("Rate limiting check failed for surface %s: %s", str(surface.get("id") or surface.get("path") or ""), exc)
        return findings

    async def check_command_injection(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            if not surface.get("path", "").endswith("/ping"):
                path = str(surface.get("path") or surface.get("url") or "")
                if "/ping" not in path and "/command" not in path and "/execute" not in path:
                    continue
            sid = str(surface.get("id", ""))
            test_payloads = ["127.0.0.1; whoami", "127.0.0.1|whoami", "`whoami`", "$(whoami)"]
            for payload in test_payloads[:2]:
                try:
                    response = await self.client.request(
                        "command_injection", "GET", self.with_parameter(surface, "ip", payload),
                        surface=sid,
                        safe_test_marker="command_injection_probe",
                    )
                    body = str(response.get("body", "")).lower()
                    status = response.get("status_code")
                    if status == 500 or any(indicator in body for indicator in ["uid=", "gid=", "root:", "daemon:"]):
                        findings.append(
                            self.make_finding(
                                "Command injection vulnerability detected",
                                "Command Injection",
                                "CRITICAL",
                                "CONFIRMED",
                                "command_injection",
                                surface,
                                response,
                                f"Command injection probe returned: status {status}, body contains command output indicators",
                                "Remote code execution allows full server compromise.",
                                "Use parameterized queries for commands; never concatenate user input with shell commands.",
                                "Test with a benign command (e.g., echo test) and confirm it is rejected or sanitized.",
                                parameter="ip",
                            )
                        )
                        break
                except Exception as exc:
                    logger.warning("Command injection check failed for surface %s: %s", sid, exc)
        return findings

    async def check_ssti(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            ssti_payloads = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]
            for payload in ssti_payloads[:2]:
                try:
                    response = await self.client.request(
                        "ssti", "GET", self.with_parameter(surface, "name", payload),
                        surface=str(surface.get("id", "")),
                        safe_test_marker="ssti_probe",
                    )
                    body = str(response.get("body", ""))
                    if "49" in body:
                        findings.append(
                            self.make_finding(
                                "Server-Side Template Injection detected",
                                "SSTI",
                                "HIGH",
                                "CONFIRMED",
                                "ssti",
                                surface,
                                response,
                                f"SSTI probe '{payload}' evaluated to 49 in response",
                                "RCE and file read/write via template engine exploitation.",
                                "Use sandboxed template engines; never allow user input in templates.",
                                "Test with a benign template expression and confirm it is rejected.",
                                parameter="name",
                            )
                        )
                        break
                except Exception as exc:
                    logger.warning("SSTI check failed for surface %s: %s", str(surface.get("id") or surface.get("path") or ""), exc)
        return findings

    async def check_xxe(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            xxe_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
            try:
                response = await self.client.request(
                    "xxe", "POST", self.surface_target(surface),
                    json_body=xxe_payload,
                    headers={"Content-Type": "application/xml"},
                    surface=str(surface.get("id", "")),
                    safe_test_marker="xxe_probe",
                )
                body = str(response.get("body", "")).lower()
                if "root:" in body and "passwd" in body:
                    findings.append(
                        self.make_finding(
                            "XML External Entity (XXE) injection detected",
                            "XXE",
                            "HIGH",
                            "CONFIRMED",
                            "xxe",
                            surface,
                            response,
                            "External entity resolved: /etc/passwd content returned",
                            "Read local files, SSRF, and DoS via billion laughs.",
                            "Disable external entity resolution; use XML schemas and secure parsers.",
                            "Test with a benign XML entity and confirm it is rejected.",
                        )
                    )
                else:
                    findings.append(
                        self.make_finding(
                            "XXE protection likely present",
                            "XXE",
                            "LOW",
                            "MEDIUM",
                            "xxe",
                            surface,
                            response,
                            "No file content returned with XXE probe; possible protection.",
                            "Missing XXE protection could lead to file disclosure or SSRF.",
                            "Ensure XML parsers reject external entities and use secure configurations.",
                            "Test with a benign XXE attempt and confirm rejection.",
                        )
                    )
            except Exception as exc:
                logger.warning("XXE check failed for surface %s: %s", str(surface.get("id") or surface.get("path") or ""), exc)
        return findings

    async def check_ssrf(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            ssrf_payloads = [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:22",
                "http://metadata.google.internal",
                "file:///etc/passwd",
            ]
            for payload in ssrf_payloads[:2]:
                try:
                    response = await self.client.request(
                        "ssrf", "GET", self.with_parameter(surface, "url", payload),
                        surface=str(surface.get("id", "")),
                        safe_test_marker="ssrf_probe",
                    )
                    body = str(response.get("body", "")).lower()
                    status = response.get("status_code")
                    if status == 200 or ("meta-data" in body or "root:" in body or "ssh" in body):
                        findings.append(
                            self.make_finding(
                                "Server-Side Request Forgery (SSRF) detected",
                                "SSRF",
                                "HIGH",
                                "CONFIRMED",
                                "ssrf",
                                surface,
                                response,
                                f"SSRF probe to {payload} succeeded: status {status}, body contains internal resource indicators",
                                "Access internal cloud metadata (IAM keys), scan internal networks, reach internal services.",
                                "Validate user input against an allowlist of allowed destinations.",
                                "Test with a benign external URL and confirm it is allowed.",
                                parameter="url",
                            )
                        )
                        break
                except Exception as exc:
                    logger.warning("SSRF check failed for surface %s: %s", str(surface.get("id") or surface.get("path") or ""), exc)
        return findings

    async def check_dependency_security(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            response = await self.client.request(
                "dependency_security", "GET", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="dependency_security_probe",
            )
            headers = response.get("headers", {})
            body = str(response.get("body", "")).lower()
            info_disclosure_indicators = []
            version_headers = ["server", "x-powered-by", "x-aspnet-version", "x-koa-version"]
            for header in version_headers:
                if header in headers and re.search(r"\d+", headers[header]):
                    info_disclosure_indicators.append(f"{header}: {headers[header][:50]}")
            if re.search(r"at java\.|\.py\.c|:\s*\d{3}\s*\(.*\) error", body):
                info_disclosure_indicators.append("Stack trace")

            if info_disclosure_indicators:
                findings.append(
                    self.make_finding(
                        "Information disclosure detected",
                        "Information Disclosure",
                        "LOW",
                        "HIGH",
                        "info_disclosure",
                        surface,
                        response,
                        f"Version or debug information disclosed: {'; '.join(info_disclosure_indicators[:3])}",
                        "Attackers know exact versions and can exploit known vulnerabilities.",
                        "Remove or obfuscate version headers; use generic server headers.",
                        "Test with a fresh request and confirm version disclosure is eliminated.",
                    )
                )
        return findings

    async def check_info_disclosure(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            responses = []
            sensitive_paths = [".env", ".git/HEAD", "phpinfo.php", "admin/", "backup/", "config/", "phpinfo"]
            for path in sensitive_paths[:3]:
                try:
                    response = await self.client.request(
                        "info_disclosure", "GET", urljoin(self.target.url, f"/{path}"),
                        surface=str(surface.get("id", "")),
                        safe_test_marker=f"info_disclosure_probe_{path}",
                    )
                    responses.append(response)
                    status = response.get("status_code")
                    body = str(response.get("body", "")).lower()
                    if status == 200 and ("api_key" in body or "debug" in body or "phpinfo" in body):
                        findings.append(
                            self.make_finding(
                                f"Sensitive file disclosure: {path}",
                                "Sensitive Exposure",
                                "MEDIUM",
                                "HIGH",
                                "sensitive_exposure",
                                surface,
                                response,
                                f"Path {path} returned sensitive content: status {status}",
                                "Configuration secrets, database credentials leaked.",
                                "Remove or protect sensitive files; use proper access controls.",
                                "Request the sensitive path and confirm it is rejected.",
                            )
                        )
                        break
                except Exception as exc:
                    logger.warning("Info disclosure check failed for surface %s: %s", str(surface.get("id") or surface.get("path") or "", exc))
            if not findings:
                findings.append(
                    self.make_finding(
                        "Sensitive file exposure appears mitigated",
                        "Sensitive Exposure",
                        "LOW",
                        "MEDIUM",
                        "sensitive_exposure",
                        surface,
                        {"url": self.target.url, "status_code": None, "headers": {}, "body": ""},
                        "Sensitive paths returned 404 or error, suggesting protection.",
                        "Missing protection could expose configuration or secrets.",
                        "Ensure .env, .git, and diagnostic files are not accessible.",
                        "Test with a benign path and confirm it returns content.",
                    )
                )
        return findings

    async def emit(
        self,
        action: str,
        details: str,
        *,
        selected_module: str | None = None,
        result: str | None = None,
        request_count: int | None = None,
    ) -> None:
        event = {
            "event": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
            "selected_module": selected_module,
            "result": result,
            "request_count": request_count if request_count is not None else self.budget.request_count,
            "sandbox_id": self.sandbox_id,
        }
        self.events.append(event)
        await add_audit_log(
            self.scan_id,
            "Active Security Engine",
            action,
            details[:2000],
            user_id=self.user_id,
            target=self.target.url,
            authorization_status=str(self.authorization_context.get("authorization_status") or "UNKNOWN"),
            selected_module=selected_module,
            result=result,
            request_count=event["request_count"],
            sandbox_id=self.sandbox_id,
        )

    def make_finding(
        self,
        title: str,
        category: str,
        severity: str,
        confidence: str,
        module: str,
        surface: dict[str, Any],
        response: dict[str, Any],
        ev_text: str,
        impact: str,
        recommendation: str,
        verification: str,
        *,
        parameter: str | None = None,
        evidence_records: list[int] | None = None,
    ) -> dict[str, Any]:
        endpoint = str(response.get("url") or surface.get("url") or surface.get("path") or self.target.url)
        response_status = response.get("status_code")
        response_observed = response_status is not None
        request_id = response.get("_request_id", "")
        has_evidence = bool(request_id) and response_observed
        used_confidence = confidence if has_evidence else "LOW"
        used_confidence = "CONFIRMED" if (has_evidence and confidence in ("CONFIRMED", "HIGH")) else used_confidence
        evidence_note = f"Evidence request_id: {request_id}. " if request_id else "No request evidence recorded. "
        evidence_note += f"HTTP status: {response_status}. Surface: {surface.get('id', 'unknown')}."
        if not response_observed:
            evidence_note += " No response received."
            evidence_note += f" Error: {response.get('error', 'unknown')}" if response.get("error") else ""
        finding = build_finding(
            title=title,
            category=category,
            severity=severity,
            confidence=used_confidence,
            target=self.target.url,
            endpoint=endpoint,
            evidence=evidence_note,
            impact=impact,
            recommendation=recommendation,
            verification=verification,
            agent="Active Security Engine",
        )
        finding.update(
            {
                "module": module,
                "parameter": parameter or self.first_parameter(surface, ""),
                "recommended_fix": recommendation,
                "remediation_status": "OPEN",
                "verification_status": "NOT_VERIFIED",
            }
        )
        if not response_observed and not has_evidence:
            finding.update({
                "confidence": "LOW",
                "evidence": f"{ev_text} No real HTTP response was recorded. {evidence_note}",
            })
        finding["_evidence_ids"] = evidence_records or []
        finding["_request_id"] = request_id
        finding["_evidence_id"] = response.get("_evidence_id")
        return finding

    def final_report(self, status: str, error: str | None) -> str:
        lines = [
            "# Active Security Report",
            f"Target: {self.target.url}",
            f"Status: {status}",
            f"Authorization: {self.authorization_context.get('authorization_status', 'UNKNOWN')}",
            f"Requests used: {self.budget.request_count}/{self.limits.max_total_requests}",
            f"Findings: {len(self.findings)}",
            f"Score: {score_findings(self.findings, len(self.attack_surface.get('surfaces', [])))['score']}",
        ]
        if error:
            lines.append(f"Limit/Error: {error}")
        if self.timed_out_modules:
            lines.append(f"Timed-out modules: {', '.join(self.timed_out_modules)}")
        for finding in self.findings:
            lines.append(f"- [{finding.get('severity')}/{finding.get('confidence')}] {finding.get('title')}")
        return "\n".join(lines)

    def safe_evidence(self) -> list[dict[str, Any]]:
        return [
            {
                "title": finding.get("title"),
                "module": finding.get("module"),
                "endpoint": redact_url(str(finding.get("endpoint", ""))),
                "evidence": redact_sensitive(str(finding.get("evidence", ""))),
            }
            for finding in self.findings
        ]

    @staticmethod
    def plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
        return {
            "surface_count": plan.get("surface_count", 0),
            "modules": [
                {"module": item.get("module"), "surface_count": len(item.get("surfaces") or [])}
                for item in plan.get("modules", [])
            ],
        }

    @staticmethod
    def has_rate_limit_headers(headers: dict[str, Any]) -> bool:
        return any(name in headers for name in ["retry-after", "ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit"])

    @staticmethod
    def is_login_surface(surface: dict[str, Any]) -> bool:
        path = str(surface.get("path") or surface.get("url") or surface.get("id") or "").lower()
        parameters = {str(parameter).lower() for parameter in surface.get("parameters") or []}
        return "login" in path or bool(parameters & {"username", "password", "email"})

    def surface_target(self, surface: dict[str, Any]) -> str:
        return str(surface.get("url") or surface.get("path") or self.target.url)

    def with_parameter(self, surface: dict[str, Any], parameter: str, value: str) -> str:
        target = self.surface_target(surface)
        parsed = urlsplit(urljoin(f"{self.target.origin}/", target) if target.startswith("/") else target)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[parameter] = value
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), ""))

    @staticmethod
    def first_parameter(surface: dict[str, Any], default: str) -> str:
        parameters = surface.get("parameters") or []
        return str(parameters[0]) if parameters else default


def score_findings(findings: list[dict[str, Any]], surface_count: int = 0) -> dict[str, Any]:
    severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 1}
    confidence_weights = {"CONFIRMED": 1.2, "HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.5, "POTENTIAL": 0.35}
    active_findings = [
        finding
        for finding in findings
        if str(finding.get("verification_status") or "").upper() != "FIX_VERIFIED"
        and str(finding.get("remediation_status") or "").upper() != "RESOLVED"
        and str(finding.get("risk_status") or "ACTIVE").upper() == "ACTIVE"
    ]
    resolved_count = sum(
        1
        for finding in findings
        if (
            str(finding.get("verification_status") or "").upper() == "FIX_VERIFIED"
            or str(finding.get("remediation_status") or "").upper() == "RESOLVED"
            or str(finding.get("risk_status") or "ACTIVE").upper() != "ACTIVE"
        )
    )
    issue_penalty = sum(
        severity_weights.get(str(finding.get("severity", "INFO")).upper(), 1)
        * confidence_weights.get(str(finding.get("confidence", "MEDIUM")).upper(), 0.75)
        for finding in active_findings
    )
    exposure_penalty = min(10, max(0, surface_count - 10) // 5) if active_findings else 0
    resolved_credit = min(20, resolved_count * 3)
    penalty = max(0, int(round(issue_penalty + exposure_penalty - resolved_credit)))
    score = max(0, min(100, 100 - penalty))
    return {
        "score": score,
        "finding_count": len(findings),
        "penalty": penalty,
        "surface_count": surface_count,
        "resolved_count": resolved_count,
    }
