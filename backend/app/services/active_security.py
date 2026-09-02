import asyncio
import hashlib
import json
import logging
import random
import re
import socket
import ssl
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from app.config import get_settings
from app.database import add_audit_log, create_evidence_record, update_evidence_finding
from app.security import build_finding, redact_sensitive, redact_url
from app.services.active_gate import ActiveTargetGate
from app.services.asset_cache import asset_cache
from app.services.authorization import TargetAuthorizationService, canonicalize_target
from app.services.callback_registry import callback_registry
from app.services.correlation_graph import build_correlation_graph
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


@dataclass(frozen=True)
class VerificationResult:
    confirmed: bool
    confidence: str
    confidence_score: float
    stage: str
    method: str
    payload: str
    evidence_text: str
    reproduction_command: str
    request_response_diff: str
    verification_hash: str
    request_id: str
    response_status: int | None
    evidence_ids: list[int]


def _normalize_body_for_fingerprint(body: str) -> str:
    text = re.sub(r"\s+", " ", str(body or "").lower()).strip()
    text = re.sub(r"[a-f0-9]{16,}", "<hex>", text)
    text = re.sub(r"\d{4,}", "<num>", text)
    return text[:8000]


def response_fingerprint(response: dict[str, Any]) -> dict[str, Any]:
    headers = response.get("headers") or {}
    normalized_body = _normalize_body_for_fingerprint(str(response.get("raw_body") or response.get("body") or ""))
    important_headers = {
        key: str(headers.get(key) or "")[:120]
        for key in ("content-type", "server", "x-vercel-id", "cf-ray", "location")
        if headers.get(key)
    }
    return {
        "status_code": response.get("status_code"),
        "content_type": str(headers.get("content-type") or "").split(";")[0].lower(),
        "body_length_bucket": len(normalized_body) // 128,
        "body_hash": hashlib.sha256(normalized_body.encode("utf-8", errors="ignore")).hexdigest()[:16],
        "headers": important_headers,
    }


def same_response_fingerprint(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return response_fingerprint(first) == response_fingerprint(second)


def _shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def build_curl_command(method: str, url: str, headers: dict[str, str] | None = None, json_body: Any = None) -> str:
    parts = ["curl", "-i", "-X", method.upper(), _shell_quote(url)]
    for key, value in sorted((headers or {}).items()):
        parts.extend(["-H", _shell_quote(f"{key}: {value}")])
    if json_body is not None:
        parts.extend(["--json", _shell_quote(json.dumps(json_body, separators=(",", ":"), default=str))])
    return " ".join(parts)


def response_time_ms(response: dict[str, Any]) -> int:
    raw = response.get("response_time_ms")
    if raw is None and isinstance(response.get("_evidence"), dict):
        raw = response["_evidence"].get("response_time_ms")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


class MarkerContextParser(HTMLParser):
    def __init__(self, token: str) -> None:
        super().__init__()
        self.token = token
        self.saw_probe_span = False
        self.saw_token_text = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "span" and values.get("data-phantomscan-token") == self.token:
            self.saw_probe_span = True

    def handle_data(self, data: str) -> None:
        if self.token in data:
            self.saw_token_text = True


class VerificationOrchestrator:
    def __init__(self, engine: "ActiveSecurityEngine") -> None:
        self.engine = engine

    async def verify_reflected_html(self, surface: dict[str, Any], parameter: str) -> VerificationResult:
        reflected = await self._verify_reflected_html_error(surface, parameter)
        if reflected.confirmed:
            return reflected
        timed = await self._verify_reflected_html_time(surface, parameter)
        if timed.confirmed:
            return timed
        oob = await self.verify_http_callback(surface, parameter, "xss")
        if oob and oob.confirmed:
            return oob
        return max([item for item in (reflected, timed, oob) if item is not None], key=lambda item: item.confidence_score)

    async def _verify_reflected_html_error(self, surface: dict[str, Any], parameter: str) -> VerificationResult:
        token = f"x-{uuid.uuid4().hex[:10]}"
        marker = f'<span data-phantomscan-token="{token}">{token}</span>'
        surface_id = str(surface.get("id", ""))
        probe = await self.engine.client.request(
            "xss",
            "GET",
            self.engine.with_parameter(surface, parameter, token),
            surface=surface_id,
            safe_test_marker=token,
        )
        confirm = await self.engine.client.request(
            "xss",
            "GET",
            self.engine.with_parameter(surface, parameter, marker),
            surface=surface_id,
            safe_test_marker="PHANTOMSCAN_XSS_CONFIRM",
        )
        body = str(confirm.get("raw_body") or confirm.get("body") or "")
        content_type = str((confirm.get("headers") or {}).get("content-type") or "").lower()
        parser = MarkerContextParser(token)
        try:
            parser.feed(body)
        except Exception:
            pass
        probe_reflected = token in str(probe.get("raw_body") or probe.get("body") or "")
        confirmed = probe_reflected and ("text/html" in content_type or content_type == "") and parser.saw_probe_span and marker.lower() in body.lower()
        evidence_text = (
            "Probe token reflected and confirmation marker parsed as live HTML."
            if confirmed
            else "Probe did not produce independent HTML execution-context evidence."
        )
        return self._result(
            confirmed=confirmed,
            confidence="HIGH" if confirmed else "LOW",
            confidence_score=0.9 if confirmed else 0.2,
            stage="error",
            method="reflected_html_context_confirmation",
            payload=marker,
            response=confirm,
            evidence_text=evidence_text,
            injection_point=f"query parameter {parameter}",
            altered_chunk=self._snippet(body, token),
        )

    async def _verify_reflected_html_time(self, surface: dict[str, Any], parameter: str) -> VerificationResult:
        control = f"x-{uuid.uuid4().hex[:10]}"
        payload = f"{control}-time-probe"
        surface_id = str(surface.get("id", ""))
        baseline = await self.engine.baseline_response("xss", surface, parameter, control)
        confirm = await self.engine.client.request(
            "xss",
            "GET",
            self.engine.with_parameter(surface, parameter, payload),
            surface=surface_id,
            safe_test_marker=payload,
        )
        base_ms = response_time_ms(baseline)
        confirm_ms = response_time_ms(confirm)
        confirmed = confirm_ms >= max(900, base_ms + 750)
        return self._result(
            confirmed=confirmed,
            confidence="HIGH" if confirmed else "LOW",
            confidence_score=0.85 if confirmed else 0.15,
            stage="time",
            method="bounded_timing_differential",
            payload=payload,
            response=confirm,
            evidence_text=(
                f"Timing differential observed: baseline {base_ms}ms, payload {confirm_ms}ms."
                if confirmed
                else f"No meaningful timing differential: baseline {base_ms}ms, payload {confirm_ms}ms."
            ),
            injection_point=f"query parameter {parameter}",
            altered_chunk=f"baseline={base_ms}ms; confirmation={confirm_ms}ms",
            extra_evidence_ids=[baseline.get("_evidence_id")],
        )

    async def verify_data_layer_error(self, surface: dict[str, Any], parameter: str) -> VerificationResult:
        error = await self._verify_data_layer_error_stage(surface, parameter)
        if error.confirmed:
            return error
        timed = await self._verify_data_layer_time(surface, parameter)
        if timed.confirmed:
            return timed
        oob = await self.verify_http_callback(surface, parameter, "injection")
        if oob and oob.confirmed:
            return oob
        return max([item for item in (error, timed, oob) if item is not None], key=lambda item: item.confidence_score)

    async def _verify_data_layer_error_stage(self, surface: dict[str, Any], parameter: str) -> VerificationResult:
        control = f"x-{uuid.uuid4().hex[:10]}"
        payload = "PHANTOMSCAN_DATA_PROBE"
        surface_id = str(surface.get("id", ""))
        baseline = await self.engine.baseline_response("injection", surface, parameter, control)
        confirm = await self.engine.client.request(
            "injection",
            "GET",
            self.engine.with_parameter(surface, parameter, payload),
            surface=surface_id,
            safe_test_marker=payload,
        )
        body = str(confirm.get("raw_body") or confirm.get("body") or "").lower()
        baseline_body = str(baseline.get("raw_body") or baseline.get("body") or "").lower()
        explicit_db_logic = any(token in body for token in ["data layer error", "sql", "sqlite", "odbc", "syntax", "query"])
        differential_error = int(confirm.get("status_code") or 0) >= 500 and int(baseline.get("status_code") or 0) < 500
        confirmed = differential_error and explicit_db_logic and body != baseline_body
        evidence_text = (
            "Control request succeeded while confirmation request returned explicit database-layer error evidence."
            if confirmed
            else "Database-layer signal was not independently confirmed by a control request."
        )
        return self._result(
            confirmed=confirmed,
            confidence="HIGH" if confirmed else "LOW",
            confidence_score=0.9 if confirmed else 0.2,
            stage="error",
            method="differential_error_with_control",
            payload=payload,
            response=confirm,
            evidence_text=evidence_text,
            injection_point=f"query parameter {parameter}",
            altered_chunk=self._snippet(str(confirm.get("raw_body") or confirm.get("body") or ""), "data"),
            extra_evidence_ids=[baseline.get("_evidence_id")],
        )

    async def _verify_data_layer_time(self, surface: dict[str, Any], parameter: str) -> VerificationResult:
        control = f"x-{uuid.uuid4().hex[:10]}"
        payload = "PHANTOMSCAN_TIME_PROBE_SLEEP_1"
        surface_id = str(surface.get("id", ""))
        baseline = await self.engine.baseline_response("injection", surface, parameter, control)
        confirm = await self.engine.client.request(
            "injection",
            "GET",
            self.engine.with_parameter(surface, parameter, payload),
            surface=surface_id,
            safe_test_marker=payload,
        )
        base_ms = response_time_ms(baseline)
        confirm_ms = response_time_ms(confirm)
        confirmed = confirm_ms >= max(900, base_ms + 750)
        return self._result(
            confirmed=confirmed,
            confidence="HIGH" if confirmed else "LOW",
            confidence_score=0.85 if confirmed else 0.15,
            stage="time",
            method="bounded_timing_differential",
            payload=payload,
            response=confirm,
            evidence_text=(
                f"Blind timing confirmation succeeded: baseline {base_ms}ms, payload {confirm_ms}ms."
                if confirmed
                else f"Blind timing confirmation failed: baseline {base_ms}ms, payload {confirm_ms}ms."
            ),
            injection_point=f"query parameter {parameter}",
            altered_chunk=f"baseline={base_ms}ms; confirmation={confirm_ms}ms",
            extra_evidence_ids=[baseline.get("_evidence_id")],
        )

    async def verify_command_timing(self, surface: dict[str, Any], parameter: str) -> VerificationResult:
        control = "127.0.0.1"
        payload = "127.0.0.1; sleep 1"
        surface_id = str(surface.get("id", ""))
        baseline = await self.engine.client.request(
            "command_injection",
            "GET",
            self.engine.with_parameter(surface, parameter, control),
            surface=surface_id,
            safe_test_marker="command_control",
        )
        confirm = await self.engine.client.request(
            "command_injection",
            "GET",
            self.engine.with_parameter(surface, parameter, payload),
            surface=surface_id,
            safe_test_marker="command_sleep_probe",
        )
        base_ms = response_time_ms(baseline)
        confirm_ms = response_time_ms(confirm)
        confirmed = confirm_ms >= max(900, base_ms + 750)
        evidence_text = (
            f"Blind timing confirmation succeeded: baseline {base_ms}ms, payload {confirm_ms}ms."
            if confirmed
            else f"Blind timing confirmation failed: baseline {base_ms}ms, payload {confirm_ms}ms."
        )
        return self._result(
            confirmed=confirmed,
            confidence="CONFIRMED" if confirmed else "LOW",
            confidence_score=0.95 if confirmed else 0.2,
            stage="probe+confirmation",
            method="blind_sleep_timing",
            payload=payload,
            response=confirm,
            evidence_text=evidence_text,
            injection_point=f"query parameter {parameter}",
            altered_chunk=f"baseline={base_ms}ms; confirmation={confirm_ms}ms",
            extra_evidence_ids=[baseline.get("_evidence_id")],
        )

    async def verify_http_callback(self, surface: dict[str, Any], parameter: str, module: str) -> VerificationResult | None:
        settings = get_settings()
        callback_base_url = settings.callback_base_url or (f"http://{settings.callback_domain}" if settings.callback_domain else "")
        if not callback_base_url:
            return None
        token = await callback_registry.create_token()
        callback_url = f"{callback_base_url.rstrip('/')}/callback/{token}"
        surface_id = str(surface.get("id", ""))
        response = await self.engine.client.request(
            module,
            "GET",
            self.engine.with_parameter(surface, parameter, callback_url),
            surface=surface_id,
            safe_test_marker=f"callback:{token}",
        )
        records = await callback_registry.wait_for_callback(token, timeout=settings.callback_wait_timeout)
        confirmed = bool(records)
        return self._result(
            confirmed=confirmed,
            confidence="HIGH" if confirmed else "LOW",
            confidence_score=0.95 if confirmed else 0.2,
            stage="oob",
            method="self_hosted_http_callback",
            payload=callback_url,
            response=response,
            evidence_text=(
                f"Self-hosted callback token {token} was observed."
                if confirmed
                else f"Self-hosted callback token {token} was not observed within the bounded wait window."
            ),
            injection_point=f"query parameter {parameter}",
            altered_chunk=json.dumps(records[:3], default=str),
        )

    def _result(
        self,
        *,
        confirmed: bool,
        confidence: str,
        confidence_score: float,
        stage: str,
        method: str,
        payload: str,
        response: dict[str, Any],
        evidence_text: str,
        injection_point: str,
        altered_chunk: str,
        extra_evidence_ids: list[Any] | None = None,
    ) -> VerificationResult:
        url = str(response.get("url") or self.engine.target.url)
        request_id = str(response.get("_request_id") or uuid.uuid4().hex[:8])
        fingerprint = hashlib.sha256(f"{method}|{url}|{payload}|{request_id}|{altered_chunk}".encode("utf-8", errors="ignore")).hexdigest()
        evidence_ids = [item for item in list(extra_evidence_ids or []) + [response.get("_evidence_id")] if isinstance(item, int)]
        curl_headers = response.get("request_headers") if isinstance(response.get("request_headers"), dict) else None
        curl_body = response.get("request_json_body")
        return VerificationResult(
            confirmed=confirmed,
            confidence=confidence,
            confidence_score=max(0.0, min(1.0, float(confidence_score))),
            stage=stage,
            method=method,
            payload=payload,
            evidence_text=evidence_text,
            reproduction_command=build_curl_command(str(response.get("method") or "GET"), url, curl_headers, curl_body),
            request_response_diff=(
                "--- request\n"
                f"+++ request with payload\nInjection point: {injection_point}\nPayload: {payload}\n"
                "--- response baseline/control\n"
                "+++ response confirmation\n"
                f"Altered response evidence: {altered_chunk}"
            ),
            verification_hash=fingerprint,
            request_id=request_id,
            response_status=response.get("status_code"),
            evidence_ids=evidence_ids,
        )

    @staticmethod
    def _snippet(body: str, needle: str, radius: int = 120) -> str:
        if not body:
            return ""
        index = body.lower().find(str(needle).lower())
        if index < 0:
            return body[: radius * 2]
        start = max(0, index - radius)
        end = min(len(body), index + len(str(needle)) + radius)
        return body[start:end]


class SurfaceHTMLParser(HTMLParser):
    def __init__(self, target_url: str) -> None:
        super().__init__()
        self.target_url = target_url
        self.forms: list[dict[str, Any]] = []
        self.links: list[dict[str, Any]] = []
        self.scripts: list[str] = []
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
        elif tag == "script":
            src = values.get("src")
            if src:
                self.scripts.append(urljoin(self.target_url, src))
        elif tag == "a":
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
        if "login" in path or "signin" in path or "auth" in path:
            hints.append("auth_session")
        if "logout" in path or "session" in path or "token" in path:
            hints.extend(["auth_session", "jwt"])
        if "admin" in path:
            hints.append("access_control")
        if "graphql" in path:
            hints.append("graphql")
        if "/api/" in path or path.startswith("/api"):
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
                    baseline = await self.collect_baselines(target)
                    return {
                        "target_url": target.url,
                        "target_origin": target.origin,
                        "source": "lab_manifest",
                        "surfaces": data["surfaces"],
                        "manifest": data,
                        "response_baselines": baseline,
                    }

        response = await self.fetch_url("mapper", "GET", target.url)
        baseline = await self.collect_baselines(target, valid_response=response)
        surfaces = self.root_surfaces(target.url)
        discovery_sources: dict[str, int] = {"root": 1}
        filtered_surfaces: list[dict[str, Any]] = []
        if response.get("status_code") == 200:
            parser = SurfaceHTMLParser(target.url)
            parser.feed(str(response.get("body") or ""))
            surfaces.extend(parser.forms)
            surfaces.extend(parser.links)
            discovery_sources["html_forms"] = len(parser.forms)
            discovery_sources["html_links"] = len(parser.links)
            script_surfaces, script_artifacts = await self.discover_from_scripts(target, parser.scripts)
            surfaces.extend(script_surfaces)
            discovery_sources["javascript"] = len(script_surfaces)
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
            discovery_sources["websocket_refs"] = len(parser.websocket_refs)
        else:
            script_artifacts = []
        document_surfaces, document_artifacts = await self.discover_from_standard_documents(target)
        surfaces.extend(document_surfaces)
        discovery_sources["standard_documents"] = len(document_surfaces)
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
        surfaces = self.dedupe_surfaces(surfaces)
        surfaces, filtered_surfaces = self.filter_spa_fallback_surfaces(surfaces, baseline)
        return {
            "target_url": target.url,
            "target_origin": target.origin,
            "source": "evidence_driven",
            "surfaces": surfaces,
            "response_baselines": baseline,
            "attack_surface_graph": self.build_attack_surface_graph(target.url, surfaces),
            "discovery_sources": discovery_sources,
            "discovery_artifacts": {
                "javascript": script_artifacts,
                "standard_documents": document_artifacts,
                "spa_filtered_surfaces": filtered_surfaces,
            },
            "coverage_limitations": self.coverage_limitations(baseline, filtered_surfaces),
        }

    async def discover_from_scripts(self, target: Any, script_urls: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            from app.services.browser_observation import JavaScriptStaticAnalyzer
        except Exception:
            return [], []
        analyzer = JavaScriptStaticAnalyzer()
        surfaces: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        for script_url in self.same_origin_urls(target, script_urls)[:3]:
            cached = asset_cache.get(script_url)
            if cached is not None:
                response = {
                    "url": script_url,
                    "status_code": 200,
                    "headers": {"content-type": "application/javascript"},
                    "raw_body": cached,
                    "body": cached,
                    "truncated": False,
                    "cached": True,
                }
            else:
                response = await self.fetch_url("javascript_discovery", "GET", script_url)
            if response.get("status_code") != 200:
                continue
            content_type = str((response.get("headers") or {}).get("content-type") or "").lower()
            if content_type and "javascript" not in content_type and not script_url.lower().split("?", 1)[0].endswith(".js"):
                continue
            source = str(response.get("raw_body") or response.get("body") or "")
            if not response.get("cached"):
                asset_cache.set(script_url, source)
            analysis = analyzer.analyze(script_url, source)
            artifacts.append(
                {
                    "script": redact_url(script_url),
                    "api_endpoints": len(analysis.get("api_endpoints") or []),
                    "routes": len(analysis.get("routes") or []),
                    "websocket_urls": len(analysis.get("websocket_urls") or []),
                    "source_map_references": len(analysis.get("source_map_references") or []),
                }
            )
            for endpoint in analysis.get("api_endpoints") or []:
                surfaces.append(self.surface_from_url(target, endpoint, "javascript_api", "Endpoint extracted from same-origin JavaScript bundle."))
            for endpoint in analysis.get("graphql_endpoints") or []:
                surface = self.surface_from_url(target, endpoint, "javascript_graphql", "GraphQL endpoint extracted from same-origin JavaScript bundle.")
                surface["module_hints"] = list(dict.fromkeys([*surface.get("module_hints", []), "graphql"]))
                surfaces.append(surface)
            for route in analysis.get("routes") or []:
                surface = self.surface_from_url(target, route, "javascript_route", "Client route extracted from same-origin JavaScript bundle.")
                surface["client_route"] = True
                surfaces.append(surface)
            for websocket_url in analysis.get("websocket_urls") or []:
                if websocket_url in self.same_origin_urls(target, [websocket_url]):
                    parsed = urlsplit(websocket_url)
                    surfaces.append(
                        {
                            "id": f"javascript_websocket_{len(surfaces) + 1}",
                            "type": "websocket",
                            "method": "WEBSOCKET",
                            "url": websocket_url,
                            "path": parsed.path or "/",
                            "parameters": [],
                            "module_hints": ["websocket"],
                            "description": "WebSocket endpoint extracted from same-origin JavaScript bundle.",
                        }
                    )
        return surfaces, artifacts

    async def discover_from_standard_documents(self, target: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        surfaces: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        robots_url = urljoin(f"{target.origin}/", "/robots.txt")
        robots = await self.fetch_url("document_discovery", "GET", robots_url)
        if robots.get("status_code") == 200:
            paths = self.parse_robots_paths(str(robots.get("raw_body") or robots.get("body") or ""))
            artifacts.append({"type": "robots", "url": redact_url(robots_url), "paths": len(paths)})
            for path in paths[:20]:
                surfaces.append(self.surface_from_url(target, path, "robots", "Path disclosed by robots.txt. Disallow is not treated as access control evidence."))
        sitemap_url = urljoin(f"{target.origin}/", "/sitemap.xml")
        sitemap = await self.fetch_url("document_discovery", "GET", sitemap_url)
        if sitemap.get("status_code") == 200:
            urls = self.parse_sitemap_urls(str(sitemap.get("raw_body") or sitemap.get("body") or ""))
            artifacts.append({"type": "sitemap", "url": redact_url(sitemap_url), "urls": len(urls)})
            for url in self.same_origin_urls(target, urls)[:20]:
                surfaces.append(self.surface_from_url(target, url, "sitemap", "URL discovered in sitemap.xml."))
        for doc_path in ("/openapi.json", "/api/openapi.json", "/swagger.json", "/api/swagger.json"):
            doc_url = urljoin(f"{target.origin}/", doc_path)
            response = await self.fetch_url("openapi_discovery", "GET", doc_url)
            if response.get("status_code") != 200:
                continue
            parsed_surfaces = self.parse_openapi_surfaces(target, doc_url, str(response.get("raw_body") or response.get("body") or ""))
            if parsed_surfaces:
                artifacts.append({"type": "openapi", "url": redact_url(doc_url), "paths": len(parsed_surfaces)})
                surfaces.extend(parsed_surfaces)
                break
        return surfaces, artifacts

    def surface_from_url(self, target: Any, url_or_path: str, source: str, description: str) -> dict[str, Any]:
        absolute = urljoin(f"{target.origin}/", url_or_path) if str(url_or_path).startswith("/") else str(url_or_path)
        try:
            candidate = canonicalize_target(absolute)
            absolute = candidate.url
        except Exception:
            absolute = urljoin(f"{target.origin}/", str(url_or_path))
        parsed = urlsplit(absolute)
        parameters = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        hints = SurfaceHTMLParser.hints_for_parameters(parameters, SurfaceHTMLParser.hints_for_url(absolute))
        return {
            "id": f"{source}_{hashlib.sha256(absolute.encode('utf-8', errors='ignore')).hexdigest()[:10]}",
            "type": source,
            "method": "GET",
            "path": parsed.path or "/",
            "url": absolute,
            "parameters": parameters,
            "module_hints": hints,
            "description": description,
            "discovery_source": source,
        }

    @staticmethod
    def parse_robots_paths(body: str) -> list[str]:
        paths: list[str] = []
        for match in re.findall(r"(?im)^\s*(?:allow|disallow)\s*:\s*(\S+)", body):
            if not match or match == "/" or "*" in match:
                continue
            paths.append(match)
        return list(dict.fromkeys(paths))

    @staticmethod
    def parse_sitemap_urls(body: str) -> list[str]:
        urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body, re.IGNORECASE)
        return list(dict.fromkeys(urls))

    def parse_openapi_surfaces(self, target: Any, doc_url: str, body: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
            return []
        surfaces: list[dict[str, Any]] = []
        for path, operations in list(data["paths"].items())[:80]:
            if not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                method_upper = str(method).upper()
                if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                params: list[str] = []
                if isinstance(operation, dict):
                    for parameter in operation.get("parameters") or []:
                        if isinstance(parameter, dict) and parameter.get("name"):
                            params.append(str(parameter["name"]))
                absolute = urljoin(f"{target.origin}/", str(path).lstrip("/"))
                parsed = urlsplit(absolute)
                hints = SurfaceHTMLParser.hints_for_parameters(params, SurfaceHTMLParser.hints_for_url(absolute))
                if "api_security" not in hints:
                    hints.append("api_security")
                surfaces.append(
                    {
                        "id": f"openapi_{method_upper.lower()}_{hashlib.sha256((method_upper + absolute).encode('utf-8', errors='ignore')).hexdigest()[:10]}",
                        "type": "openapi",
                        "method": method_upper,
                        "path": parsed.path or "/",
                        "url": absolute,
                        "parameters": list(dict.fromkeys(params)),
                        "module_hints": list(dict.fromkeys(hints)),
                        "description": f"Endpoint defined by exposed OpenAPI document {redact_url(doc_url)}.",
                        "discovery_source": "openapi",
                    }
                )
        return surfaces

    @staticmethod
    def same_origin_urls(target: Any, urls: list[str]) -> list[str]:
        same_origin: list[str] = []
        for url in urls:
            text = str(url).strip()
            if not text:
                continue
            absolute = urljoin(f"{target.origin}/", text) if text.startswith("/") else text
            parsed = urlsplit(absolute)
            if parsed.scheme in {"ws", "wss"}:
                if parsed.netloc.lower() == urlsplit(target.origin).netloc.lower():
                    same_origin.append(absolute)
                continue
            try:
                if canonicalize_target(absolute).origin == target.origin:
                    same_origin.append(absolute)
            except Exception:
                continue
        return list(dict.fromkeys(same_origin))

    @staticmethod
    def filter_spa_fallback_surfaces(surfaces: list[dict[str, Any]], baseline: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        classifications = baseline.get("classifications") or {}
        if not classifications.get("spa_or_wildcard_fallback"):
            return surfaces, []
        kept: list[dict[str, Any]] = []
        filtered: list[dict[str, Any]] = []
        for surface in surfaces:
            hints = {normalize_module(str(hint)) for hint in surface.get("module_hints") or []}
            is_client_page = surface.get("type") in {"link", "javascript_route", "sitemap", "robots"}
            if is_client_page and not surface.get("parameters") and not (hints & {"api_security", "auth_session", "graphql", "websocket"}):
                filtered.append({"path": surface.get("path"), "source": surface.get("discovery_source") or surface.get("type")})
                continue
            kept.append(surface)
        return kept, filtered

    @staticmethod
    def build_attack_surface_graph(target_url: str, surfaces: list[dict[str, Any]]) -> dict[str, Any]:
        nodes = [{"id": "target", "type": "target", "url": redact_url(target_url)}]
        edges: list[dict[str, Any]] = []
        for surface in surfaces:
            node_id = str(surface.get("id") or hashlib.sha256(str(surface.get("url") or surface.get("path")).encode()).hexdigest()[:10])
            nodes.append(
                {
                    "id": node_id,
                    "type": surface.get("type") or "endpoint",
                    "method": surface.get("method") or "GET",
                    "path": surface.get("path"),
                    "parameters": surface.get("parameters") or [],
                    "module_hints": surface.get("module_hints") or [],
                }
            )
            edges.append({"from": "target", "to": node_id, "source": surface.get("discovery_source") or surface.get("type") or "unknown"})
        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def coverage_limitations(baseline: dict[str, Any], filtered_surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        limitations: list[dict[str, Any]] = []
        classifications = baseline.get("classifications") or {}
        if classifications.get("blanket_denial"):
            limitations.append({"type": "BLOCKED_BY_EDGE_OR_WAF", "details": "Random nonexistent paths returned the same denial fingerprint."})
        if classifications.get("spa_or_wildcard_fallback"):
            limitations.append({"type": "SPA_OR_WILDCARD_FALLBACK", "details": f"{len(filtered_surfaces)} fallback-like page routes were not treated as independent server endpoints."})
        return limitations

    async def collect_baselines(self, target: Any, valid_response: dict[str, Any] | None = None) -> dict[str, Any]:
        random_token = f"phantomscan-no-such-{uuid.uuid4().hex[:12]}"
        probes = {
            "valid_url": target.url,
            "random_nonexistent": urljoin(f"{target.origin}/", f"/{random_token}"),
            "random_nested_nonexistent": urljoin(f"{target.origin}/", f"/{random_token}/nested/{uuid.uuid4().hex[:8]}"),
            "invalid_query_parameter": self._with_query(target.url, f"{random_token}_param", random_token),
        }
        responses: dict[str, Any] = {}
        raw_responses: dict[str, dict[str, Any]] = {}
        for name, url in probes.items():
            if name == "valid_url" and valid_response is not None:
                response = valid_response
            else:
                response = await self.fetch_url("baseline", "GET", url)
            raw_responses[name] = response
            responses[name] = {
                "url": redact_url(str(response.get("url") or url)),
                "status_code": response.get("status_code"),
                "fingerprint": response_fingerprint(response),
            }
        responses["classifications"] = {
            "spa_or_wildcard_fallback": same_response_fingerprint(raw_responses["valid_url"], raw_responses["random_nonexistent"]),
            "consistent_nonexistent_status": raw_responses["random_nonexistent"].get("status_code") == raw_responses["random_nested_nonexistent"].get("status_code"),
            "blanket_denial": bool(
                raw_responses["random_nonexistent"].get("status_code") in {401, 403}
                and same_response_fingerprint(raw_responses["random_nonexistent"], raw_responses["random_nested_nonexistent"])
            ),
        }
        return responses

    @staticmethod
    def _with_query(url: str, name: str, value: str) -> str:
        parsed = urlsplit(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[name] = value
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), ""))

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
    STATIC_ASSET_RE = re.compile(r"\.(?:css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|webm|zip)(?:$|[?#])", re.IGNORECASE)

    def create_plan(self, attack_surface: dict[str, Any], selected_modules: list[str] | None = None) -> dict[str, Any]:
        surfaces = self.prune_surfaces([surface for surface in attack_surface.get("surfaces", []) if isinstance(surface, dict)])
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

    def prune_surfaces(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pruned: list[dict[str, Any]] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        for surface in surfaces:
            target = str(surface.get("url") or surface.get("path") or surface.get("id") or "")
            if self.STATIC_ASSET_RE.search(target):
                continue
            parsed = urlsplit(target)
            path = parsed.path or target or "/"
            normalized_path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
            normalized_path = re.sub(r"/[a-f0-9]{16,}(?=/|$)", "/{id}", normalized_path, flags=re.IGNORECASE)
            parameters = tuple(sorted(str(item).lower() for item in surface.get("parameters") or []))
            key = (str(surface.get("method") or "GET").upper(), normalized_path, parameters)
            if key in seen:
                continue
            seen.add(key)
            pruned.append(surface)
        return pruned

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
        self.semaphore = asyncio.Semaphore(max(1, int(get_settings().active_max_concurrency)))

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
        throttle_delay = 0.0
        try:
            for attempt in range(3):
                if throttle_delay > 0:
                    await asyncio.sleep(throttle_delay)
                async with self.semaphore:
                    async with httpx.AsyncClient(
                        timeout=timeout,
                        follow_redirects=False,
                        trust_env=False,
                        transport=self.transport,
                        headers={"User-Agent": "PhantomScan-ActiveSecurity/1.0"},
                    ) as client:
                        async with client.stream(method, candidate.url, headers=headers, json=json_body) as response:
                            if response.status_code in {429, 503} and attempt < 2:
                                retry_after = response.headers.get("retry-after")
                                try:
                                    throttle_delay = min(5.0, max(0.5, float(retry_after or 0)))
                                except ValueError:
                                    throttle_delay = 0.5
                                throttle_delay = min(5.0, throttle_delay * (2 ** attempt) + random.uniform(0.05, 0.25))
                                continue
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
                                "method": method,
                                "status_code": response.status_code,
                                "headers": {key.lower(): value for key, value in response.headers.items()},
                                "request_headers": headers or {},
                                "request_json_body": json_body,
                                "raw_body": decoded,
                                "body": redact_sensitive(decoded, self.budget.limits.max_response_size),
                                "response_time_ms": duration_ms,
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
                "method": method,
                "status_code": None,
                "headers": {},
                "body": "",
                "response_time_ms": None,
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
        profile = str((workflow_rules or {}).get("confidence_profile") or "balanced").lower()
        if profile == "strict":
            self.confidence_high_threshold = 0.9
            self.confidence_medium_threshold = 0.7
        elif profile == "aggressive":
            self.confidence_high_threshold = 0.75
            self.confidence_medium_threshold = 0.5
        else:
            self.confidence_high_threshold = get_settings().confidence_high
            self.confidence_medium_threshold = get_settings().confidence_medium
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
        self.verifier = VerificationOrchestrator(self)
        self.events: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.timed_out_modules: list[str] = []
        self.module_timeout = get_settings().module_timeout
        self._sink_cache: list[dict[str, Any]] | None = None
        self._baseline_cache: dict[tuple[str, str, str], dict[str, Any]] = {}

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
                if was_timeout:
                    await self.emit("module_timed_out", f"{module}: timed out after {self.module_timeout}s", selected_module=module, result="TIMED_OUT")
                else:
                    await self.emit("module_completed", f"{module}: {len(module_findings)} findings", selected_module=module)
                await self.emit("progress", f"Active security progress {progress}%", selected_module=module, request_count=self.budget.request_count)
            if self.timed_out_modules and status == "complete":
                status = "limited"
                error = f"Timed-out modules: {', '.join(self.timed_out_modules)}"
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
            "correlation_graph": build_correlation_graph(self.attack_surface, self.findings),
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
            results = await asyncio.wait_for(handler(self.planner.prune_surfaces(surfaces)), timeout=self.module_timeout)
        except asyncio.TimeoutError:
            logger.warning("Module %s timed out after %ds", module, self.module_timeout)
            await self.emit("module_timeout", f"{module} timed out after {self.module_timeout}s", selected_module=module)
            self.timed_out_modules.append(module)
            return []
        for surface in self.planner.prune_surfaces(surfaces):
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
            parameter = self.select_best_parameter(surface, vulnerability_type="injection")
            if parameter is None:
                continue
            try:
                verification = await asyncio.wait_for(
                    self.verifier.verify_data_layer_error(surface, parameter),
                    timeout=min(8.0, max(3.0, self.module_timeout / 2)),
                )
            except asyncio.TimeoutError:
                logger.info("Injection verifier timed out for surface %s parameter %s", surface.get("id") or surface.get("path"), parameter)
                continue
            except ExecutionLimitError:
                raise
            except Exception as exc:
                logger.warning("Injection verifier failed for surface %s parameter %s: %s", surface.get("id") or surface.get("path"), parameter, exc)
                continue
            if verification is None:
                logger.info("Injection verifier returned no result for surface %s parameter %s", surface.get("id") or surface.get("path"), parameter)
                continue
            if verification.confirmed:
                findings.append(
                    self.make_finding(
                        "Controlled data-layer probe caused an error response",
                        "Data-Layer Handling",
                        "HIGH",
                        verification.confidence,
                        "injection",
                        surface,
                        {"url": self.with_parameter(surface, parameter, verification.payload), "status_code": verification.response_status, "_request_id": verification.request_id},
                        verification.evidence_text,
                        "Untrusted input may be reaching query construction or interpreter boundaries unsafely.",
                        "Use parameterized data access APIs, strict allowlists, and uniform error handling.",
                        "Repeat the controlled data-layer probe and confirm no interpreter error or marker-specific behavior occurs.",
                        parameter=parameter,
                        evidence_records=verification.evidence_ids,
                        verification_result=verification,
                    )
                )
        return findings

    async def check_xss(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces:
            parameter = self.select_best_parameter(surface, vulnerability_type="xss")
            if parameter is None:
                continue
            try:
                verification = await asyncio.wait_for(
                    self.verifier.verify_reflected_html(surface, parameter),
                    timeout=min(8.0, max(3.0, self.module_timeout / 2)),
                )
            except asyncio.TimeoutError:
                logger.info("XSS verifier timed out for surface %s parameter %s", surface.get("id") or surface.get("path"), parameter)
                continue
            except ExecutionLimitError:
                raise
            except Exception as exc:
                logger.warning("XSS verifier failed for surface %s parameter %s: %s", surface.get("id") or surface.get("path"), parameter, exc)
                continue
            if verification is None:
                logger.info("XSS verifier returned no result for surface %s parameter %s", surface.get("id") or surface.get("path"), parameter)
                continue
            if verification.confirmed:
                findings.append(
                    self.make_finding(
                        "HTML-like input marker reflected without encoding",
                        "Output Encoding",
                        "MEDIUM",
                        verification.confidence,
                        "xss",
                        surface,
                        {"url": self.with_parameter(surface, parameter, verification.payload), "status_code": verification.response_status, "_request_id": verification.request_id},
                        verification.evidence_text,
                        "Executable markup could run in a browser if attacker-controlled input reaches the same context.",
                        "Apply context-aware output encoding and deploy a restrictive Content Security Policy.",
                        "Rerun the output-encoding check and confirm the marker is HTML-encoded.",
                        parameter=parameter,
                        evidence_records=verification.evidence_ids,
                        verification_result=verification,
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
        findings: list[dict[str, Any]] = []
        parsed_target = urlsplit(self.target.url)
        host = parsed_target.netloc
        main_url = urlunsplit((parsed_target.scheme or "https", host, "/", "", ""))
        candidates = [{"id": "main", "url": main_url, "path": "/", "parameters": []}]
        for surface in self.planner.prune_surfaces(surfaces):
            url = self.surface_target(surface)
            parsed = urlsplit(urljoin(f"{self.target.origin}/", url) if url.startswith("/") else url)
            if parsed.netloc == host and (parsed.path or "/") != "/":
                candidates.append(surface)

        grouped: dict[str, dict[str, Any]] = {}
        responses: dict[str, dict[str, Any]] = {}
        for surface in candidates[:20]:
            response = await self.client.request(
                "security_headers", "GET", self.surface_target(surface),
                surface=str(surface.get("id", "")),
                safe_test_marker="security_headers_probe",
            )
            headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
            url = str(response.get("url") or self.surface_target(surface))
            responses[url] = response
            content_type = headers.get("content-type", "")
            if content_type and "html" not in content_type.lower():
                continue
            body = str(response.get("raw_body") or response.get("body") or "")
            is_main = self._same_origin_path(url, main_url, "/")

            csp = headers.get("content-security-policy", "")
            if not csp:
                self._add_header_issue(grouped, host, "content-security-policy", "Missing Content-Security-Policy", "MEDIUM", url, "Header Content-Security-Policy expected but not found.")
            elif self._weak_csp(csp) and re.search(r"<script\b", body, re.IGNORECASE):
                self._add_header_issue(grouped, host, "content-security-policy", "Weak Content-Security-Policy", "HIGH", url, f"CSP value is weak while scripts are present: {csp[:300]}")

            if "x-content-type-options" not in headers:
                self._add_header_issue(grouped, host, "x-content-type-options", "Missing X-Content-Type-Options", "MEDIUM", url, "Header X-Content-Type-Options expected but not found.")
            elif headers.get("x-content-type-options", "").lower() != "nosniff":
                self._add_header_issue(grouped, host, "x-content-type-options", "Weak X-Content-Type-Options", "HIGH", url, f"Expected nosniff, observed {headers.get('x-content-type-options')}.")

            if "referrer-policy" not in headers:
                self._add_header_issue(grouped, host, "referrer-policy", "Missing Referrer-Policy", "MEDIUM", url, "Header Referrer-Policy expected but not found.")

            has_frame_control = "x-frame-options" in headers or "frame-ancestors" in csp.lower()
            if not has_frame_control:
                self._add_header_issue(grouped, host, "frame-protection", "Missing frame protection", "MEDIUM", url, "Expected X-Frame-Options or CSP frame-ancestors but neither was found.")

            if is_main and parsed_target.scheme == "https" and not self._valid_hsts(headers.get("strict-transport-security", "")):
                observed = headers.get("strict-transport-security", "")
                reason = "Header Strict-Transport-Security expected on HTTPS main document but not found." if not observed else f"Strict-Transport-Security is invalid: {observed}."
                self._add_header_issue(grouped, host, "strict-transport-security", "Missing or invalid HSTS", "MEDIUM", url, reason)

        for issue in grouped.values():
            first_url = issue["affected_urls"][0]
            response = responses.get(first_url) or {"url": first_url, "status_code": None, "headers": {}}
            finding = self.make_finding(
                issue["title"],
                "Security Headers",
                "MEDIUM" if issue["confidence"] != "LOW" else "LOW",
                issue["confidence"],
                "security_headers",
                {"id": issue["header"], "url": first_url, "parameters": []},
                response,
                f"{issue['evidence']} Affected URLs: {', '.join(issue['affected_urls'][:10])}.",
                "Missing or weak browser security headers can increase impact from content injection, clickjacking, MIME sniffing, or data leakage.",
                f"Set a correct {issue['header']} header on the affected HTML responses.",
                f"Run curl -sI against each affected URL and confirm {issue['header']} is present and valid.",
            )
            self._apply_header_evidence(finding, issue)
            findings.append(finding)
        return findings

    async def check_tls_https(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        parsed = urlsplit(self.target.url)
        hostname = parsed.hostname or ""
        is_lab_target = ActiveTargetGate.is_builtin_lab_target(self.target.url) or ActiveTargetGate.is_loopback_host(hostname)
        surface = surfaces[0] if surfaces else {"id": "root", "url": self.target.url, "path": parsed.path or "/", "parameters": []}
        if not is_lab_target:
            tls = await self.probe_tls(hostname, parsed.port or 443)
            if tls.get("supports_tls12") or tls.get("supports_tls13"):
                if tls.get("certificate_ok", True):
                    return []
                command = f"openssl s_client -connect {hostname}:{parsed.port or 443} -servername {hostname} -tls1_2 </dev/null"
                diff = f"TLS handshake succeeded, but certificate validation failed: {tls.get('certificate_error')}"
                fake_resp = {"url": self.target.url, "status_code": None, "headers": {}, "body": "", "method": "OPENSSL"}
                finding = self.make_finding(
                    "TLS certificate validation failed",
                    "TLS and HTTPS",
                    "MEDIUM",
                    "HIGH",
                    "tls_https",
                    surface,
                    fake_resp,
                    diff,
                    "Expired, self-signed, or untrusted certificates can break secure transport guarantees.",
                    "Install a valid certificate from a trusted CA and renew it before expiry.",
                    "Repeat the OpenSSL command and confirm certificate verification succeeds.",
                )
                self._apply_tls_evidence(finding, command, diff, tls)
                return [finding]
            command = f"openssl s_client -connect {hostname}:{parsed.port or 443} -servername {hostname} -tls1_3 </dev/null"
            diff = f"TLS 1.2 and TLS 1.3 handshakes both failed: tls1.2={tls.get('tls12_error')}; tls1.3={tls.get('tls13_error')}"
            fake_resp = {"url": self.target.url, "status_code": None, "headers": {}, "body": "", "method": "OPENSSL"}
            finding = self.make_finding(
                "TLS 1.2/1.3 handshake could not be established",
                "TLS and HTTPS",
                "HIGH",
                "HIGH",
                "tls_https",
                surface,
                fake_resp,
                diff,
                "Clients may be unable to establish modern encrypted transport to this target.",
                "Enable TLS 1.2 or TLS 1.3 with a valid certificate and supported cipher suites.",
                "Repeat the OpenSSL TLS 1.2 and TLS 1.3 commands and confirm at least one handshake succeeds.",
            )
            self._apply_tls_evidence(finding, command, diff, tls)
            return [finding]
        lab_vulnerable = any(surface.get("vulnerable") for surface in surfaces) and self.authorization_context.get("authorization_status") == "TRAINING"
        if not lab_vulnerable:
            return []
        fake_resp = {"url": self.target.url, "status_code": None, "headers": {}, "body": ""}
        return [
            self.make_finding(
                "HTTPS transport enforcement is not demonstrated",
                "TLS and HTTPS",
                "LOW",
                "POTENTIAL",
                "tls_https",
                surface,
                fake_resp,
                "Lab marks scenario as vulnerable.",
                "Credentials and session data should not be sent over cleartext transport outside local training.",
                "Serve production targets over HTTPS and deploy HSTS after confirming all subresources use HTTPS.",
                "Repeat the scan using the HTTPS origin and confirm HSTS is present where applicable.",
            )
        ]

    @staticmethod
    def _same_origin_path(url: str, expected_url: str, expected_path: str) -> bool:
        parsed = urlsplit(url)
        expected = urlsplit(expected_url)
        return parsed.scheme == expected.scheme and parsed.netloc == expected.netloc and (parsed.path or "/") == expected_path

    @staticmethod
    def _valid_hsts(value: str) -> bool:
        if not value:
            return False
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.IGNORECASE)
        return bool(match and int(match.group(1)) > 0)

    @staticmethod
    def _weak_csp(value: str) -> bool:
        lowered = value.lower()
        return "'unsafe-inline'" in lowered or "*" in lowered or "default-src" not in lowered

    @staticmethod
    def _add_header_issue(
        grouped: dict[str, dict[str, Any]],
        host: str,
        header: str,
        title: str,
        confidence: str,
        url: str,
        evidence: str,
    ) -> None:
        signature = f"security_headers|{host}|{header}|{title.lower()}"
        issue = grouped.setdefault(
            signature,
            {
                "title": title,
                "header": header,
                "confidence": confidence,
                "affected_urls": [],
                "evidence": evidence,
                "signature": signature,
            },
        )
        if url not in issue["affected_urls"]:
            issue["affected_urls"].append(url)
        if confidence == "HIGH":
            issue["confidence"] = "HIGH"
        elif issue["confidence"] != "HIGH" and confidence == "MEDIUM":
            issue["confidence"] = "MEDIUM"

    def _apply_header_evidence(self, finding: dict[str, Any], issue: dict[str, Any]) -> None:
        url = str(issue["affected_urls"][0])
        header = str(issue["header"])
        command = f"curl -sI {_shell_quote(url)} | grep -i {_shell_quote(header)}"
        diff = (
            "--- expected\n"
            f"{header}: <valid value>\n"
            "+++ observed\n"
            f"{issue['evidence']}\n"
            f"Affected URLs: {', '.join(issue['affected_urls'])}"
        )
        verification_hash = hashlib.sha256(f"{issue['signature']}|{','.join(issue['affected_urls'])}|{issue['evidence']}".encode("utf-8", errors="ignore")).hexdigest()
        verification_result = {
            "confirmed": True,
            "confidence": issue["confidence"],
            "confidence_score": finding.get("confidence_score"),
            "stage": "header_evidence",
            "method": "header_presence_validation",
            "payload": header,
            "evidence_text": issue["evidence"],
            "reproduction_command": command,
            "request_response_diff": diff,
            "verification_hash": verification_hash,
            "request_id": finding.get("request_id"),
            "response_status": None,
            "evidence_ids": finding.get("_evidence_ids", []),
            "affected_urls": issue["affected_urls"],
            "evidence_signature": issue["signature"],
        }
        finding.update(
            {
                "reproduction_command": command,
                "request_response_diff": diff,
                "verification_hash": verification_hash,
                "verification_method": "header_presence_validation",
                "verification_stage": "header_evidence",
                "verification_result": verification_result,
                "affected_urls": issue["affected_urls"],
                "evidence_signature": issue["signature"],
            }
        )

    async def probe_tls(self, hostname: str, port: int = 443) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._probe_tls_sync, hostname, port)

    @staticmethod
    def _probe_tls_sync(hostname: str, port: int) -> dict[str, Any]:
        result: dict[str, Any] = {
            "supports_tls12": False,
            "supports_tls13": False,
            "certificate_ok": True,
            "certificate_error": None,
            "tls12_error": None,
            "tls13_error": None,
        }

        def handshake(version: ssl.TLSVersion) -> str | None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    return tls_sock.version()

        try:
            result["tls12_version"] = handshake(ssl.TLSVersion.TLSv1_2)
            result["supports_tls12"] = True
        except Exception as exc:
            result["tls12_error"] = str(exc)[:300]

        if hasattr(ssl.TLSVersion, "TLSv1_3"):
            try:
                result["tls13_version"] = handshake(ssl.TLSVersion.TLSv1_3)
                result["supports_tls13"] = True
            except Exception as exc:
                result["tls13_error"] = str(exc)[:300]

        if result["supports_tls12"] or result["supports_tls13"]:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        pass
            except ssl.SSLError as exc:
                result["certificate_ok"] = False
                result["certificate_error"] = str(exc)[:300]
            except Exception as exc:
                result["certificate_ok"] = False
                result["certificate_error"] = str(exc)[:300]
        return result

    def _apply_tls_evidence(self, finding: dict[str, Any], command: str, diff: str, tls: dict[str, Any]) -> None:
        verification_hash = hashlib.sha256(f"tls_https|{self.target.url}|{diff}|{json.dumps(tls, sort_keys=True, default=str)}".encode("utf-8", errors="ignore")).hexdigest()
        finding.update(
            {
                "reproduction_command": command,
                "request_response_diff": diff,
                "verification_hash": verification_hash,
                "verification_method": "openssl_tls_probe",
                "verification_stage": "tls_handshake",
                "verification_result": {
                    "confirmed": True,
                    "confidence": finding.get("confidence"),
                    "confidence_score": finding.get("confidence_score"),
                    "stage": "tls_handshake",
                    "method": "openssl_tls_probe",
                    "payload": command,
                    "evidence_text": diff,
                    "reproduction_command": command,
                    "request_response_diff": diff,
                    "verification_hash": verification_hash,
                    "request_id": finding.get("request_id"),
                    "response_status": None,
                    "evidence_ids": finding.get("_evidence_ids", []),
                    "tls": tls,
                },
            }
        )

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
                    await self.emit("control_observed", f"Rate limiting indicators observed: {', '.join(rate_limit_indicators)}", selected_module="rate_limiting", result="CONTROL_PRESENT")
                elif status in {200, 401, 403} and self.is_login_surface(surface):
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
            try:
                verification = await self.verifier.verify_command_timing(surface, "ip")
                if verification.confirmed:
                    findings.append(
                        self.make_finding(
                            "Command injection vulnerability detected",
                            "Command Injection",
                            "CRITICAL",
                            verification.confidence,
                            "command_injection",
                            surface,
                            {"url": self.with_parameter(surface, "ip", verification.payload), "status_code": 200},
                            verification.evidence_text,
                            "Remote code execution allows full server compromise.",
                            "Avoid shell invocation with user input; use safe APIs, argument arrays, allowlists, and timeouts.",
                            "Repeat the benign timing proof and confirm the delayed branch is impossible after remediation.",
                            parameter="ip",
                            evidence_records=verification.evidence_ids,
                            verification_result=verification,
                        )
                    )
            except Exception as exc:
                logger.warning("Command injection check failed for surface %s: %s", str(surface.get("id") or surface.get("path") or ""), exc)
        return findings

    async def check_ssti(self, surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for surface in surfaces[:1]:
            ssti_payloads = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]
            control_response = await self.client.request(
                "ssti", "GET", self.with_parameter(surface, "name", "PHANTOMSCAN_SSTI_CONTROL"),
                surface=str(surface.get("id", "")),
                safe_test_marker="ssti_control",
            )
            control_body = str(control_response.get("body", ""))
            for payload in ssti_payloads[:2]:
                try:
                    response = await self.client.request(
                        "ssti", "GET", self.with_parameter(surface, "name", payload),
                        surface=str(surface.get("id", "")),
                        safe_test_marker="ssti_probe",
                    )
                    body = str(response.get("body", ""))
                    if "49" in body and payload not in body and "49" not in control_body:
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
                    if "meta-data" in body or "root:" in body or "ssh" in body:
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
        confidence: str | float,
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
        verification_result: VerificationResult | None = None,
    ) -> dict[str, Any]:
        endpoint = str(response.get("url") or surface.get("url") or surface.get("path") or self.target.url)
        response_status = response.get("status_code")
        response_observed = response_status is not None
        request_id = str(response.get("_request_id") or (verification_result.request_id if verification_result else "") or uuid.uuid4().hex[:8])
        has_evidence = (bool(request_id) and response_observed) or bool(verification_result and verification_result.evidence_ids)
        confidence_score = self.confidence_score(verification_result, confidence, has_evidence)
        confidence_label = self.confidence_label(confidence_score)
        used_confidence = confidence_label if has_evidence else "LOW"
        used_severity = self.derived_severity(module, severity, confidence_score)
        reproduction_command = (
            verification_result.reproduction_command
            if verification_result
            else build_curl_command(str(response.get("method") or "GET"), endpoint)
        )
        verification_hash = verification_result.verification_hash if verification_result else hashlib.sha256(
            f"{module}|{endpoint}|{parameter or ''}|{request_id}|{ev_text}".encode("utf-8", errors="ignore")
        ).hexdigest()
        request_response_diff = verification_result.request_response_diff if verification_result else (
            "--- request\n"
            f"+++ request\nEndpoint: {endpoint}\nParameter: {parameter or self.first_parameter(surface, '')}\n"
            "--- response\n"
            f"+++ response\nStatus: {response_status}\nEvidence: {ev_text[:1000]}"
        )
        verification_payload = asdict(verification_result) if verification_result else {
            "confirmed": has_evidence,
            "confidence": used_confidence,
            "confidence_score": confidence_score,
            "stage": "observed_response" if response_observed else "unverified",
            "method": "response_evidence",
            "payload": "",
            "evidence_text": ev_text,
            "reproduction_command": reproduction_command,
            "request_response_diff": request_response_diff,
            "verification_hash": verification_hash,
            "request_id": request_id,
            "response_status": response_status,
            "evidence_ids": list(evidence_records or []),
        }
        evidence_note = f"Evidence request_id: {request_id}. " if request_id else "No request evidence recorded. "
        evidence_note += f"HTTP status: {response_status}. Surface: {surface.get('id', 'unknown')}."
        evidence_note += f" Validation: {ev_text}"
        if verification_result:
            evidence_note += (
                f" Verification stage: {verification_result.stage}."
                f" Method: {verification_result.method}."
                f" Confidence score: {confidence_score:.2f}."
                f" Verification hash: {verification_result.verification_hash}."
            )
        if not response_observed:
            evidence_note += " No response received."
            evidence_note += f" Error: {response.get('error', 'unknown')}" if response.get("error") else ""
        finding = build_finding(
            title=title,
            category=category,
            severity=used_severity,
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
                "request_id": request_id,
                "confidence_score": confidence_score,
                "confidence_label": confidence_label,
                "reproduction_command": reproduction_command,
                "request_response_diff": request_response_diff,
                "verification_hash": verification_hash,
                "verification_method": verification_result.method if verification_result else verification_payload["method"],
                "verification_stage": verification_result.stage if verification_result else verification_payload["stage"],
                "verification_result": verification_payload,
                "source_correlation": self.source_correlation_for(surface, module, parameter or self.first_parameter(surface, "")),
                "scan_id": self.scan_id,
            }
        )
        if verification_result:
            finding.update(
                {
                    "poc": {
                        "payload": verification_result.payload,
                        "method": verification_result.method,
                        "confirmed": verification_result.confirmed,
                    },
                }
            )
        if not response_observed and not has_evidence:
            finding.update({
                "confidence": "LOW",
                "evidence": f"{ev_text} No real HTTP response was recorded. {evidence_note}",
            })
        finding["_evidence_ids"] = list(evidence_records or [])
        if response.get("_evidence_id") and response.get("_evidence_id") not in finding["_evidence_ids"]:
            finding["_evidence_ids"].append(response.get("_evidence_id"))
        finding["_request_id"] = request_id
        finding["_evidence_id"] = response.get("_evidence_id")
        return finding

    def source_correlation_for(self, surface: dict[str, Any], module: str, parameter: str | None) -> dict[str, Any] | None:
        embedded = surface.get("source_correlation")
        if isinstance(embedded, dict):
            return embedded
        if surface.get("file_path") or surface.get("code_snippet"):
            return {
                "reachable": True,
                "indicator": "reachable_from_code",
                "file_path": surface.get("file_path"),
                "line_number": surface.get("line_number"),
                "code_snippet": surface.get("code_snippet"),
                "parameter": parameter,
            }
        sinks = self._dangerous_sinks()
        parameter_text = str(parameter or "").lower()
        for sink in sinks:
            sink_text = f"{sink.get('sink')} {sink.get('code_snippet')}".lower()
            if parameter_text and parameter_text in sink_text:
                return {**sink, "reachable": True, "indicator": "reachable_from_code", "parameter": parameter}
        return {"reachable": False, "indicator": "unreachable_or_not_mapped", "parameter": parameter} if parameter else None

    def _dangerous_sinks(self) -> list[dict[str, Any]]:
        if self._sink_cache is not None:
            return self._sink_cache
        root = Path(get_settings().clone_dir)
        if not root.exists() or not root.is_dir():
            self._sink_cache = []
            return self._sink_cache
        sink_re = re.compile(r"\b(exec|query|execute|innerHTML|dangerouslySetInnerHTML|document\.write|os\.system|subprocess)\b")
        suffixes = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb", ".go"}
        sinks: list[dict[str, Any]] = []
        scanned = 0
        try:
            for path in root.rglob("*"):
                if scanned >= 2000 or len(sinks) >= 200:
                    break
                if not path.is_file() or path.suffix.lower() not in suffixes:
                    continue
                scanned += 1
                try:
                    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                        match = sink_re.search(line)
                        if not match:
                            continue
                        sinks.append(
                            {
                                "file_path": str(path.relative_to(root)),
                                "line_number": line_number,
                                "code_snippet": line.strip()[:500],
                                "sink": match.group(1),
                            }
                        )
                        if len(sinks) >= 200:
                            break
                except OSError:
                    continue
        except OSError:
            sinks = []
        self._sink_cache = sinks
        return self._sink_cache

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

    async def baseline_response(self, module: str, surface: dict[str, Any], parameter: str, control_value: str) -> dict[str, Any]:
        target = self.surface_target(surface)
        parsed = urlsplit(urljoin(f"{self.target.origin}/", target) if target.startswith("/") else target)
        key = (module, str(surface.get("method") or "GET").upper(), parsed.path or "/")
        cached = self._baseline_cache.get(key)
        if cached is not None:
            return cached
        response = await self.client.request(
            module,
            "GET",
            self.with_parameter(surface, parameter, control_value),
            surface=str(surface.get("id", "")),
            safe_test_marker=control_value,
        )
        self._baseline_cache[key] = response
        return response

    def select_best_parameter(
        self,
        surface: dict[str, Any],
        *,
        default: str | None = None,
        vulnerability_type: str = "",
    ) -> str | None:
        candidates: dict[str, str] = {}

        def add(name: Any, value: Any = "") -> None:
            text = str(name or "").strip()
            if text and text not in candidates:
                candidates[text] = str(value or "")

        for parameter in surface.get("parameters") or []:
            if isinstance(parameter, dict):
                add(parameter.get("name") or parameter.get("key"), parameter.get("value") or parameter.get("example"))
            else:
                add(parameter)
        for key in ("query", "query_params", "body", "body_params", "body_parameters", "path_params", "path_parameters"):
            value = surface.get(key)
            if isinstance(value, dict):
                for name, param_value in value.items():
                    add(name, param_value)
            elif isinstance(value, list):
                for parameter in value:
                    if isinstance(parameter, dict):
                        add(parameter.get("name") or parameter.get("key"), parameter.get("value") or parameter.get("example"))
                    else:
                        add(parameter)
        target = self.surface_target(surface)
        for name, value in parse_qsl(urlsplit(target).query, keep_blank_values=True):
            add(name, value)

        if not candidates:
            return default

        common_impact = {"id", "user", "username", "file", "url", "q", "redirect", "path", "next", "return"}
        attack_hints = {
            "injection": {"customer", "account", "account_number", "id", "user", "username", "search", "query", "q", "filter", "sort", "where"},
            "xss": {"q", "search", "query", "message", "comment", "name", "title", "redirect", "next", "return", "url"},
        }.get(vulnerability_type, set())

        def score(item: tuple[str, str]) -> tuple[int, int, str]:
            parameter, value = item
            lower = parameter.lower()
            value_text = str(value or "")
            points = 0
            if lower in attack_hints:
                points += 70
            if vulnerability_type == "injection" and lower == "customer":
                points += 50
            if vulnerability_type == "injection" and lower == "id" and not value_text:
                points -= 25
            if vulnerability_type == "injection" and lower == "q":
                points -= 35
            if lower in common_impact:
                points += 35
            if any(token in lower for token in attack_hints):
                points += 15
            if value_text and not re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value_text.strip()):
                points += 25
            if len(value_text) >= 4:
                points += 10
            if not re.search(r"(?:^|_)(count|page|limit|offset|size|num|number)(?:$|_)", lower):
                points += 10
            if len(parameter) >= 4:
                points += 5
            return (points, len(value_text), parameter)

        return max(candidates.items(), key=score)[0]

    @staticmethod
    def first_parameter(surface: dict[str, Any], default: str) -> str:
        parameters = surface.get("parameters") or []
        return str(parameters[0]) if parameters else default

    @staticmethod
    def confidence_score(verification_result: VerificationResult | None, confidence: str | float, has_evidence: bool) -> float:
        if not has_evidence:
            return 0.2
        if verification_result is not None:
            return max(0.0, min(1.0, float(verification_result.confidence_score)))
        if isinstance(confidence, (int, float)):
            return max(0.0, min(1.0, float(confidence)))
        return {"CONFIRMED": 0.99, "HIGH": 0.91, "MEDIUM": 0.65, "LOW": 0.35, "POTENTIAL": 0.2}.get(str(confidence).upper(), 0.5)

    @staticmethod
    def confidence_label(confidence_score: float) -> str:
        settings = get_settings()
        high = max(0.0, min(1.0, float(settings.confidence_high)))
        medium = max(0.0, min(high, float(settings.confidence_medium)))
        if confidence_score >= high:
            return "HIGH"
        if confidence_score >= medium:
            return "MEDIUM"
        return "LOW"

    def confidence_label_for_scan(self, confidence_score: float) -> str:
        high = max(0.0, min(1.0, float(self.confidence_high_threshold)))
        medium = max(0.0, min(high, float(self.confidence_medium_threshold)))
        if confidence_score >= high:
            return "HIGH"
        if confidence_score >= medium:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def derived_severity(module: str, original: str, confidence_score: float) -> str:
        normalized = normalize_module(module)
        if normalized == "injection":
            return "CRITICAL" if confidence_score >= get_settings().confidence_high else "HIGH"
        if normalized == "xss":
            return "HIGH" if confidence_score >= get_settings().confidence_high else "MEDIUM"
        if normalized == "command_injection":
            return "CRITICAL" if confidence_score >= get_settings().confidence_high else "HIGH"
        return str(original or "INFO").upper()

    def derived_severity_for_scan(self, module: str, original: str, confidence_score: float) -> str:
        normalized = normalize_module(module)
        if normalized == "injection":
            return "CRITICAL" if confidence_score >= self.confidence_high_threshold else "HIGH"
        if normalized == "xss":
            return "HIGH" if confidence_score >= self.confidence_high_threshold else "MEDIUM"
        if normalized == "command_injection":
            return "CRITICAL" if confidence_score >= self.confidence_high_threshold else "HIGH"
        return str(original or "INFO").upper()


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
