import asyncio
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx

from app.security import build_finding, redact_sensitive, redact_url
from app.services.asset_cache import asset_cache
from app.services.authorization import canonicalize_target
from app.services.execution import ExecutionBudget, ExecutionLimitError, SafetyLimits, ScanCancelled
from app.services.redaction import SecretRedactionService, redaction_service
from app.websockets import scan_event_broker

logger = logging.getLogger("phantomscan.browser_observation")


@dataclass
class BrowserSession:
    target: str
    mode: str
    authorization: dict[str, Any]
    browser_context: str
    cookies: list[dict[str, Any]] = field(default_factory=list)
    storage: dict[str, Any] = field(default_factory=dict)
    network_events: list[dict[str, Any]] = field(default_factory=list)
    console_events: list[dict[str, Any]] = field(default_factory=list)
    page_events: list[dict[str, Any]] = field(default_factory=list)
    websocket_events: list[dict[str, Any]] = field(default_factory=list)
    security_events: list[dict[str, Any]] = field(default_factory=list)


class ScanSafetyPolicy:
    def __init__(
        self,
        target_url: str,
        limits: SafetyLimits,
        *,
        authorization_context: dict[str, Any] | None = None,
        max_pages: int = 8,
    ) -> None:
        self.target = canonicalize_target(target_url)
        self.limits = limits
        self.authorization_context = authorization_context or {}
        self.max_pages = max(1, max_pages)
        self.page_count = 0
        self.repeated_server_errors = 0
        self.latency_spikes = 0
        self.safety_paused = False
        self.pause_reason: str | None = None
        self.events: list[dict[str, Any]] = []

    def assert_in_scope(self, url: str) -> None:
        if not self.is_in_scope(url):
            self.pause(f"Out-of-scope navigation blocked: {redact_url(url)}")
            raise ExecutionLimitError("Browser observation cannot leave the admitted target origin")

    def is_in_scope(self, url: str) -> bool:
        parsed = urlsplit(str(url))
        if parsed.scheme in {"ws", "wss"}:
            expected_host = urlsplit(self.target.origin).netloc.lower()
            return parsed.netloc.lower() == expected_host
        try:
            candidate = canonicalize_target(str(url))
        except Exception:
            return False
        return candidate.origin == self.target.origin

    def can_visit_page(self) -> bool:
        return not self.safety_paused and self.page_count < self.max_pages

    def reserve_page(self, url: str) -> None:
        self.assert_in_scope(url)
        if self.page_count >= self.max_pages:
            self.pause("Browser page limit reached")
            raise ExecutionLimitError("Browser page limit reached")
        self.page_count += 1

    def record_response(self, status_code: int | None, duration_ms: float, url: str) -> None:
        if status_code is not None and status_code >= 500:
            self.repeated_server_errors += 1
        if duration_ms > max(3000, self.limits.max_scan_duration * 100):
            self.latency_spikes += 1
        if self.repeated_server_errors >= 3:
            self.pause("Repeated server errors observed")
        if self.latency_spikes >= 3:
            self.pause("Repeated latency spikes observed")
        self.events.append(
            {
                "event": "response_observed",
                "url": redact_url(url),
                "status": status_code,
                "duration_ms": round(duration_ms, 2),
            }
        )

    def pause(self, reason: str) -> None:
        if self.safety_paused:
            return
        self.safety_paused = True
        self.pause_reason = reason
        self.events.append({"event": "SAFETY_PAUSE", "reason": reason})

    def snapshot(self) -> dict[str, Any]:
        return {
            "target_origin": self.target.origin,
            "max_pages": self.max_pages,
            "page_count": self.page_count,
            "safety_paused": self.safety_paused,
            "pause_reason": self.pause_reason,
            "repeated_server_errors": self.repeated_server_errors,
            "latency_spikes": self.latency_spikes,
            "events": self.events,
        }


def classify_network_request(url: str, method: str = "GET", resource_type: str = "", page_origin: str | None = None) -> str:
    parsed = urlsplit(str(url))
    path = parsed.path.lower()
    query_names = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    resource = resource_type.lower()
    if page_origin and parsed.scheme in {"http", "https"}:
        try:
            if canonicalize_target(url).origin != page_origin:
                third_party = True
            else:
                third_party = False
        except Exception:
            third_party = False
        if third_party and not any(token in parsed.netloc.lower() for token in ["google-analytics", "segment", "sentry", "stripe", "paypal"]):
            return "THIRD_PARTY"
    if parsed.scheme in {"ws", "wss"} or resource == "websocket":
        return "WEBSOCKET"
    if "graphql" in path:
        return "GRAPHQL"
    if any(token in path for token in ["login", "logout", "signin", "signup", "register", "password", "session", "token", "oauth", "mfa"]):
        return "AUTH"
    if any(token in parsed.netloc.lower() for token in ["google-analytics", "segment", "sentry", "mixpanel", "amplitude"]):
        return "ANALYTICS"
    if "/api/" in path or method.upper() not in {"GET", "HEAD"} or "api" in query_names:
        return "API"
    if resource in {"document", "main_frame"}:
        return "DOCUMENT"
    if resource in {"script"} or path.endswith(".js"):
        return "SCRIPT"
    if resource == "stylesheet" or path.endswith(".css"):
        return "STYLE"
    if resource == "image" or path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")):
        return "IMAGE"
    if resource == "font" or path.endswith((".woff", ".woff2", ".ttf", ".otf")):
        return "FONT"
    if resource in {"media"} or path.endswith((".mp4", ".webm", ".mp3", ".wav")):
        return "MEDIA"
    return "UNKNOWN"


def infer_json_schema(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "unknown"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        if not value:
            return ["unknown"]
        schemas = [infer_json_schema(item, depth + 1) for item in value[:5]]
        return [schemas[0]] if all(item == schemas[0] for item in schemas) else schemas
    if isinstance(value, dict):
        schema: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SecretRedactionService.SENSITIVE_KEYS or "token" in key_text.lower() or "password" in key_text.lower():
                schema[key_text] = "redacted_secret"
            else:
                schema[key_text] = infer_json_schema(item, depth + 1)
        return schema
    return type(value).__name__


def summarize_headers(headers: dict[str, Any]) -> dict[str, Any]:
    interesting = {
        "content-type",
        "cache-control",
        "pragma",
        "expires",
        "content-security-policy",
        "content-security-policy-report-only",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "location",
        "set-cookie",
    }
    return redaction_service.redact_headers({key: value for key, value in headers.items() if key.lower() in interesting})


def parse_cookie_metadata(headers: dict[str, Any]) -> list[dict[str, Any]]:
    raw_values: list[str] = []
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            raw_values.extend(str(value).split(", "))
    cookies: list[dict[str, Any]] = []
    for raw in raw_values:
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            cookies.append(
                {
                    "name": redaction_service.redact_text(name, 120),
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                    "domain": morsel["domain"] or None,
                    "path": morsel["path"] or None,
                    "expires": morsel["expires"] or None,
                }
            )
    return cookies


def parse_csp(headers: dict[str, Any]) -> dict[str, Any]:
    header = str(headers.get("content-security-policy") or headers.get("Content-Security-Policy") or "")
    report_only = str(headers.get("content-security-policy-report-only") or headers.get("Content-Security-Policy-Report-Only") or "")
    directives: dict[str, list[str]] = {}
    for chunk in header.split(";"):
        parts = chunk.strip().split()
        if not parts:
            continue
        directives[parts[0].lower()] = parts[1:]
    if not directives:
        return {"status": "missing", "directives": {}, "report_only": bool(report_only), "weaknesses": ["CSP header missing"]}
    weaknesses: list[str] = []
    script_src = directives.get("script-src") or directives.get("default-src") or []
    has_nonce_or_dynamic = any(v.startswith("'nonce-") or v == "'strict-dynamic'" for v in script_src)
    if "'unsafe-inline'" in script_src or "*" in script_src:
        if not has_nonce_or_dynamic:
            weaknesses.append("script-src allows unsafe inline or wildcard sources")
        else:
            weaknesses.append("script-src allows unsafe-inline but nonce/strict-dynamic mitigates risk")
    if "object-src" not in directives or "'none'" not in directives.get("object-src", []):
        weaknesses.append("object-src is not locked to 'none'")
    if "frame-ancestors" not in directives:
        weaknesses.append("frame-ancestors missing")
    status = "strong" if not weaknesses else "weak"
    return {"status": status, "directives": directives, "report_only": bool(report_only), "weaknesses": weaknesses}


class BrowserHTMLParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.forms: list[dict[str, Any]] = []
        self.inputs: list[dict[str, Any]] = []
        self.iframes: list[dict[str, Any]] = []
        self.scripts: list[dict[str, Any]] = []
        self.links: list[str] = []
        self.event_handlers: list[dict[str, Any]] = []
        self.inline_script_blocks: list[str] = []
        self.websocket_urls: list[str] = []
        self._current_form: dict[str, Any] | None = None
        self._in_script = False
        self._current_inline_script = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        for name, value in values.items():
            if name.startswith("on"):
                self.event_handlers.append({"page": self.page_url, "tag": tag, "handler": name, "value": redact_sensitive(value, 300)})
        if tag == "form":
            action = values.get("action") or self.page_url
            self._current_form = {
                "page": self.page_url,
                "action": urljoin(self.page_url, action),
                "method": (values.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag == "input":
            item = {
                "page": self.page_url,
                "name": values.get("name") or "",
                "type": (values.get("type") or "text").lower(),
                "autocomplete": values.get("autocomplete") or "",
                "hidden": (values.get("type") or "").lower() == "hidden",
            }
            self.inputs.append(item)
            if self._current_form is not None:
                self._current_form["inputs"].append(item)
        elif tag == "iframe":
            self.iframes.append(
                {
                    "page": self.page_url,
                    "src": redact_url(urljoin(self.page_url, values.get("src") or "")),
                    "sandbox": values.get("sandbox") or "",
                }
            )
        elif tag == "script":
            src = values.get("src")
            self._in_script = True
            self._current_inline_script = ""
            self.scripts.append(
                {
                    "page": self.page_url,
                    "src": urljoin(self.page_url, src) if src else None,
                    "inline": not bool(src),
                    "integrity": values.get("integrity") or None,
                    "crossorigin": values.get("crossorigin") or None,
                }
            )
        elif tag == "a":
            href = values.get("href")
            if href:
                self.links.append(urljoin(self.page_url, href))

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._current_inline_script += data
        for match in re.findall(r"wss?://[^\s'\"<>]+", data):
            self.websocket_urls.append(match)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        if tag == "script" and self._in_script:
            if self._current_inline_script.strip():
                self.inline_script_blocks.append(redact_sensitive(self._current_inline_script.strip(), 1500))
            self._in_script = False
            self._current_inline_script = ""


class DOMSecurityAgent:
    def extract(self, html: str, page_url: str) -> dict[str, Any]:
        parser = BrowserHTMLParser(page_url)
        parser.feed(html)
        return {
            "page": page_url,
            "forms": parser.forms,
            "inputs": parser.inputs,
            "hidden_inputs": [item for item in parser.inputs if item.get("hidden")],
            "iframes": parser.iframes,
            "scripts": parser.scripts,
            "links": parser.links,
            "event_handlers": parser.event_handlers,
            "inline_script_count": len(parser.inline_script_blocks),
            "inline_scripts": parser.inline_script_blocks[:5],
            "websocket_urls": parser.websocket_urls,
            "auth_forms": [form for form in parser.forms if any(input_item.get("type") == "password" for input_item in form.get("inputs", []))],
            "file_uploads": [item for item in parser.inputs if item.get("type") == "file"],
        }


class JavaScriptStaticAnalyzer:
    API_PATTERN = re.compile(r"[\"']((?:https?://[^\"']+)?/(?:api|graphql|auth|login|logout|users|orders|projects|documents)[^\"']*)[\"']", re.IGNORECASE)
    ROUTE_PATTERN = re.compile(r"[\"'](/(?:admin|dashboard|settings|reports|profile|login|logout|register|reset|orders|projects)[^\"']*)[\"']", re.IGNORECASE)
    WS_PATTERN = re.compile(r"[\"'](wss?://[^\"']+)[\"']", re.IGNORECASE)
    STORAGE_PATTERN = re.compile(r"(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\([\"']([^\"']+)[\"']", re.IGNORECASE)
    SINK_PATTERNS = {
        "HTML rendering": re.compile(r"\.innerHTML\s*=|insertAdjacentHTML\(|dangerouslySetInnerHTML", re.IGNORECASE),
        "URL assignment": re.compile(r"(?:location\.href|window\.location|\.src)\s*=", re.IGNORECASE),
        "script construction": re.compile(r"createElement\([\"']script[\"']\)|eval\(|new Function\(", re.IGNORECASE),
        "DOM insertion": re.compile(r"appendChild\(|replaceChildren\(|document\.write\(", re.IGNORECASE),
        "storage usage": re.compile(r"localStorage|sessionStorage|indexedDB", re.IGNORECASE),
        "navigation": re.compile(r"pushState\(|replaceState\(|router\.push|navigate\(", re.IGNORECASE),
    }

    def analyze(self, url: str, source: str) -> dict[str, Any]:
        text = redact_sensitive(source, 200_000)
        sinks = [name for name, pattern in self.SINK_PATTERNS.items() if pattern.search(text)]
        source_maps = re.findall(r"sourceMappingURL=([^\s*]+)", text)
        return {
            "url": redact_url(url),
            "api_endpoints": sorted(set(self.API_PATTERN.findall(text)))[:100],
            "routes": sorted(set(self.ROUTE_PATTERN.findall(text)))[:100],
            "websocket_urls": sorted(set(self.WS_PATTERN.findall(text)))[:50],
            "graphql_endpoints": sorted({item for item in self.API_PATTERN.findall(text) if "graphql" in item.lower()})[:20],
            "environment_identifiers": sorted(set(re.findall(r"\b(?:NODE_ENV|VITE_|REACT_APP_|NEXT_PUBLIC_)[A-Z0-9_]*", text)))[:50],
            "feature_flags": sorted(set(re.findall(r"\b(?:feature|flag)[A-Za-z0-9_:-]{2,}", text, re.IGNORECASE)))[:50],
            "third_party_domains": sorted(set(re.findall(r"https?://([^/'\"\s]+)", text)))[:80],
            "storage_keys": sorted(set(self.STORAGE_PATTERN.findall(text)))[:80],
            "auth_references": sorted(set(re.findall(r"\b(?:login|logout|token|session|oauth|mfa|password|authorization)\b", text, re.IGNORECASE)))[:80],
            "debug_references": sorted(set(re.findall(r"\b(?:debug|console\.(?:log|warn|error)|stacktrace|sourceMap)\b", text, re.IGNORECASE)))[:80],
            "source_map_references": source_maps[:20],
            "sink_classifications": sinks,
        }


class ClientDataFlowAnalyzer:
    def analyze(self, dom_pages: list[dict[str, Any]], network_events: list[dict[str, Any]], javascript: list[dict[str, Any]]) -> dict[str, Any]:
        api_urls = {event.get("url") for event in network_events if event.get("classification") in {"API", "AUTH", "GRAPHQL"}}
        form_flows = []
        for dom in dom_pages:
            for form in dom.get("forms", []):
                action = form.get("action")
                related_api = action if action in api_urls else None
                form_flows.append(
                    {
                        "page": dom.get("page"),
                        "input_names": [item.get("name") for item in form.get("inputs", []) if item.get("name")],
                        "handler": "form_submit",
                        "api_request": related_api or action,
                    }
                )
        response_to_dom = []
        sinks = sorted({sink for item in javascript for sink in item.get("sink_classifications", [])})
        if sinks and api_urls:
            response_to_dom.append({"api_response": "observed API traffic", "javascript_sinks": sinks, "dom_rendering": "potential client rendering surface"})
        return {"input_to_api": form_flows, "api_to_dom": response_to_dom, "sink_classifications": sinks}


class AuthenticationFlowAgent:
    def map_flow(self, pages: list[dict[str, Any]], network_events: list[dict[str, Any]], cookies: list[dict[str, Any]]) -> dict[str, Any]:
        steps: list[dict[str, Any]] = []
        for page in pages:
            url = str(page.get("url") or page.get("page") or "")
            if any(token in url.lower() for token in ["login", "signin", "register", "password", "logout"]):
                steps.append({"type": "page", "label": self.flow_label(url), "url": redact_url(url)})
        for event in network_events:
            if event.get("classification") == "AUTH":
                steps.append({"type": "api", "label": f"{event.get('method')} {urlsplit(str(event.get('url'))).path}", "url": event.get("url"), "status": event.get("status")})
        if cookies:
            steps.append({"type": "session", "label": "Session cookie observed", "cookie_count": len(cookies)})
        logout_seen = any("logout" in str(event.get("url", "")).lower() for event in network_events)
        return {
            "steps": steps,
            "session_created": bool(cookies),
            "logout_observed": logout_seen,
            "session_lifecycle": {
                "creation": "cookie_or_token_observed" if cookies else "not_observed",
                "refresh": "not_observed",
                "logout_invalidation": "observed" if logout_seen else "not_observed",
            },
        }

    @staticmethod
    def flow_label(url: str) -> str:
        path = urlsplit(url).path.lower()
        if "logout" in path:
            return "Logout"
        if "register" in path or "signup" in path:
            return "Registration"
        if "password" in path or "reset" in path:
            return "Password Reset"
        return "Login Page"


class EvidenceCorrelationEngine:
    def correlate(self, result: dict[str, Any], previous_findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        dom = result.get("dom", [])
        network = result.get("network_events", [])
        console = result.get("console_events", [])
        js = result.get("javascript", [])
        related: dict[str, Any] = {
            "external_script_origins": sorted(
                {
                    urlsplit(str(script.get("src"))).netloc
                    for page in dom
                    for script in page.get("scripts", [])
                    if script.get("src") and not result.get("safety", {}).get("target_origin", "") in str(script.get("src"))
                }
            ),
            "inline_script_blocks": sum(int(page.get("inline_script_count", 0)) for page in dom),
            "user_controlled_inputs": sum(len(page.get("inputs", [])) for page in dom),
            "api_calls": sum(1 for event in network if event.get("classification") in {"API", "AUTH", "GRAPHQL"}),
            "console_errors": sum(1 for event in console if str(event.get("type", "")).lower() in {"error", "warning"}),
            "javascript_sinks": sorted({sink for item in js for sink in item.get("sink_classifications", [])}),
            "previous_related_findings": len(previous_findings or []),
        }
        signals = sum(1 for value in related.values() if bool(value))
        confidence = "HIGH" if signals >= 3 else "MEDIUM" if signals == 2 else "LOW" if signals == 1 else "POTENTIAL"
        return {"related_observations": related, "independent_signal_count": signals, "confidence_hint": confidence}

    def enhance_findings(self, findings: list[dict[str, Any]], correlation: dict[str, Any]) -> list[dict[str, Any]]:
        related = correlation.get("related_observations", {})
        suffix = f" Related observations: {json.dumps(related, ensure_ascii=True, default=str)[:1600]}"
        enhanced = []
        for finding in findings:
            item = dict(finding)
            item["evidence"] = f"{item.get('evidence', '')}{suffix}"
            if item.get("confidence") in {"LOW", "POTENTIAL"} and correlation.get("independent_signal_count", 0) >= 3:
                item["confidence"] = "MEDIUM"
            enhanced.append(item)
        return enhanced


class BrowserObservationEngine:
    def __init__(
        self,
        *,
        target_url: str,
        mode: str,
        authorization_context: dict[str, Any],
        limits: SafetyLimits,
        scan_id: int,
        budget: ExecutionBudget | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        max_pages: int = 8,
        use_playwright: bool = True,
    ) -> None:
        self.target = canonicalize_target(target_url)
        self.mode = mode
        self.authorization_context = authorization_context
        self.limits = limits
        self.scan_id = scan_id
        self.budget = budget or ExecutionBudget(limits)
        self.transport = transport
        self.safety = ScanSafetyPolicy(target_url, limits, authorization_context=authorization_context, max_pages=max_pages)
        self.use_playwright = use_playwright
        self.dom_agent = DOMSecurityAgent()
        self.js_analyzer = JavaScriptStaticAnalyzer()
        self.dataflow_analyzer = ClientDataFlowAnalyzer()
        self.auth_agent = AuthenticationFlowAgent()
        self.correlation_engine = EvidenceCorrelationEngine()

    async def run(self) -> dict[str, Any]:
        session = BrowserSession(
            target=self.target.url,
            mode=self.mode,
            authorization=self.authorization_context,
            browser_context=f"browser-session-{self.scan_id}-{int(time.time())}",
        )
        result: dict[str, Any]
        try:
            self.budget.check()
            if self.use_playwright and self.transport is None and sys.platform == "win32":
                session.security_events.append({"event": "browser_fallback", "reason": "Playwright disabled on Windows; using HTTP observer"})
                result = await self.run_http_observation(session)
                result["browser_engine"] = "http_fallback"
                result["browser_fallback_reason"] = "Playwright disabled on Windows; using HTTP observer"
            elif self.use_playwright and self.transport is None:
                result = await self.run_playwright(session)
            else:
                result = await self.run_http_observation(session)
        except ScanCancelled as exc:
            return self.empty_result(session, "cancelled", str(exc))
        except Exception as exc:
            if self.use_playwright:
                logger.warning(
                    "Playwright browser observation failed for %s (engine=%s); falling back to HTTP observation: %s",
                    self.target.url,
                    "playwright_chromium",
                    redact_sensitive(str(exc), 1000),
                )
                session.security_events.append({"event": "browser_fallback", "reason": redact_sensitive(str(exc), 1000)})
                result = await self.run_http_observation(session)
                result["browser_engine"] = "http_fallback"
                result["browser_fallback_reason"] = redact_sensitive(str(exc), 1000)
            else:
                return self.empty_result(session, "error", str(exc))
        result["correlation"] = self.correlation_engine.correlate(result)
        result["findings"] = self.correlation_engine.enhance_findings(self.create_findings(result), result["correlation"])
        return redaction_service.redact_payload(result)

    async def run_playwright(self, session: BrowserSession) -> dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed") from exc

        pages: list[dict[str, Any]] = []
        dom_pages: list[dict[str, Any]] = []
        javascript: list[dict[str, Any]] = []
        source_maps: list[dict[str, Any]] = []
        screenshots: list[dict[str, Any]] = []
        browser = None
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            await context.add_init_script(
                """
                window.__phantomCspViolations = [];
                document.addEventListener('securitypolicyviolation', function (event) {
                  window.__phantomCspViolations.push({blockedURI: event.blockedURI, violatedDirective: event.violatedDirective, sourceFile: event.sourceFile, lineNumber: event.lineNumber});
                });
                """
            )
            page = await context.new_page()
            request_starts: dict[str, float] = {}
            page.on("console", lambda message: session.console_events.append(self.console_event(message.type, self.target.url, message.text, "browser")))
            page.on("pageerror", lambda error: session.console_events.append(self.console_event("error", self.target.url, str(error), "pageerror")))
            page.on("request", lambda request: request_starts.__setitem__(request.url, time.monotonic()))
            page.on("response", lambda response: asyncio.create_task(self.capture_playwright_response(response, request_starts, session)))
            page.on("requestfailed", lambda request: session.security_events.append({"event": "failed_resource_load", "url": redact_url(request.url), "failure": str(request.failure)}))
            page.on("websocket", lambda ws: self.capture_playwright_websocket(ws, session))
            self.safety.reserve_page(self.target.url)
            await page.goto(self.target.url, wait_until="domcontentloaded", timeout=min(self.limits.max_scan_duration, 30) * 1000)
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            content = await page.content()
            current_url = page.url
            self.safety.assert_in_scope(current_url)
            pages.append({"url": redact_url(current_url), "title": await page.title()})
            dom = self.dom_agent.extract(content, current_url)
            dom_pages.append(dom)
            session.page_events.append({"event": "page_visited", "url": redact_url(current_url), "title": pages[-1].get("title")})
            try:
                storage = await page.evaluate(
                    """() => ({
                    localStorage: Object.fromEntries(Object.entries(localStorage)),
                    sessionStorage: Object.fromEntries(Object.entries(sessionStorage))
                    })"""
                )
            except Exception:
                storage = {"localStorage": {}, "sessionStorage": {}}
            session.storage = self.safe_storage(storage)
            session.cookies = self.safe_playwright_cookies(await context.cookies())
            try:
                csp_violations = await page.evaluate("() => window.__phantomCspViolations || []")
            except Exception:
                csp_violations = []
            for violation in csp_violations:
                session.security_events.append({"event": "csp_violation", **redaction_service.redact_payload(violation)})
            try:
                screenshot = await page.screenshot(full_page=False)
                screenshots.append({"page": redact_url(current_url), "bytes": len(screenshot), "stored": False})
            except Exception:
                pass
            script_sources = [script.get("src") for script in dom.get("scripts", []) if script.get("src") and self.safety.is_in_scope(str(script.get("src")))]
            for index, script_url in enumerate(script_sources[:10], start=1):
                await self.publish_asset_progress(str(script_url), index, min(len(script_sources), 10))
                asset = await self.fetch_text(str(script_url), session, "script")
                if asset is None:
                    continue
                analysis = self.js_analyzer.analyze(str(script_url), asset)
                javascript.append(analysis)
                source_maps.extend(await self.fetch_source_maps(str(script_url), asset, session))
            await context.close()
            await browser.close()
        return self.compose_result(session, "complete", pages, dom_pages, javascript, source_maps, screenshots)

    async def capture_playwright_response(self, response: Any, starts: dict[str, float], session: BrowserSession) -> None:
        request = response.request
        started = starts.pop(request.url, time.monotonic())
        duration = (time.monotonic() - started) * 1000
        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        classification = classify_network_request(request.url, request.method, request.resource_type, self.target.origin)
        schema = None
        content_type = headers.get("content-type", "")
        if "json" in content_type and self.safety.is_in_scope(request.url):
            try:
                schema = infer_json_schema(json.loads(await response.text()))
            except Exception:
                schema = None
        event = {
            "url": redact_url(request.url),
            "method": request.method,
            "resource_type": request.resource_type,
            "classification": classification,
            "status": response.status,
            "content_type": content_type,
            "duration_ms": round(duration, 2),
            "initiator": "browser",
            "redirect_chain": self.playwright_redirect_chain(request),
            "request_headers_summary": {},
            "response_headers_summary": summarize_headers(headers),
            "authentication_state": self.authentication_state(headers),
            "response_schema": schema,
        }
        session.network_events.append(event)
        session.cookies.extend(parse_cookie_metadata(headers))
        self.safety.record_response(response.status, duration, request.url)

    def capture_playwright_websocket(self, websocket: Any, session: BrowserSession) -> None:
        event = {"url": redact_url(websocket.url), "connection_time": time.time(), "authentication_state": "unknown", "origin": self.target.origin, "messages": []}
        session.websocket_events.append(event)
        websocket.on("framesent", lambda payload: event["messages"].append(self.websocket_message("sent", payload)))
        websocket.on("framereceived", lambda payload: event["messages"].append(self.websocket_message("received", payload)))
        websocket.on("close", lambda: event.update({"disconnect_behavior": "closed"}))

    async def run_http_observation(self, session: BrowserSession) -> dict[str, Any]:
        pages: list[dict[str, Any]] = []
        dom_pages: list[dict[str, Any]] = []
        javascript: list[dict[str, Any]] = []
        source_maps: list[dict[str, Any]] = []
        screenshots: list[dict[str, Any]] = []
        queue = [self.target.url]
        seen: set[str] = set()
        async with httpx.AsyncClient(
            timeout=min(10.0, max(1.0, self.limits.max_scan_duration / 4)),
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
            headers={"User-Agent": "PhantomScan-BrowserObservation/1.0"},
        ) as client:
            while queue and self.safety.can_visit_page():
                self.budget.check()
                url = queue.pop(0)
                if url in seen or not self.safety.is_in_scope(url):
                    continue
                seen.add(url)
                self.safety.reserve_page(url)
                response = await self.safe_request(client, "GET", url, session, "document")
                if response is None:
                    continue
                body = str(response.get("body") or "")
                pages.append({"url": redact_url(url), "title": self.extract_title(body), "status": response.get("status")})
                session.page_events.append({"event": "page_visited", "url": redact_url(url), "status": response.get("status")})
                dom = self.dom_agent.extract(body, url)
                dom_pages.append(dom)
                for link in dom.get("links", [])[:20]:
                    if self.safety.is_in_scope(link) and link not in seen and len(queue) < self.safety.max_pages:
                        queue.append(link)
                for websocket_url in dom.get("websocket_urls", []):
                    session.websocket_events.append({"url": redact_url(websocket_url), "connection_time": None, "authentication_state": "not_connected", "origin": self.target.origin, "message_schema": None})
                scripts = dom.get("scripts", [])[:20]
                for index, script in enumerate(scripts, start=1):
                    script_url = script.get("src")
                    if not script_url:
                        continue
                    if not self.safety.is_in_scope(str(script_url)):
                        continue
                    await self.publish_asset_progress(str(script_url), index, len(scripts))
                    source = await self.fetch_text(str(script_url), session, "script", client)
                    if source is None:
                        continue
                    analysis = self.js_analyzer.analyze(str(script_url), source)
                    javascript.append(analysis)
                    for websocket_url in analysis.get("websocket_urls", []):
                        session.websocket_events.append({"url": redact_url(websocket_url), "connection_time": None, "authentication_state": "not_connected", "message_schema": None})
                    source_maps.extend(await self.fetch_source_maps(str(script_url), source, session, client))
        return self.compose_result(session, "complete", pages, dom_pages, javascript, source_maps, screenshots)

    async def safe_request(self, client: httpx.AsyncClient, method: str, url: str, session: BrowserSession, resource_type: str) -> dict[str, Any] | None:
        self.safety.assert_in_scope(url)
        request_number = await self.budget.reserve_request()
        started = time.monotonic()
        try:
            response = await client.request(method, url)
        except httpx.HTTPError as exc:
            session.security_events.append({"event": "failed_resource_load", "url": redact_url(url), "failure": redact_sensitive(str(exc), 1000)})
            return None
        duration = (time.monotonic() - started) * 1000
        headers = {key.lower(): value for key, value in response.headers.items()}
        classification = classify_network_request(url, method, resource_type, self.target.origin)
        body = response.text[: self.limits.max_response_size]
        schema = None
        if "json" in headers.get("content-type", ""):
            try:
                schema = infer_json_schema(response.json())
            except Exception:
                schema = None
        session.cookies.extend(parse_cookie_metadata(headers))
        session.network_events.append(
            {
                "url": redact_url(str(response.url)),
                "method": method,
                "resource_type": resource_type,
                "classification": classification,
                "status": response.status_code,
                "content_type": headers.get("content-type", ""),
                "duration_ms": round(duration, 2),
                "initiator": "browser_observer",
                "redirect_chain": [],
                "request_headers_summary": {"user-agent": "PhantomScan-BrowserObservation/1.0"},
                "response_headers_summary": summarize_headers(headers),
                "authentication_state": self.authentication_state(headers),
                "response_schema": schema,
                "request_count": request_number,
            }
        )
        self.safety.record_response(response.status_code, duration, url)
        if 300 <= response.status_code < 400:
            location = headers.get("location")
            if location:
                destination = urljoin(url, location)
                if not self.safety.is_in_scope(destination):
                    self.safety.pause(f"Unexpected redirect outside scope: {redact_url(destination)}")
                session.page_events.append({"event": "redirect_observed", "from": redact_url(url), "to": redact_url(destination), "status": response.status_code})
        return {"status": response.status_code, "headers": headers, "body": redact_sensitive(body, self.limits.max_response_size)}

    async def fetch_text(self, url: str, session: BrowserSession, resource_type: str, client: httpx.AsyncClient | None = None) -> str | None:
        if self.cacheable_asset(resource_type, url):
            cached = asset_cache.get(url)
            if cached is not None:
                session.security_events.append({"event": "asset_cache_hit", "url": redact_url(url), "resource_type": resource_type})
                return cached

        close_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False, headers={"User-Agent": "PhantomScan-BrowserObservation/1.0"})
            close_client = True
        try:
            response = await self.safe_request(client, "GET", url, session, resource_type)
        finally:
            if close_client:
                await client.aclose()
        if response is None:
            return None

        body = str(response.get("body") or "")
        if response.get("status") == 200 and self.cacheable_asset(resource_type, url):
            asset_cache.set(url, body)
        return body

    async def fetch_source_maps(self, script_url: str, source: str, session: BrowserSession, client: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
        maps = []
        for reference in re.findall(r"sourceMappingURL=([^\s*]+)", source)[:3]:
            map_url = urljoin(script_url, reference.strip())
            if not self.safety.is_in_scope(map_url):
                continue
            body = await self.fetch_text(map_url, session, "source_map", client)
            if body is None:
                continue
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {}
            maps.append(
                {
                    "script": redact_url(script_url),
                    "source_map": redact_url(map_url),
                    "sources": [redact_sensitive(str(item), 500) for item in parsed.get("sources", [])[:50]] if isinstance(parsed, dict) else [],
                    "exposed": True,
                }
            )
        return maps

    @staticmethod
    def cacheable_asset(resource_type: str, url: str) -> bool:
        parsed = urlsplit(url)
        path = parsed.path.lower()
        return resource_type in {"script", "source_map", "stylesheet", "style"} or path.endswith((".js", ".mjs", ".map", ".css"))

    async def publish_asset_progress(self, url: str, index: int, total: int) -> None:
        if total <= 0:
            return
        progress = 35 + int((index / total) * 10)
        try:
            await scan_event_broker.publish(
                self.scan_id,
                {
                    "type": "browser_asset_scan",
                    "phase": "asset_scan",
                    "message": f"Checking {redact_url(url)}",
                    "progress": min(45, progress),
                },
            )
        except Exception:
            logger.debug("Browser asset progress publish failed", exc_info=True)

    def compose_result(
        self,
        session: BrowserSession,
        status: str,
        pages: list[dict[str, Any]],
        dom_pages: list[dict[str, Any]],
        javascript: list[dict[str, Any]],
        source_maps: list[dict[str, Any]],
        screenshots: list[dict[str, Any]],
    ) -> dict[str, Any]:
        api_inventory = self.api_inventory(session.network_events)
        csp = [parse_csp(event.get("response_headers_summary", {})) for event in session.network_events if event.get("classification") == "DOCUMENT"]
        storage = self.analyze_storage(session.storage)
        auth_flow = self.auth_agent.map_flow(pages, session.network_events, session.cookies)
        dataflow = self.dataflow_analyzer.analyze(dom_pages, session.network_events, javascript)
        technologies = self.third_party_inventory(dom_pages, javascript)
        return {
            "status": status,
            "target_url": self.target.url,
            "browser_engine": "playwright_chromium" if self.use_playwright and self.transport is None else "http_observer",
            "session": asdict(session),
            "pages": pages,
            "routes": self.discover_routes(dom_pages, javascript),
            "dom": dom_pages,
            "network_events": session.network_events,
            "console_events": session.console_events,
            "api_inventory": api_inventory,
            "storage": storage,
            "cookies": self.dedupe_cookies(session.cookies),
            "csp": csp,
            "csp_violations": [event for event in session.security_events if event.get("event") == "csp_violation"],
            "javascript": javascript,
            "source_maps": source_maps,
            "auth_flow": auth_flow,
            "websockets": session.websocket_events,
            "service_workers": [],
            "cache": self.cache_analysis(session.network_events),
            "third_party": technologies,
            "dataflow": dataflow,
            "screenshots": screenshots,
            "safety": self.safety.snapshot(),
            "request_count": self.budget.request_count,
            "findings": [],
        }

    def empty_result(self, session: BrowserSession, status: str, error: str) -> dict[str, Any]:
        return {
            "status": status,
            "target_url": self.target.url,
            "browser_engine": "none",
            "session": asdict(session),
            "pages": [],
            "routes": [],
            "dom": [],
            "network_events": [],
            "console_events": [],
            "api_inventory": [],
            "storage": {},
            "cookies": [],
            "csp": [],
            "csp_violations": [],
            "javascript": [],
            "source_maps": [],
            "auth_flow": {"steps": []},
            "websockets": [],
            "service_workers": [],
            "cache": [],
            "third_party": [],
            "dataflow": {},
            "screenshots": [],
            "safety": self.safety.snapshot(),
            "request_count": self.budget.request_count,
            "findings": [],
            "error": redact_sensitive(error, 1000),
        }

    def create_findings(self, result: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for event in result.get("console_events", []):
            text = f"{event.get('type')} {event.get('message')}".lower()
            if any(token in text for token in ["stack", "trace", "debug", "token", "auth", "csp", "mixed content", "internal"]):
                findings.append(
                    build_finding(
                        title="Security-relevant browser console output observed",
                        category="Browser Console",
                        severity="LOW",
                        confidence="MEDIUM",
                        target=self.target.url,
                        endpoint=str(event.get("page") or self.target.url),
                        evidence=f"Console {event.get('type')}: {event.get('message')}. Source: {event.get('source')}",
                        impact="Console output can expose implementation details or authentication failure behavior to users and attackers.",
                        recommendation="Remove development logging and ensure client-side errors are handled without sensitive diagnostic output.",
                        verification="Reload the page in PhantomScan Browser observation and confirm the console event is absent.",
                        agent="Browser Security Agent",
                        module="browser_console",
                        recommended_fix="Remove debug console output and sanitize client-side error handling.",
                    )
                )
                break
        for csp in result.get("csp", []):
            if csp.get("status") in {"missing", "weak"}:
                findings.append(
                    build_finding(
                        title="CSP missing or weak with browser-observed script surfaces",
                        category="CSP",
                        severity="LOW",
                        confidence="HIGH" if result.get("dom") else "MEDIUM",
                        target=self.target.url,
                        endpoint=self.target.url,
                        evidence=f"CSP status: {csp.get('status')}. Weaknesses: {', '.join(csp.get('weaknesses') or [])}.",
                        impact="Weak CSP increases the impact of client-side injection and third-party script compromise.",
                        recommendation="Deploy a restrictive CSP including script-src, object-src 'none', base-uri, frame-ancestors, and form-action.",
                        verification="Rerun Browser observation and confirm CSP parses as strong with no violation events.",
                        agent="Browser Security Agent",
                        module="csp_analysis",
                        recommended_fix="Define and enforce a restrictive Content-Security-Policy.",
                    )
                )
                break
        for cookie in result.get("cookies", []):
            if cookie.get("name") and (not cookie.get("secure") or not cookie.get("httponly") or not cookie.get("samesite")):
                findings.append(
                    build_finding(
                        title="Browser-observed cookie lacks hardened attributes",
                        category="Cookie Security",
                        severity="MEDIUM",
                        confidence="HIGH",
                        target=self.target.url,
                        endpoint=self.target.url,
                        evidence=f"Cookie {cookie.get('name')} flags: Secure={cookie.get('secure')}, HttpOnly={cookie.get('httponly')}, SameSite={cookie.get('samesite')}.",
                        impact="Weak cookie flags can expose sessions to script access, cross-site requests, or cleartext transport.",
                        recommendation="Set Secure, HttpOnly, and SameSite on session cookies and scope Domain/Path narrowly.",
                        verification="Rerun Browser storage analysis and confirm hardened flags are present.",
                        agent="Browser Security Agent",
                        module="browser_storage",
                        recommended_fix="Harden all session cookies with Secure, HttpOnly, and SameSite.",
                    )
                )
                break
        if result.get("storage", {}).get("sensitive_client_storage"):
            findings.append(
                build_finding(
                    title="Sensitive-looking client storage key observed",
                    category="Browser Storage",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    target=self.target.url,
                    endpoint=self.target.url,
                    evidence=f"Sensitive storage metadata: {result['storage']['sensitive_client_storage']}.",
                    impact="Tokens or secrets in local/session storage are accessible to client-side script and may persist longer than intended.",
                    recommendation="Prefer HttpOnly cookies for session material and avoid storing secrets in browser storage.",
                    verification="Rerun Browser storage analysis and confirm sensitive keys are absent.",
                    agent="Browser Security Agent",
                    module="browser_storage",
                    recommended_fix="Move sensitive session state out of script-readable browser storage.",
                )
            )
        if result.get("source_maps"):
            findings.append(
                build_finding(
                    title="Source Map Exposure",
                    category="JavaScript Static Analysis",
                    severity="LOW",
                    confidence="CONFIRMED",
                    target=self.target.url,
                    endpoint=str(result["source_maps"][0].get("source_map") or self.target.url),
                    evidence=f"Public source map detected for {result['source_maps'][0].get('script')}.",
                    impact="Source maps can reveal frontend architecture, internal route names, and API references.",
                    recommendation="Disable public source-map publication for production builds or restrict access.",
                    verification="Request the source map URL after remediation and confirm it is not publicly accessible.",
                    agent="Browser Security Agent",
                    module="javascript_static_analysis",
                    recommended_fix="Remove public source map artifacts from production deployments.",
                )
            )
        sinks = result.get("dataflow", {}).get("sink_classifications", [])
        if sinks:
            findings.append(
                build_finding(
                    title="Potential Client Security Surface",
                    category="Client-Side Dataflow",
                    severity="INFO",
                    confidence="POTENTIAL",
                    target=self.target.url,
                    endpoint=self.target.url,
                    evidence=f"Statically observed JavaScript sink categories: {', '.join(sinks)}.",
                    impact="These patterns are not vulnerabilities by themselves but should be prioritized for output encoding and navigation review.",
                    recommendation="Review the identified client-side sinks and ensure user-controlled data is encoded or validated before use.",
                    verification="Review the affected JavaScript and rerun static browser analysis after changes.",
                    agent="Browser Security Agent",
                    module="client_dataflow",
                    recommended_fix="Add tests around client rendering/navigation sinks and enforce safe wrappers.",
                )
            )
        return findings

    def api_inventory(self, network_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        inventory: dict[tuple[str, str], dict[str, Any]] = {}
        for event in network_events:
            if event.get("classification") not in {"API", "AUTH", "GRAPHQL"}:
                continue
            parsed = urlsplit(str(event.get("url") or ""))
            key = (str(event.get("method") or "GET"), parsed.path)
            item = inventory.get(key) or {
                "endpoint": parsed.path,
                "method": key[0],
                "content_type": event.get("content_type"),
                "authentication": event.get("authentication_state"),
                "observed_parameters": [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)],
                "response_fields": [],
                "status_codes": [],
                "initiating_page": event.get("initiator"),
                "classification": event.get("classification"),
            }
            if event.get("status") not in item["status_codes"]:
                item["status_codes"].append(event.get("status"))
            schema = event.get("response_schema")
            if isinstance(schema, dict):
                item["response_fields"] = sorted(set(item["response_fields"]) | set(schema.keys()))
            inventory[key] = item
        return list(inventory.values())

    def analyze_storage(self, storage: dict[str, Any]) -> dict[str, Any]:
        sensitive = []
        safe_storage = redaction_service.redact_payload(storage)
        for area, values in (storage or {}).items():
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                text = f"{key} {value}".lower()
                if any(token in text for token in ["token", "jwt", "session", "password", "secret", "auth"]):
                    sensitive.append({"area": area, "key": redact_sensitive(str(key), 120), "value_type": infer_json_schema(value)})
        return {"localStorage": safe_storage.get("localStorage", {}), "sessionStorage": safe_storage.get("sessionStorage", {}), "indexedDB": {"metadata_observed": False}, "sensitive_client_storage": sensitive}

    @staticmethod
    def safe_storage(storage: dict[str, Any]) -> dict[str, Any]:
        return redaction_service.redact_payload(storage)

    @staticmethod
    def safe_playwright_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        safe = []
        for cookie in cookies:
            safe.append(
                {
                    "name": redact_sensitive(str(cookie.get("name") or ""), 120),
                    "secure": bool(cookie.get("secure")),
                    "httponly": bool(cookie.get("httpOnly")),
                    "samesite": cookie.get("sameSite"),
                    "domain": cookie.get("domain"),
                    "path": cookie.get("path"),
                    "expires": cookie.get("expires"),
                }
            )
        return safe

    @staticmethod
    def console_event(kind: str, page: str, message: str, source: str) -> dict[str, Any]:
        return {"page": redact_url(page), "timestamp": time.time(), "type": kind, "message": redact_sensitive(message, 2000), "source": source}

    @staticmethod
    def websocket_message(direction: str, payload: Any) -> dict[str, Any]:
        text = str(payload)
        try:
            schema = infer_json_schema(json.loads(text)) if text.startswith("{") else "string"
        except json.JSONDecodeError:
            schema = "string"
        return {"direction": direction, "schema": schema, "size": len(text)}

    @staticmethod
    def playwright_redirect_chain(request: Any) -> list[str]:
        chain = []
        current = getattr(request, "redirected_from", None)
        while current is not None and len(chain) < 10:
            chain.append(redact_url(str(current.url)))
            current = getattr(current, "redirected_from", None)
        return list(reversed(chain))

    @staticmethod
    def authentication_state(headers: dict[str, Any]) -> str:
        if any(key.lower() == "set-cookie" for key in headers):
            return "session_cookie_observed"
        if any("authorization" == key.lower() for key in headers):
            return "authorization_header_observed"
        return "unknown"

    @staticmethod
    def dedupe_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        unique = []
        for cookie in cookies:
            key = (cookie.get("name"), cookie.get("domain"), cookie.get("path"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(cookie)
        return unique

    @staticmethod
    def discover_routes(dom_pages: list[dict[str, Any]], javascript: list[dict[str, Any]]) -> list[dict[str, Any]]:
        routes: dict[str, dict[str, Any]] = {}
        for dom in dom_pages:
            page = dom.get("page")
            routes[str(page)] = {"route": page, "source": "browser_navigation"}
            for link in dom.get("links", [])[:50]:
                routes[str(link)] = {"route": redact_url(str(link)), "source": "dom_link"}
        for js in javascript:
            for route in js.get("routes", []):
                routes[str(route)] = {"route": route, "source": "javascript_static"}
        return list(routes.values())

    @staticmethod
    def cache_analysis(network_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results = []
        for event in network_events:
            headers = event.get("response_headers_summary", {})
            cache_control = str(headers.get("cache-control") or headers.get("Cache-Control") or "")
            if event.get("classification") in {"AUTH", "API"}:
                results.append(
                    {
                        "url": event.get("url"),
                        "classification": event.get("classification"),
                        "cache_control": cache_control or "not_present",
                        "sensitive_response_cacheable": bool(cache_control and "no-store" not in cache_control.lower() and "private" not in cache_control.lower()),
                    }
                )
        return results

    @staticmethod
    def third_party_inventory(dom_pages: list[dict[str, Any]], javascript: list[dict[str, Any]]) -> list[dict[str, Any]]:
        entries: dict[str, dict[str, Any]] = {}
        for dom in dom_pages:
            page = str(dom.get("page") or "")
            page_origin = urlsplit(page).netloc
            for script in dom.get("scripts", []):
                src = script.get("src")
                if not src:
                    continue
                domain = urlsplit(str(src)).netloc
                if domain and domain != page_origin:
                    entries[domain] = {
                        "domain": domain,
                        "resource": redact_url(str(src)),
                        "page": redact_url(page),
                        "purpose": BrowserObservationEngine.infer_third_party_purpose(domain),
                        "integrity": bool(script.get("integrity")),
                        "crossorigin": script.get("crossorigin"),
                    }
        for js in javascript:
            for domain in js.get("third_party_domains", []):
                entries.setdefault(domain, {"domain": domain, "resource": "javascript_reference", "page": js.get("url"), "purpose": BrowserObservationEngine.infer_third_party_purpose(domain)})
        return list(entries.values())

    @staticmethod
    def infer_third_party_purpose(domain: str) -> str:
        lowered = domain.lower()
        if "analytics" in lowered or "tagmanager" in lowered:
            return "analytics"
        if "stripe" in lowered or "paypal" in lowered:
            return "payments"
        if "sentry" in lowered or "datadog" in lowered:
            return "monitoring"
        if "cdn" in lowered or "cloudflare" in lowered or "jsdelivr" in lowered:
            return "cdn"
        return "unknown"

    @staticmethod
    def extract_title(html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return redact_sensitive(match.group(1).strip(), 200) if match else ""
