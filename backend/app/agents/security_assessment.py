import base64
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Iterator
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from app.agents import Agent
from app.security import build_finding, mask_value, redact_sensitive, redact_url


Finding = dict[str, Any]


@dataclass(slots=True)
class _Capture:
    endpoint: str
    status: int | None
    headers: dict[str, str]
    body: str
    request_headers: dict[str, str]
    request_known: bool
    metadata: dict[str, Any]


@dataclass(slots=True)
class _Context:
    target_url: str
    scanner_output: dict[str, Any]
    shadow_output: dict[str, Any]
    captures: list[_Capture]
    text: str
    technologies: list[str]

    @classmethod
    def create(
        cls,
        target_url: str,
        scanner_output: dict[str, Any] | None,
        shadow_output: dict[str, Any] | None,
    ) -> "_Context":
        scanner = scanner_output or {}
        shadow = shadow_output or {}
        captures = _collect_captures(scanner, target_url) + _collect_captures(shadow, target_url)
        unique: list[_Capture] = []
        seen: set[tuple[Any, ...]] = set()
        for capture in captures:
            key = (
                capture.endpoint,
                capture.status,
                tuple(sorted(capture.headers.items())),
                tuple(sorted(capture.request_headers.items())),
                capture.body[:2048],
            )
            if key not in seen:
                seen.add(key)
                unique.append(capture)
        return cls(
            target_url=target_url,
            scanner_output=scanner,
            shadow_output=shadow,
            captures=unique,
            text=_flatten_text((scanner, shadow)),
            technologies=_collect_technologies((scanner, shadow)),
        )


def _walk_dicts(value: Any) -> Iterator[dict[str, Any]]:
    stack = [value]
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if id(item) in seen:
                continue
            seen.add(id(item))
            yield item
            stack.extend(item.values())
        elif isinstance(item, (list, tuple, set)):
            stack.extend(item)


def _flatten_text(value: Any, limit: int = 400_000) -> str:
    parts: list[str] = []
    size = 0
    stack = [value]
    seen: set[int] = set()
    while stack and size < limit:
        item = stack.pop()
        if isinstance(item, str):
            part = item[:20_000]
            parts.append(part)
            size += len(part)
        elif isinstance(item, dict):
            if id(item) in seen:
                continue
            seen.add(id(item))
            stack.extend(item.values())
        elif isinstance(item, (list, tuple, set)):
            stack.extend(item)
    return "\n".join(parts)[:limit]


def _headers(value: Any) -> dict[str, str]:
    normalized: dict[str, str] = {}
    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, (list, tuple)):
        pairs: list[tuple[Any, Any]] = []
        for item in value:
            if isinstance(item, dict) and "name" in item:
                pairs.append((item["name"], item.get("value", "")))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((item[0], item[1]))
        items = pairs
    else:
        return normalized
    for key, raw in items:
        name = str(key).strip().lower().replace("_", "-")
        if isinstance(raw, (list, tuple)):
            value_text = "\n".join(str(item) for item in raw)
        else:
            value_text = str(raw)
        normalized[name] = value_text[:50_000]
    return normalized


def _first(record: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def _as_status(value: Any) -> int | None:
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


def _as_body(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:200_000]
    try:
        return json.dumps(value, ensure_ascii=True, default=str)[:200_000]
    except (TypeError, ValueError):
        return str(value)[:200_000]


def _collect_captures(source: Any, target_url: str) -> list[_Capture]:
    captures: list[_Capture] = []
    seen: set[int] = set()

    def visit(
        value: Any,
        inherited_endpoint: str,
        inherited_request_headers: dict[str, str],
        inherited_request_known: bool,
        role: str = "generic",
    ) -> None:
        if isinstance(value, (list, tuple, set)):
            for item in value:
                visit(item, inherited_endpoint, inherited_request_headers, inherited_request_known, role)
            return
        if not isinstance(value, dict) or id(value) in seen:
            return
        seen.add(id(value))

        endpoint_value = _first(value, ("url", "endpoint", "request_url", "response_url", "path"))
        endpoint = str(endpoint_value) if isinstance(endpoint_value, (str, int)) else inherited_endpoint
        request_headers = dict(inherited_request_headers)
        request_known = inherited_request_known or "request_headers" in value
        direct_request_headers = _headers(value.get("request_headers"))
        if direct_request_headers or "request_headers" in value:
            request_headers = direct_request_headers

        request = value.get("request")
        if isinstance(request, dict):
            request_known = True
            request_endpoint = _first(request, ("url", "endpoint", "request_url", "path"))
            if isinstance(request_endpoint, (str, int)):
                endpoint = str(request_endpoint)
            nested_headers = _headers(request.get("headers"))
            if nested_headers or "headers" in request:
                request_headers = nested_headers

        response_headers_value = value.get("response_headers")
        if response_headers_value is None and role != "request":
            response_headers_value = value.get("headers")
        response_headers = _headers(response_headers_value)
        status = _as_status(_first(value, ("status_code", "http_status", "response_status", "status")))
        body_present = any(name in value for name in ("body", "response_body", "content", "text", "html"))
        body = _as_body(_first(value, ("body", "response_body", "content", "text", "html")))
        has_response = role != "request" and (
            response_headers_value is not None or body_present or status is not None
        )
        if has_response:
            captures.append(
                _Capture(
                    endpoint=endpoint,
                    status=status,
                    headers=response_headers,
                    body=body,
                    request_headers=request_headers,
                    request_known=request_known,
                    metadata=value,
                )
            )

        for key, child in value.items():
            if key == "request":
                visit(child, endpoint, request_headers, request_known, "request")
            elif key == "response":
                visit(child, endpoint, request_headers, request_known, "response")
            else:
                visit(child, endpoint, request_headers, request_known, role)

    visit(source, target_url, {}, False)
    return captures


def _collect_technologies(source: Any) -> list[str]:
    found: set[str] = set()
    scalar_keys = {
        "technology",
        "technologies",
        "framework",
        "frameworks",
        "software",
        "server",
        "x_powered_by",
        "x-powered-by",
    }
    collection_keys = {"dependencies", "dependency", "packages", "components", "libraries"}
    for record in _walk_dicts(source):
        for key, value in record.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {item.replace("-", "_") for item in scalar_keys}:
                values = value if isinstance(value, (list, tuple, set)) else [value]
                for item in values:
                    if isinstance(item, (str, int, float)) and str(item).strip():
                        found.add(str(item).strip()[:500])
            elif normalized in collection_keys and isinstance(value, dict):
                for name, version in value.items():
                    if isinstance(version, (str, int, float)):
                        found.add(f"{name} {version}"[:500])
    return sorted(found, key=str.lower)


def _safe_url(value: str) -> str:
    text = str(value)[:4000]
    try:
        parsed = urlsplit(text)
        netloc = parsed.netloc
        if "@" in netloc:
            userinfo, hostinfo = netloc.rsplit("@", 1)
            username, separator, password = userinfo.partition(":")
            masked = mask_value(username)
            if separator:
                masked = f"{masked}:{mask_value(password)}"
            netloc = f"{masked}@{hostinfo}"
        rebuilt = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
        return redact_sensitive(redact_url(rebuilt), 4000)
    except ValueError:
        return redact_sensitive(text, 4000)


def _scheme(endpoint: str, target_url: str) -> str:
    candidate = endpoint if "://" in endpoint else target_url
    try:
        return urlsplit(candidate).scheme.lower()
    except ValueError:
        return ""


def _path(endpoint: str) -> str:
    try:
        return urlsplit(endpoint).path.lower()
    except ValueError:
        return endpoint.lower().split("?", 1)[0]


def _query_secrets(endpoint: str) -> list[str]:
    sensitive = {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "jwt",
        "key",
        "password",
        "passwd",
        "secret",
        "session",
        "sessionid",
        "token",
    }
    try:
        return sorted(
            {
                name
                for name, value in parse_qsl(urlsplit(endpoint).query, keep_blank_values=True)
                if name.lower() in sensitive and value
            }
        )
    except ValueError:
        return []


def _label(value: Any, limit: int = 120) -> str:
    return re.sub(r"[^A-Za-z0-9_.:/ -]", "?", str(value))[:limit]


def _has_rate_limit_signal(headers: dict[str, str]) -> bool:
    return any(
        name == "retry-after" or name.startswith("ratelimit-") or name.startswith("x-ratelimit-")
        for name in headers
    )


def _is_password_page(body: str) -> bool:
    return bool(re.search(r"<input\b[^>]*\btype\s*=\s*['\"]?password\b", body, re.IGNORECASE))


def _is_api_capture(capture: _Capture) -> bool:
    content_type = capture.headers.get("content-type", "").lower()
    path = _path(capture.endpoint)
    return (
        "/api/" in path
        or path.startswith("/api")
        or "graphql" in path
        or "application/json" in content_type
        or capture.body.lstrip().startswith(("{", "["))
    )


def _is_cross_origin(origin: str, target_url: str) -> bool:
    if origin.lower() == "null":
        return True
    try:
        target = urlsplit(target_url if "://" in target_url else f"https://{target_url}")
        supplied = urlsplit(origin)
        return bool(supplied.netloc and supplied.netloc.lower() != target.netloc.lower())
    except ValueError:
        return False


def _record_endpoint(record: dict[str, Any], fallback: str) -> str:
    value = _first(record, ("url", "endpoint", "request_url", "path"))
    return str(value) if isinstance(value, (str, int)) else fallback


def _named_values(source: Any, key_name: str) -> list[Any]:
    values: list[Any] = []
    expected = key_name.lower().replace("-", "_")
    for record in _walk_dicts(source):
        for key, value in record.items():
            if str(key).lower().replace("-", "_") == expected:
                values.append(value)
    return values


class _AssessmentAgent(Agent, ABC):
    NAME: ClassVar[str]

    def __init__(self) -> None:
        super().__init__(self.NAME)

    async def run(
        self,
        target_url: str,
        scan_id: int,
        scanner_output: dict[str, Any] | None,
        shadow_output: dict[str, Any] | None = None,
    ) -> dict[str, list[Finding]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Analyzing captured data for {_safe_url(target_url)}")
        findings = await self.analyze(_Context.create(target_url, scanner_output, shadow_output))
        unique: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for finding in findings:
            key = (str(finding["title"]), str(finding["category"]), str(finding["endpoint"]))
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        self.status = "complete"
        await self.log_action("completed", f"Completed pure analysis with {len(unique)} findings")
        return {"findings": unique}

    @abstractmethod
    async def analyze(self, context: _Context) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        context: _Context,
        *,
        title: str,
        category: str,
        severity: str,
        confidence: str,
        endpoint: str,
        evidence: str,
        impact: str,
        recommendation: str,
        verification: str,
        cve_id: str | None = None,
        cvss_score: float | None = None,
    ) -> Finding:
        return build_finding(
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            target=_safe_url(context.target_url),
            endpoint=_safe_url(endpoint),
            evidence=redact_sensitive(evidence),
            impact=impact,
            recommendation=recommendation,
            verification=verification,
            agent=self.name,
            cve_id=cve_id,
            cvss_score=cvss_score,
        )


class AuthSecurityAgent(_AssessmentAgent):
    NAME = "Authentication Security Agent"
    _AUTH_PATH = re.compile(r"(?:^|[/_.-])(login|sign-?in|auth|oauth|token)(?:$|[/_.?-])", re.IGNORECASE)

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in {context.target_url, *(capture.endpoint for capture in context.captures)}:
            names = _query_secrets(endpoint)
            if names:
                findings.append(self.finding(
                    context, title="Credential-like value placed in URL query", category="Authentication Security",
                    severity="MEDIUM", confidence="HIGH", endpoint=endpoint,
                    evidence=f"Captured URL contains populated credential-like parameter(s): {', '.join(_label(name) for name in names)}. Values are masked.",
                    impact="URL credentials can leak through logs, browser history, analytics, and referrer data.",
                    recommendation="Send credentials in a protected request body or authorization header and invalidate exposed values.",
                    verification="Confirm authentication flows no longer place secrets in URLs and review relevant logs for masked historical values.",
                ))

        for capture in context.captures:
            is_password_page = _is_password_page(capture.body)
            if is_password_page and _scheme(capture.endpoint, context.target_url) == "http":
                findings.append(self.finding(
                    context, title="Password form served over cleartext HTTP", category="Authentication Security",
                    severity="HIGH", confidence="HIGH", endpoint=capture.endpoint,
                    evidence=f"A captured HTTP {capture.status or 'response'} contains a password input and uses the http scheme.",
                    impact="Credentials can be observed or modified by an on-path attacker.",
                    recommendation="Redirect all HTTP traffic to HTTPS and submit credentials only over TLS.",
                    verification="Load the captured endpoint over HTTP and confirm it redirects to HTTPS before any credential form is served.",
                ))
            challenge = capture.headers.get("www-authenticate", "")
            if challenge.lower().lstrip().startswith("basic") and _scheme(capture.endpoint, context.target_url) == "http":
                findings.append(self.finding(
                    context, title="HTTP Basic authentication offered without TLS", category="Authentication Security",
                    severity="HIGH", confidence="HIGH", endpoint=capture.endpoint,
                    evidence="The captured response advertises a Basic authentication challenge on a cleartext HTTP endpoint.",
                    impact="Basic credentials are only encoded and can be intercepted without transport encryption.",
                    recommendation="Require HTTPS before authentication and disable cleartext access to the protected realm.",
                    verification="Confirm cleartext requests redirect before a WWW-Authenticate: Basic challenge is returned.",
                ))
            auth_surface = bool(self._AUTH_PATH.search(_path(capture.endpoint))) or is_password_page
            if auth_surface and capture.headers and capture.status in {200, 401, 403} and not _has_rate_limit_signal(capture.headers):
                findings.append(self.finding(
                    context, title="Authentication throttling is not visible in captured response", category="Authentication Security",
                    severity="LOW", confidence="POTENTIAL", endpoint=capture.endpoint,
                    evidence="A captured authentication response has no Retry-After or standard rate-limit headers; one response cannot prove throttling is absent.",
                    impact="If no server-side throttling exists, automated credential attacks may be easier.",
                    recommendation="Apply per-account and per-source throttling, progressive delays, and abuse monitoring.",
                    verification="With authorization, perform a low-volume repeated-login test and confirm documented throttling or HTTP 429 behavior.",
                ))
        return findings


class AccessControlAgent(_AssessmentAgent):
    NAME = "Access Control Agent"
    _SENSITIVE_PATH = re.compile(r"/(admin|manage|internal|debug|actuator|dashboard|accounts?|users?)(?:/|$)", re.IGNORECASE)

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        for record in _walk_dicts((context.scanner_output, context.shadow_output)):
            flags = [
                key for key in ("authorization_bypass", "access_control_bypass", "unauthorized_access", "idor", "bola")
                if record.get(key) is True
            ]
            if flags:
                findings.append(self.finding(
                    context, title="Captured scanner result indicates an authorization bypass", category="Access Control",
                    severity="HIGH", confidence="HIGH", endpoint=_record_endpoint(record, context.target_url),
                    evidence=f"Supplied scanner metadata explicitly marks {', '.join(flags)} as true; no request was replayed by this agent.",
                    impact="An unauthorized user may access another user's object or a privileged function.",
                    recommendation="Enforce object and function authorization server-side on every request and deny by default.",
                    verification="Reproduce the supplied case with two approved test identities and confirm the unauthorized identity receives 403 without data.",
                ))

        for capture in context.captures:
            path = _path(capture.endpoint)
            explicit_unauthenticated = any(
                capture.metadata.get(key) is False
                for key in ("authenticated", "is_authenticated", "has_credentials")
            )
            no_request_credentials = capture.request_known and not any(
                name in capture.request_headers for name in ("authorization", "cookie", "x-api-key", "proxy-authorization")
            )
            if (
                capture.status == 200
                and self._SENSITIVE_PATH.search(path)
                and (explicit_unauthenticated or no_request_credentials)
                and not _is_password_page(capture.body)
            ):
                findings.append(self.finding(
                    context, title="Sensitive route may be accessible without authentication", category="Access Control",
                    severity="MEDIUM", confidence="MEDIUM", endpoint=capture.endpoint,
                    evidence="A sensitive-looking route returned HTTP 200 and supplied request metadata contains no authentication credential. Route naming alone does not prove protected content was exposed.",
                    impact="If privileged content is present, unauthenticated users may reach protected data or functions.",
                    recommendation="Require authentication and role/object authorization for the route and its backing API operations.",
                    verification="Request the route with no credentials and a least-privileged approved account; confirm protected content is denied.",
                ))

            origin = capture.request_headers.get("origin", "").strip()
            allowed_origin = capture.headers.get("access-control-allow-origin", "").strip()
            credentials = capture.headers.get("access-control-allow-credentials", "").strip().lower()
            if origin and allowed_origin == origin and credentials == "true" and _is_cross_origin(origin, context.target_url):
                findings.append(self.finding(
                    context, title="Credentialed cross-origin request origin was accepted", category="Access Control",
                    severity="HIGH", confidence="HIGH", endpoint=capture.endpoint,
                    evidence=f"The response echoed captured cross-origin Origin {_safe_url(origin)} while allowing credentials.",
                    impact="An untrusted origin may be able to read authenticated responses in a victim's browser.",
                    recommendation="Use an exact trusted-origin allowlist and never reflect arbitrary Origin values with credentials enabled.",
                    verification="Repeat with an untrusted test origin and confirm no matching allow-origin header is returned.",
                ))
        return findings


class ApiSecurityAgent(_AssessmentAgent):
    NAME = "API Security Agent"

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        for capture in context.captures:
            origin = capture.headers.get("access-control-allow-origin", "").strip()
            credentials = capture.headers.get("access-control-allow-credentials", "").strip().lower()
            if origin == "*":
                findings.append(self.finding(
                    context,
                    title="Credentialed CORS policy uses a wildcard origin" if credentials == "true" else "API response permits reads from any origin",
                    category="API Security", severity="MEDIUM" if credentials == "true" else "LOW",
                    confidence="MEDIUM", endpoint=capture.endpoint,
                    evidence=f"Captured response sets Access-Control-Allow-Origin: *{'; credentials are also enabled' if credentials == 'true' else ''}.",
                    impact="The policy may expose browser-readable API data to untrusted sites; conforming browsers reject the wildcard/credentials combination but it signals unsafe policy intent.",
                    recommendation="Allow only required trusted origins and enable credentials only for endpoints that need them.",
                    verification="Send approved requests from trusted and untrusted origins and confirm only trusted origins receive an allow-origin response.",
                ))

            advertised = " ".join((capture.headers.get("allow", ""), capture.headers.get("access-control-allow-methods", "")))
            methods = sorted(set(re.findall(r"\b(?:CONNECT|DELETE|PATCH|PUT|TRACE)\b", advertised.upper())))
            if methods and _is_api_capture(capture):
                findings.append(self.finding(
                    context, title="API advertises sensitive HTTP methods", category="API Security",
                    severity="MEDIUM" if "TRACE" in methods or "CONNECT" in methods else "LOW",
                    confidence="POTENTIAL", endpoint=capture.endpoint,
                    evidence=f"Captured method policy advertises: {', '.join(methods)}. Advertisement does not establish missing authorization.",
                    impact="Unneeded methods increase attack surface; state-changing methods are dangerous if authorization is inconsistent.",
                    recommendation="Disable unused methods and enforce authentication, object authorization, validation, and CSRF controls where applicable.",
                    verification="Confirm each advertised method is required and that unauthorized requests are rejected server-side.",
                ))

            body_lower = capture.body.lower()
            if "__schema" in body_lower and ("graphql" in _path(capture.endpoint) or '"data"' in body_lower):
                findings.append(self.finding(
                    context, title="GraphQL schema introspection data is exposed", category="API Security",
                    severity="LOW", confidence="HIGH", endpoint=capture.endpoint,
                    evidence="The captured GraphQL response contains __schema introspection data.",
                    impact="Unauthenticated schema details can simplify discovery of sensitive operations and types.",
                    recommendation="Restrict production introspection when appropriate and enforce authorization in every resolver.",
                    verification="Repeat an introspection query without credentials and confirm it is rejected or intentionally limited.",
                ))
            docs_path = any(item in _path(capture.endpoint) for item in ("/swagger", "/openapi", "/api-docs"))
            if capture.status == 200 and (docs_path or "swagger-ui" in body_lower) and ("openapi" in body_lower or "swagger" in body_lower):
                findings.append(self.finding(
                    context, title="API documentation is publicly reachable", category="API Security",
                    severity="LOW", confidence="POTENTIAL", endpoint=capture.endpoint,
                    evidence="A captured HTTP 200 response contains Swagger/OpenAPI documentation markers.",
                    impact="Public operation and schema details can reduce the effort required to map the API attack surface.",
                    recommendation="Publish only intended documentation and require appropriate access controls for private APIs.",
                    verification="Request the documentation without credentials and confirm its visibility matches the intended exposure policy.",
                ))
            stack_markers = ("traceback (most recent call last)", "stack trace:", '"exception":', " at java.")
            marker = next((item for item in stack_markers if item in body_lower), None)
            if marker and (capture.status is None or capture.status >= 500 or _is_api_capture(capture)):
                findings.append(self.finding(
                    context, title="Verbose API exception details are exposed", category="API Security",
                    severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                    evidence=f"Captured response contains the diagnostic marker {_label(marker)!r} with HTTP status {capture.status}.",
                    impact="Stack and exception details can reveal internal code paths, libraries, and data handling behavior.",
                    recommendation="Return generic client errors and retain detailed diagnostics only in access-controlled server logs.",
                    verification="Trigger a safe validation error and confirm the response omits stack and exception internals.",
                ))
        return findings


@dataclass(slots=True)
class _Cookie:
    name: str
    attributes: set[str]
    same_site: str
    jwt_value: bool


def _session_cookies(capture: _Capture) -> list[_Cookie]:
    raw_header = capture.headers.get("set-cookie", "")
    cookies: list[_Cookie] = []
    for line in raw_header.splitlines():
        parts = [part.strip() for part in line.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name, value = parts[0].split("=", 1)
        attributes: set[str] = set()
        same_site = ""
        for attribute in parts[1:]:
            key, separator, attribute_value = attribute.partition("=")
            attributes.add(key.strip().lower())
            if key.strip().lower() == "samesite" and separator:
                same_site = attribute_value.strip().lower()
        if re.search(r"(?:session|sess|sid|auth|token|jwt|remember|identity)", name, re.IGNORECASE) or value.startswith("eyJ"):
            cookies.append(_Cookie(_label(name, 80), attributes, same_site, value.startswith("eyJ")))
    return cookies


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\b")


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    decoded: list[dict[str, Any]] = []
    try:
        for part in token.split(".")[:2]:
            payload = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
            value = json.loads(payload.decode("utf-8"))
            if not isinstance(value, dict):
                return None
            decoded.append(value)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return decoded[0], decoded[1]


class SessionSecurityAgent(_AssessmentAgent):
    NAME = "Session Security Agent"

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        for capture in context.captures:
            for cookie in _session_cookies(capture):
                if "secure" not in cookie.attributes:
                    findings.append(self.finding(
                        context, title=f"Session cookie {cookie.name} lacks Secure", category="Session Security",
                        severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                        evidence=f"Captured Set-Cookie metadata for {cookie.name} omits Secure; the cookie value is not retained in evidence.",
                        impact="The browser may send the session cookie over an unencrypted request.",
                        recommendation="Set Secure on session cookies and enforce HTTPS across the application.",
                        verification="Inspect a new session response and confirm the cookie has Secure and is never sent over HTTP.",
                    ))
                if "httponly" not in cookie.attributes:
                    findings.append(self.finding(
                        context, title=f"Session cookie {cookie.name} lacks HttpOnly", category="Session Security",
                        severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                        evidence=f"Captured Set-Cookie metadata for {cookie.name} omits HttpOnly; the cookie value is masked.",
                        impact="Client-side script execution could read and exfiltrate the session token.",
                        recommendation="Set HttpOnly on every cookie that does not require JavaScript access.",
                        verification="Inspect a new session response and confirm the cookie has HttpOnly.",
                    ))
                if "samesite" not in cookie.attributes:
                    findings.append(self.finding(
                        context, title=f"Session cookie {cookie.name} lacks SameSite", category="Session Security",
                        severity="LOW", confidence="HIGH", endpoint=capture.endpoint,
                        evidence=f"Captured Set-Cookie metadata for {cookie.name} contains no SameSite attribute.",
                        impact="The cookie may accompany cross-site requests, increasing CSRF exposure depending on browser defaults and application behavior.",
                        recommendation="Set SameSite=Lax or Strict where possible; use None only with Secure and an explicit cross-site requirement.",
                        verification="Inspect a new session cookie and test that cross-site requests follow the intended SameSite policy.",
                    ))

            body_lower = capture.body.lower()
            if re.search(r"(?:local|session)storage\.setitem\s*\([^)]*(?:token|jwt|auth)", body_lower):
                findings.append(self.finding(
                    context, title="Client code stores an authentication token in Web Storage", category="Session Security",
                    severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                    evidence="Captured client code calls Web Storage for a token-like key; no token value is included.",
                    impact="Any script executing in the origin can read Web Storage tokens, increasing the impact of XSS.",
                    recommendation="Prefer short-lived sessions in Secure, HttpOnly cookies where the architecture permits and harden against XSS.",
                    verification="Review the login flow and confirm authentication tokens are absent from localStorage and sessionStorage.",
                ))

            for token in list(dict.fromkeys(_JWT_RE.findall(capture.body)))[:5]:
                decoded = _decode_jwt(token)
                if decoded is None:
                    continue
                header, claims = decoded
                if str(header.get("alg", "")).lower() == "none":
                    findings.append(self.finding(
                        context, title="Captured JWT declares the none algorithm", category="Session Security",
                        severity="HIGH", confidence="MEDIUM", endpoint=capture.endpoint,
                        evidence="A masked JWT-shaped value decodes locally to an alg value of none; server acceptance was not tested.",
                        impact="If accepted, unsigned tokens could permit identity or privilege forgery.",
                        recommendation="Reject none and unexpected algorithms and pin verification to an explicit asymmetric or symmetric algorithm.",
                        verification="Using an approved test token, confirm unsigned and algorithm-substituted JWTs are rejected.",
                    ))
                if "exp" not in claims:
                    findings.append(self.finding(
                        context, title="Captured JWT has no expiration claim", category="Session Security",
                        severity="MEDIUM", confidence="MEDIUM", endpoint=capture.endpoint,
                        evidence="A masked JWT-shaped value was decoded locally and its claim names do not include exp.",
                        impact="If used as an access token, it may remain usable indefinitely after theft.",
                        recommendation="Require and validate short expiration, issuer, audience, not-before, and token type claims.",
                        verification="Issue a test token and confirm missing or expired exp claims are rejected.",
                    ))

            if _JWT_RE.search(capture.body) and (
                "text/html" in capture.headers.get("content-type", "").lower() or "<html" in body_lower
            ):
                findings.append(self.finding(
                    context, title="JWT-like token embedded in HTML response", category="Session Security",
                    severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                    evidence="The captured HTML contains a JWT-shaped value, which is masked in all evidence.",
                    impact="Tokens embedded in HTML are exposed to client scripts, browser tooling, caching, and accidental disclosure.",
                    recommendation="Keep bearer tokens out of rendered HTML and use protected session storage appropriate to the application.",
                    verification="Load the page with a test account and confirm no token appears in HTML source or script data.",
                ))
        return findings


class InjectionAnalysisAgent(_AssessmentAgent):
    NAME = "Injection Analysis Agent"
    _ERRORS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("SQL/database", r"sql syntax|sqlstate\[|unterminated quoted string|ora-\d{5}|sqlite3?\.|pg_query\(|mysql_fetch"),
        ("server-side template", r"jinja2?\.exceptions|twig\\error|freemarker|template syntax error|undefinederror"),
        ("OS command", r"/bin/(?:ba)?sh:|cmd\.exe|not recognized as an internal or external command|subprocess\.calledprocesserror"),
        ("LDAP/XPath", r"ldap_search\(|invalid dn syntax|xpath exception|xpathexception"),
    )

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        for capture in context.captures:
            body_lower = capture.body.lower()
            for family, pattern in self._ERRORS:
                if re.search(pattern, body_lower):
                    findings.append(self.finding(
                        context, title=f"{family} error signature exposed", category="Injection Analysis",
                        severity="MEDIUM", confidence="MEDIUM", endpoint=capture.endpoint,
                        evidence=f"Captured response contains a recognized {family} diagnostic signature with HTTP status {capture.status}; this does not alone prove injection.",
                        impact="Detailed interpreter errors can reveal internals and may indicate untrusted input reaches a sensitive parser.",
                        recommendation="Use parameterized APIs, strict input validation, safe interpreter interfaces, and generic client error responses.",
                        verification="Replay the original approved input after remediation and confirm it is safely rejected without interpreter diagnostics.",
                    ))

            if re.search(r"(?m)^root:[^:\r\n]*:0:0:", capture.body):
                findings.append(self.finding(
                    context, title="Local account-file content indicator captured", category="Injection Analysis",
                    severity="HIGH", confidence="HIGH", endpoint=capture.endpoint,
                    evidence="The captured response contains a Unix account-file root record; this agent did not issue or replay a traversal request.",
                    impact="A file-read weakness could expose credentials, keys, configuration, or application source available to the service account.",
                    recommendation="Resolve paths beneath a fixed base, reject traversal and absolute paths, and avoid user-controlled filesystem access.",
                    verification="Repeat the supplied authorized case and confirm traversal input is rejected without local file content.",
                ))

            try:
                query = parse_qsl(urlsplit(capture.endpoint).query, keep_blank_values=True)
            except ValueError:
                query = []
            for name, value in query:
                suspicious = bool(re.search(r"(?:<script|['\"]\s*or\s+\d|\.\./|\{\{|\$\{|phantomscan)", value, re.IGNORECASE))
                if suspicious and value and value in capture.body:
                    findings.append(self.finding(
                        context, title="Injection probe marker is reflected without visible encoding", category="Injection Analysis",
                        severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                        evidence=f"The value of captured query parameter {_label(name)!r} appears verbatim in the response; the value itself is masked.",
                        impact="Depending on output context, unencoded reflection can enable script or markup injection.",
                        recommendation="Apply context-aware output encoding and validate input without relying on denylisted payloads.",
                        verification="Repeat with a harmless marker and confirm it is encoded for the exact HTML, attribute, URL, or script context.",
                    ))
        return findings


class InfrastructureAgent(_AssessmentAgent):
    NAME = "Infrastructure Agent"

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        header_captures = [capture for capture in context.captures if capture.headers]
        primary = max(header_captures, key=lambda item: len(item.headers), default=None)
        if primary is not None:
            headers = primary.headers
            csp = headers.get("content-security-policy", "").lower()
            checks = [
                (not csp, "Missing Content Security Policy", "MEDIUM", "No Content-Security-Policy header was captured.", "Deploy a restrictive, application-specific Content-Security-Policy."),
                (_scheme(primary.endpoint, context.target_url) == "https" and "strict-transport-security" not in headers, "Missing HTTP Strict Transport Security", "MEDIUM", "No Strict-Transport-Security header was captured on an HTTPS endpoint.", "Send Strict-Transport-Security with an appropriate max-age after validating HTTPS coverage."),
                ("x-frame-options" not in headers and "frame-ancestors" not in csp, "Missing frame embedding protection", "MEDIUM", "Neither X-Frame-Options nor CSP frame-ancestors was captured.", "Set CSP frame-ancestors or X-Frame-Options to the intended embedding policy."),
                (headers.get("x-content-type-options", "").lower() != "nosniff", "Missing MIME sniffing protection", "LOW", "X-Content-Type-Options: nosniff was not captured.", "Send X-Content-Type-Options: nosniff on application responses."),
            ]
            for condition, title, severity, evidence, recommendation in checks:
                if condition:
                    findings.append(self.finding(
                        context, title=title, category="Infrastructure Security", severity=severity,
                        confidence="HIGH", endpoint=primary.endpoint, evidence=evidence,
                        impact="Missing browser defense-in-depth controls can increase the impact of a separate content injection or UI-redress weakness.",
                        recommendation=recommendation,
                        verification="Capture the remediated response and confirm the header is present with the intended policy.",
                    ))
            if csp and ("'unsafe-eval'" in csp or ("'unsafe-inline'" in csp and "script-src" in csp)):
                has_nonce_or_dynamic = "'nonce-" in csp or "'strict-dynamic'" in csp
                findings.append(self.finding(
                    context, title="Content Security Policy permits unsafe script execution", category="Infrastructure Security",
                    severity="LOW" if has_nonce_or_dynamic else "MEDIUM", confidence="HIGH", endpoint=primary.endpoint,
                    evidence="The captured CSP script policy includes unsafe-inline or unsafe-eval; nonce and hash values are omitted from evidence." if not has_nonce_or_dynamic else "Nonce or strict-dynamic present; overrides unsafe-inline (CSP3 compliant).",
                    impact="The policy provides reduced protection if attacker-controlled script or markup reaches the page." if not has_nonce_or_dynamic else "Nonce/strict-dynamic mitigates inline script risk; residual legacy browser exposure.",
                    recommendation="Remove unsafe-eval and migrate inline scripts to nonces or hashes with narrowly scoped sources." if not has_nonce_or_dynamic else "Consider removing unsafe-inline for cleaner CSP.",
                    verification="Capture the policy after deployment and confirm scripts work without unsafe-eval or broad unsafe-inline allowances.",
                ))
            hsts = headers.get("strict-transport-security", "").lower()
            if hsts and ("max-age=0" in hsts or "max-age" not in hsts):
                findings.append(self.finding(
                    context, title="HTTP Strict Transport Security is disabled or invalid", category="Infrastructure Security",
                    severity="MEDIUM", confidence="HIGH", endpoint=primary.endpoint,
                    evidence="The captured Strict-Transport-Security policy has no effective positive max-age.",
                    impact="Browsers may not enforce HTTPS for subsequent visits, leaving downgrade opportunities.",
                    recommendation="Set a positive max-age after confirming complete HTTPS support and consider includeSubDomains.",
                    verification="Capture the HTTPS response and confirm a valid positive HSTS max-age.",
                ))
            disclosures = [
                f"{name}: {redact_sensitive(headers[name], 160)}"
                for name in ("server", "x-powered-by", "x-generator")
                if headers.get(name) and re.search(r"\d", headers[name])
            ]
            if disclosures:
                findings.append(self.finding(
                    context, title="Detailed technology versions disclosed in headers", category="Infrastructure Security",
                    severity="LOW", confidence="HIGH", endpoint=primary.endpoint,
                    evidence=f"Captured version-bearing headers: {'; '.join(disclosures)}.",
                    impact="Precise versions help an attacker prioritize version-specific exploits.",
                    recommendation="Remove unnecessary product/version headers without relying on obscurity as a primary control.",
                    verification="Capture a new response and confirm unnecessary version details are absent.",
                ))

        if _scheme(context.target_url, context.target_url) == "http":
            findings.append(self.finding(
                context, title="Target uses cleartext HTTP", category="Infrastructure Security",
                severity="HIGH", confidence="HIGH", endpoint=context.target_url,
                evidence="The supplied target URL explicitly uses the http scheme.",
                impact="Traffic can be observed and modified in transit, undermining confidentiality and integrity.",
                recommendation="Serve the application exclusively over HTTPS and redirect cleartext requests.",
                verification="Confirm the HTTP endpoint redirects to HTTPS and no sensitive content is served before redirecting.",
            ))

        risky_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 2375: "Docker", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}
        observed: set[int] = set()
        for value in _named_values((context.scanner_output, context.shadow_output), "open_ports"):
            items = value if isinstance(value, (list, tuple, set)) else [value]
            for item in items:
                try:
                    port = int(item)
                except (TypeError, ValueError):
                    continue
                if port in risky_ports:
                    observed.add(port)
        if observed:
            labels = ", ".join(f"{port}/{risky_ports[port]}" for port in sorted(observed))
            findings.append(self.finding(
                context, title="Sensitive service ports are externally observable", category="Infrastructure Security",
                severity="MEDIUM", confidence="MEDIUM", endpoint=context.target_url,
                evidence=f"Supplied reconnaissance lists open service port(s): {labels}. No service connection was made by this agent.",
                impact="Internet-exposed administrative or data services increase attack surface and may expose weakly protected interfaces.",
                recommendation="Restrict service ports to required trusted networks and enforce authentication, TLS, patching, and monitoring.",
                verification="Review firewall exposure and use an approved network vantage point to confirm only required ports remain reachable.",
            ))

        weak_protocols: set[str] = set()
        for key in ("tls_versions", "protocols", "supported_protocols"):
            for value in _named_values((context.scanner_output, context.shadow_output), key):
                text = " ".join(str(item) for item in value) if isinstance(value, (list, tuple, set)) else str(value)
                weak_protocols.update(re.findall(r"SSLv?[23]|TLSv?1\.(?:0|1)", text, re.IGNORECASE))
        if weak_protocols:
            findings.append(self.finding(
                context, title="Legacy TLS protocol support reported", category="Infrastructure Security",
                severity="MEDIUM", confidence="MEDIUM", endpoint=context.target_url,
                evidence=f"Supplied TLS data lists legacy protocol(s): {', '.join(sorted(weak_protocols))}.",
                impact="Legacy protocols expose clients to obsolete cryptography and downgrade risks.",
                recommendation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; prefer TLS 1.2 and 1.3.",
                verification="Repeat an approved TLS configuration scan and confirm legacy handshakes fail.",
            ))
        tls_versions_text = " ".join(str(v) for v in _named_values((context.scanner_output, context.shadow_output), "tls_versions"))
        if tls_versions_text and "TLSv1.3" not in tls_versions_text and "tlsv1.3" not in tls_versions_text.lower():
            findings.append(self.finding(
                context, title="TLS 1.3 is not supported", category="Infrastructure Security",
                severity="LOW", confidence="MEDIUM", endpoint=context.target_url,
                evidence="Captured TLS data does not report TLS 1.3 support.",
                impact="TLS 1.3 provides improved security and performance over TLS 1.2.",
                recommendation="Enable TLS 1.3 on the server and disable TLS 1.0/1.1.",
                verification="Capture a TLS handshake and confirm TLS 1.3 is offered.",
            ))
        tls_cert_text = " ".join(str(v) for v in _named_values((context.scanner_output, context.shadow_output), "certificate"))
        if tls_cert_text and "issuer" in tls_cert_text.lower():
            issuer_match = re.search(r"issuer.*?organizationName=([^,]+)", tls_cert_text, re.IGNORECASE)
            if issuer_match and issuer_match.group(1).strip().lower() in ("", "unknown"):
                findings.append(self.finding(
                    context, title="Certificate issuer information is missing or incomplete", category="Infrastructure Security",
                    severity="MEDIUM", confidence="MEDIUM", endpoint=context.target_url,
                    evidence="The captured certificate data has an empty or unknown issuer organization name.",
                    impact="Incomplete certificate chain validation can allow MITM attacks.",
                    recommendation="Ensure the full certificate chain is served and the issuer is properly configured.",
                    verification="Capture the certificate chain and confirm the issuer is a trusted CA.",
                ))
        for capture in context.captures:
            if re.search(r"<title>\s*index of\s*/|<h1>\s*index of\s*/", capture.body, re.IGNORECASE):
                findings.append(self.finding(
                    context, title="Directory listing is enabled", category="Infrastructure Security",
                    severity="LOW", confidence="HIGH", endpoint=capture.endpoint,
                    evidence=f"Captured HTTP {capture.status} response contains a standard directory-index marker.",
                    impact="Directory listings can disclose backups, source artifacts, and otherwise unlinked files.",
                    recommendation="Disable automatic directory indexes and explicitly publish only intended files.",
                    verification="Request the directory and confirm a listing is no longer returned.",
                ))
        return findings


class WebSocketSecurityAgent(_AssessmentAgent):
    NAME = "WebSocket Security Agent"
    _URL = re.compile(r"\bwss?://[^\s'\"<>\\]+", re.IGNORECASE)

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        socket_urls = sorted(set(self._URL.findall(context.text)))[:50]
        for endpoint in socket_urls:
            if endpoint.lower().startswith("ws://"):
                findings.append(self.finding(
                    context, title="Cleartext WebSocket endpoint referenced", category="WebSocket Security",
                    severity="HIGH" if _scheme(context.target_url, context.target_url) == "https" else "MEDIUM",
                    confidence="HIGH", endpoint=endpoint,
                    evidence="Captured content references a ws:// endpoint; query values are masked.",
                    impact="WebSocket messages and authentication material can be intercepted or modified in transit.",
                    recommendation="Use wss:// exclusively and enforce modern TLS for every WebSocket endpoint.",
                    verification="Inspect client configuration and confirm only wss:// connections are attempted.",
                ))
            names = _query_secrets(endpoint)
            if names:
                findings.append(self.finding(
                    context, title="WebSocket URL contains credential-like query data", category="WebSocket Security",
                    severity="HIGH", confidence="HIGH", endpoint=endpoint,
                    evidence=f"Captured WebSocket URL includes populated parameter(s) {', '.join(_label(name) for name in names)}; values are masked.",
                    impact="URL credentials can leak into logs, telemetry, browser history, and intermediary infrastructure.",
                    recommendation="Authenticate with a short-lived one-time handshake mechanism or protected cookie/header and scrub URL logs.",
                    verification="Confirm WebSocket connection URLs contain no reusable credentials.",
                ))

        for capture in context.captures:
            handshake = capture.status == 101 or capture.headers.get("upgrade", "").lower() == "websocket"
            if not handshake:
                continue
            origin = capture.request_headers.get("origin", "")
            if capture.status == 101 and origin and _is_cross_origin(origin, context.target_url):
                findings.append(self.finding(
                    context, title="Cross-origin WebSocket handshake was accepted", category="WebSocket Security",
                    severity="HIGH", confidence="HIGH", endpoint=capture.endpoint,
                    evidence=f"Captured HTTP 101 handshake accepted cross-origin Origin {_safe_url(origin)}.",
                    impact="If ambient cookies authenticate the socket, an untrusted site may establish a cross-site WebSocket session.",
                    recommendation="Validate Origin against an exact allowlist and require explicit authentication plus per-message authorization.",
                    verification="Attempt an approved handshake from an untrusted origin and confirm it is rejected before upgrade.",
                ))
            if capture.status == 101 and capture.request_known and not any(
                name in capture.request_headers for name in ("authorization", "cookie", "x-api-key")
            ):
                findings.append(self.finding(
                    context, title="WebSocket handshake has no visible authentication credential", category="WebSocket Security",
                    severity="LOW", confidence="POTENTIAL", endpoint=capture.endpoint,
                    evidence="A captured HTTP 101 request has explicit request-header metadata but no Authorization, Cookie, or API-key header.",
                    impact="If the channel is not intentionally public, unauthenticated clients may receive or send sensitive messages.",
                    recommendation="Authenticate during or immediately after the handshake and authorize every message and subscription.",
                    verification="Connect without credentials using an approved client and confirm sensitive operations remain unavailable.",
                ))
            ws_url = capture.endpoint
            if ws_url and ws_url.lower().startswith("ws://") and _scheme(context.target_url, context.target_url) == "https":
                findings.append(self.finding(
                    context, title="WebSocket endpoint uses cleartext ws:// on HTTPS page", category="WebSocket Security",
                    severity="HIGH", confidence="HIGH", endpoint=ws_url,
                    evidence="A captured WebSocket URL uses ws:// while the target is served over HTTPS.",
                    impact="WebSocket messages can be intercepted or modified in transit.",
                    recommendation="Use wss:// exclusively for WebSocket connections on HTTPS pages.",
                    verification="Inspect the client-side WebSocket configuration and confirm wss:// is used.",
                ))
        return findings


@dataclass(frozen=True, slots=True)
class _DependencyRule:
    name: str
    pattern: re.Pattern[str]
    minimum: tuple[int, ...]
    fixed: tuple[int, ...]
    severity: str
    cve_id: str | None
    cvss_score: float | None
    issue: str


_DEPENDENCY_RULES = (
    _DependencyRule("jQuery", re.compile(r"\bjquery(?:[./ @_-]+|\s+v)(\d+\.\d+(?:\.\d+)?)", re.I), (0,), (3, 5, 0), "MEDIUM", "CVE-2020-11022", 6.1, "known pre-3.5 HTML manipulation weaknesses"),
    _DependencyRule("Lodash", re.compile(r"\blodash(?:[./ @_-]+|\s+v)(\d+\.\d+(?:\.\d+)?)", re.I), (0,), (4, 17, 21), "HIGH", "CVE-2021-23337", 7.2, "a known command-injection-affected version range"),
    _DependencyRule("Log4j", re.compile(r"\blog4j(?:-core)?(?:[./ @_-]+|\s+v)(2\.\d+(?:\.\d+)?)", re.I), (2, 0, 0), (2, 15, 0), "CRITICAL", "CVE-2021-44228", 10.0, "the Log4Shell-affected version range"),
    _DependencyRule("AngularJS", re.compile(r"\bangular(?:js)?(?:\.min)?(?:[./ @_-]+|\s+v)(1\.\d+(?:\.\d+)?)", re.I), (1, 0, 0), (2, 0, 0), "MEDIUM", None, None, "the unsupported AngularJS 1.x line"),
)


def _version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _version_lt(left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) < right + (0,) * (width - len(right))


class DependencyAgent(_AssessmentAgent):
    NAME = "Dependency Agent"

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        dependency_text = "\n".join((*context.technologies, context.text))
        for rule in _DEPENDENCY_RULES:
            for match in rule.pattern.finditer(dependency_text):
                parsed = _version(match.group(1))
                if not _version_lt(parsed, rule.minimum) and _version_lt(parsed, rule.fixed):
                    findings.append(self.finding(
                        context, title=f"Potentially vulnerable {rule.name} {match.group(1)} detected", category="Dependency Security",
                        severity=rule.severity, confidence="MEDIUM", endpoint=context.target_url,
                        evidence=f"Supplied technology, asset, or response data contains {rule.name} {match.group(1)}, which falls in {rule.issue}. Fingerprinting does not prove runtime reachability.",
                        impact="An affected and reachable dependency may expose the application to publicly documented attacks.",
                        recommendation=f"Upgrade {rule.name} to a currently supported release and verify transitive copies are also removed.",
                        verification="Generate a software bill of materials and confirm no deployed artifact contains the affected version.",
                        cve_id=rule.cve_id, cvss_score=rule.cvss_score,
                    ))

        manifest_names = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "requirements.txt", "pipfile.lock", "gemfile.lock")
        for capture in context.captures:
            path = _path(capture.endpoint)
            if capture.status == 200 and capture.body.strip() and path.endswith(manifest_names):
                findings.append(self.finding(
                    context, title="Dependency manifest is publicly retrievable", category="Dependency Security",
                    severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                    evidence=f"Captured HTTP 200 response serves dependency manifest {_label(path.rsplit('/', 1)[-1])}.",
                    impact="Exact direct and transitive versions simplify targeted vulnerability research and may disclose private package names.",
                    recommendation="Remove build manifests and lockfiles from public deployment artifacts unless deliberately published.",
                    verification="Request the manifest without credentials and confirm it is no longer served.",
                ))
            if capture.status == 200 and path.endswith(".map") and '"sourcescontent"' in capture.body.lower():
                findings.append(self.finding(
                    context, title="Source map exposes bundled source content", category="Dependency Security",
                    severity="MEDIUM", confidence="HIGH", endpoint=capture.endpoint,
                    evidence="A captured source-map response contains a sourcesContent field; source text is excluded from evidence.",
                    impact="Original source and dependency structure can reveal hidden routes, implementation details, and embedded secrets.",
                    recommendation="Do not publish production source maps containing source text, or protect them with appropriate access controls.",
                    verification="Request the map after deployment and confirm it is absent or contains no private source content.",
                ))
        return findings


def _whois_date(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value)
    match = re.search(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})", text)
    if not match:
        match = re.search(r"datetime(?:\.datetime)?\((20\d{2}),\s*(\d{1,2}),\s*(\d{1,2})", text)
    if not match:
        return None
    try:
        return datetime(*(int(part) for part in match.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None


class ThreatIntelligenceAgent(_AssessmentAgent):
    NAME = "Threat Intelligence Agent"
    _SENSITIVE_PATH = re.compile(r"(?:admin|backup|config|debug|internal|private|staging|\.env|\.git|\.sql|\.bak)", re.I)

    async def analyze(self, context: _Context) -> list[Finding]:
        findings: list[Finding] = []
        threat_flags: set[str] = set()
        for record in _walk_dicts((context.scanner_output, context.shadow_output)):
            for key in ("malicious", "blacklisted", "compromised", "phishing"):
                if record.get(key) is True:
                    threat_flags.add(key)
        if threat_flags:
            findings.append(self.finding(
                context, title="Supplied threat data flags the target", category="Threat Intelligence",
                severity="HIGH", confidence="HIGH", endpoint=context.target_url,
                evidence=f"Captured intelligence metadata explicitly marks: {', '.join(sorted(threat_flags))}. This agent performed no reputation lookup.",
                impact="A malicious or compromised classification may indicate active abuse, unsafe content, or loss of infrastructure control.",
                recommendation="Validate the source and timestamp of the intelligence, isolate affected assets, and begin incident triage.",
                verification="Corroborate the indicator through approved internal intelligence sources and document false-positive handling.",
            ))

        subdomains: set[str] = set()
        for value in _named_values((context.scanner_output, context.shadow_output), "subdomains"):
            items = value if isinstance(value, (list, tuple, set)) else [value]
            subdomains.update(str(item) for item in items if isinstance(item, str))
        exposed = sorted(
            host for host in subdomains
            if re.search(r"(?:^|\.)(?:dev|test|stage|staging|qa|uat|beta|old|admin|internal)\.", f".{host.lower()}")
        )
        if exposed:
            safe_hosts = ", ".join(redact_sensitive(host, 200) for host in exposed[:10])
            findings.append(self.finding(
                context, title="Non-production or administrative hostnames discovered", category="Threat Intelligence",
                severity="LOW", confidence="POTENTIAL", endpoint=context.target_url,
                evidence=f"Supplied reconnaissance includes sensitive-looking hostname(s): {safe_hosts}.",
                impact="Forgotten or less-hardened environments can expand the externally reachable attack surface.",
                recommendation="Inventory each hostname, retire unused systems, and apply production-equivalent access controls and patching.",
                verification="Confirm ownership, purpose, and access policy for every listed hostname.",
            ))

        robots = context.shadow_output.get("robots_txt")
        robots_body = str(robots.get("body", "")) if isinstance(robots, dict) else (robots if isinstance(robots, str) else "")
        if isinstance(robots, dict) and _as_status(robots.get("status_code")) == 200 or (isinstance(robots, str) and robots.strip()):
            paths = re.findall(r"(?im)^\s*(?:allow|disallow)\s*:\s*(\S+)", robots_body)
            sensitive_paths = [path for path in paths if self._SENSITIVE_PATH.search(path)]
            if sensitive_paths:
                evidence_paths = ", ".join(_safe_url(path) for path in sensitive_paths[:10])
                findings.append(self.finding(
                    context, title="robots.txt discloses sensitive-looking paths", category="Threat Intelligence",
                    severity="LOW", confidence="POTENTIAL", endpoint=str(robots.get("url", context.target_url)),
                    evidence=f"Captured robots.txt names path(s): {evidence_paths}. Disallow does not enforce access control.",
                    impact="Published path names can help attackers discover administrative, backup, or internal surfaces.",
                    recommendation="Remove unnecessary sensitive path hints and enforce authentication regardless of crawler directives.",
                    verification="Review each path without credentials and confirm it is absent or properly access controlled.",
                ))

        whois = context.shadow_output.get("whois")
        if isinstance(whois, dict):
            now = datetime.now(timezone.utc)
            created = next((_whois_date(whois.get(key)) for key in ("creation_date", "created", "registered_on") if whois.get(key)), None)
            expires = next((_whois_date(whois.get(key)) for key in ("expiration_date", "expires", "registry_expiry_date") if whois.get(key)), None)
            if created and 0 <= (now - created).days < 90:
                findings.append(self.finding(
                    context, title="Recently registered domain indicator", category="Threat Intelligence",
                    severity="LOW", confidence="POTENTIAL", endpoint=context.target_url,
                    evidence=f"Supplied WHOIS data reports creation date {created.date().isoformat()}, less than 90 days ago.",
                    impact="Recent registration is a contextual risk signal, not proof of malicious activity.",
                    recommendation="Correlate domain age with ownership, certificate, hosting, and internal asset records before taking action.",
                    verification="Validate the registration date against an approved authoritative WHOIS/RDAP source.",
                ))
            if expires and 0 <= (expires - now).days <= 30:
                findings.append(self.finding(
                    context, title="Domain registration expires soon", category="Threat Intelligence",
                    severity="MEDIUM", confidence="MEDIUM", endpoint=context.target_url,
                    evidence=f"Supplied WHOIS data reports expiration date {expires.date().isoformat()}, within 30 days.",
                    impact="Registration lapse can cause outage and may eventually enable hostile re-registration.",
                    recommendation="Confirm auto-renewal, registrar access, payment status, and registry lock with the domain owner.",
                    verification="Verify renewal status through the approved registrar account and authoritative registry data.",
                ))

        secret_markers = (
            ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
            ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
            ("live payment key", re.compile(r"\bsk_live_[A-Za-z0-9_-]{8,}\b", re.I)),
            ("assigned API key", re.compile(r"api[_-]?key\s*[:=]\s*['\"]?[^\s'\"]{6,}", re.I)),
            ("assigned password", re.compile(r"password\s*[:=]\s*['\"]?[^\s'\"]{4,}", re.I)),
        )
        for capture in context.captures:
            kinds = [name for name, pattern in secret_markers if pattern.search(capture.body)]
            if kinds:
                findings.append(self.finding(
                    context, title="Secret-like material appears in captured response", category="Threat Intelligence",
                    severity="HIGH", confidence="MEDIUM", endpoint=capture.endpoint,
                    evidence=f"Local pattern analysis detected {', '.join(kinds)}; all matched values are omitted and masked.",
                    impact="A valid exposed secret could permit unauthorized access to application or cloud resources.",
                    recommendation="Remove the material, rotate potentially exposed credentials, and inspect deployment history and logs.",
                    verification="Confirm the response no longer contains secret patterns and validate rotation through the owning secret manager.",
                ))
        return findings
