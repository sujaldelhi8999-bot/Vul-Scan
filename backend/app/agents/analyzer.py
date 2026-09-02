import asyncio
import logging
import random
import re
import ssl
import string
import warnings
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from app.agents import Agent
from app.ml.false_positive_filter import FalsePositiveFilter
from app.ml.risk_prioritizer import calculate_severity
from app.parsers.cookie_parser import parse_cookie_header
from app.scanner.http_client import build_http_client

logger = logging.getLogger("phantomscan.analyzer")


SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "XFO",
    "x-content-type-options": "XCTO",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
    "origin-agent-cluster": "OAC",
}

CSP_DANGEROUS_DIRECTIVES = {
    "unsafe-inline": "script-src allows inline scripts, weakening XSS protection",
    "unsafe-eval": "script-src allows eval(), enabling dynamic code execution",
    "unsafe-hashes": "script-src allows unsafe hashes, reducing CSP effectiveness",
    "unsafe-allow-redirects": "connect-src allows redirects, enabling SSRF risk",
    "data:": "script-src allows data: URIs, enabling inline script injection",
    "blob:": "script-src allows blob: URIs, enabling object URL injection",
    "filesystem:": "script-src allows filesystem: URIs",
}

CSP_MISSING_DIRECTIVES = {
    "default-src": "No default-src fallback; all resource types are unrestricted",
    "script-src": "No script-src directive; inline scripts and eval() are allowed by default",
    "style-src": "No style-src directive; inline styles are allowed by default",
    "img-src": "No img-src directive; images can be loaded from any origin",
    "font-src": "No font-src directive; fonts can be loaded from any origin",
    "connect-src": "No connect-src directive; fetch/XHR can target any origin",
    "frame-src": "No frame-src directive; frames can embed any origin",
    "media-src": "No media-src directive; audio/video can be loaded from any origin",
    "object-src": "No object-src directive; Flash/Java applets can be loaded from any origin",
    "base-uri": "No base-uri directive; base tag injection can redirect relative URLs",
    "form-action": "No form-action directive; forms can submit to any origin",
    "frame-ancestors": "No frame-ancestors directive; clickjacking is possible",
}

HSTS_MIN_MAX_AGE = 31536000


class AnalyzerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Analyzer Agent")

    async def run(
        self, target_url: str, scan_id: int,
        scanner_output: dict[str, Any] | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Analyzing {target_url}")

        findings: list[dict[str, Any]] = []

        page = await self._fetch_page(target_url, scanner_output)
        if page is None:
            # TLS/connection failure: record a single LOW informational
            # finding and skip ALL passive checks — a failed handshake tells
            # us nothing about the target's headers or cookies.
            logger.warning("TLS/connection failed for %s; skipping passive header checks", target_url)
            findings.append(self._finding(
                "Could not establish TLS connection", "TLS", "low",
                f"Failed to establish a verified HTTPS connection to {target_url}",
                "TLS may be misconfigured or the host may be unreachable",
                "Ensure HTTPS and a valid certificate are properly configured", target_url
            ))
        else:
            final_url = str(page["final_url"])
            logger.debug("Analyzing final URL after redirects: %s (status %s)", final_url, page["status_code"])

            try:
                fp_filter = FalsePositiveFilter()
            except Exception as exc:
                logger.debug("Soft-404 filter init failed: %s", exc)
                fp_filter = None
            if fp_filter is not None:
                await self._establish_soft404_baseline(final_url, fp_filter)

            if page["status_code"] in (404, 410):
                soft_404 = True
            elif fp_filter is not None:
                try:
                    soft_404 = fp_filter.is_soft_404(page["response"])
                except Exception as exc:
                    logger.debug("Soft-404 check failed: %s", exc)
                    soft_404 = False
            else:
                soft_404 = False

            if soft_404:
                logger.info(
                    "Page %s is a 404/soft-404; skipping passive header/cookie/CORS checks",
                    final_url,
                )
            else:
                headers = page["headers"]
                try:
                    findings.extend(self._check_headers(headers, final_url))
                except Exception:
                    logger.exception("Failed to check headers for %s", final_url)
                    raise

                try:
                    findings.extend(self._check_cookies(headers))
                except Exception:
                    logger.exception("Failed to check cookies for %s", final_url)
                    raise

                try:
                    findings.extend(self._check_info_leakage(headers))
                except Exception:
                    logger.exception("Failed to check info leakage for %s", final_url)
                    raise

                try:
                    findings.extend(await self._check_cors(final_url))
                except Exception:
                    logger.exception("Failed to check CORS for %s", final_url)
                    raise

                try:
                    findings.extend(await self._check_http_methods(final_url))
                except Exception:
                    logger.exception("Failed to check HTTP methods for %s", final_url)
                    raise

        if page is not None:
            try:
                findings.extend(await self._check_tls(str(page["final_url"])))
            except Exception:
                logger.exception("Failed to check TLS for %s", target_url)
                raise

        findings = await self._ml_postprocess(findings)

        self.status = "complete"
        await self.log_action("completed", f"Generated {len(findings)} findings")
        return {
            "findings": findings,
            "header_findings": [f for f in findings if f.get("category") == "Security Headers"],
            "cors_issues": [f for f in findings if f.get("category") == "CORS"],
            "cookie_issues": [f for f in findings if f.get("category") == "Cookies"],
            "tls_issues": [f for f in findings if f.get("category") == "TLS"],
            "info_leakage": [f for f in findings if f.get("category") == "Information Disclosure"],
            "http_method_issues": [f for f in findings if f.get("category") == "HTTP Methods"],
        }

    async def _fetch_page(
        self, target_url: str, scanner_output: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """Fetch the target page with redirects followed and TLS verified.

        Returns ``None`` when the connection/TLS handshake fails so callers
        can skip passive checks instead of inventing false findings.  The
        returned dict contains the final response headers (including all
        ``Set-Cookie`` values), the final URL after redirects, the status
        code and the raw httpx response for soft-404 detection.
        """
        url = target_url if "://" in target_url else f"https://{target_url}"
        try:
            async with build_http_client(timeout=10.0) as c:
                resp = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
        except (httpx.ConnectError, httpx.TimeoutException, ssl.SSLError) as e:
            logger.warning("TLS/connection failure for %s: %s", url, e)
            return None
        except Exception as e:
            logger.error("Unexpected failure fetching %s: %s", url, e)
            return None

        try:
            content = resp.content
        except Exception:
            content = b""
        try:
            text = resp.text[:200_000]
        except Exception:
            text = ""

        return {
            "headers": resp.headers,
            "final_url": str(resp.url),
            "status_code": resp.status_code,
            "response": resp,
            "content": content,
            "text": text,
        }

    async def _establish_soft404_baseline(self, final_url: str, fp_filter: FalsePositiveFilter) -> None:
        """Fetch a random non-existent path to fingerprint the server's 404 page."""
        try:
            parsed = urlparse(final_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            probe = f"{origin}/_phantom_404_{''.join(random.choices(string.ascii_lowercase, k=10))}"
            async with build_http_client(timeout=5.0) as c:
                resp = await c.get(probe)
            fp_filter.set_baseline(resp)
        except Exception as e:
            logger.debug("Soft-404 baseline probe failed for %s: %s", final_url, e)

    def _check_headers(self, headers: dict[str, str], target: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        headers = self._lower_headers(headers)

        def sev_for(finding_type: str) -> str:
            return calculate_severity(finding_type, {"url": target}).lower()

        present = {k.lower() for k in headers}

        if "content-security-policy" not in present:
            findings.append(self._finding(
                "Missing Content Security Policy", "Security Headers", sev_for("missing_csp"),
                "No CSP header found", "XSS and data injection attacks are easier without CSP",
                "Add: Content-Security-Policy: default-src 'self'", target
            ))
        else:
            csp = headers.get("content-security-policy", "")
            csp_lower = csp.lower()
            has_nonce_or_dynamic = "'nonce-" in csp_lower or "'strict-dynamic'" in csp_lower

            for directive, desc in CSP_DANGEROUS_DIRECTIVES.items():
                if directive in csp_lower:
                    if directive in ("unsafe-inline", "unsafe-eval"):
                        sev = "low" if has_nonce_or_dynamic else "high"
                    else:
                        sev = "medium"
                    findings.append(self._finding(
                        f"CSP contains dangerous directive: {directive}", "Security Headers", sev,
                        f"CSP {directive}: {desc}", "Reduces CSP protection against injection attacks",
                        f"Remove or restrict the {directive} directive in CSP", target
                    ))

            for directive in CSP_MISSING_DIRECTIVES:
                if directive not in csp_lower and directive not in ("default-src",):
                    findings.append(self._finding(
                        f"CSP missing {directive} directive", "Security Headers", "low",
                        f"CSP does not include {directive}", CSP_MISSING_DIRECTIVES[directive],
                        f"Add {directive} directive to Content-Security-Policy header", target
                    ))

            if "unsafe-inline" in csp_lower and "script-src" in csp_lower:
                sev = "low" if has_nonce_or_dynamic else "high"
                findings.append(self._finding(
                    "CSP allows unsafe-inline scripts", "Security Headers", sev,
                    "script-src includes 'unsafe-inline'",
                    "Bypasses CSP protection against XSS" if not has_nonce_or_dynamic else "Nonce/strict-dynamic overrides unsafe-inline (CSP3 compliant)",
                    "Remove 'unsafe-inline' from script-src; use nonces or hashes" if not has_nonce_or_dynamic else "Consider removing unsafe-inline for cleaner CSP", target
                ))

        if "strict-transport-security" not in present:
            findings.append(self._finding(
                "Missing HTTP Strict Transport Security", "Security Headers", sev_for("missing_hsts"),
                "No HSTS header", "SSL stripping and MITM attacks possible",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", target
            ))
        else:
            hsts = headers.get("strict-transport-security", "")
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < HSTS_MIN_MAX_AGE:
                findings.append(self._finding(
                    "HSTS max-age too short", "Security Headers", "medium",
                    f"HSTS max-age={m.group(1)} < {HSTS_MIN_MAX_AGE}",
                    "Short max-age weakens protection against SSL stripping",
                    f"Set max-age to at least {HSTS_MIN_MAX_AGE}", target
                ))
        if "x-frame-options" not in present and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(self._finding(
                "Missing Clickjacking Protection", "Security Headers", sev_for("missing_xfo"),
                "No X-Frame-Options or CSP frame-ancestors",
                "Page can be embedded in malicious iframes",
                "Add: X-Frame-Options: DENY or frame-ancestors 'none'", target
            ))

        if "x-content-type-options" not in present:
            findings.append(self._finding(
                "Missing X-Content-Type-Options", "Security Headers", sev_for("missing_xcto"),
                "No X-Content-Type-Options: nosniff",
                "Browser may MIME-sniff responses, enabling drive-download attacks",
                "Add: X-Content-Type-Options: nosniff", target
            ))

        if "referrer-policy" not in present:
            findings.append(self._finding(
                "Missing Referrer-Policy", "Security Headers", sev_for("missing_referrer_policy"),
                "No Referrer-Policy header",
                "Referrer URL may leak in cross-origin requests",
                "Add: Referrer-Policy: strict-origin-when-cross-origin", target
            ))

        if "permissions-policy" not in present:
            findings.append(self._finding(
                "Missing Permissions-Policy", "Security Headers", sev_for("missing_permissions_policy"),
                "No Permissions-Policy header",
                "Browser features (camera, mic, etc.) unrestricted",
                "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()", target
            ))

        if "cross-origin-embedder-policy" not in present:
            findings.append(self._finding(
                "Missing Cross-Origin-Embedder-Policy", "Security Headers", sev_for("missing_coep"),
                "No COEP header", "Page is not isolated from cross-origin embeddings; Spectre/Meltdown mitigations are weakened",
                "Add: Cross-Origin-Embedder-Policy: require-corp", target
            ))

        if "cross-origin-opener-policy" not in present:
            findings.append(self._finding(
                "Missing Cross-Origin-Opener-Policy", "Security Headers", sev_for("missing_coop"),
                "No COOP header", "Top-level navigations can open the page in a pop-up window and access it via window.opener",
                "Add: Cross-Origin-Opener-Policy: same-origin", target
            ))

        if "cross-origin-resource-policy" not in present:
            findings.append(self._finding(
                "Missing Cross-Origin-Resource-Policy", "Security Headers", sev_for("missing_corp"),
                "No CORP header", "Cross-origin requests can load the resource, enabling data exfiltration",
                "Add: Cross-Origin-Resource-Policy: same-origin", target
            ))

        if "origin-agent-cluster" not in present:
            findings.append(self._finding(
                "Missing Origin-Agent-Cluster", "Security Headers", sev_for("missing_oac"),
                "No OAC header", "The page is not isolated in its own agent cluster; cross-origin attacks may affect it",
                "Add: Origin-Agent-Cluster: ?1", target
            ))

        return findings

    async def _check_cors(self, target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        url = target_url if "://" in target_url else f"https://{target_url}"

        async with build_http_client(timeout=8.0) as c:
            try:
                r1 = await c.options(url, headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "GET"
                })
                acao1 = r1.headers.get("access-control-allow-origin", "")
                acac1 = r1.headers.get("access-control-allow-credentials", "")

                if acao1 == "*":
                    findings.append(self._finding(
                        "Wildcard CORS allowed", "CORS", "medium",
                        "Access-Control-Allow-Origin: *", "Any origin can read responses",
                        "Restrict to specific trusted origins", target_url
                    ))
                elif acao1 == "https://evil.com":
                    is_dynamic_reflection = False
                    try:
                        r2 = await c.options(url, headers={
                            "Origin": "https://attacker-different-test.com",
                            "Access-Control-Request-Method": "GET"
                        })
                        acao2 = r2.headers.get("access-control-allow-origin", "")
                        if acao2 == "https://attacker-different-test.com":
                            is_dynamic_reflection = True
                    except Exception as e:
                        logger.debug("CORS reflection test failed: %s", e)

                    if is_dynamic_reflection:
                        findings.append(self._finding(
                            "Reflected CORS origin (dynamic reflection)", "CORS", "high",
                            "Server reflects arbitrary Origin header values", "Attacker can read authenticated responses cross-origin from any domain",
                            "Validate Origin against a strict allowlist; do not reflect arbitrary origins", target_url
                        ))
                    else:
                        findings.append(self._finding(
                            "Reflected CORS origin (static)", "CORS", "medium",
                            f"Server echoed Origin: {acao1}", "Server may have a permissive CORS policy",
                            "Verify if evil.com is an intentional trusted origin; otherwise restrict to specific origins", target_url
                        ))

                if acao1 and acac1.lower() == "true" and acao1 != "*":
                    is_wildcard_creds = False
                    if acao1 == "https://evil.com":
                        try:
                            r3 = await c.options(url, headers={
                                "Origin": "https://another-test.com",
                                "Access-Control-Request-Method": "GET"
                            })
                            acao3 = r3.headers.get("access-control-allow-origin", "")
                            acac3 = r3.headers.get("access-control-allow-credentials", "")
                            if acao3 == "https://another-test.com" and acac3.lower() == "true":
                                is_wildcard_creds = True
                        except Exception as e:
                            logger.debug("CORS wildcard credentials test failed: %s", e)

                    if is_wildcard_creds:
                        findings.append(self._finding(
                            "CORS with credentials from arbitrary origin (dynamic)", "CORS", "high",
                            f"ACAO: {acao1}, ACAC: true (reflected from multiple origins)", "Authenticated cross-origin reads possible from any domain",
                            "Restrict ACAO to a specific allowlist and never enable credentials with reflected origins", target_url
                        ))
                    elif acao1 != "https://evil.com":
                        findings.append(self._finding(
                            "CORS with credentials from non-wildcard origin", "CORS", "low",
                            f"ACAO: {acao1}, ACAC: true", "CORS policy allows credentials from a specific non-wildcard origin",
                            "Verify the allowed origin is intentional and properly restricted", target_url
                        ))
            except Exception as e:
                logger.debug("CORS check failed for %s: %s", target_url, e)

        return findings

    def _check_cookies(self, headers: Any) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        get_list = getattr(headers, "get_list", None)
        if callable(get_list):
            raw_values = [v for v in get_list("set-cookie") if v]
        else:
            raw_values = [headers.get("set-cookie", "")]

        cookies: list[dict[str, Any]] = []
        for raw_value in raw_values:
            cookies.extend(parse_cookie_header(raw_value))

        seen_cookies: set[str] = set()
        for cookie in cookies:
            name = cookie.get("name", "")
            if not name or name.lower() in seen_cookies:
                continue
            seen_cookies.add(name.lower())

            if not cookie.get("secure"):
                findings.append(self._finding(
                    f"Cookie '{name}' missing Secure flag", "Cookies",
                    calculate_severity("cookie_missing_flag").lower(),
                    f"Set-Cookie: {name}=[redacted]", "Cookie sent over unencrypted HTTP",
                    "Add Secure flag", None
                ))
            if not cookie.get("httponly"):
                findings.append(self._finding(
                    f"Cookie '{name}' missing HttpOnly flag", "Cookies",
                    calculate_severity("cookie_missing_flag").lower(),
                    f"Set-Cookie: {name}=[redacted]", "JavaScript can read cookie",
                    "Add HttpOnly flag", None
                ))
            if not cookie.get("samesite"):
                findings.append(self._finding(
                    f"Cookie '{name}' missing SameSite attribute", "Cookies",
                    calculate_severity("cookie_missing_flag").lower(),
                    f"Set-Cookie: {name}=[redacted]", "CSRF protection weakened",
                    "Add SameSite=Lax or SameSite=Strict", None
                ))

        return findings

    async def _check_tls(self, target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        if parsed.scheme != "https":
            return findings
        host = parsed.hostname or parsed.netloc.split(":")[0]
        port = parsed.port or 443

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=5.0
            )
            cert = w.get_extra_info("ssl_object").getpeercert()
            cipher = w.get_extra_info("ssl_object").cipher()
            w.close()
            await w.wait_closed()

            if await self._probe_tls_version(host, port, ssl.TLSVersion.TLSv1):
                findings.append(self._finding(
                    "Legacy TLS 1.0 supported", "TLS", "high",
                    "Server accepted a TLS 1.0 handshake", "Deprecated TLS allows downgrade attacks",
                    "Disable TLS 1.0 and 1.1; use TLS 1.2+", target_url
                ))
            if await self._probe_tls_version(host, port, ssl.TLSVersion.TLSv1_1):
                findings.append(self._finding(
                    "Legacy TLS 1.1 supported", "TLS", "high",
                    "Server accepted a TLS 1.1 handshake", "Deprecated TLS allows downgrade attacks",
                    "Disable TLS 1.0 and 1.1; use TLS 1.2+", target_url
                ))

            weak = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"]
            if cipher and any(w in str(cipher[0]).upper() for w in weak):
                findings.append(self._finding(
                    f"Weak cipher: {cipher[0]}", "TLS", "high",
                    f"Cipher suite: {cipher[0]}", "Weak cipher can be broken by attackers",
                    "Disable weak ciphers; use AEAD ciphers (AES-GCM, ChaCha20)", target_url
                ))

            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if expiry < datetime.now(timezone.utc):
                        findings.append(self._finding(
                            "Expired SSL certificate", "TLS", "high",
                            f"Expired: {not_after}", "Expired cert triggers browser warnings",
                            "Renew certificate before expiry", target_url
                        ))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                if issuer.get("organizationName") == "self-signed":
                    findings.append(self._finding(
                        "Self-signed SSL certificate", "TLS", "high",
                        "Certificate is self-signed", "Users cannot verify identity",
                        "Use a trusted CA-signed certificate", target_url
                    ))

        except Exception as e:
            logger.warning("TLS connection check failed for %s:%d: %s", host, port, e)
            findings.append(self._finding(
                "Could not establish TLS connection", "TLS", "low",
                f"Failed to connect to {host}:{port}", "TLS may not be available",
                "Ensure HTTPS is properly configured", target_url
            ))

        return findings

    async def _probe_tls_version(self, host: str, port: int, version: ssl.TLSVersion) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=3.0,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    def _check_info_leakage(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        headers = self._lower_headers(headers)
        leaky = {
            "server": "Server version disclosure",
            "x-powered-by": "X-Powered-By disclosure",
            "x-aspnet-version": "ASP.NET version disclosure",
            "x-debug-token": "Debug token disclosure",
            "x-generator": "Generator tag disclosure",
            "x-runtime": "Runtime header disclosure",
        }

        for hdr, title in leaky.items():
            val = headers.get(hdr)
            if val:
                findings.append(self._finding(
                    title, "Information Disclosure", "low",
                    f"Header '{hdr}: {val}'", "Attackers fingerprint stack for targeted exploits",
                    f"Remove or obfuscate the '{hdr}' header in server config", None
                ))

        return findings

    @staticmethod
    def _lower_headers(headers: Any) -> dict[str, str]:
        return {str(k).lower(): str(v) for k, v in dict(headers).items()}

    async def _verify_trace_method(self, client, url: str, target_url: str) -> dict[str, Any] | None:
        try:
            trace_resp = await client.request("TRACE", url, timeout=10.0)
            if trace_resp.status_code == 200 and "TRACE" in trace_resp.text:
                return self._finding(
                    "HTTP TRACE method is enabled", "HTTP Methods", "high",
                    "Server echoed TRACE request back",
                    "TRACE method can be used for cross-site tracing attacks",
                    "Disable the TRACE method on the server", target_url
                )
        except Exception:
            pass
        return None

    async def _check_http_methods(self, target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        url = target_url if "://" in target_url else f"https://{target_url}"

        async with build_http_client(timeout=8.0) as c:
            try:
                r = await c.options(url, headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "GET"
                })
                allowed = r.headers.get("access-control-allow-methods", "")
                allow_header = r.headers.get("allow", "")
                methods_str = allowed or allow_header
                methods = [m.strip().upper() for m in methods_str.split(",") if m.strip()]

                dangerous = {"TRACE", "CONNECT", "TRACK"}
                for method in methods:
                    if method == "TRACE":
                        trace_finding = await self._verify_trace_method(c, url, target_url)
                        if trace_finding:
                            findings.append(trace_finding)
                    elif method in dangerous:
                        findings.append(self._finding(
                            f"HTTP {method} method is enabled", "HTTP Methods", "high",
                            f"Allow header advertises {method}",
                            f"{method} method can be used for cross-site tracing or tunneling attacks",
                            f"Disable the {method} method on the server", target_url
                        ))

                if "PUT" in methods or "DELETE" in methods:
                    state_changing = []
                    if "PUT" in methods:
                        state_changing.append("PUT")
                    if "DELETE" in methods:
                        state_changing.append("DELETE")
                    findings.append(self._finding(
                        f"State-changing HTTP methods exposed: {', '.join(state_changing)}",
                        "HTTP Methods", "medium",
                        f"Allow header advertises {', '.join(state_changing)}",
                        "State-changing methods without proper authorization can be exploited",
                        "Ensure authentication and authorization are enforced for state-changing methods", target_url
                    ))

                if "OPTIONS" in methods and not methods:
                    pass

                if not methods:
                    resp = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                    allow = resp.headers.get("allow", "")
                    if allow:
                        get_methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
                        if "GET" in get_methods and "POST" not in get_methods:
                            findings.append(self._finding(
                                "Only GET method is allowed; POST not advertised", "HTTP Methods", "info",
                                "Allow header only lists GET", "POST endpoints may be hidden or not implemented",
                                "Verify POST endpoints are intentionally hidden or properly secured", target_url
                            ))
            except Exception as e:
                logger.debug("HTTP methods check failed for %s: %s", target_url, e)

        return findings

    async def _ml_postprocess(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from app.ml.severity_predictor import SeverityPredictor

        fp_filter = FalsePositiveFilter()
        severity_predictor = SeverityPredictor()
        for finding in findings:
            try:
                finding["ml_fp"] = await fp_filter.filter_finding(finding)
            except Exception as exc:
                logger.debug("FP filter failed for %s: %s", finding.get("title"), exc)
            try:
                finding["ml_severity"] = await severity_predictor.predict_severity(finding)
            except Exception as exc:
                logger.debug("Severity prediction failed for %s: %s", finding.get("title"), exc)
        return findings

    def _finding(
        self, title: str, category: str, severity: str,
        evidence: str, impact: str, fix: str, endpoint: str | None
    ) -> dict[str, Any]:
        return {
            "title": title,
            "category": category,
            "severity": severity,
            "evidence": evidence,
            "impact": impact,
            "fix": fix,
            "endpoint": endpoint or "",
            "cve_id": None,
            "cvss_score": None,
        }
