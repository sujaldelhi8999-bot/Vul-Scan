import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from app.config import get_settings
from app.database import get_ai_cache, set_ai_cache
from app.security import redact_payload, redact_sensitive
from app.services.openrouter_client import call_openrouter, ai_usage_logger
from app.services.redaction import redaction_service
from app.skills import get_skills_for_prompt

AIProvider = Callable[[dict[str, Any]], Awaitable[str]]

SEVERITY_WEIGHT = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 45, "LOW": 20, "INFO": 5}
CONFIDENCE_WEIGHT = {"CONFIRMED": 1.2, "HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.5, "POTENTIAL": 0.35}
ACTIVE_RISK_STATUSES = {"ACTIVE"}


class OpenRouterAnalysisProvider:
    def __init__(self, api_key: str, *, model: str = "openrouter/free", timeout: float = 20.0) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    async def __call__(self, prompt: dict[str, Any]) -> str:
        if not self.api_key:
            return ""
        
        # Extract target technologies and vulnerability types from prompt for skill selection
        target_tech = self._extract_technologies(prompt)
        vuln_types = self._extract_vulnerability_types(prompt)
        
        # Get relevant skills for context
        skills_context = get_skills_for_prompt(
            target_tech=target_tech,
            vulnerability_types=vuln_types,
            max_skills=5
        )
        
        system_prompt = (
            "You are PhantomScan's final security analyst. Use only the provided redacted "
            "scanner evidence. Do not invent findings, secrets, users, payloads, or exploitability. "
            "Never start or imply that you started active tests.\n\n"
            f"EXPERT KNOWLEDGE BASE:\n{skills_context}"
        )
        user_content = json.dumps(redact_payload(prompt), ensure_ascii=True, default=str)
        return await call_openrouter(
            user_content,
            system_prompt,
            model=self.model,
            max_tokens=900,
            timeout=self.timeout,
            retry_limit=1,
        )
    
    def _extract_technologies(self, prompt: dict[str, Any]) -> list[str]:
        """Extract technology stack from prompt evidence."""
        tech = set()
        # From technologies
        tech_stack = prompt.get("technologies", {})
        if isinstance(tech_stack, dict):
            for category, items in tech_stack.items():
                if isinstance(items, list):
                    tech.update(items)
                elif isinstance(items, str):
                    tech.add(items)
        
        # From findings
        for finding in prompt.get("findings", []):
            if isinstance(finding, dict):
                category = finding.get("category", "").lower()
                module = finding.get("module", "").lower()
                tech.update([category, module])
        
        # From browser observations
        api_inventory = prompt.get("api_inventory", [])
        for api in api_inventory:
            if isinstance(api, dict):
                endpoint = api.get("endpoint", "")
                tech.add(endpoint.split("/")[1] if "/" in endpoint else endpoint)
        
        return list(tech)[:20]
    
    def _extract_vulnerability_types(self, prompt: dict[str, Any]) -> list[str]:
        """Extract vulnerability types from findings."""
        vulns = set()
        for finding in prompt.get("findings", []):
            if isinstance(finding, dict):
                category = finding.get("category", "").lower()
                title = finding.get("title", "").lower()
                module = finding.get("module", "").lower()
                vulns.update([category, module])
                # Map common terms
                if "sql" in title or "injection" in title:
                    vulns.add("sql_injection")
                if "xss" in title or "cross-site" in title:
                    vulns.add("xss")
                if "ssrf" in title:
                    vulns.add("ssrf")
                if "idor" in title or "object reference" in title:
                    vulns.add("idor")
                if "jwt" in title or "json web token" in title:
                    vulns.add("jwt")
                if "race" in title:
                    vulns.add("race_conditions")
                if "business" in title or "logic" in title:
                    vulns.add("business_logic")
                if "file upload" in title or "upload" in title:
                    vulns.add("file_upload")
                if "template" in title or "ssti" in title:
                    vulns.add("ssti")
                if "xxe" in title or "xml" in title:
                    vulns.add("xxe")
        return list(vulns)[:10]


def create_ai_security_analyst() -> "AISecurityAnalyst":
    settings = get_settings()
    model = settings.openrouter_model if settings.openrouter_api_key else "deterministic-analyst"
    provider = OpenRouterAnalysisProvider(settings.openrouter_api_key, model=model) if settings.openrouter_api_key else None
    return AISecurityAnalyst(ai_provider=provider, model=model)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_hash(value: Any) -> str:
    serialized = json.dumps(redact_payload(value), sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def finding_reference(finding: dict[str, Any], source: str = "Finding") -> dict[str, Any]:
    return {
        "type": "finding",
        "id": int(finding.get("id", 0)) if str(finding.get("id", "")).isdigit() else finding.get("id"),
        "label": f"Finding #{finding.get('id', '?')}",
        "title": finding.get("title"),
        "endpoint": finding.get("endpoint") or finding.get("target"),
        "source": source,
    }


def is_resolved_or_excluded(finding: dict[str, Any]) -> bool:
    return (
        str(finding.get("verification_status") or "").upper() == "FIX_VERIFIED"
        or str(finding.get("remediation_status") or "").upper() == "RESOLVED"
        or str(finding.get("risk_status") or "ACTIVE").upper() not in ACTIVE_RISK_STATUSES
    )


class SecurityPriorityEngine:
    def rank(self, findings: list[dict[str, Any]], browser_output: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        browser_output = browser_output or {}
        api_endpoints = {str(api.get("endpoint") or "") for api in browser_output.get("api_inventory", []) if isinstance(api, dict)}
        priorities = []
        for finding in findings:
            if is_resolved_or_excluded(finding):
                continue
            severity = str(finding.get("severity") or "INFO").upper()
            confidence = str(finding.get("confidence") or "POTENTIAL").upper()
            score = SEVERITY_WEIGHT.get(severity, 5) * CONFIDENCE_WEIGHT.get(confidence, 0.35)
            endpoint = str(finding.get("endpoint") or "")
            category_text = f"{finding.get('category', '')} {finding.get('title', '')} {finding.get('module', '')}".lower()
            factors = [f"severity={severity}", f"confidence={confidence}"]
            if endpoint and endpoint.startswith("http"):
                score += 8
                factors.append("internet or browser-reachable endpoint")
            if any(token in category_text for token in ["auth", "session", "access", "jwt", "csrf"]):
                score += 15
                factors.append("authentication or authorization impact")
            if any(api_endpoint and api_endpoint in endpoint for api_endpoint in api_endpoints):
                score += 8
                factors.append("browser-observed API surface")
            if finding.get("cvss_score"):
                score += min(20, float(finding.get("cvss_score") or 0) * 2)
                factors.append("CVE score present")
            if str(finding.get("remediation_status") or "") == "IN_PROGRESS":
                score -= 5
                factors.append("already in progress")
            priorities.append(
                {
                    "priority": 0,
                    "finding_id": finding.get("id"),
                    "title": finding.get("title"),
                    "score": round(score, 2),
                    "severity": severity,
                    "confidence": confidence,
                    "recommended_action": finding.get("recommended_fix") or finding.get("recommendation") or finding.get("fix") or "Review evidence and remediate.",
                    "factors": factors,
                    "citation": finding_reference(finding),
                }
            )
        priorities.sort(key=lambda item: item["score"], reverse=True)
        for index, item in enumerate(priorities, start=1):
            item["priority"] = index
        return priorities


class RelatedFindingCorrelation:
    def correlate(self, findings: list[dict[str, Any]], artifacts: dict[str, Any]) -> list[dict[str, Any]]:
        active = [finding for finding in findings if not is_resolved_or_excluded(finding)]
        chains = []
        for finding in active:
            related = []
            endpoint = str(finding.get("endpoint") or "")
            module = str(finding.get("module") or finding.get("category") or "").lower()
            for candidate in active:
                if candidate.get("id") == finding.get("id"):
                    continue
                same_endpoint = endpoint and endpoint == str(candidate.get("endpoint") or "")
                same_module = module and module in str(candidate.get("module") or candidate.get("category") or "").lower()
                cve_related = finding.get("cve_id") or candidate.get("cve_id")
                if same_endpoint or same_module or cve_related:
                    related.append(finding_reference(candidate, "Related finding"))
            if related:
                chains.append(
                    {
                        "title": f"Related Security Chain: {finding.get('title')}",
                        "primary": finding_reference(finding),
                        "related": related[:5],
                        "explanation": "These observations share an endpoint, category/module, or CVE context. PhantomScan does not label this an exploit chain without direct proof.",
                    }
                )
        browser = artifacts.get("browser_security_output") or {}
        source_maps = browser.get("source_maps") or []
        apis = browser.get("api_inventory") or []
        debug_findings = [finding for finding in active if "debug" in str(finding.get("title", "")).lower() or "source map" in str(finding.get("title", "")).lower()]
        if source_maps and apis and debug_findings:
            chains.append(
                {
                    "title": "Related Security Chain: source map plus API exposure",
                    "primary": finding_reference(debug_findings[0]),
                    "related": [finding_reference(item) for item in debug_findings[1:4]],
                    "explanation": "Public source maps, discovered internal API routes, and debug indicators are related reconnaissance signals. They are not treated as exploitation without additional evidence.",
                    "evidence": {"source_maps": len(source_maps), "api_inventory": len(apis)},
                }
            )
        return chains[:12]


class RootCauseGrouper:
    GROUP_RULES = [
        ("Session Management", ["session", "cookie", "jwt", "token", "logout"]),
        ("Authentication", ["auth", "login", "password", "mfa", "oauth"]),
        ("Access Control", ["access", "authorization", "admin", "object"]),
        ("Input and Output Handling", ["xss", "input", "validation", "injection", "encoding"]),
        ("Browser Security Policy", ["csp", "headers", "cors", "frame", "mixed"]),
        ("File and Path Handling", ["file", "path", "upload", "download"]),
        ("Dependency and CVE", ["cve", "dependency", "version"]),
    ]

    def group(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            if is_resolved_or_excluded(finding):
                continue
            text = f"{finding.get('title', '')} {finding.get('category', '')} {finding.get('module', '')}".lower()
            group_name = "Application Security"
            for candidate, needles in self.GROUP_RULES:
                if any(needle in text for needle in needles):
                    group_name = candidate
                    break
            groups.setdefault(group_name, []).append(finding)
        result = []
        for name, items in groups.items():
            result.append(
                {
                    "name": name,
                    "finding_count": len(items),
                    "highest_severity": self.highest_severity(items),
                    "finding_ids": [item.get("id") for item in items],
                    "summary": f"{len(items)} related finding{'s' if len(items) != 1 else ''} appear to share this root area.",
                }
            )
        result.sort(key=lambda item: SEVERITY_WEIGHT.get(str(item["highest_severity"]).upper(), 0), reverse=True)
        return result

    @staticmethod
    def highest_severity(findings: list[dict[str, Any]]) -> str:
        return max((str(item.get("severity") or "INFO").upper() for item in findings), key=lambda severity: SEVERITY_WEIGHT.get(severity, 0), default="INFO")


class RemediationPlanner:
    def plan(self, priorities: list[dict[str, Any]]) -> dict[str, Any]:
        buckets = {"IMMEDIATE": [], "TODAY": [], "THIS_WEEK": []}
        for item in priorities:
            if item["priority"] <= 2 or item["score"] >= 85:
                bucket = "IMMEDIATE"
            elif item["score"] >= 45:
                bucket = "TODAY"
            else:
                bucket = "THIS_WEEK"
            buckets[bucket].append(
                {
                    "priority": item["priority"],
                    "finding_id": item["finding_id"],
                    "title": item["title"],
                    "action": item["recommended_action"],
                    "citation": item["citation"],
                }
            )
        return buckets


class ScanComparisonEngine:
    def compare(
        self,
        current_scan: dict[str, Any],
        current_findings: list[dict[str, Any]],
        previous_scan: dict[str, Any] | None,
        previous_findings: list[dict[str, Any]],
        artifacts: dict[str, Any],
        previous_artifacts: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        current_titles = {str(item.get("title")) for item in current_findings}
        previous_titles = {str(item.get("title")) for item in previous_findings}
        browser = artifacts.get("browser_security_output") or {}
        previous_browser = (previous_artifacts or {}).get("browser_security_output") or {}
        current_routes = {str(item.get("route") or item.get("url") or "") for item in browser.get("routes", []) if isinstance(item, dict)}
        previous_routes = {str(item.get("route") or item.get("url") or "") for item in previous_browser.get("routes", []) if isinstance(item, dict)}
        current_apis = {str(item.get("endpoint") or "") for item in browser.get("api_inventory", []) if isinstance(item, dict)}
        previous_apis = {str(item.get("endpoint") or "") for item in previous_browser.get("api_inventory", []) if isinstance(item, dict)}
        current_third = {str(item.get("domain") or "") for item in browser.get("third_party", []) if isinstance(item, dict)}
        previous_third = {str(item.get("domain") or "") for item in previous_browser.get("third_party", []) if isinstance(item, dict)}
        return {
            "previous_scan_id": previous_scan.get("id") if previous_scan else None,
            "new_findings": sorted(current_titles - previous_titles),
            "resolved_findings": sorted(previous_titles - current_titles),
            "worsened_findings": [],
            "new_routes": sorted(item for item in current_routes - previous_routes if item),
            "new_apis": sorted(item for item in current_apis - previous_apis if item),
            "new_technologies": [],
            "new_third_parties": sorted(item for item in current_third - previous_third if item),
            "new_authentication_surfaces": sorted(item for item in current_apis - previous_apis if any(token in item.lower() for token in ["login", "auth", "session", "token"])),
            "removed_exposure": sorted(item for item in (previous_routes | previous_apis | previous_third) - (current_routes | current_apis | current_third) if item),
        }


class ScoreExplainer:
    def explain(self, findings: list[dict[str, Any]], artifacts: dict[str, Any]) -> dict[str, Any]:
        deductions = []
        credits = []
        active = [finding for finding in findings if not is_resolved_or_excluded(finding)]
        for severity, weight in [("CRITICAL", 24), ("HIGH", 14), ("MEDIUM", 7), ("LOW", 2)]:
            count = sum(1 for finding in active if str(finding.get("severity") or "").upper() == severity)
            if count:
                deductions.append({"label": f"{count} {severity.title()} severity finding{'s' if count != 1 else ''}", "points": -(count * weight)})
        auth_count = sum(1 for finding in active if any(token in f"{finding.get('title')} {finding.get('category')} {finding.get('module')}".lower() for token in ["auth", "session", "access", "jwt"]))
        if auth_count:
            deductions.append({"label": "Authentication or authorization risk", "points": -min(10, auth_count * 3)})
        resolved = [finding for finding in findings if is_resolved_or_excluded(finding)]
        if resolved:
            credits.append({"label": f"{len(resolved)} verified/resolved/excluded finding{'s' if len(resolved) != 1 else ''}", "points": min(12, len(resolved) * 3)})
        positives = PositiveControlDetector().detect(findings, artifacts)
        if positives:
            credits.append({"label": f"{len(positives)} positive security control{'s' if len(positives) != 1 else ''}", "points": min(8, len(positives) * 2)})
        score = max(0, min(100, 100 + sum(item["points"] for item in deductions) + sum(item["points"] for item in credits)))
        return {"score": score, "deductions": deductions, "credits": credits}


class PositiveControlDetector:
    def detect(self, findings: list[dict[str, Any]], artifacts: dict[str, Any]) -> list[dict[str, Any]]:
        positives = []
        browser = artifacts.get("browser_security_output") or {}
        for csp in browser.get("csp", []) or []:
            if isinstance(csp, dict) and csp.get("status") == "strong":
                positives.append({"title": "Strong CSP detected", "evidence": "Browser observation parsed CSP as strong."})
                break
        cookies = browser.get("cookies", []) or []
        if cookies and all(cookie.get("secure") and cookie.get("httponly") and cookie.get("samesite") for cookie in cookies if isinstance(cookie, dict)):
            positives.append({"title": "Secure cookies detected", "evidence": "Observed cookies include Secure, HttpOnly, and SameSite metadata."})
        headers = []
        for event in browser.get("network_events", []) or []:
            if isinstance(event, dict):
                headers.append(event.get("response_headers_summary") or {})
        if any("strict-transport-security" in {str(key).lower() for key in header.keys()} for header in headers if isinstance(header, dict)):
            positives.append({"title": "HSTS enabled", "evidence": "Browser network evidence includes Strict-Transport-Security."})
        if not any(str(finding.get("category") or "").upper() == "CVE" and str(finding.get("severity") or "").upper() in {"CRITICAL", "HIGH"} for finding in findings):
            positives.append({"title": "No high-risk CVEs detected", "evidence": "Persisted findings contain no high or critical CVE result."})
        if any(str(finding.get("verification_status") or "") == "FIX_VERIFIED" for finding in findings):
            positives.append({"title": "Fix successfully verified", "evidence": "At least one finding has FIX_VERIFIED status."})
        return positives


class SecurityTimelineBuilder:
    def build(self, scan: dict[str, Any], findings: list[dict[str, Any]], logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        events = []
        for log in logs:
            text = f"{log.get('action')} {log.get('details')}"
            if any(token in text.lower() for token in ["finding", "verified", "resolved", "api", "route", "scan", "fix", "browser"]):
                events.append({"timestamp": log.get("timestamp"), "title": str(log.get("action") or "event").replace("_", " "), "detail": redact_sensitive(str(log.get("details") or ""), 500), "source": log.get("agent_name")})
        for finding in findings:
            events.append({"timestamp": finding.get("timestamp"), "title": f"{finding.get('severity')} finding detected", "detail": finding.get("title"), "source": "Finding", "finding_id": finding.get("id")})
            if finding.get("verification_status") == "FIX_VERIFIED":
                events.append({"timestamp": finding.get("timestamp"), "title": "Fix verified", "detail": finding.get("title"), "source": "Verification", "finding_id": finding.get("id")})
        return sorted(events, key=lambda item: str(item.get("timestamp") or ""))[-50:]


class AISecurityAnalyst:
    def __init__(
        self,
        *,
        ai_provider: AIProvider | None = None,
        model: str = "deterministic-analyst",
        max_context_size: int = 24000,
        max_findings: int = 30,
        timeout: float = 20.0,
        retry_limit: int = 1,
    ) -> None:
        self.ai_provider = ai_provider
        self.model = model
        self.max_context_size = max_context_size
        self.max_findings = max_findings
        self.timeout = timeout
        self.retry_limit = retry_limit
        self.priority_engine = SecurityPriorityEngine()
        self.correlation = RelatedFindingCorrelation()
        self.root_causes = RootCauseGrouper()
        self.remediation = RemediationPlanner()
        self.comparison = ScanComparisonEngine()
        self.score = ScoreExplainer()
        self.positives = PositiveControlDetector()
        self.timeline = SecurityTimelineBuilder()

    def evidence_pack(
        self,
        *,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
        artifacts: dict[str, Any] | None,
        previous_scan: dict[str, Any] | None = None,
        previous_findings: list[dict[str, Any]] | None = None,
        previous_artifacts: dict[str, Any] | None = None,
        logs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        artifacts = artifacts or {}
        browser = artifacts.get("browser_security_output") or {}
        scanner = artifacts.get("scanner_output") or {}
        active = artifacts.get("active_security_output") or {}
        pack = {
            "target": scan.get("target_url"),
            "scan_id": scan.get("id") or scan.get("scan_id"),
            "mode": scan.get("mode"),
            "attack_surface": {
                "browser_routes": browser.get("routes", [])[:80],
                "active_surfaces": (active.get("attack_surface") or {}).get("surfaces", [])[:80] if isinstance(active.get("attack_surface"), dict) else [],
            },
            "findings": [self.safe_finding(item) for item in findings[: self.max_findings]],
            "browser_observations": {
                "pages": browser.get("pages", [])[:30],
                "console_events": browser.get("console_events", [])[:50],
                "storage": browser.get("storage", {}),
                "csp": browser.get("csp", []),
                "websockets": browser.get("websockets", [])[:30],
            },
            "network_observations": browser.get("network_events", [])[:120],
            "api_inventory": browser.get("api_inventory", [])[:100],
            "authentication_flows": browser.get("auth_flow", {}),
            "technologies": scanner.get("tech_stack", {}),
            "cve_intelligence": [self.safe_finding(item) for item in findings if item.get("cve_id")][:20],
            "previous_scan": previous_scan or {},
            "previous_findings": [self.safe_finding(item) for item in (previous_findings or [])[: self.max_findings]],
            "previous_artifacts": {"browser_security_output": (previous_artifacts or {}).get("browser_security_output", {})},
            "logs": (logs or [])[-80:],
        }
        safe = redact_payload(pack)
        serialized = json.dumps(safe, ensure_ascii=True, default=str)
        if len(serialized) > self.max_context_size:
            safe["findings"] = safe["findings"][:15]
            safe["network_observations"] = safe["network_observations"][:40]
            safe["logs"] = safe["logs"][-30:]
        return redact_payload(safe)

    @staticmethod
    def safe_finding(finding: dict[str, Any]) -> dict[str, Any]:
        keys = ["id", "title", "category", "severity", "confidence", "target", "endpoint", "evidence", "impact", "recommendation", "verification", "agent", "timestamp", "cve_id", "cvss_score", "parameter", "module", "recommended_fix", "remediation_status", "verification_status", "risk_status"]
        return {key: finding.get(key) for key in keys if key in finding}

    async def analyze(
        self,
        *,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
        artifacts: dict[str, Any] | None,
        previous_scan: dict[str, Any] | None = None,
        previous_findings: list[dict[str, Any]] | None = None,
        previous_artifacts: dict[str, Any] | None = None,
        logs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        pack = self.evidence_pack(
            scan=scan,
            findings=findings,
            artifacts=artifacts,
            previous_scan=previous_scan,
            previous_findings=previous_findings,
            previous_artifacts=previous_artifacts,
            logs=logs,
        )
        artifacts = artifacts or {}
        priorities = self.priority_engine.rank(findings, artifacts.get("browser_security_output") or {})
        related = self.correlation.correlate(findings, artifacts)
        root_causes = self.root_causes.group(findings)
        remediation_plan = self.remediation.plan(priorities)
        comparison = self.comparison.compare(scan, findings, previous_scan, previous_findings or [], artifacts, previous_artifacts)
        score_explanation = self.score.explain(findings, artifacts)
        positive_controls = self.positives.detect(findings, artifacts)
        timeline = self.timeline.build(scan, findings, logs or [])
        summary = self.security_summary(findings, priorities, comparison, positive_controls)
        ai_narrative = await self.optional_ai_summary(pack, summary)
        return {
            "generated_at": utc_now(),
            "ai_available": bool(ai_narrative),
            "ai_status": "AI Analysis Available" if ai_narrative else "AI Analysis Unavailable - deterministic analysis shown",
            "safety": {"grounded_in_scan_evidence": True, "can_start_active_test": False, "active_tests": "recommend_only"},
            "security_summary": summary,
            "ai_narrative": ai_narrative,
            "priorities": priorities,
            "related_security_chains": related,
            "root_causes": root_causes,
            "remediation_plan": remediation_plan,
            "score_explanation": score_explanation,
            "positive_controls": positive_controls,
            "scan_comparison": comparison,
            "security_timeline": timeline,
            "executive_report": self.executive_report(summary, priorities, comparison, positive_controls),
            "developer_report": self.developer_report(findings, priorities, related),
            "suggested_prompts": self.suggested_prompts(),
            "citations": [item["citation"] for item in priorities[:10]],
            "grounding": {"source": "scanner-generated evidence only", "evidence_hash": evidence_hash(pack)},
        }

    def security_summary(
        self,
        findings: list[dict[str, Any]],
        priorities: list[dict[str, Any]],
        comparison: dict[str, Any],
        positives: list[dict[str, Any]],
    ) -> dict[str, Any]:
        active = [finding for finding in findings if not is_resolved_or_excluded(finding)]
        high_conf_auth = [finding for finding in active if str(finding.get("confidence") or "").upper() in {"CONFIRMED", "HIGH"} and any(token in f"{finding.get('title')} {finding.get('category')} {finding.get('module')}".lower() for token in ["auth", "session", "access", "jwt"])]
        high_or_critical = sum(1 for finding in active if str(finding.get("severity") or "").upper() in {"CRITICAL", "HIGH"})
        if high_or_critical >= 3:
            posture = "High Risk"
        elif high_or_critical or len(active) >= 5:
            posture = "Moderate Risk"
        elif active:
            posture = "Low to Moderate Risk"
        else:
            posture = "No Active Findings"
        immediate = [item for item in priorities if item["priority"] <= 2]
        return {
            "overall_security_posture": posture,
            "most_important_risks": [item["title"] for item in immediate],
            "what_changed": self.change_text(comparison),
            "immediate_attention": f"{len(immediate)} priority item{'s' if len(immediate) != 1 else ''} need immediate attention." if immediate else "No immediate priority active findings.",
            "can_wait": [item["title"] for item in priorities if item["priority"] > 2][:5],
            "positive_security_controls": [item["title"] for item in positives],
            "recommended_next_action": immediate[0]["recommended_action"] if immediate else "Maintain current controls and rerun after changes.",
            "authentication_focus": f"{len(high_conf_auth)} high-confidence authentication/session/access finding{'s' if len(high_conf_auth) != 1 else ''}." if high_conf_auth else "No high-confidence authentication findings in active risk set.",
        }

    @staticmethod
    def change_text(comparison: dict[str, Any]) -> str:
        parts = []
        if comparison.get("new_findings"):
            parts.append(f"{len(comparison['new_findings'])} new finding(s)")
        if comparison.get("resolved_findings"):
            parts.append(f"{len(comparison['resolved_findings'])} resolved finding(s)")
        if comparison.get("new_apis"):
            parts.append(f"{len(comparison['new_apis'])} new API route(s)")
        if comparison.get("new_routes"):
            parts.append(f"{len(comparison['new_routes'])} new route(s)")
        return ", ".join(parts) if parts else "No previous-scan delta available."

    async def optional_ai_summary(self, pack: dict[str, Any], summary: dict[str, Any]) -> str:
        if self.ai_provider is None:
            return ""
        prompt = {"task": "Summarize only these PhantomScan facts. Do not invent findings.", "summary": summary, "evidence": pack}
        for _ in range(max(1, self.retry_limit)):
            try:
                return redact_sensitive(await asyncio.wait_for(self.ai_provider(prompt), timeout=self.timeout), 4000)
            except Exception:
                continue
        return ""

    @staticmethod
    def executive_report(summary: dict[str, Any], priorities: list[dict[str, Any]], comparison: dict[str, Any], positives: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "Overall Posture": summary.get("overall_security_posture"),
            "Major Risks": [item["title"] for item in priorities[:3]],
            "Improvements": comparison.get("resolved_findings", []),
            "New Exposure": comparison.get("new_apis", []) + comparison.get("new_routes", []) + comparison.get("new_third_parties", []),
            "Recommended Priorities": [item["recommended_action"] for item in priorities[:3]],
            "Verification Status": summary.get("immediate_attention"),
            "What's Already Secure": [item.get("title") for item in positives],
        }

    @staticmethod
    def developer_report(findings: list[dict[str, Any]], priorities: list[dict[str, Any]], related: list[dict[str, Any]]) -> list[dict[str, Any]]:
        priority_by_id = {item["finding_id"]: item for item in priorities}
        related_by_id: dict[Any, list[str]] = {}
        for chain in related:
            primary_id = chain.get("primary", {}).get("id")
            related_by_id.setdefault(primary_id, []).append(chain.get("title"))
        report = []
        for finding in findings:
            report.append(
                {
                    "finding_id": finding.get("id"),
                    "affected_endpoint": finding.get("endpoint"),
                    "evidence": finding.get("evidence"),
                    "observed_behavior": finding.get("description") or finding.get("evidence"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "related_findings": related_by_id.get(finding.get("id"), []),
                    "technology": finding.get("cve_id") or "derived from scan artifacts when available",
                    "remediation": finding.get("recommended_fix") or finding.get("recommendation"),
                    "verification": finding.get("verification"),
                    "recommended_priority": priority_by_id.get(finding.get("id"), {}).get("priority"),
                }
            )
        return report

    @staticmethod
    def suggested_prompts() -> list[str]:
        return [
            "What should I fix first?",
            "Why is my security score this value?",
            "Which findings affect authentication?",
            "Which APIs are highest priority?",
            "What changed since my previous scan?",
            "Which findings are confirmed?",
            "Explain this issue in Hindi.",
            "Give me a remediation checklist.",
            "Which issues were resolved?",
            "Which attack surfaces are new?",
        ]

    async def explain_finding_cached(self, finding: dict[str, Any], *, language: str = "en") -> dict[str, Any]:
        model = self.model
        hash_value = evidence_hash(self.safe_finding(finding))
        cache_key = f"finding:{finding.get('id')}:{hash_value}:{language}:{model}"
        cached = await get_ai_cache(cache_key)
        if cached and cached.get("response"):
            return {**cached["response"], "cached": True}
        response = self.finding_explanation(finding, language=language)
        if self.ai_provider is not None:
            ai_text = await self.optional_ai_summary({"finding": self.safe_finding(finding)}, {"title": finding.get("title")})
            if ai_text:
                response["ai_text"] = ai_text
        await set_ai_cache(cache_key, finding_id=int(finding.get("id", 0) or 0), evidence_hash=hash_value, language=language, model=model, response=response)
        return {**response, "cached": False}

    @staticmethod
    def finding_explanation(finding: dict[str, Any], *, language: str = "en") -> dict[str, Any]:
        confirmed = str(finding.get("confidence") or "").upper() == "CONFIRMED"
        evidence = str(finding.get("evidence") or "")
        signals = []
        if "browser" in evidence.lower() or "Browser" in str(finding.get("agent")):
            signals.append("Browser evidence reproduced or observed the behavior")
        if "HTTP status" in evidence or "response" in evidence.lower() or finding.get("endpoint"):
            signals.append("Network or endpoint evidence is attached")
        if str(finding.get("verification_status") or "") == "FIX_VERIFIED":
            signals.append("Fix verification has since passed")
        if not signals:
            signals.append("Scanner evidence exists, but additional reproduction signals were not recorded")
        if language.lower().startswith("hi"):
            return {
                "title": "हिन्दी विश्लेषण",
                "summary": f"यह निष्कर्ष {finding.get('title')} उपलब्ध PhantomScan evidence पर आधारित है।",
                "why_confirmed": signals if confirmed else [],
                "why_potential": [] if confirmed else ["संदिग्ध संकेत मिला, लेकिन पर्याप्त स्वतंत्र verification evidence उपलब्ध नहीं है।"],
                "citations": [finding_reference(finding)],
            }
        return {
            "title": "AI Analysis",
            "summary": f"PhantomScan is interpreting scanner evidence for: {finding.get('title')}",
            "why_confirmed": signals if confirmed else [],
            "why_potential": [] if confirmed else ["Suspicious behavior was observed, but active/browser verification did not produce enough independent evidence for CONFIRMED."],
            "evidence_required_for_confirmation": "Repeatable browser or active verification, matching network response evidence, and consistent behavior across attempts." if not confirmed else "Already confirmed by available evidence.",
            "citations": [finding_reference(finding)],
        }


class AskPhantomScanResponder:
    def answer(self, question: str, analysis: dict[str, Any], findings: list[dict[str, Any]], artifacts: dict[str, Any] | None = None) -> dict[str, Any]:
        q = question.lower().strip()
        citations = []
        answer = "I can only answer from available PhantomScan evidence. I do not have enough matching scan evidence for that question."
        priorities = analysis.get("priorities", [])
        summary = analysis.get("security_summary", {})
        comparison = analysis.get("scan_comparison", {})
        score = analysis.get("score_explanation", {})
        artifacts = artifacts or {}
        if any(token in q for token in ["fix first", "what should i fix", "fix", "priority", "today"]):
            if priorities:
                top = priorities[:3]
                answer = "Fix these first: " + "; ".join(f"Priority {item['priority']}: {item['title']}" for item in top)
                citations = [item.get("citation") for item in top if item.get("citation")]
        elif "score" in q:
            answer = f"Security score is {score.get('score', 'unknown')}. Deductions: {score.get('deductions', [])}. Credits: {score.get('credits', [])}."
        elif "authentication" in q or "login" in q:
            auth_findings = [finding for finding in findings if any(token in f"{finding.get('title')} {finding.get('category')} {finding.get('module')}".lower() for token in ["auth", "login", "session", "access", "jwt"])]
            answer = f"{len(auth_findings)} finding(s) affect authentication/session/access control."
            citations = [finding_reference(item) for item in auth_findings[:5]]
        elif "api" in q:
            apis = (artifacts.get("browser_security_output") or {}).get("api_inventory", [])
            answer = f"{len(apis)} API endpoint(s) were observed. Highest-priority APIs are those linked to active priority findings."
            citations = [item.get("citation") for item in priorities[:5] if item.get("citation")]
        elif "changed" in q or "new" in q:
            answer = f"What changed: {AISecurityAnalyst.change_text(comparison)}."
        elif "confirmed" in q:
            confirmed = [finding for finding in findings if str(finding.get("confidence") or "").upper() == "CONFIRMED"]
            answer = f"{len(confirmed)} finding(s) are CONFIRMED."
            citations = [finding_reference(item) for item in confirmed[:8]]
        elif "hindi" in q or "हिंदी" in q or "हिन्दी" in q:
            answer = f"सारांश: सुरक्षा स्थिति {summary.get('overall_security_posture', 'unknown')} है। प्राथमिक कार्य: {summary.get('recommended_next_action', 'उपलब्ध नहीं')}"
            citations = [item.get("citation") for item in priorities[:3] if item.get("citation")]
        elif "checklist" in q or "remediation" in q:
            plan = analysis.get("remediation_plan", {})
            answer = "Remediation checklist: " + json.dumps(plan, ensure_ascii=False, default=str)[:2500]
            citations = [item.get("citation") for item in priorities[:5] if item.get("citation")]
        elif "resolved" in q:
            resolved = [finding for finding in findings if is_resolved_or_excluded(finding)]
            answer = f"{len(resolved)} finding(s) are resolved, accepted, false-positive, or fix-verified and excluded from active prioritization."
            citations = [finding_reference(item) for item in resolved[:8]]
        elif "surface" in q or "route" in q:
            routes = (artifacts.get("browser_security_output") or {}).get("routes", [])
            answer = f"{len(routes)} browser/application route surface(s) are available in the current evidence. New surfaces: {comparison.get('new_routes', [])[:10]}"
        return {"answer": redact_sensitive(answer, 6000), "citations": [item for item in citations if item], "grounded": True, "can_start_active_test": False}
