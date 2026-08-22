import json
from typing import Any

from app.agents import Agent
from app.config import get_settings
from app.services.openrouter_client import call_openrouter
from app.skills import load_skill
from app.skills.loader import get_loader
from app.models import PRDescriptionRequest, PRDescriptionResponse


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_RANGES = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.0, 3.9),
    "info": (None, None),
}

OWNER_MAP: dict[str, str] = {
    "xss": "frontend",
    "csp": "frontend",
    "xfo": "frontend",
    "cors": "backend",
    "csrf": "backend",
    "sqli": "backend",
    "ssrf": "backend",
    "rce": "devops",
    "lfi": "backend",
    "idor": "backend",
    "jwt": "backend",
    "xxe": "backend",
    "ssti": "backend",
    "tls": "devops",
    "hsts": "devops",
    "cookie": "backend",
    "info": "devops",
    "open_redirect": "backend",
    "upload": "backend",
    "auth": "backend",
    "ratelimit": "devops",
}

ETA_MAP: dict[str, str] = {
    "critical": "1h",
    "high": "4h",
    "medium": "1d",
    "low": "1w",
    "info": "1w",
}


class FixerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Fixer Agent")
        self.settings = get_settings()

    async def run(
        self, findings: list[dict[str, Any]], scan_id: int
    ) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Generating remediation checklist for {len(findings)} findings")

        checklist = self._generate_checklist(findings)
        
        # Generate patches for high-severity findings with code locations
        patches = await self._generate_patches(findings)
        
        markdown = self._to_markdown(checklist, patches)

        self.status = "complete"
        await self.log_action("completed", f"Remediation checklist generated with {len(patches)} patches")
        return {"markdown_report": markdown, "checklist": checklist, "patches": patches}

    def _generate_checklist(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped = self._group_by_severity(findings)
        checklist: list[dict[str, Any]] = []
        for sev in SEVERITY_ORDER:
            for f in grouped.get(sev, []):
                title = str(f.get("title", "Unknown finding"))
                component = str(f.get("endpoint", "") or f.get("affected_component", "") or "unknown")
                raw_fix = str(f.get("fix", "") or f.get("recommendation", "") or "Review manually")
                category = str(f.get("category", "")).lower()

                # Enhance fix with skill-based remediation patterns
                enhanced_fix = self._enhance_fix_with_skills(title, category, raw_fix)

                owner = self._assign_owner(title, category)
                eta = ETA_MAP.get(sev, "1d")

                checklist.append({
                    "severity": sev.upper(),
                    "title": title,
                    "affected": component,
                    "fix": enhanced_fix,
                    "owner": owner,
                    "eta": eta,
                })
        return checklist

    def _enhance_fix_with_skills(self, title: str, category: str, raw_fix: str) -> str:
        """Enhance remediation with skill-based patterns."""
        vuln_key = self._map_to_skill(title, category)
        if not vuln_key:
            return raw_fix

        skill = load_skill(vuln_key)
        if not skill:
            return raw_fix

        loader = get_loader()
        skill_patterns = skill.payload.remediation_patterns
        if not skill_patterns:
            return raw_fix

        # Combine raw fix with skill patterns
        enhanced = raw_fix
        if skill_patterns:
            enhanced += "\n\n**Expert Remediation Patterns:**\n"
            for pattern in skill_patterns[:3]:  # Limit to top 3 patterns
                enhanced += f"- {pattern}\n"

        return enhanced

    def _map_to_skill(self, title: str, category: str) -> str | None:
        """Map finding title/category to skill name."""
        t = (title + " " + category).lower()
        skill_map = {
            "sql_injection": ["sql", "injection", "sqli"],
            "xss": ["xss", "cross-site scripting"],
            "ssrf": ["ssrf", "server-side request forgery"],
            "idor": ["idor", "insecure direct object reference", "object reference"],
            "jwt": ["jwt", "json web token", "token"],
            "race_conditions": ["race condition", "race"],
            "business_logic": ["business logic", "workflow", "logic flaw"],
            "file_upload": ["file upload", "upload", "webshell"],
            "ssti": ["ssti", "server-side template injection", "template injection"],
            "xxe": ["xxe", "xml external entity", "xml injection"],
            "prototype_pollution": ["prototype pollution", "prototype"],
            "http_request_smuggling": ["request smuggling", "smuggling", "desync"],
        }
        for skill_name, keywords in skill_map.items():
            if any(kw in t for kw in keywords):
                return skill_name
        return None

    async def _generate_patches(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate code patches for findings with code location evidence."""
        eligible: list[dict[str, Any]] = []
        for finding in findings:
            severity = str(finding.get("severity", "")).lower()
            if severity not in ("critical", "high"):
                continue
            endpoint = finding.get("endpoint", "")
            parameter = finding.get("parameter", "")
            if not endpoint and not parameter:
                continue
            eligible.append(finding)

        if not eligible:
            return []
        return await self._batch_generate_patches(eligible)

    async def _batch_generate_patches(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate patches for multiple findings in a single LLM call."""
        batch_input = []
        for i, f in enumerate(findings):
            batch_input.append({
                "finding_id": i,
                "title": str(f.get("title", "")),
                "category": str(f.get("category", "")),
                "severity": str(f.get("severity", "")),
                "endpoint": str(f.get("endpoint", "")),
                "parameter": str(f.get("parameter", "")),
                "evidence": str(f.get("evidence", ""))[:2000],
                "recommendation": str(f.get("recommendation") or f.get("fix") or f.get("recommended_fix", "")),
            })
        system_prompt = (
            "You are a senior security engineer. Generate unified diff patches to fix these vulnerabilities. "
            "Return a JSON object with a 'results' array. Each entry must have 'finding_id', "
            "'patch' (unified diff), 'file_path', 'language'."
        )
        user_prompt = (
            f"Generate patches for {len(findings)} findings:\n"
            f"{json.dumps(batch_input, default=str)}"
        )
        patches: list[dict[str, Any]] = []
        try:
            result = await call_openrouter(
                user_prompt, system_prompt,
                scan_id=self.scan_id, max_tokens=4000,
                json_response=True,
            )
            if result:
                parsed = json.loads(result)
                items = parsed.get("results", parsed) if isinstance(parsed, dict) else parsed
                if isinstance(items, list):
                    for item in items:
                        idx = item.get("finding_id")
                        if isinstance(idx, int) and 0 <= idx < len(findings):
                            patch_text = str(item.get("patch", ""))
                            if patch_text and ("diff" in patch_text.lower() or patch_text.strip().startswith("---") or patch_text.strip().startswith("@@")):
                                patches.append({
                                    "finding_id": findings[idx].get("id"),
                                    "finding_title": findings[idx].get("title"),
                                    "patch": patch_text.strip(),
                                    "file_path": str(item.get("file_path", "")),
                                    "language": str(item.get("language", "")),
                                })
        except Exception:
            for f in findings:
                patch = await self._generate_patch_for_finding(f)
                if patch:
                    patches.append(patch)
        return patches

    async def _generate_patch_for_finding(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Generate a code patch for a specific finding using LLM."""
        title = finding.get("title", "")
        category = finding.get("category", "")
        severity = finding.get("severity", "")
        endpoint = finding.get("endpoint", "")
        evidence = finding.get("evidence", "")
        parameter = finding.get("parameter", "")
        recommendation = finding.get("recommendation") or finding.get("fix") or finding.get("recommended_fix", "")
        
        # Load relevant skill for context
        vuln_key = self._map_to_skill(title, category)
        skill_context = ""
        if vuln_key:
            skill = load_skill(vuln_key)
            if skill:
                loader = get_loader()
                skill_context = loader.format_skill_for_prompt(skill)
        
        system_prompt = (
            "You are a senior security engineer. Generate a precise code patch to fix the vulnerability. "
            "Output ONLY a unified diff patch. No explanations, no markdown formatting, just the diff.\n\n"
            f"EXPERT KNOWLEDGE:\n{skill_context}"
        )
        
        user_prompt = (
            f"Vulnerability: {title}\n"
            f"Category: {category}\n"
            f"Severity: {severity}\n"
            f"Endpoint: {endpoint}\n"
            f"Parameter: {parameter}\n"
            f"Evidence: {evidence[:2000]}\n"
            f"Recommendation: {recommendation}\n\n"
            "Generate a unified diff patch that fixes this vulnerability. "
            "Assume the codebase uses common patterns (parameterized queries, input validation, output encoding). "
            "Include file paths as 'path/to/vulnerable/file.ext' if not specified in evidence."
        )
        
        try:
            result = await call_openrouter(
                user_prompt, system_prompt,
                scan_id=self.scan_id, max_tokens=1500
            )
            
            if result and ("diff" in result.lower() or result.strip().startswith("---") or result.strip().startswith("@@")):
                return {
                    "finding_id": finding.get("id"),
                    "finding_title": title,
                    "patch": result.strip(),
                    "file_path": self._extract_file_path(evidence, endpoint),
                    "language": self._detect_language(category, endpoint),
                }
        except Exception as e:
            await self.log_action("patch_generation_error", f"Failed to generate patch for {title}: {e}")
        
        return None

    def _extract_file_path(self, evidence: str, endpoint: str) -> str:
        """Extract or infer file path from evidence/endpoint."""
        import re
        # Look for file paths in evidence
        paths = re.findall(r'[\w/\\.-]+\.(py|js|ts|java|php|go|rb|cs)', evidence)
        if paths:
            return paths[0]
        # Infer from endpoint
        if endpoint:
            path = endpoint.split("?")[0].strip("/")
            if path:
                return f"src/{path.replace('/', '/')}.py"
        return "src/vulnerable_code.py"

    def _detect_language(self, category: str, endpoint: str) -> str:
        """Detect programming language from category/endpoint."""
        cat = category.lower()
        if "sql" in cat:
            return "sql"
        if "xss" in cat or "javascript" in cat:
            return "javascript"
        if "template" in cat or "ssti" in cat:
            return "python"  # Jinja2, etc.
        if endpoint:
            if ".php" in endpoint:
                return "php"
            if ".js" in endpoint or "/api/" in endpoint:
                return "javascript"
            if ".java" in endpoint:
                return "java"
            if ".go" in endpoint:
                return "go"
        return "python"

    def _group_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in SEVERITY_ORDER}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev not in grouped:
                sev = "info"
            grouped[sev].append(f)
        return grouped

    async def generate_pr_description(
        self,
        finding_ids: list[int],
        base_branch: str,
        head_branch: str,
        repo_url: str,
        include_fix_details: bool = True,
        include_verification_steps: bool = True,
    ) -> PRDescriptionResponse:
        """Generate a PR description for fixing the findings."""
        self.status = "active"
        await self.log_action("pr_description_started", f"Generating PR description for {len(finding_ids)} findings")

        # Find the findings
        from app.database import get_finding
        findings = []
        for fid in finding_ids:
            finding = await get_finding(fid)
            if finding:
                findings.append(finding)

        if not findings:
            return PRDescriptionResponse(
                title="Security Fixes",
                body="No valid findings provided.",
                labels=[],
                reviewers=[],
                related_issues=[],
            )

        # Group findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "INFO"), 4))

        # Generate title
        critical_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if critical_high:
            title = f"Security Fix: {len(critical_high)} Critical/High severity vulnerabilities"
        else:
            title = f"Security Fix: {len(findings)} vulnerabilities"

        # Build PR body
        body_parts = [
            f"# Security Fix PR\n",
            f"This PR addresses **{len(findings)} security vulnerabilities** identified by PhantomScan.\n",
            "## Summary\n",
        ]

        for finding in findings:
            sev = finding.get("severity", "INFO")
            title = finding.get("title", "Unknown")
            category = finding.get("category", "")
            endpoint = finding.get("endpoint", "")
            parameter = finding.get("parameter", "")

            body_parts.append(f"### {sev}: {title}")
            body_parts.append(f"- **Category**: {category}")
            body_parts.append(f"- **Endpoint**: {endpoint or 'N/A'}")
            if parameter:
                body_parts.append(f"- **Parameter**: {parameter}")
            body_parts.append(f"- **Description**: {finding.get('evidence', 'N/A')[:200]}")
            body_parts.append("")

        if include_fix_details:
            body_parts.append("## Fix Details\n")
            for finding in findings:
                sev = finding.get("severity", "INFO")
                title = finding.get("title", "Unknown")
                recommendation = finding.get("recommendation") or finding.get("fix") or finding.get("recommended_fix", "See patch")
                body_parts.append(f"### {sev}: {title}")
                body_parts.append(f"{recommendation}")
                body_parts.append("")

        if include_verification_steps:
            body_parts.append("## Verification Steps\n")
            for finding in findings:
                sev = finding.get("severity", "INFO")
                title = finding.get("title", "Unknown")
                verification = finding.get("verification", "Re-run scan to verify fix")
                body_parts.append(f"### {sev}: {title}")
                body_parts.append(f"{verification}")
                body_parts.append("")

        body_parts.append("## Related Information")
        body_parts.append(f"- **Scan ID**: {self.scan_id}")
        body_parts.append(f"- **Target**: {findings[0].get('target', 'N/A')}")
        body_parts.append(f"- **Base Branch**: {base_branch}")
        body_parts.append(f"- **Head Branch**: {head_branch}")
        body_parts.append("")

        body_parts.append("---\n*Generated by PhantomScan*")

        # Labels
        labels = ["security", "bug"]
        for f in findings:
            sev = f.get("severity", "").lower()
            if sev in ("critical", "high"):
                labels.append(f"severity:{sev}")
            cat = f.get("category", "").lower()
            if cat:
                labels.append(f"category:{cat}")

        # Reviewers (can be extended)
        reviewers = []

        # Related issues
        related_issues = [f"#{fid}" for fid in finding_ids]

        return PRDescriptionResponse(
            title=title,
            body="\n".join(body_parts),
            labels=labels,
            reviewers=reviewers,
            related_issues=related_issues,
        )

    def _group_by_severity(self, findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in SEVERITY_ORDER}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev not in grouped:
                sev = "info"
            grouped[sev].append(f)
        return grouped

    def _assign_owner(self, title: str, category: str) -> str:
        t = (title + " " + category).lower()
        for keyword, owner in OWNER_MAP.items():
            if keyword in t:
                return owner
        return "backend"

    def _to_markdown(self, checklist: list[dict[str, Any]], patches: list[dict[str, Any]] | None = None) -> str:
        lines = ["# PhantomScan Remediation Checklist", ""]
        current_sev = ""
        for item in checklist:
            if item["severity"] != current_sev:
                current_sev = item["severity"]
                lines.append(f"## {current_sev}")
                lines.append("")
            lines.append(f"- [ ] **[{current_sev}]** {item['title']}")
            lines.append(f"  - Affected: {item['affected']}")
            lines.append(f"  - Fix: `{item['fix']}`")
            lines.append(f"  - Owner: {item['owner']}")
            lines.append(f"  - ETA: {item['eta']}")
            lines.append("")
        
        if patches:
            lines.append("## Generated Patches")
            lines.append("")
            for patch in patches:
                lines.append(f"### Patch for: {patch['finding_title']}")
                lines.append(f"**File**: `{patch['file_path']}` ({patch['language']})")
                lines.append("```diff")
                lines.append(patch['patch'])
                lines.append("```")
                lines.append("")
        
        return "\n".join(lines)
