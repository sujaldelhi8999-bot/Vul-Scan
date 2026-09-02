"""Rule-based scanner engine — walks files, applies detection rules, returns findings.

Ported from VULSCAN/backend/services/scanner_engine.py.
92 regex rules across 3 categories: secrets, security, docker.
"""

import asyncio
import fnmatch
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("phantomscan.rule_scanner")

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"

SCAN_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".pyi", ".pyw",
    ".java", ".go", ".rs", ".rb", ".php", ".cs", ".swift", ".kt",
    ".yaml", ".yml", ".toml", ".cfg", ".ini", ".conf", ".properties",
    ".json", ".xml",
    ".env", ".env.example", ".env.local", ".env.production", ".env.test",
    ".sh", ".bash", ".zsh", ".fish",
    ".dockerfile", ".tf", ".hcl", ".tfvars",
    ".md", ".txt", ".rst",
    ".html", ".htm", ".css", ".scss", ".less",
    ".sql", ".graphql", ".gql",
    ".gradle", ".sbt",
    ".vue", ".svelte",
    ".dockerignore",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".cache", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".nyc_output", "vendor",
    ".eggs", ".gradle", "target", "out", "bin", "obj",
    ".idea", ".vs", ".vscode",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "uv.lock",
    "pnpm-lock.yaml", "Pipfile.lock", "composer.lock", "Cargo.lock",
    "go.sum", "Gemfile.lock",
}

MAX_FILE_SIZE = 1_000_000  # 1MB


def _excluded_by_pattern(file_path: Path, target: Path, exclude_patterns: list[str]) -> bool:
    try:
        rel = file_path.relative_to(target if target.is_dir() else target.parent).as_posix()
    except ValueError:
        rel = file_path.as_posix()
    name = file_path.name
    for raw_pattern in exclude_patterns:
        pattern = raw_pattern.strip().replace("\\", "/").lstrip("./")
        if not pattern:
            continue
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern) or Path(rel).match(pattern):
            return True
    return False


CONTEXT_AWARE_RULES: dict[str, dict[str, Any]] = {
    "SQL_Injection": {
        "patterns": [
            r"\bSELECT\b[^\n;]*(?:\+|%\s*\(|\.format\(|\{[^}]+\})",
            r"\b(?:execute|query)\s*\([^\n)]*(?:\+|%\s*\(|\.format\(|f[\"'])",
            r"f[\"'][^\"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\{[^}]+\}",
        ],
        "severity": "critical",
        "category": "SAST",
        "message": "Potential SQL injection: user-controlled data appears to be concatenated into a query.",
        "fix": "Use parameterized queries or an ORM query builder; never concatenate request data into SQL.",
    },
    "XSS_Reflected": {
        "patterns": [
            r"\.innerHTML\s*=",
            r"\.outerHTML\s*=",
            r"document\.write\s*\(",
            r"\$\([^)]*\)\.html\s*\(",
            r"<%=[\s\S]*?%>",
        ],
        "severity": "high",
        "category": "SAST",
        "message": "Potential XSS sink: untrusted content may be rendered as HTML.",
        "fix": "Render untrusted content as text, escape template output, or sanitize HTML with a vetted sanitizer such as DOMPurify.",
    },
    "Path_Traversal": {
        "patterns": [
            r"\bopen\s*\([^\n)]*\+[^\n)]*\)",
            r"\breadFileSync\s*\([^\n)]*\+[^\n)]*\)",
            r"\b(?:sendFile|download)\s*\([^\n)]*(?:req\.|request\.|\+)",
            r"\.\.[/\\]",
        ],
        "severity": "high",
        "category": "SAST",
        "message": "Potential path traversal: user input may influence filesystem paths.",
        "fix": "Resolve the requested path, normalize it, and enforce that it remains inside an allowed base directory.",
    },
    "Hardcoded_Secrets": {
        "patterns": [
            r"\b(?:password|passwd|pwd|api[_-]?key|secret|token|private[_-]?key)\b\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']",
            r"\bAWS_SECRET_ACCESS_KEY\b\s*[:=]",
            r"\bsk-[A-Za-z0-9]{32,}\b",
            r"\bghp_[A-Za-z0-9]{36,}\b",
        ],
        "severity": "critical",
        "category": "Secrets",
        "message": "Hardcoded secret detected.",
        "fix": "Move the secret into a secrets manager or environment variable, rotate it, and remove it from version control history.",
    },
}

CONTEXT_RULES_BY_EXTENSION: dict[str, list[str]] = {
    ".js": ["XSS_Reflected", "Path_Traversal", "Hardcoded_Secrets"],
    ".jsx": ["XSS_Reflected", "Path_Traversal", "Hardcoded_Secrets"],
    ".ts": ["XSS_Reflected", "Path_Traversal", "Hardcoded_Secrets"],
    ".tsx": ["XSS_Reflected", "Path_Traversal", "Hardcoded_Secrets"],
    ".vue": ["XSS_Reflected", "Hardcoded_Secrets"],
    ".svelte": ["XSS_Reflected", "Hardcoded_Secrets"],
    ".py": ["SQL_Injection", "Path_Traversal", "Hardcoded_Secrets"],
    ".php": ["SQL_Injection", "XSS_Reflected", "Path_Traversal", "Hardcoded_Secrets"],
    ".html": ["XSS_Reflected", "Hardcoded_Secrets"],
    ".htm": ["XSS_Reflected", "Hardcoded_Secrets"],
    ".java": ["SQL_Injection", "Path_Traversal", "Hardcoded_Secrets"],
    ".go": ["SQL_Injection", "Path_Traversal", "Hardcoded_Secrets"],
    ".rb": ["SQL_Injection", "Path_Traversal", "Hardcoded_Secrets"],
    ".env": ["Hardcoded_Secrets"],
}


class RuleScanner:
    """Scans source code for security vulnerabilities and secrets using regex rules."""

    def __init__(self) -> None:
        self._rules: list[dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        rule_files = ["secrets_rules.json", "security_rules.json", "docker_rules.json"]
        for rule_file in rule_files:
            path = RULES_DIR / rule_file
            if path.exists():
                try:
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                        self._rules.extend(data.get("rules", []))
                except Exception as exc:
                    logger.warning("Failed to load rules from %s: %s", path, exc)
        logger.info("Loaded %d rules", len(self._rules))

    def _should_scan_file(self, file_path: Path) -> bool:
        name = file_path.name
        if name in SKIP_FILES:
            return False
        ext = file_path.suffix.lower()
        if ext in SCAN_EXTENSIONS:
            return True
        if "dockerfile" in name.lower():
            return True
        if name.startswith(".env"):
            return True
        return False

    def _is_dockerfile(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")

    def _get_applicable_rules(self, file_path: Path, rules: list[dict], content: str) -> list[dict]:
        applicable = []
        is_docker = self._is_dockerfile(file_path)
        for rule in rules:
            file_filter = rule.get("file_filter", "")
            if not file_filter:
                applicable.append(rule)
                continue
            if file_filter == "dockerfile":
                if is_docker:
                    applicable.append(rule)
            elif file_filter == "dockerfile-nouser":
                if is_docker:
                    has_from = re.search(r"^\s*FROM\s+", content, re.IGNORECASE | re.MULTILINE)
                    has_user = re.search(r"^\s*USER\s+", content, re.IGNORECASE | re.MULTILINE)
                    if has_from and not has_user:
                        applicable.append(rule)
            elif file_filter == "dockerfile-nohealthcheck":
                if is_docker:
                    has_hc = re.search(r"^\s*HEALTHCHECK\s+", content, re.IGNORECASE | re.MULTILINE)
                    if not has_hc:
                        applicable.append(rule)
            elif file_filter == "dockerfile-nomultistage":
                if is_docker:
                    from_count = len(re.findall(r"^\s*FROM\s+", content, re.IGNORECASE | re.MULTILINE))
                    if from_count <= 1:
                        applicable.append(rule)
            else:
                applicable.append(rule)
        return applicable

    def _collect_files(self, target_path: str, exclude_patterns: list[str] | None = None) -> list[Path]:
        files = []
        target = Path(target_path)
        excludes = exclude_patterns or []
        if target.is_file():
            if self._should_scan_file(target) and not _excluded_by_pattern(target, target, excludes):
                files.append(target)
            return files
        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for filename in filenames:
                file_path = Path(root) / filename
                if self._should_scan_file(file_path) and not _excluded_by_pattern(file_path, target, excludes):
                    files.append(file_path)
        return files

    def _scan_file_content(
        self, file_path: Path, content: str, rules: list[dict],
        sensitivity: str = "medium", target_root: str = "",
    ) -> list[dict[str, Any]]:
        findings = []
        lines = content.split("\n")
        display_path = str(file_path)
        if target_root:
            try:
                display_path = str(file_path.relative_to(target_root))
            except ValueError:
                display_path = str(file_path)

        for rule in rules:
            rule_severity = rule.get("severity", "medium")
            if sensitivity == "low" and rule_severity in ("low", "info"):
                continue
            if sensitivity == "medium" and rule_severity == "info":
                continue
            pattern_str = rule.get("pattern", "")
            if not pattern_str:
                continue
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            for line_num, line in enumerate(lines, 1):
                for match in pattern.finditer(line):
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                        continue
                    snippet = "\n".join(
                        lines[max(0, line_num - 3):min(len(lines), line_num + 2)]
                    )
                    findings.append({
                        "rule_id": rule.get("id", ""),
                        "title": rule.get("title", "Unknown"),
                        "description": rule.get("description", ""),
                        "severity": rule_severity,
                        "category": rule.get("category", "other"),
                        "file_path": display_path,
                        "line_number": line_num,
                        "matched_text": match.group(0)[:200],
                        "code_snippet": snippet[:2000],
                        "recommendation": rule.get("recommendation", ""),
                        "fix_recommendation": rule.get("recommendation", ""),
                        "owasp_category": rule.get("owasp", ""),
                    })
        return findings

    def _scan_context_aware_rules(
        self, file_path: Path, content: str, sensitivity: str, target_root: str,
    ) -> list[dict[str, Any]]:
        findings = []
        lines = content.split("\n")
        ext = file_path.suffix.lower()
        display_path = str(file_path)
        if target_root:
            try:
                display_path = str(file_path.relative_to(target_root))
            except ValueError:
                display_path = str(file_path)

        applicable_rule_names = CONTEXT_RULES_BY_EXTENSION.get(ext, [])
        if not applicable_rule_names:
            applicable_rule_names = list(CONTEXT_AWARE_RULES.keys())

        for rule_name in applicable_rule_names:
            rule = CONTEXT_AWARE_RULES.get(rule_name)
            if not rule:
                continue
            rule_severity = rule.get("severity", "medium")
            if sensitivity == "low" and rule_severity in ("low", "info"):
                continue
            for pattern_str in rule["patterns"]:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                except re.error:
                    continue
                for line_num, line in enumerate(lines, 1):
                    for match in pattern.finditer(line):
                        stripped = line.strip()
                        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                            continue
                        snippet = "\n".join(
                            lines[max(0, line_num - 3):min(len(lines), line_num + 2)]
                        )
                        findings.append({
                            "rule_id": rule_name,
                            "title": f"{rule_name.replace('_', ' ')}: {rule.get('message', '')}",
                            "description": rule.get("message", ""),
                            "severity": rule_severity,
                            "category": rule.get("category", "SAST"),
                            "file_path": display_path,
                            "line_number": line_num,
                            "matched_text": match.group(0)[:200],
                            "code_snippet": snippet[:2000],
                            "recommendation": rule.get("fix", ""),
                            "fix_recommendation": rule.get("fix", ""),
                            "owasp_category": "",
                            "source": "context_aware_rule_scanner",
                        })
        return findings

    async def scan(self, path: str, sensitivity: str = "medium", exclude_patterns: list[str] | None = None) -> list[dict[str, Any]]:
        """Scan a directory or file for security issues using regex rules."""
        start = time.time()
        if not path or not os.path.exists(path):
            return []
        files = self._collect_files(path, exclude_patterns)
        if not files:
            return []
        rules = self._rules
        if sensitivity == "low":
            rules = [r for r in rules if r.get("severity") in ("critical", "high")]
        elif sensitivity == "medium":
            rules = [r for r in rules if r.get("severity") in ("critical", "high", "medium")]

        all_findings: list[dict[str, Any]] = []
        for i, file_path in enumerate(files):
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="replace")
                file_rules = self._get_applicable_rules(file_path, rules, content)
                findings = self._scan_file_content(file_path, content, file_rules, sensitivity, path)
                all_findings.extend(findings)
                context_findings = self._scan_context_aware_rules(file_path, content, sensitivity, path)
                all_findings.extend(context_findings)
            except Exception as exc:
                logger.debug("Error scanning %s: %s", file_path, exc)
            if i % 50 == 0:
                await asyncio.sleep(0)

        seen: set[tuple[str, str, int]] = set()
        unique: list[dict[str, Any]] = []
        for f in all_findings:
            key = (f["rule_id"], f["file_path"], f["line_number"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        elapsed = round(time.time() - start, 2)
        logger.info("Rule scan complete: %d findings in %ds (%d files)", len(unique), elapsed, len(files))
        return unique
