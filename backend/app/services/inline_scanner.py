"""
Inline Scanner - Self-contained regex-based code scanner (ported from VULSCAN).

Scans source files against 91 detection rules (47 security + 29 secrets + 15 Docker)
without requiring external tools like semgrep or trufflehog.
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("phantomscan.inline_scanner")

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

SKIP_FILE_PATTERNS = [
    re.compile(r"^report-\d{4}-\d{2}-\d{2}\.md$"),
    re.compile(r"^scan-results.*"),
]


@dataclass
class InlineFinding:
    rule_id: str
    title: str
    severity: str
    category: str
    file_path: str
    line_number: int
    matched_text: str
    description: str = ""
    recommendation: str = ""
    owasp_category: str = ""
    masked_text: str = ""


@dataclass
class InlineScanResult:
    findings: list[InlineFinding] = field(default_factory=list)
    total_files: int = 0
    scanned_files: int = 0
    lines_scanned: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    secrets_found: int = 0
    scan_duration_seconds: float = 0.0


class InlineScanner:
    """Self-contained regex-based code scanner."""

    def __init__(self) -> None:
        self._rules: list[dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        rule_files = [
            "security_rules.json",
            "secrets_rules.json",
            "docker_rules.json",
        ]
        for rule_file in rule_files:
            path = RULES_DIR / rule_file
            if path.exists():
                try:
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                        self._rules.extend(data.get("rules", []))
                except Exception as e:
                    logger.warning("Failed to load rules from %s: %s", path, e)

    def _should_scan_file(self, file_path: Path) -> bool:
        name = file_path.name
        if name in SKIP_FILES:
            return False
        for pattern in SKIP_FILE_PATTERNS:
            if pattern.match(name):
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

    def _scan_file_content(
        self,
        file_path: Path,
        content: str,
        rules: list[dict],
        sensitivity: str,
        target_root: str,
    ) -> list[InlineFinding]:
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
                matches = list(pattern.finditer(line))
                for match in matches:
                    matched_text = match.group(0)
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                        continue
                    findings.append(InlineFinding(
                        rule_id=rule.get("id", ""),
                        title=rule.get("title", "Unknown"),
                        severity=rule_severity,
                        category=rule.get("category", "other"),
                        file_path=display_path,
                        line_number=line_num,
                        matched_text=matched_text[:200],
                        description=rule.get("description", ""),
                        recommendation=rule.get("recommendation", ""),
                        owasp_category=rule.get("owasp", ""),
                    ))
        return findings

    async def scan(
        self,
        target_path: str,
        sensitivity: str = "medium",
        progress_callback=None,
    ) -> InlineScanResult:
        """Run inline scan on a directory."""
        start = time.time()
        result = InlineScanResult()
        target = Path(target_path)
        if not target.exists():
            return result

        if target.is_file():
            files = [target] if self._should_scan_file(target) else []
        else:
            files = []
            for root, dirs, filenames in os.walk(target):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fname in filenames:
                    fp = Path(root) / fname
                    if self._should_scan_file(fp):
                        files.append(fp)

        result.total_files = len(files)
        rules = self._rules
        if sensitivity == "low":
            rules = [r for r in rules if r.get("severity") in ("critical", "high")]
        elif sensitivity == "medium":
            rules = [r for r in rules if r.get("severity") in ("critical", "high", "medium")]

        all_findings: list[InlineFinding] = []
        scanned = 0
        lines_scanned = 0

        for fp in files:
            try:
                fsize = fp.stat().st_size
                if fsize > 512 * 1024:
                    continue
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeDecodeError):
                    continue
                file_lines = content.count("\n") + 1
                lines_scanned += file_lines
                file_rules = self._get_applicable_rules(fp, rules, content)
                findings = self._scan_file_content(fp, content, file_rules, sensitivity, target_path)
                all_findings.extend(findings)
                scanned += 1
                if progress_callback and scanned % 10 == 0:
                    progress = (scanned / result.total_files) * 100
                    await progress_callback(progress, f"Inline scan: {fp.name}")
                if scanned % 50 == 0:
                    await asyncio.sleep(0)
            except Exception as e:
                logger.debug("Error scanning %s: %s", fp, e)
                continue

        # Deduplicate
        seen = set()
        unique = []
        for f in all_findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        result.findings = unique
        result.scanned_files = scanned
        result.lines_scanned = lines_scanned
        for f in unique:
            sev = f.severity
            if sev == "critical":
                result.critical += 1
            elif sev == "high":
                result.high += 1
            elif sev == "medium":
                result.medium += 1
            elif sev == "low":
                result.low += 1
            elif sev == "info":
                result.info += 1
            if f.category == "secrets":
                result.secrets_found += 1
        result.scan_duration_seconds = round(time.time() - start, 2)
        return result
