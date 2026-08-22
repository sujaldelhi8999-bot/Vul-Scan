"""
Regex Fallback Scanner - Self-contained SAST + secrets detection that works
even when external tools (semgrep, truffleHog, gitleaks) are not installed.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("phantomscan.regex_scanner")

SAST_PATTERNS: list[tuple[str, str, str]] = [
    ("eval", r"\beval\s*\(", "HIGH"),
    ("exec", r"\bexec\s*\(", "HIGH"),
    ("os_system", r"\bos\.system\s*\(", "HIGH"),
    ("command_subprocess_shell", r"\bsubprocess\s*\.\s*(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True", "HIGH"),
    ("shell_exec", r"\bshell_exec\s*\(", "HIGH"),
    ("system_exec", r"\bsystem\s*\(", "HIGH"),
    ("pickle_loads", r"\bpickle\.(?:loads|load)\s*\(", "HIGH"),
    ("yaml_load", r"\byaml\.load\s*\((?![^)]*Loader)", "MEDIUM"),
    ("xml_parser", r"\bxml\.etree|XMLParser\s*\([^)]*resolve_entities\s*=\s*True", "MEDIUM"),
    ("sql_string_concat", r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+", "MEDIUM"),
    ("sql_fstring", r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?f[\"']", "MEDIUM"),
    ("eval_html", r"\binnerHTML\s*=\s*[^;]*\+", "MEDIUM"),
    ("dangerous_function", r"\b(?:child_process|cp)\s*\.\s*exec(?:Sync)?\s*\(", "HIGH"),
    ("dangerous_function_node", r"\bvm\.runInNewContext|new\s+Function\s*\(", "MEDIUM"),
    ("deserialization", r"\bunserialize\s*\(|Marshal\.load|objectify\.load", "MEDIUM"),
    ("hardcoded_credentials", r"(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']", "HIGH"),
    ("command_concat", r"(?:os\.system|subprocess\.\w+|exec|system)\s*\([^)]*\+", "HIGH"),
]

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS_ACCESS_KEY", r"\bAKIA[0-9A-Z]{16}\b", "CRITICAL"),
    ("AWS_SECRET_KEY", r"\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[\"'][^\"']{8,}[\"']", "CRITICAL"),
    ("GITHUB_TOKEN", r"\bghp_[0-9A-Za-z]{36}\b", "CRITICAL"),
    ("GITHUB_OAUTH", r"\bgho_[0-9A-Za-z]{36}\b", "CRITICAL"),
    ("GITLAB_TOKEN", r"\bglpat-[0-9A-Za-z\-_]{20,}\b", "CRITICAL"),
    ("SLACK_TOKEN", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "CRITICAL"),
    ("STRIPE_KEY", r"\bsk_live_[0-9A-Za-z]{20,}\b", "CRITICAL"),
    ("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z\-_]{35}\b", "CRITICAL"),
    ("JWT_TOKEN", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "MEDIUM"),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "CRITICAL"),
    ("GENERIC_SECRET", r"\bsecret\s*[:=]\s*[\"'][^\"']{8,}[\"']", "HIGH"),
]

TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rb", ".c", ".cpp",
    ".h", ".hpp", ".cs", ".swift", ".kt", ".rs", ".scala", ".sh", ".bash", ".ps1",
    ".sql", ".xml", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".tf", ".dockerfile", ".html", ".htm", ".vue", ".svelte",
    ".md", ".txt", ".gradle", ".plist", ".lock",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".jar", ".war", ".class", ".pyc", ".so", ".dll",
}

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__", ".venv", "venv", ".next", ".nuxt"}

MAX_FILE_BYTES = 2 * 1024 * 1024


@dataclass
class RegexFinding:
    type: str
    tool: str
    rule_id: str
    severity: str
    title: str
    message: str
    file_path: str
    line_number: int
    code_snippet: str
    pattern: str


@dataclass
class RegexScanResult:
    findings: list[RegexFinding] = field(default_factory=list)


class RegexFallbackScanner:
    """Scans a codebase for dangerous patterns and secrets using pure regex."""

    async def scan(self, path: str, sensitivity: str = "medium") -> RegexScanResult:
        result = RegexScanResult()
        root = Path(path)
        if not root.exists():
            logger.warning("Regex fallback scan: path does not exist: %s", path)
            return result

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in filenames:
                file_path = Path(dirpath) / filename
                ext = file_path.suffix.lower()
                # Skip known binary formats
                if ext in BINARY_EXTENSIONS:
                    continue
                # Accept if extension is in the text set, OR the filename itself
                # is a recognised extensionless file (Dockerfile, .env, .env.*).
                is_known_ext = ext in TEXT_EXTENSIONS
                is_env_file = filename.startswith(".env") or filename in ("Dockerfile", "Makefile")
                if not is_known_ext and not is_env_file:
                    continue
                try:
                    if file_path.stat().st_size > MAX_FILE_BYTES:
                        continue
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                self._scan_content(content, file_path, result, sensitivity)
        return result

    def _scan_content(self, content: str, file_path: Path, result: RegexScanResult, sensitivity: str) -> None:
        patterns = SAST_PATTERNS + SECRET_PATTERNS
        if sensitivity == "low":
            patterns = [p for p in patterns if p[2] in ("CRITICAL", "HIGH")]
        elif sensitivity == "high":
            patterns = SAST_PATTERNS + SECRET_PATTERNS + [("low_confidence", r"TODO|FIXME|HACK", "INFO")]

        for rule_id, regex, severity in patterns:
            try:
                for match in re.finditer(regex, content, re.IGNORECASE):
                    snippet = match.group(0)[:200]
                    line_number = content.count("\n", 0, match.start()) + 1
                    finding_type = "secret" if severity == "CRITICAL" or any(
                        s in rule_id for s in ("TOKEN", "KEY", "SECRET", "PRIVATE", "JWT")
                    ) else "sast"
                    result.findings.append(
                        RegexFinding(
                            type=finding_type,
                            tool="regex_fallback",
                            rule_id=rule_id,
                            severity=severity,
                            title=f"Potential {rule_id.replace('_', ' ').title()} detected",
                            message=f"Pattern '{regex}' matched {rule_id.replace('_', ' ')}",
                            file_path=str(file_path),
                            line_number=line_number,
                            code_snippet=snippet,
                            pattern=rule_id,
                        )
                    )
                    if finding_type == "secret":
                        break
            except re.error:
                logger.debug("Invalid regex pattern %s", rule_id)
                continue

    def to_finding_dicts(self, result: RegexScanResult) -> list[dict[str, Any]]:
        findings = []
        for f in result.findings:
            findings.append(
                {
                    "type": f.type,
                    "tool": f.tool,
                    "rule_id": f.rule_id,
                    "severity": f.severity.upper(),
                    "title": f.title,
                    "message": f.message,
                    "file_path": f.file_path,
                    "line_start": f.line_number,
                    "line_end": f.line_number,
                    "code_snippet": f.code_snippet,
                    "pattern": f.pattern,
                }
            )
        return findings