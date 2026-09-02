"""
SAST Worker - Runs static analysis in sandbox using Semgrep and other tools.

Execution order (most-reliable first so findings always appear):
  Phase 1 — Pure-Python scanners (inline, regex_fallback, rule_scanner).
             Always produce results even if no external tools are installed.
  Phase 2 — External tools (semgrep, trufflehog, gitleaks, sca, iac).
             Each has a hard 5-minute timeout so a missing/slow binary
             cannot block the rest of the scan.
  Phase 3 — Network dependency scan (OSV/NVD).
             Skipped immediately if DNS/network is down.
"""

import asyncio
import fnmatch
import json
import logging
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("phantomscan.sast_worker")

# Hard timeout for every external subprocess call.
# Prevents a missing binary from hanging the scan for hours.
_TOOL_TIMEOUT = 300  # 5 minutes per tool

# Per-file network timeout for the OSV/NVD dependency scanner.
_DEP_NET_TIMEOUT = 10  # seconds

DEFAULT_EXCLUDE_PATTERNS = [
    "**/*.md",
    "**/*.rst",
    "**/docs/**",
    "**/documentation/**",
    "**/examples/**",
    "**/sample/**",
    "**/samples/**",
    "**/tests/**",
    "**/test/**",
    "**/__tests__/**",
    "**/fixtures/**",
    "**/fonts/**",
    "**/i18n/**",
    "**/locales/**",
    "**/data/**",
    "**/*.min.js",
    "**/*.map",
]


def _tool_available(name: str) -> bool:
    """Return True when *name* is found on PATH."""
    return shutil.which(name) is not None


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

async def execute(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute SAST scan in sandbox."""
    scan_id = int(payload["scan_id"])
    source_config = payload.get("source_config", {})
    source_type = source_config.get("type", "local")
    target_path = source_config.get("path", ".")
    languages = source_config.get("languages", [])
    frameworks = source_config.get("frameworks", [])
    exclude_patterns = _normalize_excludes(source_config.get("exclude_patterns", []))
    include_patterns = source_config.get("include_patterns", [])

    findings: list[dict[str, Any]] = []
    artifacts: dict[str, Any] = {}
    work_dir: Path | None = None

    try:
        # ── Resolve working directory ──────────────────────────────────────
        if source_type == "github":
            repo_url = source_config.get("repo_url")
            branch = source_config.get("branch", "main")
            github_token = source_config.get("github_token") or source_config.get("pat_token")
            work_dir = Path(tempfile.mkdtemp(prefix=f"sast-{scan_id}-"))
            logger.info("Cloning %s (branch=%s) into %s", repo_url, branch, work_dir)
            try:
                await clone_repo(work_dir, repo_url, branch, github_token=github_token)
            except RuntimeError:
                # A failed clone can leave partial files behind; git refuses to
                # clone into a non-empty directory, so reset before retrying.
                shutil.rmtree(work_dir, ignore_errors=True)
                work_dir.mkdir(parents=True, exist_ok=True)
                if branch == "main":
                    logger.info("main branch failed, trying master")
                    await clone_repo(work_dir, repo_url, "master", github_token=github_token)
                else:
                    raise
            target_path = str(work_dir)
        else:
            work_dir = Path(target_path)
            if not work_dir.exists():
                return {
                    "status": "error",
                    "error": (
                        f"Source path does not exist on server: {target_path}. "
                        "Use zip upload to transfer code from your computer."
                    ),
                    "result": {
                        "findings": [], "artifacts": {},
                        "total_findings": 0,
                        "source_type": source_type,
                        "target_path": target_path,
                    },
                }

        # ══════════════════════════════════════════════════════════════════
        # PHASE 1 — Pure-Python scanners (always run, no external deps)
        # ══════════════════════════════════════════════════════════════════

        for stage_name, coro_factory in [
            ("inline_scanner",  lambda: run_inline_scan(work_dir, source_config)),
            ("regex_fallback",  lambda: run_regex_fallback(work_dir, source_config)),
            ("rule_scanner",    lambda: run_rule_scanner(work_dir, source_config)),
        ]:
            try:
                stage_findings = await coro_factory()
                # inline_scanner returns InlineFinding dataclass objects; convert them
                if stage_findings and not isinstance(stage_findings[0], dict):
                    stage_findings = _inline_findings_to_dicts(stage_findings)
                findings.extend(stage_findings)
                artifacts[stage_name] = {
                    "findings": stage_findings,
                    "count": len(stage_findings),
                }
                logger.info("Phase-1 %s: %d findings", stage_name, len(stage_findings))
            except Exception as exc:
                logger.error("Phase-1 scanner %s failed: %s", stage_name, exc, exc_info=True)
                artifacts[stage_name] = {"error": str(exc), "count": 0}

        # ══════════════════════════════════════════════════════════════════
        # PHASE 2 — External tools with per-stage 5-minute timeouts
        # ══════════════════════════════════════════════════════════════════

        external_stages: list[tuple[str, Any]] = [
            ("semgrep",     run_semgrep(work_dir, languages, frameworks, exclude_patterns, include_patterns)),
            ("trufflehog",  run_trufflehog(work_dir, exclude_patterns)),
            ("gitleaks",    run_gitleaks(work_dir, exclude_patterns)),
            ("sca",         run_sca_scan(work_dir, exclude_patterns)),
            ("iac",         run_iac_scan(work_dir, exclude_patterns)),
        ]
        if source_type == "github" and source_config.get("include_workflows", True):
            external_stages.append(("github_workflows", run_github_workflow_scan(work_dir, exclude_patterns)))

        for stage_name, coro in external_stages:
            try:
                stage_findings = await asyncio.wait_for(coro, timeout=_TOOL_TIMEOUT)
                findings.extend(stage_findings)
                artifacts[stage_name] = {
                    "findings": stage_findings,
                    "count": len(stage_findings),
                }
                logger.info("Phase-2 %s: %d findings", stage_name, len(stage_findings))
            except asyncio.TimeoutError:
                logger.warning(
                    "Phase-2 %s timed out after %ds — continuing", stage_name, _TOOL_TIMEOUT
                )
                artifacts[stage_name] = {"error": f"{stage_name} timed out", "count": 0}
            except Exception as exc:
                logger.error("Phase-2 %s failed: %s", stage_name, exc, exc_info=True)
                artifacts[stage_name] = {"error": str(exc), "count": 0}

        # ══════════════════════════════════════════════════════════════════
        # PHASE 3 — Network dependency scan (OSV + NVD)
        # ══════════════════════════════════════════════════════════════════

        dep_findings = await run_dep_scan(work_dir, exclude_patterns)
        findings.extend(dep_findings)
        artifacts["dependency_scanner"] = {
            "findings": dep_findings,
            "count": len(dep_findings),
        }

        # ── Persist artifacts summary ──────────────────────────────────────
        artifacts_path = work_dir / "sast_artifacts.json"
        try:
            artifacts_path.write_text(json.dumps(artifacts, indent=2, default=str))
        except Exception:
            pass

        # Drop error-sentinel dicts; keep only real findings
        valid_findings = [f for f in findings if isinstance(f, dict) and "error" not in f]
        valid_findings = _post_process_findings(
            valid_findings,
            work_dir,
            sensitivity=str(source_config.get("sensitivity") or "medium"),
        )

        logger.info(
            "Scan complete: %d valid findings (total=%d) for scan_id=%s",
            len(valid_findings), len(findings), scan_id,
        )
        return {
            "status": "complete",
            "result": {
                "findings": valid_findings,
                "artifacts": artifacts,
                "artifacts_path": str(artifacts_path),
                "source_type": source_type,
                "target_path": target_path,
                "total_findings": len(valid_findings),
            },
        }

    except Exception as exc:
        logger.error("Scan failed: %s: %s", type(exc).__name__, exc, exc_info=True)
        return {
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "result": {
                "findings": [], "artifacts": {},
                "total_findings": 0,
                "source_type": source_type,
                "target_path": target_path,
            },
        }
    finally:
        # Only clean up temp dirs we created (GitHub clones)
        if source_type == "github" and work_dir and work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _inline_findings_to_dicts(findings: list) -> list[dict[str, Any]]:
    """Convert InlineFinding dataclass objects to plain dicts."""
    result = []
    for f in findings:
        try:
            result.append({
                "type": "inline_sast",
                "tool": "inline_scanner",
                "rule_id": f.rule_id,
                "severity": f.severity.upper(),
                "message": f.title,
                "title": f.title,
                "file_path": f.file_path,
                "line_start": f.line_number,
                "line_end": f.line_number,
                "code_snippet": f.matched_text,
                "description": f.description,
                "recommendation": f.recommendation,
                "owasp_category": f.owasp_category,
                "category": f.category,
            })
        except Exception:
            pass
    return result


def _normalize_excludes(exclude_patterns: Any) -> list[str]:
    if isinstance(exclude_patterns, str):
        values = [item.strip() for item in exclude_patterns.split(",")]
    elif isinstance(exclude_patterns, list):
        values = [str(item).strip() for item in exclude_patterns]
    else:
        values = []
    merged = [*DEFAULT_EXCLUDE_PATTERNS, *[item for item in values if item]]
    return list(dict.fromkeys(merged))


def _line_number(finding: dict[str, Any]) -> int:
    for name in ("line_number", "line_start", "start_line", "line_end"):
        try:
            value = int(finding.get(name) or 0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0


def _severity_rank(value: Any) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(str(value or "").upper(), 0)


def _normalize_location(value: Any, root: Path) -> str:
    if not value:
        return ""
    path_text = str(value).replace("\\", "/")
    try:
        path = Path(path_text)
        if path.is_absolute():
            path_text = path.relative_to(root).as_posix()
    except (OSError, ValueError):
        pass
    return path_text.lower().lstrip("./")


def _finding_family(finding: dict[str, Any]) -> str:
    text = " ".join(
        str(finding.get(name) or "")
        for name in ("rule_id", "title", "message", "category", "detector_name", "secret_type", "vulnerability_id")
    ).lower()
    if finding.get("vulnerability_id") or finding.get("cve_id"):
        return f"sca:{finding.get('package_name', '')}:{finding.get('vulnerability_id') or finding.get('cve_id')}".lower()
    families = (
        ("secret", ("secret", "token", "password", "private key", "aws", "github pat")),
        ("sql-injection", ("sql", "sqli")),
        ("xss", ("xss", "innerhtml", "document.write", "html rendering")),
        ("command-injection", ("command", "exec", "shell", "os_system", "subprocess")),
        ("path-traversal", ("path traversal", "readfile", "open(")),
        ("crypto", ("crypto", "md5", "sha1", "des", "rc4", "hmac")),
        ("deserialization", ("deserialize", "pickle", "yaml.load", "unserialize")),
        ("ssrf", ("ssrf",)),
        ("csrf", ("csrf",)),
        ("cors", ("cors",)),
        ("github-workflow", ("github actions", "workflow", "pull_request_target")),
        ("iac", ("terraform", "kubernetes", "iac")),
    )
    for family, needles in families:
        if any(needle in text for needle in needles):
            return family
    return re.sub(r"[^a-z0-9_.:-]+", "-", str(finding.get("rule_id") or finding.get("title") or "generic").lower())[:80]


def _confidence_for_group(group: list[dict[str, Any]]) -> tuple[float, str]:
    score = 0.0
    for finding in group:
        tool = str(finding.get("tool") or "").lower()
        if tool == "semgrep":
            item_score = 0.78
        elif tool == "trufflehog":
            item_score = 0.98 if finding.get("verified") else 0.72
        elif tool == "gitleaks":
            item_score = 0.70
        elif tool in {"osv_nvd", "pip-audit", "npm-audit"}:
            item_score = 0.95 if tool == "osv_nvd" else 0.88
        elif tool in {"inline_scanner", "rule_scanner"} or finding.get("source") == "context_aware_rule_scanner":
            item_score = 0.55
        elif tool == "regex_fallback":
            item_score = 0.45
        else:
            item_score = 0.50
        severity = _severity_rank(finding.get("severity"))
        item_score += {4: 0.08, 3: 0.05, 2: 0.02}.get(severity, 0.0)
        evidence = " ".join(str(finding.get(name) or "") for name in ("matched_content", "matched_text", "code_snippet"))
        if re.search(r"\b(example|dummy|placeholder|changeme)\b", evidence, re.IGNORECASE):
            item_score -= 0.10
        score = max(score, item_score)
    tools = {str(item.get("tool") or item.get("source") or "custom") for item in group}
    if len(tools) > 1:
        score += min(0.15, 0.05 * (len(tools) - 1))
    score = max(0.05, min(0.99, score))
    if score >= 0.95:
        return score, "CONFIRMED"
    if score >= 0.75:
        return score, "HIGH"
    if score >= 0.55:
        return score, "MEDIUM"
    if score >= 0.35:
        return score, "LOW"
    return score, "POTENTIAL"


def _post_process_findings(findings: list[dict[str, Any]], root: Path, sensitivity: str = "medium") -> list[dict[str, Any]]:
    noisy_rules = {"sec-no-rate-limit"}
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if sensitivity != "high" and rule_id in noisy_rules:
            continue
        location = _normalize_location(finding.get("file_path") or finding.get("path") or finding.get("endpoint"), root)
        family = _finding_family(finding)
        if finding.get("package_name") or finding.get("vulnerability_id"):
            key = ("sca", str(finding.get("package_name") or "").lower(), str(finding.get("vulnerability_id") or "").lower(), location)
        else:
            key = (str(finding.get("type") or "").lower(), family, location, _line_number(finding))
        grouped.setdefault(key, []).append(finding)

    processed: list[dict[str, Any]] = []
    for group in grouped.values():
        best = max(
            group,
            key=lambda item: (
                _severity_rank(item.get("severity")),
                1 if str(item.get("tool") or "").lower() in {"semgrep", "trufflehog", "gitleaks", "osv_nvd"} else 0,
            ),
        )
        merged = dict(best)
        score, label = _confidence_for_group(group)
        tools = sorted({str(item.get("tool") or item.get("source") or "custom") for item in group})
        rule_ids = sorted({str(item.get("rule_id") or item.get("detector_name") or "") for item in group if item.get("rule_id") or item.get("detector_name")})
        merged["confidence_score"] = round(score, 4)
        merged["confidence_label"] = label
        merged["confidence"] = label
        merged["source_correlation"] = {
            "engine_count": len(tools),
            "engines": tools,
            "rule_ids": rule_ids,
            "deduplicated_count": len(group),
            "family": _finding_family(best),
        }
        if len(group) > 1:
            merged["verification_method"] = "static_multi_engine_correlation"
        processed.append(merged)

    processed.sort(
        key=lambda item: (
            -_severity_rank(item.get("severity")),
            str(item.get("file_path") or ""),
            _line_number(item),
            str(item.get("rule_id") or ""),
        )
    )
    return processed


def _is_excluded(path: Path, root: Path, exclude_patterns: list[str]) -> bool:
    try:
        rel = path.relative_to(root if root.is_dir() else root.parent).as_posix()
    except ValueError:
        rel = path.as_posix()
    name = path.name
    for raw_pattern in exclude_patterns:
        pattern = raw_pattern.strip().replace("\\", "/").lstrip("./")
        if not pattern:
            continue
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern) or Path(rel).match(pattern):
            return True
    return False


async def clone_repo(
    work_dir: Path,
    repo_url: str,
    branch: str,
    github_token: str | None = None,
) -> None:
    """Clone a GitHub repository with a 120-second timeout."""
    clone_url = repo_url
    token = github_token
    if token and "github.com" in repo_url:
        clone_url = repo_url.replace("https://github.com/", f"https://{token}@github.com/")

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--branch", branch, clone_url, str(work_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise RuntimeError("git clone timed out after 120 s")

    if proc.returncode != 0:
        stderr_text = stderr.decode(errors="replace")
        if token:
            stderr_text = stderr_text.replace(token, "***")
        raise RuntimeError(f"Failed to clone repo: {stderr_text}")


# ──────────────────────────────────────────────────────────────────────────────
# Phase 1 — pure-Python scanners
# ──────────────────────────────────────────────────────────────────────────────

async def run_inline_scan(
    work_dir: Path, source_config: dict[str, Any]
) -> list:
    """Run the inline regex scanner (loads rules/*.json, no external tools)."""
    from app.services.inline_scanner import InlineScanner
    sensitivity = source_config.get("sensitivity", "medium")
    exclude_patterns = _normalize_excludes(source_config.get("exclude_patterns", []))
    result = await InlineScanner().scan(str(work_dir), sensitivity=sensitivity, exclude_patterns=exclude_patterns)
    return result.findings  # list[InlineFinding] — converted in execute()


async def run_regex_fallback(
    work_dir: Path, source_config: dict[str, Any]
) -> list[dict[str, Any]]:
    """Run hardcoded Python regex patterns (self-contained, no JSON rules needed)."""
    from app.services.regex_scanner import RegexFallbackScanner
    scanner = RegexFallbackScanner()
    sensitivity = source_config.get("sensitivity", "medium")
    exclude_patterns = _normalize_excludes(source_config.get("exclude_patterns", []))
    result = await scanner.scan(str(work_dir), sensitivity=sensitivity, exclude_patterns=exclude_patterns)
    return scanner.to_finding_dicts(result)


async def run_rule_scanner(
    work_dir: Path, source_config: dict[str, Any]
) -> list[dict[str, Any]]:
    """Run the context-aware rule scanner (loads rules/*.json, no external tools)."""
    from app.services.rule_scanner import RuleScanner
    sensitivity = source_config.get("sensitivity", "medium")
    exclude_patterns = _normalize_excludes(source_config.get("exclude_patterns", []))
    return await RuleScanner().scan(str(work_dir), sensitivity=sensitivity, exclude_patterns=exclude_patterns)


# ──────────────────────────────────────────────────────────────────────────────
# Phase 2 — external tools (each wrapped in the outer timeout in execute())
# ──────────────────────────────────────────────────────────────────────────────

async def run_semgrep(
    work_dir: Path,
    languages: list[str],
    frameworks: list[str],
    exclude_patterns: list[str],
    include_patterns: list[str],
) -> list[dict[str, Any]]:
    """Run Semgrep SAST scan. Skipped if semgrep is not on PATH."""
    if not _tool_available("semgrep"):
        logger.warning("semgrep not found on PATH — skipping SAST scan")
        return [{"error": "semgrep not installed"}]

    config_args = ["--config=auto", "--config=p/owasp-top-ten", "--config=p/secrets"]
    for lang in languages:
        config_args.append(f"--config=p/{lang}")
    for fw in frameworks:
        config_args.append(f"--config=p/{fw}")
    for pattern in exclude_patterns:
        config_args.append(f"--exclude={pattern}")
    for pattern in include_patterns:
        config_args.append(f"--include={pattern}")
    config_args.extend(["--json", "--quiet"])

    cmd = ["semgrep", "scan"] + config_args + [str(work_dir)]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
        )
        stdout, stderr = await proc.communicate()
    except Exception as exc:
        return [{"error": f"semgrep could not start: {exc}"}]

    if proc.returncode not in (0, 1):
        return [{"error": f"Semgrep failed (rc={proc.returncode}): {stderr.decode(errors='replace')[:500]}"}]
    if not stdout:
        return []

    try:
        result = json.loads(stdout.decode(errors="replace"))
    except json.JSONDecodeError:
        return [{"error": "Semgrep returned invalid JSON"}]

    findings = []
    for item in result.get("results", []):
        findings.append({
            "type": "sast",
            "tool": "semgrep",
            "rule_id": item.get("check_id"),
            "severity": _map_semgrep_severity(item.get("extra", {}).get("severity", "WARNING")),
            "message": item.get("extra", {}).get("message", ""),
            "file_path": item.get("path"),
            "line_start": item.get("start", {}).get("line"),
            "line_end": item.get("end", {}).get("line"),
            "code_snippet": item.get("extra", {}).get("lines", ""),
            "rule_name": item.get("extra", {}).get("metadata", {}).get("name", ""),
            "references": item.get("extra", {}).get("metadata", {}).get("references", []),
            "cwe_ids": _extract_cwe_ids(item.get("extra", {}).get("metadata", {})),
            "owasp_category": item.get("extra", {}).get("metadata", {}).get("owasp", ""),
        })
    return findings


def _map_semgrep_severity(severity: str) -> str:
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(severity.upper(), "MEDIUM")


def _extract_cwe_ids(metadata: dict[str, Any]) -> list[str]:
    cwe_val = metadata.get("cwe")
    if not cwe_val:
        return []
    if isinstance(cwe_val, list):
        return [str(c) for c in cwe_val]
    return [str(cwe_val)]


async def run_trufflehog(work_dir: Path, exclude_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Run TruffleHog secrets scan. Skipped if not on PATH."""
    if not _tool_available("trufflehog"):
        logger.warning("trufflehog not found on PATH — skipping secrets scan")
        return [{"error": "trufflehog not installed"}]

    try:
        proc = await asyncio.create_subprocess_exec(
            "trufflehog", "filesystem", str(work_dir), "--json", "--no-update",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
    except Exception as exc:
        return [{"error": f"trufflehog could not start: {exc}"}]

    excludes = exclude_patterns or []
    findings = []
    for line in stdout.decode(errors="replace").strip().splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            file_path = (
                item.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file", "")
            )
            if file_path and _is_excluded(Path(file_path), work_dir, excludes):
                continue
            findings.append({
                "type": "secret",
                "tool": "trufflehog",
                "detector_name": item.get("DetectorName", ""),
                "secret_type": item.get("DetectorType", ""),
                "file_path": file_path,
                "line_number": (
                    item.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("line", 0)
                ),
                "matched_content": item.get("Raw", "")[:200],
                "entropy": item.get("Entropy", 0),
                "verified": item.get("Verified", False),
            })
        except json.JSONDecodeError:
            continue
    return findings


async def run_gitleaks(work_dir: Path, exclude_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Run gitleaks secrets scan. Skipped if not on PATH."""
    if not _tool_available("gitleaks"):
        logger.warning("gitleaks not found on PATH — skipping secrets scan")
        return [{"error": "gitleaks not installed"}]

    try:
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect", "--source", str(work_dir),
            "--report-format", "json", "--verbose",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
    except Exception as exc:
        return [{"error": f"gitleaks could not start: {exc}"}]

    excludes = exclude_patterns or []
    findings = []
    if stdout:
        try:
            for item in json.loads(stdout.decode(errors="replace")):
                file_path = item.get("File", "")
                if file_path and _is_excluded(Path(file_path), work_dir, excludes):
                    continue
                findings.append({
                    "type": "secret",
                    "tool": "gitleaks",
                    "detector_name": item.get("RuleID", ""),
                    "secret_type": item.get("Description", ""),
                    "file_path": file_path,
                    "line_number": item.get("StartLine", 0),
                    "matched_content": item.get("Secret", "")[:200],
                    "entropy": item.get("Entropy", 0),
                    "verified": False,
                })
        except json.JSONDecodeError:
            pass
    return findings


async def run_sca_scan(work_dir: Path, exclude_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Run SCA via pip-audit / npm audit."""
    findings: list[dict[str, Any]] = []
    excludes = exclude_patterns or []

    # Python
    req_files = (
        list(work_dir.rglob("requirements*.txt"))
        + list(work_dir.rglob("pyproject.toml"))
        + list(work_dir.rglob("setup.py"))
    )
    req_files = [file_path for file_path in req_files if not _is_excluded(file_path, work_dir, excludes)]
    for req_file in req_files:
        findings.extend(await _scan_python_deps(req_file, work_dir))

    # Node
    for pkg_file in work_dir.rglob("package.json"):
        if _is_excluded(pkg_file, work_dir, excludes):
            continue
        findings.extend(await _scan_npm_deps(pkg_file))

    return findings


async def _scan_python_deps(req_file: Path, work_dir: Path) -> list[dict[str, Any]]:
    if not _tool_available("pip-audit"):
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "pip-audit", "-r", str(req_file), "--format", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
        )
        stdout, _ = await proc.communicate()
        if not stdout:
            return []
        items = json.loads(stdout.decode(errors="replace"))
    except Exception as exc:
        logger.debug("pip-audit failed for %s: %s", req_file, exc)
        return []

    findings = []
    for item in items:
        vulns = item.get("vulns", [])
        findings.append({
            "type": "sca",
            "tool": "pip-audit",
            "package_name": item.get("name", ""),
            "package_version": item.get("version", ""),
            "ecosystem": "pypi",
            "vulnerability_id": vulns[0].get("id", "") if vulns else "",
            "fixed_version": vulns[0].get("fix_versions", [""])[0] if vulns else "",
            "cvss_score": None,
            "advisory_url": vulns[0].get("url", "") if vulns else "",
        })
    return findings


async def _scan_npm_deps(pkg_file: Path) -> list[dict[str, Any]]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "audit", "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(pkg_file.parent),
        )
        stdout, _ = await proc.communicate()
        if not stdout:
            return []
        items = json.loads(stdout.decode(errors="replace"))
    except Exception as exc:
        logger.debug("npm audit failed for %s: %s", pkg_file, exc)
        return []

    findings = []
    for vuln_id, vuln in items.get("vulnerabilities", {}).items():
        fix = vuln.get("fixAvailable")
        findings.append({
            "type": "sca",
            "tool": "npm-audit",
            "package_name": vuln.get("name", ""),
            "package_version": vuln.get("version", ""),
            "ecosystem": "npm",
            "vulnerability_id": vuln_id,
            "vulnerable_versions": vuln.get("range", ""),
            "fixed_version": fix.get("version", "") if isinstance(fix, dict) else "",
            "cvss_score": None,
            "advisory_url": f"https://github.com/advisories/{vuln_id}",
        })
    return findings


async def run_iac_scan(work_dir: Path, exclude_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Run IaC scanning via semgrep (Terraform + Kubernetes). Skipped if semgrep missing."""
    findings: list[dict[str, Any]] = []
    excludes = exclude_patterns or []
    if not _tool_available("semgrep"):
        return findings

    async def _semgrep_config(config: str, label: str) -> list[dict[str, Any]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "scan", f"--config={config}", "--json", "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(work_dir),
            )
            stdout, _ = await proc.communicate()
            if not stdout:
                return []
            return [
                {
                    "type": "iac",
                    "tool": "semgrep",
                    "resource_type": label,
                    "file_path": item.get("path"),
                    "line_start": item.get("start", {}).get("line"),
                    "line_end": item.get("end", {}).get("line"),
                    "misconfiguration_type": (
                        item.get("extra", {}).get("metadata", {}).get("name", "")
                    ),
                    "platform": label,
                }
                for item in json.loads(stdout.decode(errors="replace")).get("results", [])
            ]
        except Exception:
            return []

    tf_files = [file_path for file_path in list(work_dir.rglob("*.tf")) + list(work_dir.rglob("*.tfvars")) if not _is_excluded(file_path, work_dir, excludes)]
    if tf_files:
        findings.extend(await _semgrep_config("p/terraform", "terraform"))

    k8s_files = [
        f for f in (list(work_dir.rglob("*.yaml")) + list(work_dir.rglob("*.yml")))
        if f.stat().st_size < 1024 * 1024 and not _is_excluded(f, work_dir, excludes) and _is_k8s_manifest(f)
    ]
    if k8s_files:
        findings.extend(await _semgrep_config("p/kubernetes", "kubernetes"))

    return findings


async def run_github_workflow_scan(work_dir: Path, exclude_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Detect high-confidence GitHub Actions workflow misconfigurations."""
    workflows_dir = work_dir / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    excludes = exclude_patterns or []
    findings: list[dict[str, Any]] = []
    for workflow in list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml")):
        if _is_excluded(workflow, work_dir, excludes):
            continue
        try:
            content = workflow.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        line_map = {line.strip(): idx for idx, line in enumerate(content.splitlines(), 1)}
        try:
            import yaml
            data = yaml.safe_load(content) or {}
        except Exception:
            data = {}

        permissions = data.get("permissions") if isinstance(data, dict) else None
        if permissions == "write-all":
            findings.append({
                "type": "github",
                "tool": "github-workflow-scan",
                "rule_id": "github-actions-write-all-permissions",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "GitHub Actions workflow grants write-all permissions",
                "message": "The workflow grants all GITHUB_TOKEN permissions write access.",
                "file_path": workflow.relative_to(work_dir).as_posix(),
                "line_start": line_map.get("permissions: write-all", 1),
                "code_snippet": "permissions: write-all",
                "recommendation": "Set least-privilege workflow permissions, for example contents: read and only the write scopes required by the job.",
            })

        event_config = (data.get("on") or data.get(True)) if isinstance(data, dict) else None
        events = set(event_config if isinstance(event_config, list) else event_config.keys() if isinstance(event_config, dict) else [event_config])
        if "pull_request_target" in events and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}", content):
            findings.append({
                "type": "github",
                "tool": "github-workflow-scan",
                "rule_id": "github-actions-pr-target-untrusted-checkout",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "title": "pull_request_target checks out untrusted PR code",
                "message": "A pull_request_target workflow checks out attacker-controlled head code while running with privileged token context.",
                "file_path": workflow.relative_to(work_dir).as_posix(),
                "line_start": next((idx for idx, line in enumerate(content.splitlines(), 1) if "github.event.pull_request.head" in line), 1),
                "code_snippet": "\n".join(line for line in content.splitlines() if "pull_request_target" in line or "github.event.pull_request.head" in line)[:2000],
                "recommendation": "Use pull_request for untrusted code, or avoid checking out the PR head in pull_request_target workflows.",
            })
    return findings


def _is_k8s_manifest(file_path: Path) -> bool:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")[:500]
        return "apiVersion:" in content or "kind:" in content
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Phase 3 — network dependency scan
# ──────────────────────────────────────────────────────────────────────────────

async def run_dep_scan(work_dir: Path, exclude_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Scan dependencies via OSV + NVD APIs.

    A quick connectivity check is done first; if DNS/network is down the stage
    returns immediately so the rest of the scan is unaffected.
    Each file scan is capped at _DEP_NET_TIMEOUT seconds.
    """
    # Quick connectivity pre-check (5 s max)
    try:
        async with httpx.AsyncClient() as client:
            await client.head(
                "https://api.osv.dev",
                timeout=5.0,
                follow_redirects=True,
            )
    except Exception as exc:
        logger.warning("dep_scan: network unavailable (%s) — skipping", exc)
        return []

    try:
        from app.services.dependency_scanner import DependencyScanner
        scanner = DependencyScanner()
        findings: list[dict[str, Any]] = []

        async def _scan_file(pkg_file: Path, ecosystem_hint: str) -> list[dict[str, Any]]:
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(scanner.scan_file, pkg_file),
                    timeout=_DEP_NET_TIMEOUT,
                )
                return [
                    {
                        "type": "sca",
                        "tool": "osv_nvd",
                        "package_name": f.package,
                        "package_version": f.version,
                        "ecosystem": f.ecosystem,
                        "vulnerability_id": f.vulnerability_id,
                        "severity": f.severity.upper() if f.severity else "UNKNOWN",
                        "cvss_score": f.cvss_score,
                        "message": f"{f.vulnerability_id}: {f.summary}",
                        "fixed_version": f.fixed_version,
                        "references": f.references,
                        "source": f.source,
                        "file_path": str(pkg_file),
                    }
                    for f in result.findings
                ]
            except asyncio.TimeoutError:
                logger.debug("dep_scan timed out for %s", pkg_file)
                return []
            except Exception as exc:
                logger.debug("dep_scan skipped %s: %s", pkg_file, exc)
                return []

        excludes = exclude_patterns or []
        npm_lock_dirs: set[Path] = set()
        for pkg_file in list(work_dir.rglob("package-lock.json")) + list(work_dir.rglob("npm-shrinkwrap.json")):
            if "node_modules" in str(pkg_file) or _is_excluded(pkg_file, work_dir, excludes):
                continue
            findings.extend(await _scan_file(pkg_file, "npm"))
            npm_lock_dirs.add(pkg_file.parent)

        for pkg_file in work_dir.rglob("package.json"):
            if pkg_file.parent in npm_lock_dirs or "node_modules" in str(pkg_file) or _is_excluded(pkg_file, work_dir, excludes):
                continue
            findings.extend(await _scan_file(pkg_file, "npm"))

        python_lock_dirs: set[Path] = set()
        for lock_file in list(work_dir.rglob("Pipfile.lock")) + list(work_dir.rglob("poetry.lock")):
            if _is_excluded(lock_file, work_dir, excludes):
                continue
            findings.extend(await _scan_file(lock_file, "pypi"))
            python_lock_dirs.add(lock_file.parent)

        for req_file in work_dir.rglob("requirements*.txt"):
            if req_file.parent in python_lock_dirs or _is_excluded(req_file, work_dir, excludes):
                continue
            findings.extend(await _scan_file(req_file, "pypi"))

        for pipfile in work_dir.rglob("Pipfile"):
            if pipfile.parent in python_lock_dirs or _is_excluded(pipfile, work_dir, excludes):
                continue
            findings.extend(await _scan_file(pipfile, "pypi"))

        return findings

    except Exception as exc:
        logger.error("dep_scan failed: %s", exc, exc_info=True)
        return [{"error": f"Dependency scanner failed: {exc}"}]


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point (invoked as a subprocess by SASTAgent)
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = asyncio.run(execute(payload))
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
    except BaseException as exc:
        sys.stdout.write(
            json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
