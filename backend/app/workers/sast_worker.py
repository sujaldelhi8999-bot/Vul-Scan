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
import json
import logging
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
    exclude_patterns = source_config.get("exclude_patterns", [])
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
            ("trufflehog",  run_trufflehog(work_dir)),
            ("gitleaks",    run_gitleaks(work_dir)),
            ("sca",         run_sca_scan(work_dir)),
            ("iac",         run_iac_scan(work_dir)),
        ]

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

        dep_findings = await run_dep_scan(work_dir)
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
    result = await InlineScanner().scan(str(work_dir), sensitivity=sensitivity)
    return result.findings  # list[InlineFinding] — converted in execute()


async def run_regex_fallback(
    work_dir: Path, source_config: dict[str, Any]
) -> list[dict[str, Any]]:
    """Run hardcoded Python regex patterns (self-contained, no JSON rules needed)."""
    from app.services.regex_scanner import RegexFallbackScanner
    scanner = RegexFallbackScanner()
    sensitivity = source_config.get("sensitivity", "medium")
    result = await scanner.scan(str(work_dir), sensitivity=sensitivity)
    return scanner.to_finding_dicts(result)


async def run_rule_scanner(
    work_dir: Path, source_config: dict[str, Any]
) -> list[dict[str, Any]]:
    """Run the context-aware rule scanner (loads rules/*.json, no external tools)."""
    from app.services.rule_scanner import RuleScanner
    sensitivity = source_config.get("sensitivity", "medium")
    return await RuleScanner().scan(str(work_dir), sensitivity=sensitivity)


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

    config_args = ["--config=auto"]
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


async def run_trufflehog(work_dir: Path) -> list[dict[str, Any]]:
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

    findings = []
    for line in stdout.decode(errors="replace").strip().splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            findings.append({
                "type": "secret",
                "tool": "trufflehog",
                "detector_name": item.get("DetectorName", ""),
                "secret_type": item.get("DetectorType", ""),
                "file_path": (
                    item.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", "")
                ),
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


async def run_gitleaks(work_dir: Path) -> list[dict[str, Any]]:
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

    findings = []
    if stdout:
        try:
            for item in json.loads(stdout.decode(errors="replace")):
                findings.append({
                    "type": "secret",
                    "tool": "gitleaks",
                    "detector_name": item.get("RuleID", ""),
                    "secret_type": item.get("Description", ""),
                    "file_path": item.get("File", ""),
                    "line_number": item.get("StartLine", 0),
                    "matched_content": item.get("Secret", "")[:200],
                    "entropy": item.get("Entropy", 0),
                    "verified": False,
                })
        except json.JSONDecodeError:
            pass
    return findings


async def run_sca_scan(work_dir: Path) -> list[dict[str, Any]]:
    """Run SCA via pip-audit / npm audit."""
    findings: list[dict[str, Any]] = []

    # Python
    req_files = (
        list(work_dir.rglob("requirements*.txt"))
        + list(work_dir.rglob("pyproject.toml"))
        + list(work_dir.rglob("setup.py"))
    )
    for req_file in req_files:
        findings.extend(await _scan_python_deps(req_file, work_dir))

    # Node
    for pkg_file in work_dir.rglob("package.json"):
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


async def run_iac_scan(work_dir: Path) -> list[dict[str, Any]]:
    """Run IaC scanning via semgrep (Terraform + Kubernetes). Skipped if semgrep missing."""
    findings: list[dict[str, Any]] = []
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

    tf_files = list(work_dir.rglob("*.tf")) + list(work_dir.rglob("*.tfvars"))
    if tf_files:
        findings.extend(await _semgrep_config("p/terraform", "terraform"))

    k8s_files = [
        f for f in (list(work_dir.rglob("*.yaml")) + list(work_dir.rglob("*.yml")))
        if f.stat().st_size < 1024 * 1024 and _is_k8s_manifest(f)
    ]
    if k8s_files:
        findings.extend(await _semgrep_config("p/kubernetes", "kubernetes"))

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

async def run_dep_scan(work_dir: Path) -> list[dict[str, Any]]:
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

        for pkg_file in work_dir.rglob("package.json"):
            if "node_modules" in str(pkg_file):
                continue
            findings.extend(await _scan_file(pkg_file, "npm"))

        for req_file in work_dir.rglob("requirements*.txt"):
            findings.extend(await _scan_file(req_file, "pypi"))

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