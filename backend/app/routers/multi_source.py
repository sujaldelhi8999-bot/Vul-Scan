"""
Multi-Source Scanning Router
"""

import asyncio
import glob
import json
import logging
import os
import shutil
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile, status

from app.auth_middleware import get_current_user
from app.agents.orchestrator import OrchestratorAgent
from app.config import get_settings
from app.database import (
    add_audit_log,
    create_scan,
    get_findings,
    get_scan,
    list_multi_source_scans,
    list_scan_sources,
    list_source_correlations,
    update_scan_status,
)
from app.models import (
    LocalCodebaseConfig,
    MultiSourceScanHistoryItem,
    MultiSourceScanRequest,
    MultiSourceScanResponse,
    SourceCorrelationSummary,
    SourceScanResult,
)
from app.services.authorization import TargetAuthorizationService
from app.services.jobs import ScanCapacityError, ScanNotRunningError, scan_job_manager
from app.services.policy import ScanPolicy
from app.services.enterprise_access import (
    enterprise_id_for,
    filter_findings_for_user,
    require_scan_access,
)

router = APIRouter(prefix="/api/multi-source", tags=["multi-source"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
scan_policy = ScanPolicy(authorization_service)
logger = logging.getLogger("phantomscan.multi_source")


_SCAN_STATUS_VALUES = {"queued", "running", "cancelling", "cancelled", "complete", "error", "failed"}


def _map_source_status(status: str | None) -> str:
    """Map DB/persistence status values to the ScanStatus Literal."""
    mapping = {
        "pending": "queued",
        "completed": "complete",
        "failed": "failed",
        "skipped": "cancelled",
    }
    normalized = str(status or "pending")
    return mapping.get(normalized, normalized if normalized in _SCAN_STATUS_VALUES else "error")


async def _load_scan(scan_id: int, user: dict[str, Any]) -> dict[str, Any]:
    return await require_scan_access(scan_id, user)


async def _fetch_sources(scan_id: int) -> list[dict[str, Any]]:
    try:
        return await list_scan_sources(scan_id)
    except Exception:
        return []


async def _fetch_findings(scan_id: int, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    try:
        findings = await get_findings(scan_id)
        return filter_findings_for_user(findings, user) if user is not None else findings
    except Exception:
        return []


async def _fetch_correlations(scan_id: int) -> list[dict[str, Any]]:
    try:
        return await list_source_correlations(scan_id)
    except Exception:
        return []


async def build_response(scan_id: int, user: dict[str, Any] | None = None) -> MultiSourceScanResponse:
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    sources = await _fetch_sources(scan_id)
    findings = await _fetch_findings(scan_id, user)
    correlations = await _fetch_correlations(scan_id)

    source_results: list[SourceScanResult] = []
    for source in sources:
        sev_counts: dict[str, int] = {}
        for finding in findings:
            if finding.get("_source_type", "") == source.get("source_type"):
                sev = str(finding.get("severity", "INFO")).upper()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
        source_results.append(
            SourceScanResult(
                source_type=source["source_type"],
                source_identifier=str(source.get("source_identifier") or ""),
                status=_map_source_status(source.get("status")),
                findings_count=int(source.get("findings_count") or 0),
                findings_by_severity=sev_counts,
                scan_duration_seconds=float(source.get("scan_duration_seconds") or 0),
                error_message=source.get("error_message"),
                artifacts=source.get("artifacts") or {},
            )
        )

    severity_totals: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "INFO")).upper()
        severity_totals[sev] = severity_totals.get(sev, 0) + 1

    return MultiSourceScanResponse(
        scan_id=scan_id,
        name=str(scan.get("target_url") or f"Multi-source scan #{scan_id}"),
        mode=str(scan.get("mode") or "multi_agent"),
        overall_status=_map_source_status(scan.get("status")),
        overall_progress=int(scan.get("progress") or 0),
        sources=source_results,
        total_findings=len(findings),
        findings_by_severity=severity_totals,
        correlated_findings_count=len(correlations),
        created_at=str(scan.get("created_at") or ""),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        total_duration_seconds=0.0,
        max_duration_minutes=int(scan.get("max_duration_minutes") or 120),
        sarif_export_url=None,
        pdf_report_url=None,
        health_score=scan.get("health_score"),
    )


async def _validate_local_sources(request: MultiSourceScanRequest) -> None:
    """Verify local codebase paths exist and are readable before scheduling the scan."""
    for source in request.sources:
        if source.type != "local":
            continue
        path = str(source.path or "").strip().strip('"')
        if not path:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Local source is missing a path")
        normalized = os.path.normpath(path)
        if not os.path.exists(normalized):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Path does not exist: {path}")
        if not os.path.isdir(normalized) and not os.path.isfile(normalized):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Path is neither a directory nor a file: {path}")
        if not os.access(normalized, os.R_OK):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Path is not readable: {path}")


_GITHUB_URL_RE = __import__("re").compile(
    r"^https?://(www\.)?github\.com/[\w.-]+/[\w.-]+/?$"
)


async def _clone_github_repo(
    repo_url: str,
    branch: str = "",
    github_token: str | None = None,
    *,
    scan_id: int | None = None,
) -> Path:
    """Clone a GitHub repo to persistent CLONE_DIR.

    Returns the local path to the cloned repo.
    Raises HTTPException on failure with descriptive status codes.
    """
    if not _GITHUB_URL_RE.match(repo_url):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL. Expected format: https://github.com/owner/repo",
        )

    from app.config import get_settings
    settings = get_settings()
    base_dir = Path(settings.clone_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    safe_name = repo_url.rstrip("/").split("/")[-1]
    clone_target = base_dir / f"{safe_name}-{scan_id or 'scan'}"

    if clone_target.exists():
        shutil.rmtree(clone_target, ignore_errors=True)

    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd.extend(["--branch", branch])

    # Build clone URL with token if available
    clone_url = repo_url
    if github_token and "github.com" in repo_url:
        clone_url = repo_url.replace("https://github.com/", f"https://{github_token}@github.com/")

    cmd.extend([clone_url, str(clone_target)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        shutil.rmtree(clone_target, ignore_errors=True)
        raise HTTPException(
            status_code=504,
            detail="Git clone timed out (120s). The repository may be too large.",
        )
    except FileNotFoundError:
        shutil.rmtree(clone_target, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail="Git is not installed or not found in PATH.",
        )

    if proc.returncode != 0:
        shutil.rmtree(clone_target, ignore_errors=True)
        error_msg = stderr.decode(errors="replace").strip()
        if github_token:
            error_msg = error_msg.replace(github_token, "***")
        if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
            raise HTTPException(status_code=404, detail=f"Repository not found or not accessible: {repo_url}")
        if "could not resolve host" in error_msg.lower():
            raise HTTPException(status_code=502, detail="Could not reach github.com. Check your internet connection.")
        raise HTTPException(status_code=502, detail=f"Git clone failed: {error_msg[:500]}")

    logger.info("Cloned %s (branch=%s) to %s", repo_url, branch or "default", clone_target)
    return clone_target


@router.post("/scan", response_model=MultiSourceScanResponse, status_code=status.HTTP_201_CREATED)
async def start_multi_source_scan(
    request: MultiSourceScanRequest,
    user: dict = Depends(get_current_user),
) -> MultiSourceScanResponse:
    """Start a coordinated multi-source security scan.

    GitHub repos are cloned synchronously so errors are returned immediately.
    The cloned path replaces the GitHub source with a local source for scanning.
    """
    logger.info("Multi-source scan request: name=%s sources=%s user=%s", request.name, [s.type for s in request.sources], user["id"])
    # Clone GitHub repos synchronously (VULSCAN approach) — errors returned to user immediately
    cloned_paths: list[Path] = []
    sources: list = list(request.sources)
    for idx, source in enumerate(sources):
        if getattr(source, "type", None) != "github":
            continue
        repo_url = str(getattr(source, "repo_url", ""))
        branch = str(getattr(source, "branch", "") or "")
        github_token = getattr(source, "pat_token", None)
        clone_path = await _clone_github_repo(repo_url, branch, github_token, scan_id=None)
        cloned_paths.append(clone_path)
        sources[idx] = LocalCodebaseConfig(path=str(clone_path))
    if cloned_paths:
        request = request.model_copy(update={"sources": sources})

    await _validate_local_sources(request)
    return await _start_scan(request, user)


async def _start_scan(request: MultiSourceScanRequest, user: dict) -> MultiSourceScanResponse:
    """Create, persist, and background-submit a multi-source scan. Returns the live response."""
    scan_id: int | None = None
    try:
        scan_id = await _create_multi_source_scan(request, user["id"], enterprise_id_for(user))
        await add_audit_log(
            scan_id,
            "System",
            "multi_source_scan_created",
            f"Created multi-source scan '{request.name or scan_id}' with sources: {', '.join(s.type for s in request.sources)}",
            user_id=user["id"],
            target="multi-source://scan",
        )
        await _submit(request, scan_id, user["id"], user["role"])
    except ScanCapacityError as exc:
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to start multi-source scan")
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc)[:1000])
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    return await build_response(scan_id, user)


async def _create_multi_source_scan(
    request: MultiSourceScanRequest, user_id: str, enterprise_id: str | None = None
) -> int:
    from app.database import create_scan
    target_url = "multi-source://scan"
    for source in request.sources:
        if source.type == "live":
            target_url = str(source.target_url)
            break
        if source.type == "github":
            target_url = str(source.repo_url)
            break
        if source.type == "local":
            target_url = f"local://{source.path}"
            break
    return await create_scan(
        target_url=target_url,
        mode="multi_agent",
        intensity=request.intensity,
        selected_tests=json.dumps([s.type for s in request.sources], separators=(",", ":")),
        user_id=user_id,
        enterprise_id=enterprise_id,
        authorization_id=None,
        authorization_confirmed=False,
        max_duration_minutes=request.max_duration_minutes,
    )


async def _submit(request: MultiSourceScanRequest, scan_id: int, user_id: str, user_role: str) -> None:
    """Submit multi-source scan to the job manager. Slot released on task completion."""
    loop = asyncio.get_running_loop()

    reservation = await scan_job_manager.reserve_slot()

    task = loop.create_task(
        OrchestratorAgent(limits=scan_job_manager.limits).run_multi_source(
            request,
            scan_id,
            user_id=user_id,
            user_role=user_role,
            authorization_context={},
        ),
        name=f"phantomscan-multi-{scan_id}",
    )

    def _release_slot_on_done(t: asyncio.Task) -> None:
        asyncio.ensure_future(scan_job_manager.release_slot(reservation))

    task.add_done_callback(_release_slot_on_done)
    await scan_job_manager.register_task(scan_id, task)


@router.get("/history", response_model=list[MultiSourceScanHistoryItem])
async def multi_source_history(user: dict = Depends(get_current_user)) -> list[MultiSourceScanHistoryItem]:
    rows = await list_multi_source_scans(user["id"], enterprise_id=enterprise_id_for(user))
    items: list[MultiSourceScanHistoryItem] = []
    for row in rows:
        sources = await _fetch_sources(int(row["id"]))
        findings = await _fetch_findings(int(row["id"]), user)
        correlations = await _fetch_correlations(int(row["id"]))
        items.append(
            MultiSourceScanHistoryItem(
                scan_id=int(row["id"]),
                name=str(row.get("target_url") or f"Multi-source scan #{row['id']}"),
                mode=str(row.get("mode") or "multi_agent"),
                overall_status=_map_source_status(row.get("status")),
                sources=[str(s.get("source_type")) for s in sources],
                total_findings=len(findings),
                correlated_findings=len(correlations),
                created_at=row.get("created_at") or "",
                completed_at=row.get("completed_at"),
            )
        )
    return items


@router.get("/{scan_id}", response_model=MultiSourceScanResponse)
async def multi_source_status(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> MultiSourceScanResponse:
    await _load_scan(scan_id, user)
    return await build_response(scan_id, user)


@router.get("/{scan_id}/correlations", response_model=dict[str, Any])
async def multi_source_correlations(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Return cross-source correlations with linked findings."""
    await _load_scan(scan_id, user)
    correlations = await _fetch_correlations(scan_id)
    findings = await _fetch_findings(scan_id, user)
    findings_by_id = {int(f["id"]): f for f in findings}

    groups: list[dict[str, Any]] = []
    for corr in correlations:
        finding_ids = [int(fid) for fid in corr.get("finding_ids", [])]
        related = [findings_by_id[fid] for fid in finding_ids if fid in findings_by_id]
        if not related:
            continue
        primary = related[0]
        group: dict[str, Any] = {
            "unified_id": str(corr.get("unified_id") or ""),
            "title": str(primary.get("title") or "Correlated findings"),
            "severity": str(primary.get("severity") or "INFO").upper(),
            "confidence": float(corr.get("confidence") or 0),
            "sources": corr.get("source_types", []),
            "correlation_type": str(corr.get("correlation_type") or "exact_match"),
            "related_findings": related,
            "evidence": corr.get("evidence") or {},
        }
        groups.append(group)

    summary = SourceCorrelationSummary(
        total_correlations=len(correlations),
        by_type={},
        by_source_pair={},
        high_confidence=sum(1 for c in correlations if float(c.get("confidence") or 0) > 0.8),
        data_flow_traces=sum(1 for c in correlations if c.get("correlation_type") == "data_flow"),
        vulnerability_chains=sum(1 for c in correlations if c.get("correlation_type") == "vulnerability_chain"),
    )
    for corr in correlations:
        ctype = str(corr.get("correlation_type") or "exact_match")
        summary.by_type[ctype] = summary.by_type.get(ctype, 0) + 1
        source_types = corr.get("source_types", [])
        if len(source_types) >= 2:
            pair = "+".join(sorted(source_types[:2]))
            summary.by_source_pair[pair] = summary.by_source_pair.get(pair, 0) + 1

    return {
        "scan_id": scan_id,
        "summary": summary.model_dump(),
        "groups": groups,
    }


@router.post("/{scan_id}/stop", response_model=dict[str, str])
async def stop_multi_source_scan(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> dict[str, str]:
    await _load_scan(scan_id, user)
    try:
        scan_status = await scan_job_manager.stop(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc
    except ScanNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"scan_id": str(scan_id), "status": scan_status}


_MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


async def _process_uploaded_codebase(scan_id: int, temp_zip_path: Path, work_dir: Path, user_id: str, max_duration_minutes: int) -> None:
    """Background task: extract zip then submit scan using the existing scan_id.

    Follows the VULSCAN approach: one scan record, files stay on disk until
    the orchestrator's _cleanup_uploaded_sources() removes them after completion.
    """
    from app.services.upload_service import extract_uploaded_zip as _extract
    from app.models import LocalCodebaseConfig, MultiSourceScanRequest
    try:
        # Extract the zip file
        scan_root = await _extract(temp_zip_path, max_bytes=_MAX_UPLOAD_BYTES, work_dir=work_dir)
        logger.info("Uploaded codebase extracted to %s for scan %d", scan_root, scan_id)

        request = MultiSourceScanRequest(
            name=f"Uploaded codebase: {os.path.basename(scan_root.rstrip(os.sep)) or 'zip'}",
            mode="multi_agent",
            intensity="medium",
            sources=[LocalCodebaseConfig(path=scan_root)],
            max_duration_minutes=max_duration_minutes,
        )
        await _validate_local_sources(request)

        # Update existing scan record to "running" and submit directly.
        # Do NOT call _start_scan() — it would create a second scan record.
        await update_scan_status(scan_id, "running")
        await add_audit_log(
            scan_id,
            "System",
            "multi_source_scan_started",
            "Scan started from uploaded codebase",
            user_id=user_id,
            target="multi-source://scan",
        )
        await _submit(request, scan_id, user_id, "user")
    except Exception as exc:
        logger.exception("Failed to process uploaded codebase for scan %d", scan_id)
        await update_scan_status(scan_id, "error", str(exc)[:1000])


@router.post("/upload-codebase")
async def upload_codebase(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    max_duration_minutes: int = Form(120, ge=5, le=1440),
    approval_request_id: int | None = Form(None),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Upload a zip archive and start scan in background. Returns immediately with scan_id."""
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    # Create scan record first to get scan_id
    scan_id = await create_scan(
        target_url=f"local://{file.filename}",
        mode="multi_agent",
        intensity="medium",
        selected_tests=json.dumps(["local"]),
        user_id=user["id"],
        enterprise_id=enterprise_id_for(user),
        authorization_id=None,
        authorization_confirmed=False,
        max_duration_minutes=max_duration_minutes,
    )

    # Create temp directory for this upload
    work_dir = Path(tempfile.mkdtemp(prefix=f"upload-{scan_id}-"))
    temp_zip_path = work_dir / "source.zip"

    # Save file to disk (streaming to avoid memory issues)
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise HTTPException(status_code=413, detail="File exceeds 200 MB limit")
    temp_zip_path.write_bytes(content)

    logger.info("Saved uploaded codebase to %s for scan %d by user %s", temp_zip_path, scan_id, user["id"])

    # Add audit log
    await add_audit_log(
        scan_id,
        "System",
        "multi_source_scan_created",
        f"Created multi-source scan from uploaded codebase: {file.filename}",
        user_id=user["id"],
        target="multi-source://scan",
    )

    # Process extraction and scan in background
    background_tasks.add_task(_process_uploaded_codebase, scan_id, temp_zip_path, work_dir, user["id"], max_duration_minutes)

    return {
        "scan_id": scan_id,
        "source_id": "local",
        "path": str(temp_zip_path),
        "status": "queued",
        "max_duration_minutes": max_duration_minutes,
        "message": "Upload accepted. Extraction and scan will start shortly.",
    }


async def cleanup_stale_uploads(max_age_hours: int = 24) -> int:
    """Remove upload-* temp dirs older than max_age_hours. Returns count removed."""
    temp_dir = Path(tempfile.gettempdir())
    removed = 0
    cutoff = time.time() - (max_age_hours * 3600)
    for upload_dir in temp_dir.glob("upload-*"):
        if upload_dir.is_dir() and upload_dir.stat().st_mtime < cutoff:
            shutil.rmtree(upload_dir, ignore_errors=True)
            removed += 1
    return removed
