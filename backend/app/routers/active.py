import asyncio
import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth_middleware import get_current_user, require_tier
from app.config import get_settings
from app.database import (
    create_scan,
    find_active_authorized_test_job,
    get_authorized_target,
    get_authorized_test_job,
    get_evidence_for_job,
    get_evidence_for_finding,
    get_finding,
    get_exploitation_results_map,
    get_findings,
    get_job_events,
    get_scan,
    get_scan_artifacts,
)
from app.models import RequestEvidence
from app.models import (
    ActiveRunRequest,
    AuthorizedTestJobResponse,
    AuthorizedTestJobResultsResponse,
    AuthorizedTestRunResponse,
    AuthorizedTestJobError,
    ComplexityResponse,
    Finding,
    JobEvent,
    JobEventsResponse,
)
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import AttackSurfaceMapper, SecurityTestPlanner, normalize_modules, compute_tci_from_attack_surface
from app.services.authorization import TargetAuthorizationService, TargetValidationError
from app.services.authorized_runner import run_authorized_test_job
from app.services.execution import SafetyLimits
from app.services.tci import TargetComplexityIndex
from app.services.enterprise_access import (
    enterprise_id_for,
    filter_findings_for_user,
    require_scan_access,
)

logger = logging.getLogger("phantomscan.active")

router = APIRouter(prefix="/api/active", tags=["active-security"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
active_gate = ActiveTargetGate(authorization_service)


class ActiveMapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    selected_modules: list[str] = Field(default_factory=list, max_length=25)
    authorization_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False
    approval_request_id: int | None = Field(default=None, ge=1)


async def admit_or_raise(request: ActiveMapRequest, user: dict):
    try:
        decision = await active_gate.admit(request.target_url, user["id"], request.authorization_id, user_role=user["role"])
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "TARGET_NOT_VERIFIED", "message": decision.reason})
    if decision.authorization_status == "VERIFIED" and not request.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTHORIZATION_CONFIRMATION_REQUIRED", "message": "Confirmed authorization is required before active mapping."},
        )
    return decision


def passive_plan_score(plan: dict[str, Any]) -> dict[str, Any]:
    selected = set(normalize_modules(plan.get("selected_modules") or []))
    vulnerable_surfaces = 0
    total_surfaces = 0
    for module in plan.get("modules", []):
        if selected and module.get("module") not in selected:
            continue
        for surface in module.get("surfaces") or []:
            total_surfaces += 1
            if surface.get("vulnerable") is True:
                vulnerable_surfaces += 1
    penalty = min(80, vulnerable_surfaces * 5)
    return {"score": max(0, 100 - penalty), "surface_count": total_surfaces, "vulnerable_surface_count": vulnerable_surfaces}


def active_limits() -> dict[str, Any]:
    limits = SafetyLimits.from_settings()
    return {
        "max_requests": limits.max_total_requests,
        "requests_per_second": limits.max_requests_per_second,
        "timeout_seconds": limits.max_scan_duration,
        "max_response_size": limits.max_response_size,
        "max_redirects": limits.max_redirect_depth,
        "max_concurrency": limits.max_concurrent_scans,
    }


async def compute_complexity(target_url: str, transport: httpx.AsyncBaseTransport | None) -> dict[str, Any]:
    tci = TargetComplexityIndex(transport=transport)
    return await tci.analyze_live(target_url)


@router.post("/map")
async def active_map(
    map_request: ActiveMapRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    decision = await admit_or_raise(map_request, user)
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    attack_surface = await AttackSurfaceMapper(transport=transport).map(decision.target_url)
    plan = SecurityTestPlanner().create_plan(attack_surface, map_request.selected_modules)
    complexity = await compute_complexity(decision.target_url, transport)
    tci = compute_tci_from_attack_surface(attack_surface)
    return {
        "gate": decision.to_context(),
        "surfaces": attack_surface.get("surfaces", []),
        "plan": plan,
        "score": passive_plan_score(plan),
        "complexity": complexity,
        "tci": tci,
        "limits": active_limits(),
    }


@router.post("/score")
async def active_score(
    score_request: ActiveMapRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    decision = await admit_or_raise(score_request, user)
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    attack_surface = await AttackSurfaceMapper(transport=transport).map(decision.target_url)
    plan = SecurityTestPlanner().create_plan(attack_surface, score_request.selected_modules)
    complexity = await compute_complexity(decision.target_url, transport)
    tci = compute_tci_from_attack_surface(attack_surface)
    return {
        "gate": decision.to_context(),
        "score": passive_plan_score(plan),
        "module_count": len(plan.get("modules", [])),
        "complexity": complexity,
        "tci": tci,
        "limits": active_limits(),
    }


@router.post("/complexity", response_model=ComplexityResponse)
async def active_complexity(
    complexity_request: ActiveMapRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> ComplexityResponse:
    decision = await admit_or_raise(complexity_request, user)
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    result = await compute_complexity(decision.target_url, transport)
    return ComplexityResponse(
        target_url=decision.target_url,
        score=result["score"],
        band=result["band"],
        band_label=result["band_label"],
        breakdown=result["breakdown"],
        source="live",
    )


async def admit_or_raise_for_run(request: ActiveRunRequest, user: dict):
    try:
        decision = await active_gate.admit(request.target_url, user["id"], request.authorization_id, user_role=user["role"])
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "TARGET_NOT_VERIFIED", "message": decision.reason})
    if decision.authorization_status == "VERIFIED" and not request.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTHORIZATION_CONFIRMATION_REQUIRED", "message": "Confirmed authorization is required before running an authorized test."},
        )
    return decision


@router.post("/run", response_model=AuthorizedTestRunResponse, status_code=status.HTTP_201_CREATED)
async def active_run(
    run_request: ActiveRunRequest,
    request: Request,
    user: dict = require_tier("PRO"),
) -> AuthorizedTestRunResponse:
    decision = await admit_or_raise_for_run(run_request, user)
    existing = await find_active_authorized_test_job(
        decision.target_origin,
        decision.authorization_id,
        enterprise_id_for(user),
        user["id"],
    )
    if existing is not None:
        return AuthorizedTestRunResponse(
            job_id=str(existing["id"]),
            status=str(existing["status"]),
            message="An authorized test is already running. Progress has been restored.",
        )
    scan_id = await create_scan(
        target_url=decision.target_url,
        mode="pentest",
        intensity="medium",
        selected_tests=json.dumps(run_request.selected_modules),
        user_id=user["id"],
        enterprise_id=enterprise_id_for(user),
        authorization_id=decision.authorization_id,
        authorization_confirmed=run_request.authorization_confirmed,
    )
    job_id = await create_authorized_test_job(
        authorization_id=decision.authorization_id,
        target_url=decision.target_url,
        normalized_target_origin=decision.target_origin,
        selected_modules=run_request.selected_modules,
        scan_id=scan_id,
        enterprise_id=enterprise_id_for(user),
        user_id=user["id"],
    )
    logger.info(
        "Authorized test job %s created for %s (authorization_id=%s, scan_id=%d)",
        job_id, decision.target_url, decision.authorization_id, scan_id,
    )
    asyncio.create_task(
        run_authorized_test_job(
            job_id=job_id,
            target_url=decision.target_url,
            normalized_target_origin=decision.target_origin,
            selected_modules=run_request.selected_modules,
            authorization_context=decision.to_context(),
            scan_id=scan_id,
            user_id=user["id"],
            sandbox_id=f"authorized-test-{job_id[:8]}",
            verified_target=decision.verified_target,
            transport=httpx.ASGITransport(app=request.app) if decision.is_lab else None,
            enable_exploitation=run_request.enable_exploitation,
            enable_ai_exploitation=run_request.enable_ai_exploitation,
        ),
        name=f"authorized-test-{job_id[:12]}",
    )
    return AuthorizedTestRunResponse(
        job_id=job_id,
        status="QUEUED",
        message="Authorized test started",
    )


async def _verify_job_ownership(job_id: str, user: dict[str, Any]) -> dict[str, Any]:
    job = await get_authorized_test_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized test job not found")
    scan_id = job.get("scan_id")
    if scan_id:
        await require_scan_access(int(scan_id), user)
    elif job.get("user_id") != user.get("id"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized test job not found")
    return job


@router.get("/jobs/{job_id}", response_model=AuthorizedTestJobResponse)
async def active_job_status(
    job_id: str,
    user: dict = Depends(get_current_user),
) -> AuthorizedTestJobResponse:
    await _verify_job_ownership(job_id, user)
    job = await get_authorized_test_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized test job not found")
    error = None
    if job.get("error_code") or job.get("error_message"):
        error = AuthorizedTestJobError(
            code=str(job.get("error_code") or "UNKNOWN"),
            message=str(job.get("error_message") or "Unknown error"),
        )
    selected_modules = []
    try:
        selected_modules = json.loads(str(job.get("selected_modules") or "[]"))
    except (json.JSONDecodeError, TypeError):
        pass
    return AuthorizedTestJobResponse(
        job_id=str(job["id"]),
        status=str(job["status"]),
        progress_percent=int(job.get("progress_percent") or 0),
        current_phase=str(job.get("current_phase") or ""),
        current_module=str(job.get("current_module") or ""),
        surfaces_total=int(job.get("surfaces_total") or 0),
        surfaces_completed=int(job.get("surfaces_completed") or 0),
        raw_surfaces_discovered=int(job.get("raw_surfaces_discovered") or 0),
        testable_surfaces=int(job.get("testable_surfaces") or 0),
        surface_groups=int(job.get("surface_groups") or 0),
        findings_count=int(job.get("findings_count") or 0),
        started_at=job.get("started_at"),
        updated_at=job.get("updated_at"),
        completed_at=job.get("completed_at"),
        error=error,
        target_url=str(job.get("target_url") or ""),
        selected_modules=selected_modules,
        authorization_id=job.get("authorization_id"),
        scan_id=job.get("scan_id"),
    )


@router.get("/jobs/{job_id}/results", response_model=AuthorizedTestJobResultsResponse)
async def active_job_results(
    job_id: str,
    user: dict = Depends(get_current_user),
) -> AuthorizedTestJobResultsResponse:
    await _verify_job_ownership(job_id, user)
    job = await get_authorized_test_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized test job not found")
    if job.get("status") not in ("COMPLETED", "FAILED", "CANCELLED"):
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail={"code": "JOB_NOT_COMPLETE", "message": "The authorized test has not completed yet. Results are not available."},
        )
    result_summary = None
    try:
        raw = job.get("result_summary")
        if raw:
            result_summary = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        pass
    scan_id = job.get("scan_id")
    findings_data = []
    if scan_id is not None:
        findings_data = filter_findings_for_user(await get_findings(int(scan_id)), user)
    poc_map = await get_exploitation_results_map([row["id"] for row in findings_data])
    for row in findings_data:
        row["poc"] = poc_map.get(int(row["id"]))
    return AuthorizedTestJobResultsResponse(
        job_id=str(job["id"]),
        status=str(job["status"]),
        target_url=str(job.get("target_url") or ""),
        surfaces_total=int(job.get("surfaces_total") or 0),
        surfaces_completed=int(job.get("surfaces_completed") or 0),
        raw_surfaces_discovered=int(job.get("raw_surfaces_discovered") or 0),
        testable_surfaces=int(job.get("testable_surfaces") or 0),
        surface_groups=int(job.get("surface_groups") or 0),
        findings_count=int(job.get("findings_count") or 0),
        started_at=job.get("started_at"),
        completed_at=job.get("completed_at"),
        findings=[Finding(**f) for f in findings_data],
        result_summary=result_summary,
    )


@router.get("/jobs/{job_id}/evidence")
async def active_job_evidence(
    job_id: str,
    finding_id: int | None = None,
    user: dict = Depends(get_current_user),
) -> list[dict[str, Any]]:
    await _verify_job_ownership(job_id, user)
    job = await get_authorized_test_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized test job not found")
    if finding_id is not None:
        finding = await get_finding(finding_id)
        if finding is None or int(finding.get("scan_id") or 0) != int(job.get("scan_id") or 0):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        if not filter_findings_for_user([finding], user):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        records = await get_evidence_for_finding(finding_id)
    else:
        records = await get_evidence_for_job(job_id)
    return records


@router.get("/jobs/{job_id}/events", response_model=JobEventsResponse)
async def active_job_events(
    job_id: str,
    after_sequence: int = 0,
    user: dict = Depends(get_current_user),
) -> JobEventsResponse:
    await _verify_job_ownership(job_id, user)
    job = await get_authorized_test_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized test job not found")
    events_data = await get_job_events(job_id, after_sequence)
    latest = max((e["sequence_number"] for e in events_data), default=0)
    return JobEventsResponse(
        job_id=job_id,
        events=[JobEvent(**e) for e in events_data],
        latest_sequence=latest,
    )


async def create_authorized_test_job(
    authorization_id: int | None,
    target_url: str,
    normalized_target_origin: str,
    selected_modules: list[str],
    scan_id: int,
    enterprise_id: str | None = None,
    user_id: str | None = None,
) -> str:
    from app.database import create_authorized_test_job as db_create_job
    return await db_create_job(
        authorization_id=authorization_id,
        target_url=target_url,
        normalized_target_origin=normalized_target_origin,
        selected_modules=selected_modules,
        scan_id=scan_id,
        enterprise_id=enterprise_id,
        user_id=user_id,
    )
