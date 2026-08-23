import asyncio
import json
import logging
from typing import Any, get_args

from fastapi import APIRouter, Depends, HTTPException, status

logger = logging.getLogger("phantomscan.scan")

from app.auth_middleware import get_current_user, require_tier
from app.config import get_settings
from app.database import (
    add_audit_log,
    create_scan,
    get_findings,
    get_scan,
    get_scan_artifacts,
    list_scans,
    update_scan_status,
)
from app.models import (
    PRDescriptionRequest,
    PRDescriptionResponse,
    ScanArtifactsResponse,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    StopScanResponse,
    TestModule,
)
from app.services.authorization import TargetAuthorizationService, TargetValidationError
from app.services.jobs import ScanCapacityError, ScanNotRunningError, scan_job_manager
from app.services.policy import ScanPolicy, ScanPolicyError
from app.services.enterprise_access import (
    enterprise_id_for,
    filter_findings_for_user,
    require_scan_access,
)

router = APIRouter(prefix="/api/scan", tags=["scan"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
scan_policy = ScanPolicy(authorization_service)
VALID_TEST_MODULES = set(get_args(TestModule))


def _selected_tests(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, list):
        return []
    return [
        item
        for item in (str(item) for item in value)
        if item in VALID_TEST_MODULES
    ]


def _int_or_default(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _scan_response(row: dict[str, Any], findings: list[dict[str, Any]]) -> ScanResponse:
    return ScanResponse(
        scan_id=_int_or_default(row.get("id")),
        target_url=str(row["target_url"]),
        mode=row["mode"],
        intensity=row["intensity"],
        selected_tests=_selected_tests(row.get("selected_tests")),
        user_id=str(row["user_id"]),
        authorization_id=row.get("authorization_id"),
        authorization_confirmed=bool(row.get("authorization_confirmed")),
        status=row["status"],
        progress=_int_or_default(row.get("progress")),
        request_count=_int_or_default(row.get("request_count")),
        sandbox_id=row.get("sandbox_id"),
        error_message=row.get("error_message"),
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        findings=findings,
    )


async def _verify_scan_ownership(scan_id: int, user: dict[str, Any]) -> dict[str, Any]:
    return await require_scan_access(scan_id, user)


@router.post("/start", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def start_scan(
    scan_request: ScanRequest,
    user: dict = Depends(get_current_user),
) -> ScanResponse:
    logger.debug("[SCAN] REQUEST RECEIVED")
    logger.info("Scan request received for target=%s mode=%s user=%s", scan_request.target_url, scan_request.mode, user["id"])

    try:
        admission = await scan_policy.admit(scan_request, user["id"], user.get("role", "user"))
    except ScanPolicyError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    try:
        reservation = await scan_job_manager.reserve_slot()
    except ScanCapacityError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    canonical_request = scan_request.model_copy(update={"target_url": admission.target_url})
    authorization_id = admission.verified_target.id if admission.verified_target is not None else None
    scan_id: int | None = None
    try:
        scan_id = await create_scan(
            target_url=admission.target_url,
            mode=canonical_request.mode,
            intensity=canonical_request.intensity,
            selected_tests=json.dumps(canonical_request.selected_tests, separators=(",", ":")),
            user_id=user["id"],
            enterprise_id=enterprise_id_for(user),
            authorization_id=authorization_id,
            authorization_confirmed=canonical_request.authorization_confirmed,
        )
        await add_audit_log(
            scan_id,
            "System",
            "scan_created",
            (
                f"Created {canonical_request.mode} scan for {admission.target_url} with "
                f"{canonical_request.intensity} intensity and modules: "
                f"{', '.join(canonical_request.selected_tests) or 'none'}"
            ),
            user_id=user["id"],
            target=admission.target_url,
            authorization_status=str(admission.authorization_context.get("authorization_status") or "NOT_REQUIRED"),
        )
        await scan_job_manager.submit(
            reservation,
            scan_id,
            canonical_request,
            admission.verified_target,
            user["id"],
            admission.authorization_context,
            user_role=user["role"],
        )
    except ScanCapacityError as exc:
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc))
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except Exception as exc:
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc)[:1000])
        raise
    finally:
        await asyncio.shield(scan_job_manager.release_slot(reservation))

    row = await get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Created scan could not be loaded")
    return _scan_response(row, filter_findings_for_user(await get_findings(scan_id), user))


@router.get("/history", response_model=list[ScanHistoryItem])
async def scan_history(user: dict = Depends(get_current_user)) -> list[ScanHistoryItem]:
    rows = await list_scans(user["id"], enterprise_id_for(user))
    return [ScanHistoryItem(**row) for row in rows]


@router.post("/{scan_id}/stop", response_model=StopScanResponse)
async def stop_scan(scan_id: int, user: dict = Depends(get_current_user)) -> StopScanResponse:
    await _verify_scan_ownership(scan_id, user)
    try:
        scan_status = await scan_job_manager.stop(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found") from exc
    except ScanNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return StopScanResponse(scan_id=scan_id, status=scan_status)


@router.get("/{scan_id}/artifacts", response_model=ScanArtifactsResponse)
async def scan_artifacts(scan_id: int, user: dict = Depends(get_current_user)) -> ScanArtifactsResponse:
    await _verify_scan_ownership(scan_id, user)
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    artifacts = await get_scan_artifacts(scan_id)
    return ScanArtifactsResponse(**{"scan_id": scan_id, **(artifacts or {})})


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: int, user: dict = Depends(get_current_user)) -> ScanResponse:
    await _verify_scan_ownership(scan_id, user)
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_response(scan, filter_findings_for_user(await get_findings(scan_id), user))


@router.post("/{scan_id}/pr-description", response_model=PRDescriptionResponse)
async def generate_pr_description(
    scan_id: int,
    request: PRDescriptionRequest,
    user: dict = Depends(get_current_user),
) -> PRDescriptionResponse:
    await _verify_scan_ownership(scan_id, user)
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    from app.agents.fixer import FixerAgent
    fixer = FixerAgent()
    try:
        response = await fixer.generate_pr_description(
            finding_ids=request.finding_ids,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            repo_url=request.repo_url,
            include_fix_details=request.include_fix_details,
            include_verification_steps=request.include_verification_steps,
        )
    except Exception as exc:
        logger.exception("PR description generation failed for scan %s", scan_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    return response
