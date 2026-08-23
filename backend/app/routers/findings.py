from datetime import datetime, timezone
import json
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app.auth_middleware import get_current_user
from app.config import get_settings
from app.database import (
    add_audit_log,
    count_findings,
    get_connection,
    get_exploitation_results_map,
    get_finding,
    get_scan,
    list_scan_sources,
    list_findings,
    set_scan_artifacts,
    update_finding,
)
from app.models import Finding
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine, CANONICAL_MODULES, normalize_module
from app.services.browser_observation import BrowserObservationEngine
from app.services.authorization import TargetAuthorizationService, TargetValidationError
from app.services.execution import SafetyLimits
from app.services.enterprise_access import (
    consume_approved_request,
    enterprise_id_for,
    filter_findings_for_user,
    is_enterprise_member,
    require_scan_access,
)
from app.agents.tools.apply_patch import create_apply_patch_tool
from app.agents.sandbox_manager import SandboxManagerAgent
from app.agents import Agent

router = APIRouter(prefix="/api/findings", tags=["findings"])
settings = get_settings()
authorization_service = TargetAuthorizationService()
active_gate = ActiveTargetGate(authorization_service)
BROWSER_VERIFICATION_MODULES = {"browser_console", "csp_analysis", "browser_storage", "javascript_static_analysis", "client_dataflow"}


class RemediationStatusRequest(BaseModel):
    remediation_status: Literal["OPEN", "IN_PROGRESS", "RESOLVED"]


class RiskStatusRequest(BaseModel):
    risk_status: Literal["ACTIVE", "FALSE_POSITIVE", "ACCEPTED_RISK"]


class ApplyPatchRequest(BaseModel):
    approval_request_id: int | None = Field(default=None, ge=1)
    patch: str = Field(min_length=1, description="Unified diff patch content")
    file_path: str = Field(min_length=1, description="Relative path to the file to patch")
    target_root: str | None = Field(default=None, description="Optional root directory containing source code")
    verify_after: bool = Field(default=True, description="Whether to run verification after applying patch")


class FindingsPageResponse(BaseModel):
    items: list[Finding]
    total: int
    limit: int
    offset: int


async def _verify_finding_ownership(finding_id: int, user: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    finding = await get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    try:
        scan = await require_scan_access(int(finding["scan_id"]), user)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found") from exc
        raise
    if not filter_findings_for_user([finding], user):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding, scan


async def _attached_source_root(scan_id: int) -> str | None:
    sources = await list_scan_sources(scan_id)
    for source in sources:
        if source.get("source_type") != "local":
            continue
        config = source.get("source_config") if isinstance(source.get("source_config"), dict) else {}
        path = config.get("path")
        if path:
            return str(path)
    return None


@router.get("", response_model=list[Finding])
async def all_findings(
    scan_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    include_details: bool = Query(default=False),
    user: dict = Depends(get_current_user),
) -> list[Finding]:
    rows = await list_findings(
        scan_id,
        user["id"],
        enterprise_id_for(user),
        limit=limit,
        offset=offset,
        include_details=include_details,
        severity=severity,
        category=category,
        query=q,
    )
    rows = filter_findings_for_user(rows, user)
    if include_details:
        poc_map = await get_exploitation_results_map([row["id"] for row in rows])
        for row in rows:
            row["poc"] = poc_map.get(int(row["id"]))
    return [Finding(**row) for row in rows]


@router.get("/page", response_model=FindingsPageResponse)
async def findings_page(
    scan_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    user: dict = Depends(get_current_user),
) -> FindingsPageResponse:
    rows = await list_findings(
        scan_id,
        user["id"],
        enterprise_id_for(user),
        limit=limit,
        offset=offset,
        include_details=False,
        severity=severity,
        category=category,
        query=q,
    )
    rows = filter_findings_for_user(rows, user)
    total = await count_findings(
        scan_id,
        user["id"],
        enterprise_id_for(user),
        severity=severity,
        category=category,
        query=q,
    )
    return FindingsPageResponse(items=[Finding(**row) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/{finding_id}", response_model=Finding)
async def finding_detail(
    finding_id: int,
    user: dict = Depends(get_current_user),
) -> Finding:
    finding, _scan = await _verify_finding_ownership(finding_id, user)
    poc_map = await get_exploitation_results_map([finding_id])
    finding["poc"] = poc_map.get(finding_id)
    return Finding(**finding)


@router.post("/{finding_id}/verify")
async def verify_finding_fix(
    finding_id: int,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    finding, scan = await _verify_finding_ownership(finding_id, user)
    module = infer_module(finding)
    browser_module = infer_browser_module(finding) if module is None else None
    if module is None and browser_module is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Finding does not map to a supported active module")
    try:
        decision = await active_gate.admit(str(scan["target_url"]), user["id"], scan.get("authorization_id"), user_role=user["role"])
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "TARGET_NOT_VERIFIED", "message": decision.reason})

    if browser_module is not None:
        return await verify_browser_finding_fix(finding_id, finding, scan, decision, browser_module, request, user["id"])

    limits = SafetyLimits.from_settings()
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    engine = ActiveSecurityEngine(
        target_url=decision.target_url,
        attack_surface=None,
        selected_modules=[module],
        limits=limits,
        authorization_context=decision.to_context(),
        workflow_rules={},
        scan_id=int(finding["scan_id"]),
        user_id=user["id"],
        sandbox_id=f"verify-{finding_id}",
        transport=transport,
    )
    result = await engine.run()
    if result.get("status") not in {"complete", "limited"}:
        await update_finding(finding_id, verification_status="VERIFY_FAILED")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Verification check did not complete")
    still_present = any(normalize_module(str(item.get("module") or "")) == module for item in result.get("findings", []))
    verification_status = "ISSUE_STILL_PRESENT" if still_present else "FIX_VERIFIED"
    remediation_status = "OPEN" if still_present else "RESOLVED"
    verification = (
        f"{verification_status} at {datetime.now(timezone.utc).isoformat()} using module {module}. "
        f"Requests used: {result.get('request_count', 0)}."
    )
    await update_finding(
        finding_id,
        verification_status=verification_status,
        remediation_status=remediation_status,
        verification=verification,
    )
    await set_scan_artifacts(int(finding["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(finding["scan_id"]),
        "Active Security Engine",
        "fix_verification_completed",
        verification,
        user_id=user["id"],
        target=str(scan["target_url"]),
        authorization_status=decision.authorization_status,
        selected_module=module,
        result=verification_status,
        request_count=int(result.get("request_count", 0)),
        sandbox_id=f"verify-{finding_id}",
    )
    return {
        "finding_id": finding_id,
        "module": module,
        "status": verification_status,
        "remediation_status": remediation_status,
        "request_count": int(result.get("request_count", 0)),
    }


@router.post("/{finding_id}/apply-patch")
async def apply_patch_to_finding(
    finding_id: int,
    payload: ApplyPatchRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    finding, scan = await _verify_finding_ownership(finding_id, user)
    if is_enterprise_member(user):
        approval_request_id = payload.approval_request_id
        if not approval_request_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="An approved code-fix request is required")
        approval = await consume_approved_request(
            approval_request_id,
            user,
            {"code_fix", "remediation"},
            finding_id=finding_id,
            patch=payload.patch,
            file_path=payload.file_path,
        )
    else:
        approval = {"details": {}}
    
    module = infer_module(finding)
    browser_module = infer_browser_module(finding) if module is None else None
    if payload.verify_after and module is None and browser_module is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Finding does not map to a supported active module")
    
    # Apply patch using sandbox
    sandbox_manager = SandboxManagerAgent()
    mock_agent = Agent("Patch Application")
    mock_agent.scan_id = int(finding["scan_id"])
    patch_tool = await create_apply_patch_tool(mock_agent, sandbox_manager)
    
    approval_details = approval.get("details") if isinstance(approval.get("details"), dict) else {}
    target_root = payload.target_root or approval_details.get("target_root") or await _attached_source_root(int(finding["scan_id"]))
    if is_enterprise_member(user) and not target_root:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No attached source workspace is available. Treat this approved change as a manual remediation task.",
        )

    patch_result = await patch_tool.apply_patch(
        patch=payload.patch,
        file_path=payload.file_path,
        scan_id=int(finding["scan_id"]),
        target_root=target_root,
    )
    
    if not patch_result.get("success"):
        await add_audit_log(
            int(finding["scan_id"]),
            "Patch Application",
            "patch_apply_failed",
            f"Failed to apply patch for finding {finding_id}: {patch_result.get('error')}",
            user_id=user["id"],
        )
        return {
            "finding_id": finding_id,
            "patch_applied": False,
            "error": patch_result.get("error"),
            "patch_result": patch_result,
        }
    if is_enterprise_member(user) and payload.approval_request_id:
        async with get_connection() as conn:
            await conn.execute(
                """
                UPDATE enterprise_approval_requests
                SET status = 'completed', completed_at = CURRENT_TIMESTAMP, execution_result = ?
                WHERE id = ? AND enterprise_id = ? AND employee_id = ?
                """,
                (
                    json.dumps({"finding_id": finding_id, "action": "patch_applied", "file_path": payload.file_path}),
                    payload.approval_request_id,
                    enterprise_id_for(user),
                    user["id"],
                ),
            )
            await conn.commit()
    
    await add_audit_log(
        int(finding["scan_id"]),
        "Patch Application",
        "patch_applied",
        f"Successfully applied patch for finding {finding_id} to {payload.file_path}",
        user_id=user["id"],
    )
    
    # If verification requested, run the test module
    if payload.verify_after:
        try:
            decision = await active_gate.admit(str(scan["target_url"]), user["id"], scan.get("authorization_id"), user_role=user["role"])
        except TargetValidationError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        if not decision.allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "TARGET_NOT_VERIFIED", "message": decision.reason})
        
        if browser_module is not None:
            limits = SafetyLimits.from_settings()
            transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
            engine = BrowserObservationEngine(
                target_url=decision.target_url,
                mode=str(scan.get("mode") or "defend"),
                authorization_context=decision.to_context(),
                limits=limits,
                scan_id=int(finding["scan_id"]),
                transport=transport,
                use_playwright=transport is None,
            )
            result = await engine.run()
            if result.get("status") not in {"complete", "limited"}:
                verification_status = "VERIFY_FAILED"
            else:
                original_title = str(finding.get("title") or "")
                still_present = any(
                    str(item.get("module") or "") == browser_module or str(item.get("title") or "") == original_title
                    for item in result.get("findings", [])
                    if isinstance(item, dict)
                )
                verification_status = "ISSUE_STILL_PRESENT" if still_present else "FIX_VERIFIED"
        else:
            limits = SafetyLimits.from_settings()
            transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
            engine = ActiveSecurityEngine(
                target_url=decision.target_url,
                attack_surface=None,
                selected_modules=[module],
                limits=limits,
                authorization_context=decision.to_context(),
                workflow_rules={},
                scan_id=int(finding["scan_id"]),
                user_id=user["id"],
                sandbox_id=f"verify-{finding_id}",
                transport=transport,
            )
            result = await engine.run()
            if result.get("status") not in {"complete", "limited"}:
                verification_status = "VERIFY_FAILED"
            else:
                still_present = any(normalize_module(str(item.get("module") or "")) == module for item in result.get("findings", []))
                verification_status = "ISSUE_STILL_PRESENT" if still_present else "FIX_VERIFIED"
        
        remediation_status = "OPEN" if verification_status == "ISSUE_STILL_PRESENT" else "RESOLVED"
        verification = (
            f"{verification_status} at {datetime.now(timezone.utc).isoformat()} using module {module or browser_module}. "
            f"Requests used: {result.get('request_count', 0)}."
        )
        await update_finding(
            finding_id,
            verification_status=verification_status,
            remediation_status=remediation_status,
            verification=verification,
        )
        await set_scan_artifacts(int(finding["scan_id"]), ai_analyst_output=None)
        await add_audit_log(
            int(finding["scan_id"]),
            "Active Security Engine",
            "fix_verification_completed",
            verification,
            user_id=user["id"],
            target=str(scan["target_url"]),
            authorization_status=decision.authorization_status,
            selected_module=module or browser_module,
            result=verification_status,
            request_count=int(result.get("request_count", 0)),
            sandbox_id=f"verify-{finding_id}",
        )
        
        return {
            "finding_id": finding_id,
            "patch_applied": True,
            "patch_result": patch_result,
            "verification_status": verification_status,
            "remediation_status": remediation_status,
            "module": module or browser_module,
            "request_count": int(result.get("request_count", 0)),
        }
    
    return {
        "finding_id": finding_id,
        "patch_applied": True,
        "patch_result": patch_result,
        "verification_status": "PENDING",
        "remediation_status": "IN_PROGRESS",
        "message": "Patch applied successfully. Run verification separately.",
    }


async def verify_browser_finding_fix(
    finding_id: int,
    finding: dict[str, Any],
    scan: dict[str, Any],
    decision: Any,
    module: str,
    request: Request,
    user_id: str,
) -> dict[str, Any]:
    limits = SafetyLimits.from_settings()
    transport = httpx.ASGITransport(app=request.app) if decision.is_lab else None
    engine = BrowserObservationEngine(
        target_url=decision.target_url,
        mode=str(scan.get("mode") or "defend"),
        authorization_context=decision.to_context(),
        limits=limits,
        scan_id=int(finding["scan_id"]),
        transport=transport,
        use_playwright=transport is None,
    )
    result = await engine.run()
    if result.get("status") not in {"complete", "limited"}:
        await update_finding(finding_id, verification_status="VERIFY_FAILED")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Browser verification check did not complete")
    original_title = str(finding.get("title") or "")
    still_present = any(
        str(item.get("module") or "") == module or str(item.get("title") or "") == original_title
        for item in result.get("findings", [])
        if isinstance(item, dict)
    )
    verification_status = "ISSUE_STILL_PRESENT" if still_present else "FIX_VERIFIED"
    remediation_status = "OPEN" if still_present else "RESOLVED"
    verification = (
        f"{verification_status} at {datetime.now(timezone.utc).isoformat()} using browser module {module}. "
        f"Requests used: {result.get('request_count', 0)}."
    )
    await update_finding(
        finding_id,
        verification_status=verification_status,
        remediation_status=remediation_status,
        verification=verification,
    )
    await set_scan_artifacts(int(finding["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(finding["scan_id"]),
        "Browser Security Agent",
        "fix_verification_completed",
        verification,
        user_id=user_id,
        target=str(scan["target_url"]),
        authorization_status=decision.authorization_status,
        selected_module=module,
        result=verification_status,
        request_count=int(result.get("request_count", 0)),
        sandbox_id=f"browser-verify-{finding_id}",
    )
    return {
        "finding_id": finding_id,
        "module": module,
        "status": verification_status,
        "remediation_status": remediation_status,
        "request_count": int(result.get("request_count", 0)),
    }


@router.patch("/{finding_id}/remediation", response_model=Finding)
async def update_finding_remediation(
    finding_id: int,
    payload: RemediationStatusRequest,
    user: dict = Depends(get_current_user),
) -> Finding:
    finding, scan = await _verify_finding_ownership(finding_id, user)
    await update_finding(finding_id, remediation_status=payload.remediation_status)
    updated = await get_finding(finding_id)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    await set_scan_artifacts(int(updated["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(updated["scan_id"]),
        "Remediation",
        "remediation_status_updated",
        f"Finding {finding_id} marked {payload.remediation_status}",
        user_id=user["id"],
        target=str(updated.get("target") or ""),
        result=payload.remediation_status,
    )
    return Finding(**updated)


@router.patch("/{finding_id}/risk", response_model=Finding)
async def update_finding_risk_status(
    finding_id: int,
    payload: RiskStatusRequest,
    user: dict = Depends(get_current_user),
) -> Finding:
    finding, scan = await _verify_finding_ownership(finding_id, user)
    await update_finding(finding_id, risk_status=payload.risk_status)
    updated = await get_finding(finding_id)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    await set_scan_artifacts(int(updated["scan_id"]), ai_analyst_output=None)
    await add_audit_log(
        int(updated["scan_id"]),
        "Risk Triage",
        "risk_status_updated",
        f"Finding {finding_id} marked {payload.risk_status}",
        user_id=user["id"],
        target=str(updated.get("target") or ""),
        result=payload.risk_status,
    )
    return Finding(**updated)


def infer_module(finding: dict[str, Any]) -> str | None:
    explicit = normalize_module(str(finding.get("module") or ""))
    if explicit in CANONICAL_MODULES:
        return explicit
    text = " ".join(str(finding.get(name) or "") for name in ["category", "title", "evidence"]).lower()
    rules = [
        ("input_security", ["input", "validation"]),
        ("injection", ["injection", "data-layer", "data layer"]),
        ("xss", ["xss", "output encoding", "html-like"]),
        ("auth_session", ["authentication", "session", "rate-limit", "rate limit"]),
        ("access_control", ["access control", "authorization", "admin"]),
        ("csrf", ["csrf"]),
        ("file_upload", ["file upload"]),
        ("path_handling", ["path"]),
        ("api_security", ["api"]),
        ("graphql", ["graphql"]),
        ("websocket", ["websocket"]),
        ("jwt", ["jwt", "token"]),
        ("redirect", ["redirect"]),
        ("cors", ["cors"]),
        ("security_headers", ["security header", "browser security"]),
        ("tls_https", ["tls", "https"]),
        ("sensitive_exposure", ["sensitive", "debug", "diagnostic"]),
        ("business_logic", ["business logic", "workflow", "transfer"]),
    ]
    for module, needles in rules:
        if any(needle in text for needle in needles):
            return module
    return None


def infer_browser_module(finding: dict[str, Any]) -> str | None:
    explicit = str(finding.get("module") or "").strip().lower()
    if explicit in BROWSER_VERIFICATION_MODULES:
        return explicit
    text = " ".join(str(finding.get(name) or "") for name in ["category", "title", "evidence"]).lower()
    rules = [
        ("browser_console", ["console", "browser warning"]),
        ("csp_analysis", ["csp", "content-security-policy"]),
        ("browser_storage", ["cookie", "storage", "localstorage", "sessionstorage"]),
        ("javascript_static_analysis", ["source map", "javascript", "script"]),
        ("client_dataflow", ["client security surface", "dataflow", "sink"]),
    ]
    for module, needles in rules:
        if any(needle in text for needle in needles):
            return module
    return None
