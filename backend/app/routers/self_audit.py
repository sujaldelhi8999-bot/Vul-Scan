from fastapi import APIRouter, Depends

from app.auth_middleware import get_current_user
from app.database import get_findings, get_latest_scan_for_agent
from app.models import SelfAuditStatusResponse

router = APIRouter(prefix="/api/self-audit", tags=["self-audit"])


@router.get("/status", response_model=SelfAuditStatusResponse)
async def self_audit_status(user: dict = Depends(get_current_user)) -> SelfAuditStatusResponse:
    scan = await get_latest_scan_for_agent("Self Audit Agent", user["id"])
    if scan is None:
        return SelfAuditStatusResponse(status="never_run")
    findings = await get_findings(int(scan["id"]))
    return SelfAuditStatusResponse(
        status=scan["status"],
        scan_id=int(scan["id"]),
        target_url=str(scan["target_url"]),
        progress=int(scan["progress"]),
        finding_count=len(findings),
        created_at=scan["created_at"],
        completed_at=scan.get("completed_at"),
    )