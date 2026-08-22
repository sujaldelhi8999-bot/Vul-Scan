import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth_middleware import get_current_user
from app.config import get_settings
from app.database import (
    add_audit_log,
    add_private_scope,
    find_private_scope,
    get_or_create_system_scan,
    list_private_scope,
    remove_private_scope,
)
from app.services.active_gate import canonicalize_hostname
from app.services.authorization import TargetValidationError, canonicalize_target

logger = logging.getLogger("phantomscan.admin_scope")

router = APIRouter(prefix="/api/admin/scope", tags=["admin-scope"])
settings = get_settings()


class AddScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)


class ScopeEntry(BaseModel):
    id: int
    target_url: str
    added_by: str
    added_at: str | None = None
    last_used: str | None = None


class ScopeAddResponse(BaseModel):
    success: bool
    message: str
    target_url: str


class ScopeRemoveResponse(BaseModel):
    success: bool
    message: str


async def _require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "ADMIN_REQUIRED", "message": "Admin privileges are required for this operation."},
        )
    return current_user


@router.post("/add", response_model=ScopeAddResponse)
async def add_to_private_scope(
    request: AddScopeRequest, current_user: dict = Depends(_require_admin)
) -> ScopeAddResponse:
    try:
        target = canonicalize_target(request.target_url)
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    hostname = canonicalize_hostname(target.url)
    await add_private_scope(hostname, added_by=current_user["id"])
    sys_scan_id = await get_or_create_system_scan()
    await add_audit_log(
        scan_id=sys_scan_id,
        agent_name="AdminScope",
        action="private_scope_add",
        details=f"Admin added {hostname} to Private Scope",
        user_id=current_user["id"],
        target=hostname,
        authorization_status="ADMIN_OVERRIDE",
    )
    logger.info("Admin %s added %s to Private Scope", current_user["id"], hostname)
    return ScopeAddResponse(
        success=True,
        message=f"Target added to Private Scope. You can now run the Full Assessment.",
        target_url=hostname,
    )


@router.get("/list", response_model=list[ScopeEntry])
async def list_private_scope_endpoint(current_user: dict = Depends(_require_admin)) -> list[ScopeEntry]:
    rows = await list_private_scope()
    return [
        ScopeEntry(
            id=row["id"],
            target_url=row["target_url"],
            added_by=row.get("added_by", "admin"),
            added_at=row.get("added_at"),
            last_used=row.get("last_used"),
        )
        for row in rows
    ]


@router.delete("/remove", response_model=ScopeRemoveResponse)
async def remove_from_private_scope(
    target_url: str = Query(min_length=4, max_length=2048),
    current_user: dict = Depends(_require_admin),
) -> ScopeRemoveResponse:
    hostname = canonicalize_hostname(target_url)
    removed = await remove_private_scope(hostname)
    if removed:
        sys_scan_id = await get_or_create_system_scan()
        await add_audit_log(
            scan_id=sys_scan_id,
            agent_name="AdminScope",
            action="private_scope_remove",
            details=f"Admin removed {hostname} from Private Scope",
            user_id=current_user["id"],
            target=hostname,
            authorization_status="ADMIN_OVERRIDE",
        )
        logger.info("Admin %s removed %s from Private Scope", current_user["id"], hostname)
        return ScopeRemoveResponse(success=True, message=f"Target removed from Private Scope.")
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "NOT_IN_SCOPE", "message": f"{hostname} is not in Private Scope."},
    )


@router.get("/role")
async def get_user_role(current_user: dict = Depends(get_current_user)) -> dict[str, str]:
    return {"role": current_user.get("role", "user")}
