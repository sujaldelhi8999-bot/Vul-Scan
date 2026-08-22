"""Tenant-aware access helpers for enterprise accounts.

Enterprise membership is the authorization boundary.  Email domains are only
an optional provisioning policy and are never used to grant access.
"""

import json
from typing import Any

from fastapi import HTTPException, status

from app.database import get_connection, get_scan


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "ALL")


def normalize_severity(value: str | None) -> str:
    normalized = str(value or "").strip().upper()
    return normalized if normalized in SEVERITY_ORDER else "INFO"


def severity_allowed(severity: str | None, maximum: str | None) -> bool:
    ceiling = str(maximum or "LOW").strip().upper()
    if ceiling == "ALL":
        return True
    return SEVERITY_ORDER.get(normalize_severity(severity), 0) <= SEVERITY_ORDER.get(ceiling, 1)


def enterprise_id_for(user: dict[str, Any]) -> str | None:
    value = user.get("enterprise_id")
    return str(value) if value else None


def is_enterprise_member(user: dict[str, Any]) -> bool:
    return enterprise_id_for(user) is not None and bool(user.get("enterprise_membership_active", True))


def enterprise_role(user: dict[str, Any]) -> str | None:
    role = user.get("enterprise_role")
    return str(role) if role else None


def can_manage_members(user: dict[str, Any]) -> bool:
    return is_enterprise_member(user) and enterprise_role(user) == "owner"


def can_approve_requests(user: dict[str, Any]) -> bool:
    return is_enterprise_member(user)


def can_request_audit(user: dict[str, Any]) -> bool:
    return is_enterprise_member(user)


def can_request_fix(user: dict[str, Any]) -> bool:
    return is_enterprise_member(user)


def can_view_severity(user: dict[str, Any], severity: str | None) -> bool:
    return True


def filter_findings_for_user(rows: list[dict[str, Any]], user: dict[str, Any]) -> list[dict[str, Any]]:
    if not is_enterprise_member(user):
        return rows
    return [row for row in rows if can_view_severity(user, row.get("severity"))]


def is_platform_admin(user: dict[str, Any]) -> bool:
    """Legacy platform admins remain able to operate platform-wide.

    An enterprise owner can still have the legacy ``admin`` user role, but the
    presence of an enterprise membership keeps that account tenant-scoped for
    enterprise resources.
    """

    return user.get("role") == "admin" and not is_enterprise_member(user)


def has_product_admin_access(user: dict[str, Any]) -> bool:
    """Grant product features to platform admins and active Enterprise members."""

    return user.get("role") == "admin" or is_enterprise_member(user)


async def require_scan_access(scan_id: int, user: dict[str, Any]) -> dict[str, Any]:
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    scan_enterprise_id = scan.get("enterprise_id")
    if scan_enterprise_id:
        if enterprise_id_for(user) != str(scan_enterprise_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return scan

    if scan.get("user_id") != user.get("id") and not is_platform_admin(user):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def require_direct_operation(user: dict[str, Any], detail: str) -> None:
    """Enterprise members can operate directly; approvals protect changes only."""

    return


async def consume_approved_request(
    request_id: int,
    user: dict[str, Any],
    expected_types: set[str],
    *,
    finding_id: int | None = None,
    patch: str | None = None,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Validate and consume an approval grant for a concrete operation."""
    enterprise_id = enterprise_id_for(user)
    if not enterprise_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise membership required")
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT * FROM enterprise_approval_requests
            WHERE id = ? AND enterprise_id = ? AND employee_id = ?
              AND status = 'approved'
            """,
            (request_id, enterprise_id, user.get("id")),
        )
        row = await cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="A matching approved enterprise request is required")
        result = dict(row)
        if result.get("request_type") not in expected_types:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Approval does not authorize this operation")
        try:
            details = json.loads(result.get("details") or "{}")
        except (TypeError, json.JSONDecodeError):
            details = {}
        if finding_id is not None and str(details.get("finding_id")) != str(finding_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Approval is for a different finding")
        if patch is not None and details.get("patch") != patch:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Patch differs from the approved change")
        if file_path is not None and details.get("file_path") != file_path:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="File path differs from the approved change")
        cursor = await connection.execute(
            "UPDATE enterprise_approval_requests SET status = 'started', started_at = CURRENT_TIMESTAMP WHERE id = ? AND enterprise_id = ? AND employee_id = ? AND status = 'approved'",
            (request_id, enterprise_id, user.get("id")),
        )
        if cursor.rowcount != 1:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Approval was already used")
        await connection.commit()
        result["details"] = details
        return result
