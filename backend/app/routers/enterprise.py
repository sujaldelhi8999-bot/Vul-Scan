"""
Enterprise RBAC Router — employee management, approval workflow, audit logs.

Roles: admin > manager > employee. Legacy 'user' accounts keep full access.
Permission levels: view < propose < execute (enforced for enterprise roles).
"""

import base64
import json
import logging
import re
import secrets
import time
import uuid
from typing import Any

import bcrypt
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from app.auth_middleware import get_current_user
from app.database import (
    create_user,
    get_connection,
    get_enterprise_membership,
    get_finding,
    get_scan,
    get_user_by_email,
    get_user_by_id,
    update_finding,
)
from app.security import decrypt_data
from app.services.enterprise_access import (
    SEVERITY_LEVELS,
    can_approve_requests,
    can_manage_members,
    can_request_audit,
    can_request_fix,
    can_view_severity,
    enterprise_id_for,
)

router = APIRouter(prefix="/api/enterprise", tags=["Enterprise"])
logger = logging.getLogger("phantomscan.enterprise")

ROLES = ("employee", "manager")
PERMISSION_ORDER = {"view": 1, "propose": 2, "execute": 3}
REQUEST_TYPES = ("code_fix", "remediation")
CHANGE_TYPES = ("code_patch", "text_update", "manual")
URGENCIES = ("low", "normal", "high", "critical")


# ── Models ────────────────────────────────────────────────────────────────────

class EmployeeCreate(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    role: str = "employee"
    max_severity: str = "LOW"
    can_request_audit: bool = False
    can_request_fix: bool = False


class EmployeeUpdate(BaseModel):
    role: str | None = None
    max_severity: str | None = None
    can_request_audit: bool | None = None
    can_request_fix: bool | None = None
    can_approve: bool | None = None
    is_active: bool | None = None


class ApprovalRequestCreate(BaseModel):
    request_type: str
    target_url: str | None = Field(default=None, max_length=2048)
    details: dict[str, Any] = Field(default_factory=dict)
    urgency: str = "normal"


class ApprovalAction(BaseModel):
    action: str  # "approve" | "reject"
    comment: str | None = Field(default=None, max_length=2000)


class PasswordSet(BaseModel):
    new_password: str = Field(min_length=8, max_length=128)


class EnterpriseSettingsUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    allowed_email_domains: list[str] | None = Field(default=None, max_length=20)


# ── Dependencies / helpers ────────────────────────────────────────────────────

async def require_manager_or_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if not can_manage_members(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise owner access required")
    return current_user


async def require_approver(current_user: dict = Depends(get_current_user)) -> dict:
    if not can_approve_requests(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise approver access required")
    return current_user


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


async def add_enterprise_audit_log(
    user_id: str,
    action: str,
    resource: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
    enterprise_id: str | None = None,
) -> None:
    try:
        async with get_connection() as conn:
            if not enterprise_id:
                cursor = await conn.execute(
                    "SELECT enterprise_id FROM enterprise_memberships WHERE user_id = ? AND is_active = 1 LIMIT 1",
                    (user_id,),
                )
                membership = await cursor.fetchone()
                enterprise_id = membership["enterprise_id"] if membership else ""
            await conn.execute(
                """
                INSERT INTO enterprise_audit_logs (enterprise_id, user_id, action, resource, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    enterprise_id or "",
                    user_id,
                    action,
                    resource,
                    json.dumps(details, default=str) if details else None,
                    request.client.host if request and request.client else None,
                    request.headers.get("user-agent", "")[:500] if request else None,
                ),
            )
            await conn.commit()
    except Exception:
        logger.exception("Failed to write enterprise audit log")


def require_permission(permission: str):
    """Require a minimum permission level. Admins/managers always pass;
    legacy 'user' role is treated as execute for backward compatibility."""
    async def dependency(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") in ("admin", "manager", "user"):
            return current_user
        level = PERMISSION_ORDER.get(current_user.get("permission_level", "view"), 0)
        if level < PERMISSION_ORDER.get(permission, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required — submit an approval request instead",
            )
        return current_user
    return dependency


def _normalize_domains(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        domain = str(value or "").strip().lower().lstrip("@")
        if domain and domain not in normalized and "@" not in domain and "/" not in domain:
            normalized.append(domain)
    return normalized


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower().strip()


def _domain_allowed(email: str, domains: list[str]) -> bool:
    if not domains:
        return True
    domain = _email_domain(email)
    return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in domains)


async def _same_enterprise_member(conn, enterprise_id: str, user_id: str) -> dict[str, Any] | None:
    cursor = await conn.execute(
        """
        SELECT m.*, u.email, u.name, u.role AS user_role, u.is_active AS user_active
        FROM enterprise_memberships m
        JOIN users u ON u.id = m.user_id
        WHERE m.enterprise_id = ? AND m.user_id = ?
        LIMIT 1
        """,
        (enterprise_id, user_id),
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


def _validate_max_severity(value: str) -> str:
    normalized = str(value or "").strip().upper()
    if normalized not in SEVERITY_LEVELS:
        raise HTTPException(status_code=400, detail=f"max_severity must be one of {list(SEVERITY_LEVELS)}")
    return normalized


async def _notify_user(
    user_id: str,
    title: str,
    body: str = "",
    *,
    type_: str = "info",
    link: str | None = None,
) -> None:
    """Insert a per-user notification. Never raises (best-effort)."""
    try:
        async with get_connection() as conn:
            await conn.execute(
                "INSERT INTO enterprise_notifications (user_id, type, title, body, link) VALUES (?, ?, ?, ?, ?)",
                (user_id, type_, title, body, link),
            )
            await conn.commit()
    except Exception:
        logger.exception("Failed to create notification for %s", user_id)


async def _pick_approver(conn, enterprise_id: str, exclude_id: str) -> str | None:
    cursor = await conn.execute(
        """
        SELECT m.user_id FROM enterprise_memberships m
        JOIN users u ON u.id = m.user_id
        WHERE m.enterprise_id = ? AND m.is_active = 1
          AND u.is_active = 1 AND m.user_id != ?
        ORDER BY CASE m.role WHEN 'owner' THEN 0 ELSE 1 END, m.created_at ASC
        LIMIT 1
        """,
        (enterprise_id, exclude_id),
    )
    row = await cursor.fetchone()
    return str(row["user_id"]) if row else None


async def _execute_approved_action(request_row: dict, approver: dict) -> None:
    """Side effects for approved requests. github_push opens a remediation PR
    (handled in decide_request); other types record the decision — the
    requesting employee re-issues the now-permitted operation."""
    logger.info(
        "Approved %s request %s for employee %s (decided by %s)",
        request_row["request_type"], request_row["id"], request_row["employee_id"], approver["id"],
    )


async def _connected_oauth_token(user_id: str) -> str | None:
    """Return the user's encrypted GitHub OAuth token, if connected."""
    try:
        async with get_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT access_token_encrypted
                FROM github_oauth_tokens
                WHERE user_id = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = await cursor.fetchone()
        return decrypt_data(row["access_token_encrypted"]) if row else None
    except Exception:
        logger.debug("No usable GitHub OAuth token for user %s", user_id, exc_info=True)
        return None


def _github_repo_name(value: Any) -> str | None:
    raw = str(value or "").strip()
    if raw.startswith("https://github.com/"):
        raw = raw[len("https://github.com/"):]
    raw = raw.split("?", 1)[0].split("#", 1)[0].strip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", raw):
        return None
    return raw


GITHUB_API = "https://api.github.com"


def _github_response_error(response: httpx.Response, action: str) -> HTTPException:
    try:
        detail = response.json().get("message", response.text[:300])
    except (ValueError, AttributeError):
        detail = response.text[:300]
    return HTTPException(status_code=502, detail=f"GitHub {action} failed: {detail}")


def _build_remediation_markdown(request_id: int, req_row: dict, findings: list[dict[str, Any]]) -> str:
    lines = [
        f"# PhantomScan Remediation Report — Request #{request_id}",
        "",
        f"- **Target:** {req_row.get('target_url') or 'n/a'}",
        f"- **Requested by:** `{req_row.get('employee_id')}`",
        f"- **Approved by:** `{req_row.get('_approver')}`",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("_No structured findings were attached to this request._")
    for i, f in enumerate(findings[:50], 1):
        title = str(f.get("title") or f.get("message") or f"Finding {i}")
        sev = str(f.get("severity", "INFO")).upper()
        loc = " : ".join(str(x) for x in (f.get("file_path") or f.get("file"), f.get("line_number") or f.get("line")) if x)
        fix = f.get("fix_recommendation") or f.get("recommendation") or f.get("fix") or ""
        lines.append(f"### {i}. [{sev}] {title}")
        if loc:
            lines.append(f"- **Location:** `{loc}`")
        if f.get("cve_id"):
            lines.append(f"- **CVE:** {f['cve_id']}")
        if fix:
            lines.append(f"- **Fix:** {fix}")
        lines.append("")
    lines.append("---")
    lines.append("_Generated automatically by PhantomScan after manager approval._")
    return "\n".join(lines)


async def _push_remediation_pr(
    repo_full_name: str,
    report_md: str,
    request_id: int,
    token: str,
) -> dict[str, Any]:
    """Create a fixes branch on GitHub, commit the remediation report to it,
    and open a PR against the default branch. Uses the approver's OAuth token."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{GITHUB_API}/repos/{repo_full_name}", headers=headers)
        if r.status_code == 404:
            raise HTTPException(status_code=400, detail=f"Repository not accessible: {repo_full_name}")
        if r.status_code == 401:
            raise HTTPException(status_code=400, detail="GitHub token invalid or expired — reconnect your account")
        if not r.is_success:
            raise _github_response_error(r, "repository lookup")
        base_branch = r.json().get("default_branch", "main")

        r = await client.get(f"{GITHUB_API}/repos/{repo_full_name}/git/ref/heads/{base_branch}", headers=headers)
        if not r.is_success:
            raise _github_response_error(r, "base branch lookup")
        base_sha = r.json()["object"]["sha"]

        branch = f"phantomscan/fixes-{request_id}-{int(time.time())}"
        r = await client.post(
            f"{GITHUB_API}/repos/{repo_full_name}/git/refs",
            headers=headers,
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        if r.status_code not in (200, 201):
            raise _github_response_error(r, "branch creation")

        path = f"SECURITY_REMEDIATION_{request_id}.md"
        r = await client.put(
            f"{GITHUB_API}/repos/{repo_full_name}/contents/{path}",
            headers=headers,
            json={
                "message": f"PhantomScan: add remediation report (request #{request_id})",
                "content": base64.b64encode(report_md.encode()).decode(),
                "branch": branch,
            },
        )
        if r.status_code not in (200, 201):
            raise _github_response_error(r, "report commit")

        r = await client.post(
            f"{GITHUB_API}/repos/{repo_full_name}/pulls",
            headers=headers,
            json={
                "title": f"[PhantomScan] Security remediation (request #{request_id})",
                "head": branch,
                "base": base_branch,
                "body": report_md,
            },
        )
        if r.status_code not in (200, 201):
            raise _github_response_error(r, "PR creation")
        pr = r.json()

    return {"branch": branch, "pr_url": pr.get("html_url"), "pr_number": pr.get("number")}


# ── Employee management ───────────────────────────────────────────────────────

@router.get("/settings")
async def enterprise_settings(current_user: dict = Depends(require_manager_or_admin)) -> dict[str, Any]:
    enterprise_id = enterprise_id_for(current_user)
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT id, name, allowed_email_domains, is_active, created_at, updated_at FROM enterprises WHERE id = ?",
            (enterprise_id,),
        )
        row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enterprise not found")
    result = dict(row)
    try:
        result["allowed_email_domains"] = json.loads(result.get("allowed_email_domains") or "[]")
    except (TypeError, json.JSONDecodeError):
        result["allowed_email_domains"] = []
    return result


@router.put("/settings")
async def update_enterprise_settings(
    payload: EnterpriseSettingsUpdate,
    request: Request,
    current_user: dict = Depends(require_manager_or_admin),
) -> dict[str, Any]:
    enterprise_id = enterprise_id_for(current_user)
    updates: list[str] = []
    values: list[Any] = []
    if payload.name is not None:
        updates.append("name = ?")
        values.append(payload.name.strip())
    if payload.allowed_email_domains is not None:
        domains = _normalize_domains(payload.allowed_email_domains)
        updates.append("allowed_email_domains = ?")
        values.append(json.dumps(domains))
    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nothing to update")
    updates.append("updated_at = CURRENT_TIMESTAMP")
    values.append(enterprise_id)
    async with get_connection() as conn:
        await conn.execute(f"UPDATE enterprises SET {', '.join(updates)} WHERE id = ?", tuple(values))
        await conn.commit()
    await add_enterprise_audit_log(
        current_user["id"],
        "enterprise_settings_updated",
        resource=enterprise_id,
        details=payload.model_dump(exclude_none=True),
        request=request,
        enterprise_id=enterprise_id,
    )
    return await enterprise_settings(current_user)

@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_employee(
    payload: EmployeeCreate,
    request: Request,
    current_user: dict = Depends(require_manager_or_admin),
) -> dict[str, Any]:
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {list(ROLES)}")
    max_severity = _validate_max_severity(payload.max_severity)
    email = payload.email.lower()
    domains = [str(item).lower() for item in current_user.get("allowed_email_domains", [])]
    if not _domain_allowed(email, domains):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Employee email is outside the enterprise's allowed email domains",
        )
    if await get_user_by_email(email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user_id = uuid.uuid4().hex
    enterprise_id = enterprise_id_for(current_user)
    global_role = "user"
    try:
        await create_user(
            user_id=user_id,
            email=email,
            password_hash=_hash_password(payload.password),
            name=payload.name,
            role=global_role,
            subscription_tier="ENTERPRISE",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not create user: {exc}") from exc

    async with get_connection() as conn:
        try:
            await conn.execute(
                """
                INSERT INTO enterprise_memberships (
                    enterprise_id, user_id, role, max_severity, can_request_audit,
                    can_request_fix, can_approve, can_manage_members
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    enterprise_id,
                    user_id,
                    payload.role,
                    "ALL",
                    1,
                    1,
                    1,
                    0,
                ),
            )
            await conn.commit()
        except Exception as exc:
            await conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            await conn.commit()
            raise HTTPException(status_code=500, detail=f"Could not attach user to enterprise: {exc}") from exc

    await add_enterprise_audit_log(
        current_user["id"], "employee_created", resource=email,
        details={
            "new_user_id": user_id,
            "role": payload.role,
            "max_severity": "ALL",
            "can_request_audit": True,
            "can_request_fix": True,
        },
        request=request,
        enterprise_id=enterprise_id,
    )
    return {
        "id": user_id,
        "email": email,
        "name": payload.name,
        "role": payload.role,
        "max_severity": "ALL",
        "can_request_audit": True,
        "can_request_fix": True,
        "can_approve": True,
        "message": "Employee created with the permanent password supplied by the administrator.",
    }


@router.get("/users")
async def list_employees(current_user: dict = Depends(require_manager_or_admin)) -> list[dict[str, Any]]:
    enterprise_id = enterprise_id_for(current_user)
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT u.id, u.email, u.name, m.role, m.max_severity,
                   m.can_request_audit, m.can_request_fix, m.can_approve,
                   m.can_manage_members, m.is_active, u.created_at, u.last_login
            FROM enterprise_memberships m
            JOIN users u ON u.id = m.user_id
            WHERE m.enterprise_id = ? AND m.role != 'owner'
            ORDER BY u.created_at DESC
            """,
            (enterprise_id,),
        )
        rows = await cursor.fetchall()
    return [dict(r) for r in rows]


@router.put("/users/{user_id}")
async def update_employee(
    user_id: str,
    payload: EmployeeUpdate,
    request: Request,
    current_user: dict = Depends(require_manager_or_admin),
) -> dict[str, Any]:
    enterprise_id = enterprise_id_for(current_user)
    async with get_connection() as conn:
        membership = await _same_enterprise_member(conn, enterprise_id or "", user_id)
    if not membership:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if membership["role"] == "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify the enterprise owner")
    if payload.role is not None and payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {list(ROLES)}")
    if payload.max_severity is not None:
        payload.max_severity = _validate_max_severity(payload.max_severity)
    if user_id == current_user["id"] and payload.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    membership_sets, membership_params = [], []
    if any(value is not None for value in (payload.max_severity, payload.can_request_audit, payload.can_request_fix, payload.can_approve)):
        membership_sets.extend(["max_severity = ?", "can_request_audit = ?", "can_request_fix = ?", "can_approve = ?"])
        membership_params.extend(["ALL", 1, 1, 1])
    if payload.role == "manager":
        membership_sets.extend(["can_approve = ?", "can_manage_members = ?", "max_severity = ?"])
        membership_params.extend([1, 0, "ALL"])
    elif payload.role == "employee":
        membership_sets.append("can_manage_members = ?")
        membership_params.append(0)
    if payload.is_active is not None:
        membership_sets.append("is_active = ?"); membership_params.append(1 if payload.is_active else 0)
    if not membership_sets and payload.role is None:
        raise HTTPException(status_code=400, detail="Nothing to update")

    async with get_connection() as conn:
        if membership_sets:
            membership_sets.append("updated_at = CURRENT_TIMESTAMP")
            await conn.execute(
                f"UPDATE enterprise_memberships SET {', '.join(membership_sets)} WHERE enterprise_id = ? AND user_id = ?",
                tuple(membership_params + [enterprise_id, user_id]),
            )
        if payload.role is not None:
            await conn.execute(
                "UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                ("user", user_id),
            )
        if payload.is_active is not None:
            await conn.execute(
                "UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (1 if payload.is_active else 0, user_id),
            )
        await conn.commit()

    await add_enterprise_audit_log(
        current_user["id"], "employee_updated", resource=membership["email"], details=payload.model_dump(exclude_none=True),
        request=request,
        enterprise_id=enterprise_id,
    )
    return {"id": user_id, "updated": payload.model_dump(exclude_none=True)}


@router.delete("/users/{user_id}")
async def deactivate_employee(
    user_id: str,
    request: Request,
    current_user: dict = Depends(require_manager_or_admin),
) -> dict[str, Any]:
    enterprise_id = enterprise_id_for(current_user)
    async with get_connection() as conn:
        membership = await _same_enterprise_member(conn, enterprise_id or "", user_id)
    if not membership:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if membership["role"] == "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot deactivate the enterprise owner")
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    async with get_connection() as conn:
        await conn.execute(
            "UPDATE enterprise_memberships SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE enterprise_id = ? AND user_id = ?",
            (enterprise_id, user_id),
        )
        await conn.execute("UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        await conn.commit()

    await add_enterprise_audit_log(
        current_user["id"], "employee_deactivated", resource=membership["email"], request=request,
        enterprise_id=enterprise_id,
    )
    return {"id": user_id, "is_active": False}


# ── Password management ───────────────────────────────────────────────────────

async def _set_employee_password(enterprise_id: str, user_id: str, new_password: str) -> dict[str, Any]:
    """Hash with bcrypt (same scheme as auth) and persist. Returns the target row."""
    async with get_connection() as conn:
        membership = await _same_enterprise_member(conn, enterprise_id, user_id)
    if not membership:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if membership.get("role") == "owner":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The enterprise owner password cannot be reset from this panel")
    async with get_connection() as conn:
        await conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (_hash_password(new_password), user_id),
        )
        await conn.commit()
    return membership


@router.post("/users/{user_id}/reset-password")
async def reset_employee_password(
    user_id: str,
    request: Request,
    current_user: dict = Depends(require_manager_or_admin),
) -> dict[str, Any]:
    """Generate a strong random password for the employee. The plaintext is
    returned exactly once (hashes are irreversible, so it cannot be viewed later)."""
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Use your profile's change-password flow for your own account")

    new_password = secrets.token_urlsafe(12)
    target = await _set_employee_password(enterprise_id_for(current_user) or "", user_id, new_password)

    await add_enterprise_audit_log(
        current_user["id"], "employee_password_reset", resource=target["email"], request=request,
        enterprise_id=enterprise_id_for(current_user),
    )
    return {
        "new_password": new_password,
        "email": target["email"],
        "message": f"Password reset for {target['email']} — shown once, copy it now.",
    }


@router.post("/users/{user_id}/set-password")
async def set_employee_password(
    user_id: str,
    payload: PasswordSet,
    request: Request,
    current_user: dict = Depends(require_manager_or_admin),
) -> dict[str, Any]:
    """Set a specific password chosen by the admin."""
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Use your profile's change-password flow for your own account")

    target = await _set_employee_password(enterprise_id_for(current_user) or "", user_id, payload.new_password)

    await add_enterprise_audit_log(
        current_user["id"], "employee_password_set", resource=target["email"], request=request,
        enterprise_id=enterprise_id_for(current_user),
    )
    return {"email": target["email"], "message": f"Password updated for {target['email']}"}


# ── Approval workflow ─────────────────────────────────────────────────────────

@router.post("/request", status_code=status.HTTP_201_CREATED)
async def submit_request(
    payload: ApprovalRequestCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    enterprise_id = enterprise_id_for(current_user)
    if not enterprise_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise membership required")
    if payload.request_type not in REQUEST_TYPES:
        raise HTTPException(status_code=400, detail=f"request_type must be one of {list(REQUEST_TYPES)}")
    if payload.urgency not in URGENCIES:
        raise HTTPException(status_code=400, detail=f"urgency must be one of {list(URGENCIES)}")

    if not can_request_fix(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your authority does not include code-fix requests")

    details = dict(payload.details)
    finding_id = details.get("finding_id")
    if finding_id is None:
        raise HTTPException(status_code=400, detail="A finding_id is required for remediation requests")
    try:
        finding_id = int(finding_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="finding_id must be an integer") from exc
    finding = await get_finding(finding_id)
    scan = await get_scan(int(finding["scan_id"])) if finding else None
    if not finding or not scan or str(scan.get("enterprise_id")) != enterprise_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    change_type = str(details.get("change_type") or "manual")
    if change_type not in CHANGE_TYPES:
        raise HTTPException(status_code=400, detail=f"change_type must be one of {list(CHANGE_TYPES)}")
    proposed_change = str(details.get("proposed_change") or details.get("note") or "").strip()
    if not proposed_change:
        raise HTTPException(status_code=400, detail="A proposed_change is required")
    if change_type == "code_patch" and (not details.get("patch") or not details.get("file_path")):
        raise HTTPException(status_code=400, detail="Code patches require patch and file_path")
    details.update(
        {
            "finding_id": finding_id,
            "scan_id": int(finding["scan_id"]),
            "change_type": change_type,
            "proposed_change": proposed_change,
            "current_text": finding.get("code_snippet") or finding.get("recommendation") or "",
            "file_path": details.get("file_path") or finding.get("file_path"),
            "line_number": finding.get("line_number"),
            "severity": finding.get("severity"),
            "finding_title": finding.get("title"),
        }
    )

    async with get_connection() as conn:
        manager_id = await _pick_approver(conn, enterprise_id, current_user["id"])
        if not manager_id:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No active enterprise approver available")
        cursor = await conn.execute(
            """
            INSERT INTO enterprise_approval_requests (enterprise_id, employee_id, manager_id, request_type, target_url, details, urgency)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                enterprise_id, current_user["id"], manager_id, payload.request_type,
                payload.target_url, json.dumps(details, default=str), payload.urgency,
            ),
        )
        new_id = cursor.lastrowid
        await conn.commit()

    await add_enterprise_audit_log(
        current_user["id"], f"approval_requested_{payload.request_type}",
        resource=payload.target_url, details={"request_id": new_id, "urgency": payload.urgency},
        request=request,
        enterprise_id=enterprise_id,
    )
    await _notify_user(
        manager_id,
        f"New approval request: {payload.request_type.replace('_', ' ')}",
        f"{current_user.get('name') or current_user.get('email')} requested "
        f"{payload.request_type.replace('_', ' ')}{f' for {payload.target_url}' if payload.target_url else ''} "
        f"(urgency: {payload.urgency}).",
        type_="warning" if payload.urgency in ("high", "critical") else "info",
        link="/enterprise",
    )
    return {"id": new_id, "status": "pending", "manager_id": manager_id, "enterprise_id": enterprise_id}


@router.get("/requests")
async def my_requests(current_user: dict = Depends(get_current_user)) -> list[dict[str, Any]]:
    enterprise_id = enterprise_id_for(current_user)
    if not enterprise_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise membership required")
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT id, request_type, target_url, details, status, urgency, comment, decided_by,
                   decided_at, started_at, completed_at, execution_result, created_at
            FROM enterprise_approval_requests WHERE enterprise_id = ? AND employee_id = ?
            ORDER BY created_at DESC LIMIT 100
            """,
            (enterprise_id, current_user["id"]),
        )
        rows = await cursor.fetchall()
    result = []
    for r in rows:
        item = dict(r)
        try:
            item["details"] = json.loads(item.get("details") or "{}")
        except (json.JSONDecodeError, TypeError):
            item["details"] = {}
        result.append(item)
    return result


@router.get("/approvals")
async def pending_approvals(current_user: dict = Depends(require_approver)) -> list[dict[str, Any]]:
    enterprise_id = enterprise_id_for(current_user)
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT r.id, r.employee_id, r.request_type, r.target_url, r.details, r.urgency,
                   r.status, r.created_at, u.email AS employee_email, u.name AS employee_name
            FROM enterprise_approval_requests r
            JOIN users u ON r.employee_id = u.id
            WHERE r.enterprise_id = ? AND r.status = 'pending' AND r.employee_id != ?
            ORDER BY CASE r.urgency WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END,
                     r.created_at ASC
            LIMIT 200
            """,
            (enterprise_id, current_user["id"]),
        )
        rows = await cursor.fetchall()
    result = []
    for r in rows:
        item = dict(r)
        try:
            item["details"] = json.loads(item.get("details") or "{}")
        except (json.JSONDecodeError, TypeError):
            item["details"] = {}
        result.append(item)
    return result


@router.put("/approvals/{request_id}")
async def decide_request(
    request_id: int,
    payload: ApprovalAction,
    request: Request,
    current_user: dict = Depends(require_approver),
) -> dict[str, Any]:
    if payload.action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")

    enterprise_id = enterprise_id_for(current_user)
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM enterprise_approval_requests WHERE id = ? AND enterprise_id = ?",
            (request_id, enterprise_id),
        )
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
        req_row = dict(row)
        if req_row["employee_id"] == current_user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Approvers cannot decide their own requests")
        if req_row["status"] != "pending":
            raise HTTPException(status_code=400, detail=f"Request already {req_row['status']}")

    # Approval only grants the request. The employee explicitly starts the
    # approved operation afterwards.
    pr_info: dict[str, Any] | None = None
    updated_details: str | None = None

    from datetime import datetime, timezone
    decided_at = datetime.now(timezone.utc).isoformat()
    async with get_connection() as conn:
        if payload.action == "approve":
            update_cursor = await conn.execute(
                """
                UPDATE enterprise_approval_requests
                SET status = 'approved', decided_by = ?, decided_at = ?, comment = ?,
                    manager_id = COALESCE(manager_id, ?), details = COALESCE(?, details)
                WHERE id = ? AND status = 'pending'
                """,
                (
                    current_user["id"], decided_at, payload.comment, current_user["id"],
                    updated_details, request_id,
                ),
            )
        else:
            update_cursor = await conn.execute(
                """
                UPDATE enterprise_approval_requests
                SET status = 'rejected', decided_by = ?, decided_at = ?, comment = ?
                WHERE id = ? AND status = 'pending'
                """,
                (current_user["id"], decided_at, payload.comment, request_id),
            )
        if update_cursor.rowcount == 0:
            raise HTTPException(status_code=409, detail="Request was already decided")
        await conn.commit()

    final_status = "approved" if payload.action == "approve" else "rejected"
    if payload.action == "approve":
        try:
            request_details = json.loads(req_row.get("details") or "{}")
        except (TypeError, json.JSONDecodeError):
            request_details = {}
        if request_details.get("change_type") in {"text_update", "manual"} and request_details.get("finding_id"):
            await update_finding(
                int(request_details["finding_id"]),
                recommended_fix=str(request_details.get("proposed_change") or ""),
                remediation_status="IN_PROGRESS",
            )
            async with get_connection() as conn:
                await conn.execute(
                    """
                    UPDATE enterprise_approval_requests
                    SET status = 'completed', completed_at = CURRENT_TIMESTAMP, execution_result = ?
                    WHERE id = ? AND enterprise_id = ?
                    """,
                    (json.dumps({"finding_id": request_details.get("finding_id"), "action": "finding_remediation_updated"}), request_id, enterprise_id),
                )
                await conn.commit()
            final_status = "completed"
        await _execute_approved_action(req_row, current_user)
        if pr_info:
            await _notify_user(
                req_row["employee_id"],
                "GitHub remediation PR opened",
                f"Your approved remediation request opened PR #{pr_info.get('pr_number')}.",
                type_="success",
                link=pr_info.get("pr_url") or "/enterprise",
            )
        else:
            await _notify_user(
                req_row["employee_id"],
                "Approval request approved",
                f"Your {req_row['request_type'].replace('_', ' ')} request was approved."
                + (f" Comment: {payload.comment}" if payload.comment else ""),
                type_="success",
                link="/enterprise",
            )
    else:
        await _notify_user(
            req_row["employee_id"],
            "Approval request rejected",
            f"Your {req_row['request_type'].replace('_', ' ')} request was rejected."
            + (f" Comment: {payload.comment}" if payload.comment else ""),
            type_="warning",
            link="/enterprise",
        )

    await add_enterprise_audit_log(
        current_user["id"], f"approval_{payload.action}d_{req_row['request_type']}",
        resource=req_row.get("target_url"),
        details={
            "request_id": request_id,
            "employee_id": req_row["employee_id"],
            **({"pr_url": pr_info["pr_url"], "pr_number": pr_info["pr_number"]} if pr_info else {}),
        },
        request=request,
        enterprise_id=enterprise_id,
    )
    return {
        "id": request_id,
        "status": final_status,
        **({"pr": pr_info} if pr_info else {}),
    }


@router.post("/requests/{request_id}/start")
async def start_approved_request(
    request_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Prepare an approval for the requesting employee's operation.

    The operation endpoint consumes the approval atomically when work actually
    begins, preventing a prepared request from being reused.
    """
    enterprise_id = enterprise_id_for(current_user)
    if not enterprise_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise membership required")
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT * FROM enterprise_approval_requests
            WHERE id = ? AND enterprise_id = ? AND employee_id = ?
            """,
            (request_id, enterprise_id, current_user["id"]),
        )
        row = await cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found")
        request_row = dict(row)
        if request_row["status"] != "approved":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Request is {request_row['status']}")

    try:
        details = json.loads(request_row.get("details") or "{}")
    except (TypeError, json.JSONDecodeError):
        details = {}
    if not isinstance(details, dict):
        details = {}
    return {
        "id": request_id,
        "status": "approved",
        "request_type": request_row["request_type"],
        "target_url": request_row.get("target_url"),
        "details": details,
        "message": "Approval ready. Start the requested operation from its workspace.",
    }


@router.get("/notifications")
async def list_notifications(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    limit = max(1, min(limit, 100))
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT id, type, title, body, link, read, created_at
            FROM enterprise_notifications
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (current_user["id"], limit),
        )
        rows = await cursor.fetchall()
        cursor = await conn.execute(
            "SELECT COUNT(*) AS count FROM enterprise_notifications WHERE user_id = ? AND read = 0",
            (current_user["id"],),
        )
        unread = await cursor.fetchone()
    return {"items": [dict(row) for row in rows], "unread_count": unread["count"] if unread else 0}


@router.post("/notifications/read-all")
async def mark_all_notifications_read(current_user: dict = Depends(get_current_user)) -> dict[str, int]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            "UPDATE enterprise_notifications SET read = 1 WHERE user_id = ? AND read = 0",
            (current_user["id"],),
        )
        await conn.commit()
    return {"updated": cursor.rowcount if cursor.rowcount >= 0 else 0}


@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    current_user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            UPDATE enterprise_notifications
            SET read = 1
            WHERE id = ? AND user_id = ?
            """,
            (notification_id, current_user["id"]),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found")
        await conn.commit()
    return {"id": notification_id, "read": True}


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit-logs")
async def audit_logs(
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    enterprise_id = enterprise_id_for(current_user)
    if not enterprise_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise membership required")
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT a.id, a.user_id, a.action, a.resource, a.details, a.ip_address, a.timestamp,
                   u.email AS user_email, u.name AS user_name
             FROM enterprise_audit_logs a LEFT JOIN users u ON a.user_id = u.id
             WHERE a.enterprise_id = ?
             ORDER BY a.timestamp DESC LIMIT ?
            """,
            (enterprise_id, limit),
        )
        rows = await cursor.fetchall()
    return [dict(r) for r in rows]
