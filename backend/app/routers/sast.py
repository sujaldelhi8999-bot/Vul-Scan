"""
SAST (GitHub Code Scan) Router
"""

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth_middleware import get_current_user
from app.agents.orchestrator import OrchestratorAgent
from app.config import get_settings
from app.database import add_audit_log, get_connection, get_findings, update_scan_status
from app.models import GitHubConfig, MultiSourceScanRequest
from app.routers.multi_source import build_response
from app.security import decrypt_data
from app.services.jobs import ScanCapacityError, scan_job_manager
from app.services.enterprise_access import enterprise_id_for, filter_findings_for_user, require_scan_access

router = APIRouter(prefix="/api/sast", tags=["SAST"])
settings = get_settings()
logger = logging.getLogger("phantomscan.sast")

DEFAULT_SAST_EXCLUDE_PATTERNS = [
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


async def _connected_oauth_token(user_id: str) -> str | None:
    """Return the user's stored GitHub OAuth token (GitHub App integration), if any.

    Attaching a valid token lets the clone reach private repos from the
    connected account; public repos clone fine authenticated or anonymously.
    Returns None when the account is not connected.
    """
    try:
        async with get_connection() as conn:
            cursor = await conn.execute(
                "SELECT access_token_encrypted FROM github_oauth_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1",
                (user_id,),
            )
            row = await cursor.fetchone()
        if not row:
            return None
        return decrypt_data(row["access_token_encrypted"])
    except Exception:
        logger.debug("No usable GitHub OAuth token for user %s", user_id, exc_info=True)
        return None


@router.post("/scan-repo", status_code=status.HTTP_202_ACCEPTED)
async def scan_repo(
    repo_url: str = Query(min_length=8, max_length=2048),
    branch: str = Query(default="main", max_length=100),
    exclude_patterns: str = Query(default="", description="Comma-separated glob patterns to exclude"),
    scan_timeout: int = Query(default=0, ge=0, le=3600, description="Custom timeout in seconds (0 = use default)"),
    approval_request_id: int | None = Query(default=None, ge=1),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Clone a public GitHub repository and scan it for secrets, insecure
    patterns, vulnerable dependencies, and IaC misconfigurations."""
    repo_url = repo_url.strip()
    if not repo_url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only public GitHub repository URLs are supported (https://github.com/owner/repo).",
        )

    try:
        reservation = await scan_job_manager.reserve_slot()
    except ScanCapacityError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    user_excludes = [p.strip() for p in exclude_patterns.split(",") if p.strip()] if exclude_patterns else []
    excludes = list(dict.fromkeys([*DEFAULT_SAST_EXCLUDE_PATTERNS, *user_excludes]))

    scan_id: int | None = None
    try:
        # Use the connected GitHub account's token (if linked) so private
        # repos from the integration are reachable; public repos are unaffected.
        pat_token = await _connected_oauth_token(user["id"])
        request = MultiSourceScanRequest(
            name=f"GitHub code scan: {repo_url}",
            mode="multi_agent",
            intensity="medium",
            sources=[GitHubConfig(
                repo_url=repo_url,
                branch=branch,
                pat_token=pat_token,
                include_dependabot=True,
                exclude_patterns=excludes,
                scan_timeout=scan_timeout if scan_timeout > 0 else None,
            )],
            correlate_findings=True,
            data_flow_tracing=False,
            generate_sarif=False,
            generate_pdf=False,
        )
        scan_id = await _create_sast_scan(repo_url, branch, user["id"], enterprise_id_for(user))
        await add_audit_log(
            scan_id,
            "System",
            "sast_scan_created",
            f"Created GitHub code scan for {repo_url} (branch: {branch})",
            user_id=user["id"],
            target=repo_url,
        )
        await _submit(request, scan_id, user["id"], user.get("role", "user"))
    except Exception as exc:
        logger.exception("Failed to start SAST scan")
        if scan_id is not None:
            await update_scan_status(scan_id, "error", str(exc)[:1000])
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    finally:
        await asyncio.shield(scan_job_manager.release_slot(reservation))

    return {"scan_id": scan_id, "status": "queued", "repo_url": repo_url, "branch": branch, "exclude_patterns": excludes}


async def _create_sast_scan(repo_url: str, branch: str, user_id: str, enterprise_id: str | None = None) -> int:
    from app.database import create_scan
    return await create_scan(
        target_url=repo_url,
        mode="multi_agent",
        intensity="medium",
        selected_tests=json.dumps(["github"], separators=(",", ":")),
        user_id=user_id,
        enterprise_id=enterprise_id,
        authorization_id=None,
        authorization_confirmed=False,
    )


async def _submit(request: MultiSourceScanRequest, scan_id: int, user_id: str, user_role: str = "user") -> None:
    loop = asyncio.get_running_loop()
    task = loop.create_task(
        OrchestratorAgent(limits=scan_job_manager.limits).run_multi_source(
            request,
            scan_id,
            user_id=user_id,
            user_role=user_role,
            authorization_context={},
        ),
        name=f"phantomscan-sast-{scan_id}",
    )
    await scan_job_manager.register_task(scan_id, task)


@router.get("/{scan_id}")
async def sast_scan_status(
    scan_id: int,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    scan = await require_scan_access(scan_id, user)

    base = (await build_response(scan_id, user)).model_dump(mode="json")
    findings = filter_findings_for_user(await get_findings(scan_id), user)
    base["findings"] = findings
    base["repo_url"] = scan.get("target_url")
    return base
