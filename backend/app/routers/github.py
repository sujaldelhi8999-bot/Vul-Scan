"""
GitHub OAuth and Webhook Router
"""

import json
import logging
import secrets
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, HttpUrl
import httpx

from app.auth_middleware import get_current_user
from app.config import get_settings
from app.database import get_connection
from app.models import (
    GitHubOAuthRequest,
    GitHubOAuthCallback,
    GitHubWebhookPayload,
    GitHubRepoResponse,
    GitHubInstallationResponse,
)
from app.security import encrypt_data, decrypt_data
from app.services.github_service import get_github_service

router = APIRouter(prefix="/api/github", tags=["github"])
settings = get_settings()
github_service = get_github_service()
logger = logging.getLogger("phantomscan.github")


class GitHubConnectRequest(BaseModel):
    redirect_url: HttpUrl | None = None
    scope: str = "repo read:org read:user user:email"


class GitHubConnectResponse(BaseModel):
    authorize_url: str
    state: str


def resolve_oauth_redirect_uri(request: Request) -> str:
    """Resolve the OAuth redirect URI: env override, else derived from this request."""
    if settings.github_redirect_uri:
        return settings.github_redirect_uri
    return str(request.base_url).rstrip("/") + "/api/github/callback"


class GitHubRepoListResponse(BaseModel):
    connected: bool = True
    repos: list[GitHubRepoResponse]
    total: int


class GitHubInstallationListResponse(BaseModel):
    installations: list[GitHubInstallationResponse]
    total: int


@router.post("/connect", response_model=GitHubConnectResponse)
async def github_connect(
    request: Request,
    oauth: GitHubConnectRequest | None = None,
    user: dict = Depends(get_current_user),
) -> GitHubConnectResponse:
    """Initiate GitHub OAuth flow."""
    state = secrets.token_urlsafe(32)
    await github_service.store_oauth_state(user["id"], state)
    oauth_request = GitHubOAuthRequest(
        redirect_url=HttpUrl(resolve_oauth_redirect_uri(request)),
        scope=oauth.scope if oauth else "repo read:org read:user user:email",
        state=state,
    )
    authorize_url = github_service.get_oauth_authorize_url(oauth_request)
    return GitHubConnectResponse(authorize_url=authorize_url, state=state)


@router.get("/callback")
async def github_callback(
    request: Request,
    code: str | None = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
) -> RedirectResponse:
    """Handle GitHub OAuth callback."""
    frontend_url = settings.frontend_url or "http://localhost:5173"

    if error or not code:
        error_msg = error or "missing_code"
        return RedirectResponse(
            url=f"{frontend_url}/github/callback?error={error_msg}",
            status_code=status.HTTP_302_FOUND,
        )

    # Consume the state row written by /connect to learn which user initiated the flow.
    user_id = await github_service.consume_oauth_state(state) if state else None
    if not user_id:
        return RedirectResponse(
            url=f"{frontend_url}/github/callback?error=invalid_state",
            status_code=status.HTTP_302_FOUND,
        )

    # Exchange code for token
    callback = GitHubOAuthCallback(code=code, state=state, redirect_uri=resolve_oauth_redirect_uri(request))
    try:
        token_response = await github_service.exchange_code_for_token(callback)
        user_info = await github_service.get_user_info(token_response.access_token)
        await github_service.store_oauth_token(user_id, user_info.id, user_info.login, token_response)
    except Exception as e:
        logger.error(f"GitHub OAuth callback failed: {e}")
        return RedirectResponse(
            url=f"{frontend_url}/github/callback?error=exchange_failed",
            status_code=status.HTTP_302_FOUND,
        )

    return RedirectResponse(
        url=f"{frontend_url}/github/callback?success=true&login={user_info.login}",
        status_code=status.HTTP_302_FOUND,
    )


@router.get("/repos", response_model=GitHubRepoListResponse)
async def list_repos(
    user: dict = Depends(get_current_user),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=100),
) -> GitHubRepoListResponse:
    """List user's GitHub repositories."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT access_token_encrypted, github_login FROM github_oauth_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1",
            (user["id"],),
        )
        row = await cursor.fetchone()
        if not row:
            return GitHubRepoListResponse(connected=False, repos=[], total=0)

    access_token = decrypt_data(row["access_token_encrypted"])
    try:
        repos = await github_service.get_user_repos(access_token, per_page=per_page * 2)  # Get extra for pagination
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            # Token is invalid/expired - remove it and return disconnected
            async with get_connection() as conn:
                await conn.execute(
                    "DELETE FROM github_oauth_tokens WHERE user_id = ?",
                    (user["id"],),
                )
                await conn.commit()
            return GitHubRepoListResponse(connected=False, repos=[], total=0)
        raise

    start = (page - 1) * per_page
    end = start + per_page
    paginated = repos[start:end]

    return GitHubRepoListResponse(connected=True, repos=paginated, total=len(repos))


@router.get("/installations", response_model=GitHubInstallationListResponse)
async def list_installations(
    user: dict = Depends(get_current_user),
) -> GitHubInstallationListResponse:
    """List user's GitHub App installations."""
    installations = await github_service.get_app_installations(user["id"])
    return GitHubInstallationListResponse(installations=installations, total=len(installations))


@router.post("/webhook")
async def github_webhook(request: Request) -> dict[str, str]:
    """Handle GitHub webhooks (PR events, etc.)."""
    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not github_service.verify_webhook_signature(payload, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    try:
        payload_data = json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )

    # Parse webhook
    webhook = github_service.parse_webhook(payload_data)

    # Handle PR events
    if webhook.action in ("opened", "synchronize", "reopened"):
        pr = webhook.pull_request
        repo = webhook.repository
        installation = webhook.installation

        if not installation:
            logger.warning("No installation info in webhook, skipping auto-scan")
            return {"status": "ignored", "reason": "no_installation"}

        # Get installation token
        try:
            installation_id = installation["id"]
            access_token = await github_service.get_installation_token(installation_id)
        except Exception as e:
            logger.error(f"Failed to get installation token: {e}")
            return {"status": "error", "reason": "token_failed"}

        # Get PR diff for scanning
        try:
            pr_data = await github_service.get_pr_diff(
                access_token,
                repo["owner"]["login"],
                repo["name"],
                pr["number"],
            )
        except Exception as e:
            logger.error(f"Failed to get PR diff: {e}")
            return {"status": "error", "reason": "diff_failed"}

        # Trigger multi-source scan with the PR diff
        try:
            from app.agents.orchestrator import OrchestratorAgent
            from app.models import GitHubConfig, MultiSourceScanRequest
            from app.services.jobs import scan_job_manager
            from app.database import create_scan, update_scan_status, add_audit_log
            import asyncio as _asyncio

            repo_full_name = repo["full_name"]
            repo_url = f"https://github.com/{repo_full_name}"
            pr_number = pr["number"]
            base_branch = pr["base"]["ref"]
            head_branch = pr["head"]["ref"]

            source = GitHubConfig(
                repo_url=repo_url,
                branch=head_branch,
                base_branch=base_branch,
                pr_number=pr_number,
                scan_mode="diff",
                auth_type="github_app",
                github_app_installation_id=str(installation_id),
            )
            scan_request = MultiSourceScanRequest(
                name=f"PR #{pr_number} security scan: {repo_full_name}",
                mode="multi_agent",
                intensity="medium",
                sources=[source],
                correlate_findings=True,
                data_flow_tracing=True,
                generate_sarif=True,
            )

            scan_id = await create_scan(
                target_url=repo_url,
                mode="multi_agent",
                intensity="medium",
                selected_tests=json.dumps(["github"]),
                user_id="webhook-user",  # Webhook doesn't have user context
                authorization_id=None,
                authorization_confirmed=False,
            )
            await add_audit_log(
                scan_id,
                "System",
                "pr_webhook_scan_started",
                f"Auto-scan started for PR #{pr_number} in {repo_full_name}",
                user_id="webhook-user",
                target=repo_url,
            )
            task = _asyncio.get_running_loop().create_task(
                OrchestratorAgent(limits=scan_job_manager.limits).run_multi_source(
                    scan_request,
                    scan_id,
                    user_id="webhook-user",
                    user_role="user",
                    authorization_context={},
                ),
                name=f"phantomscan-pr-{repo_full_name}-{pr_number}",
            )
            await scan_job_manager.register_task(scan_id, task)
            logger.info(
                f"PR #{pr_number} in {repo_full_name} - {len(pr_data.get('files', []))} files changed, scan #{scan_id} started"
            )
            return {"status": "ok", "scan_id": scan_id}
        except Exception as e:
            logger.error(f"Failed to trigger PR scan: {e}")
            return {"status": "error", "reason": "scan_trigger_failed"}

    return {"status": "ok"}


@router.delete("/disconnect")
async def disconnect_github(user: dict = Depends(get_current_user)) -> dict[str, str]:
    """Disconnect GitHub account."""
    async with get_connection() as conn:
        await conn.execute(
            "DELETE FROM github_oauth_tokens WHERE user_id = ?",
            (user["id"],),
        )
        await conn.execute(
            "DELETE FROM github_app_installations WHERE user_id = ?",
            (user["id"],),
        )
        await conn.commit()
    return {"status": "disconnected"}


@router.get("/status")
async def github_status(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Get GitHub connection status."""
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT access_token_encrypted, github_login, updated_at FROM github_oauth_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1",
            (user["id"],),
        )
        row = await cursor.fetchone()

    if not row:
        return {"connected": False}

    # Validate token with GitHub API
    access_token = decrypt_data(row["access_token_encrypted"])
    is_valid = await github_service.validate_token(access_token)
    if not is_valid:
        # Token is invalid/expired - remove it
        async with get_connection() as conn:
            await conn.execute(
                "DELETE FROM github_oauth_tokens WHERE user_id = ?",
                (user["id"],),
            )
            await conn.commit()
        return {"connected": False}

    return {
        "connected": True,
        "login": row["github_login"],
        "connected_at": row["updated_at"],
    }