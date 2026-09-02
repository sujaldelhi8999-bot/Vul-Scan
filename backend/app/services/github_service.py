"""
GitHub Service - Handles GitHub OAuth, GitHub App, and API interactions.
"""

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from app.config import get_settings
from app.database import get_connection
from app.models import (
    GitHubOAuthRequest,
    GitHubOAuthCallback,
    GitHubTokenResponse,
    GitHubUserResponse,
    GitHubRepoResponse,
    GitHubWebhookPayload,
)
from app.security import encrypt_data, decrypt_data


class GitHubService:
    """Service for GitHub integration (OAuth, App, API)."""

    GITHUB_API_BASE = "https://api.github.com"
    GITHUB_OAUTH_AUTHORIZE = "https://github.com/login/oauth/authorize"
    GITHUB_OAUTH_TOKEN = "https://github.com/login/oauth/access_token"

    def __init__(self):
        self.settings = get_settings()
        self._client_id = self.settings.github_client_id
        self._client_secret = self.settings.github_client_secret
        self._app_id = self.settings.github_app_id
        self._app_private_key = self.settings.github_app_private_key
        self._webhook_secret = self.settings.github_webhook_secret

    @staticmethod
    def _response_message(response: httpx.Response, fallback: str) -> str:
        try:
            data = response.json()
            if isinstance(data, dict) and data.get("message"):
                return str(data["message"])
        except Exception:
            pass
        return fallback

    # ============================================================
    # OAuth User Flow
    # ============================================================

    def get_oauth_authorize_url(self, request: GitHubOAuthRequest) -> str:
        """Generate GitHub OAuth authorize URL."""
        state = request.state or secrets.token_urlsafe(32)
        params = {
            "client_id": self._client_id,
            "redirect_uri": str(request.redirect_url),
            "scope": request.scope,
            "state": state,
            "allow_signup": "true",
        }
        return f"{self.GITHUB_OAUTH_AUTHORIZE}?{urlencode(params)}"

    async def exchange_code_for_token(self, callback: GitHubOAuthCallback) -> GitHubTokenResponse:
        """Exchange authorization code for access token."""
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": callback.code,
        }
        if callback.redirect_uri:
            data["redirect_uri"] = callback.redirect_uri
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.GITHUB_OAUTH_TOKEN,
                headers={"Accept": "application/json"},
                data=data,
            )
            response.raise_for_status()
            data = response.json()
            return GitHubTokenResponse(**data)

    async def get_user_info(self, access_token: str) -> GitHubUserResponse:
        """Get authenticated user info."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.GITHUB_API_BASE}/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            )
            response.raise_for_status()
            return GitHubUserResponse(**response.json())

    async def validate_token(self, access_token: str) -> bool:
        """Validate a GitHub access token by making a test request.
        Returns True if valid, False if 401/403, re-raises other errors.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.GITHUB_API_BASE}/user",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                )
                return response.status_code == 200
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                return False
            raise

    async def get_user_orgs(self, access_token: str) -> list[dict[str, Any]]:
        """Get user's organizations."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.GITHUB_API_BASE}/user/orgs",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            )
            response.raise_for_status()
            return response.json()

    async def get_user_repos(self, access_token: str, per_page: int = 100) -> list[GitHubRepoResponse]:
        """Get user's repositories."""
        async with httpx.AsyncClient() as client:
            repos = []
            page = 1
            while True:
                response = await client.get(
                    f"{self.GITHUB_API_BASE}/user/repos",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                    params={"per_page": per_page, "page": page, "sort": "updated", "affiliation": "owner,collaborator"},
                )
                response.raise_for_status()
                page_repos = response.json()
                if not page_repos:
                    break
                repos.extend([GitHubRepoResponse(**r) for r in page_repos])
                if len(page_repos) < per_page:
                    break
                page += 1
            return repos

    async def get_repo(self, access_token: str, owner: str, repo: str) -> GitHubRepoResponse:
        """Get single repository info."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            )
            response.raise_for_status()
            return GitHubRepoResponse(**response.json())

    async def get_dependabot_alerts(
        self,
        access_token: str,
        owner: str,
        repo: str,
        state: str = "open",
        per_page: int = 100,
    ) -> dict[str, Any]:
        """Fetch Dependabot alerts when the token has access.

        GitHub returns 403/404 when alerts are disabled or the token lacks the
        required security-events access; that is captured as metadata instead of
        failing the repository scan.
        """
        alerts: list[dict[str, Any]] = []
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient() as client:
            page = 1
            while True:
                response = await client.get(
                    f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/dependabot/alerts",
                    headers=headers,
                    params={"state": state, "per_page": per_page, "page": page},
                )
                if response.status_code in (403, 404):
                    return {
                        "available": False,
                        "reason": self._response_message(response, "dependabot alerts unavailable"),
                        "alerts": alerts,
                        "rate_limit_remaining": response.headers.get("x-ratelimit-remaining"),
                    }
                response.raise_for_status()
                page_alerts = response.json()
                if not page_alerts:
                    break
                alerts.extend(page_alerts)
                if len(page_alerts) < per_page:
                    break
                page += 1
            return {
                "available": True,
                "alerts": alerts,
                "rate_limit_remaining": response.headers.get("x-ratelimit-remaining") if 'response' in locals() else None,
            }

    async def get_branch_protection_status(
        self,
        access_token: str,
        owner: str,
        repo: str,
        branch: str,
    ) -> dict[str, Any]:
        """Return branch protection state without making scan startup brittle."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/branches/{branch}/protection",
                headers=headers,
            )
            if response.status_code == 404:
                return {"available": True, "protected": False, "reason": "branch protection not configured"}
            if response.status_code == 403:
                return {"available": False, "protected": None, "reason": self._response_message(response, "branch protection unavailable")}
            response.raise_for_status()
            return {"available": True, "protected": True, "settings": response.json()}

    async def get_repo_security_insights(
        self,
        access_token: str,
        owner: str,
        repo: str,
        branch: str = "main",
    ) -> dict[str, Any]:
        """Collect GitHub-native security signals for repo scans."""
        dependabot = await self.get_dependabot_alerts(access_token, owner, repo)
        branch_protection = await self.get_branch_protection_status(access_token, owner, repo, branch)
        return {
            "dependabot": dependabot,
            "branch_protection": branch_protection,
        }

    async def get_repo_contents(
        self, access_token: str, owner: str, repo: str, path: str = "", ref: str | None = None
    ) -> list[dict[str, Any]]:
        """Get repository contents (files/directories)."""
        async with httpx.AsyncClient() as client:
            params = {}
            if ref:
                params["ref"] = ref
            response = await client.get(
                f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                params=params,
            )
            response.raise_for_status()
            return response.json()

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str, ref: str | None = None
    ) -> str:
        """Get raw file content from repository."""
        async with httpx.AsyncClient() as client:
            params = {"ref": ref} if ref else {}
            response = await client.get(
                f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.raw+json",
                },
                params=params,
            )
            response.raise_for_status()
            return response.text

    # ============================================================
    # OAuth State (state -> user mapping for the callback)
    # ============================================================

    async def store_oauth_state(self, user_id: str, state: str) -> None:
        """Persist state->user so the callback can attribute the token. TTL 10 min."""
        async with get_connection() as conn:
            await conn.execute(
                "DELETE FROM github_oauth_states WHERE created_at < datetime('now', '-10 minutes')"
            )
            await conn.execute(
                "INSERT INTO github_oauth_states (user_id, state) VALUES (?, ?)",
                (user_id, state),
            )
            await conn.commit()

    async def consume_oauth_state(self, state: str | None) -> Optional[str]:
        """Single-use lookup of the user who initiated the flow. Returns None if unknown/expired."""
        if not state:
            return None
        async with get_connection() as conn:
            cursor = await conn.execute(
                "SELECT user_id FROM github_oauth_states WHERE state = ?",
                (state,),
            )
            row = await cursor.fetchone()
            await conn.execute("DELETE FROM github_oauth_states WHERE state = ?", (state,))
            await conn.commit()
        return row["user_id"] if row else None

    # ============================================================
    # GitHub App
    # ============================================================

    def _generate_jwt(self) -> str:
        """Generate JWT for GitHub App authentication."""
        import jwt

        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + 600,  # 10 minutes
            "iss": self._app_id,
        }
        return jwt.encode(payload, self._app_private_key, algorithm="RS256")

    async def get_installation_token(self, installation_id: int) -> str:
        """Get installation access token for GitHub App."""
        jwt_token = self._generate_jwt()
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {jwt_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            response.raise_for_status()
            return response.json()["token"]

    async def get_installation_repos(self, installation_id: int, access_token: str) -> list[GitHubRepoResponse]:
        """Get repositories accessible by an installation."""
        async with httpx.AsyncClient() as client:
            repos = []
            page = 1
            while True:
                response = await client.get(
                    f"{self.GITHUB_API_BASE}/installation/repositories",
                    headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
                    params={"per_page": 100, "page": page},
                )
                response.raise_for_status()
                data = response.json()
                if not data.get("repositories"):
                    break
                repos.extend([GitHubRepoResponse(**r) for r in data["repositories"]])
                if len(data["repositories"]) < 100:
                    break
                page += 1
            return repos

    # ============================================================
    # Webhook Handling
    # ============================================================

    def verify_webhook_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature."""
        if not self._webhook_secret:
            return False
        expected = "sha256=" + hmac.new(
            self._webhook_secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def parse_webhook(self, payload: dict[str, Any]) -> GitHubWebhookPayload:
        """Parse webhook payload."""
        return GitHubWebhookPayload(**payload)

    # ============================================================
    # PR / Diff Scanning
    # ============================================================

    async def get_pr_diff(
        self, access_token: str, owner: str, repo: str, pr_number: int
    ) -> dict[str, Any]:
        """Get PR diff and changed files."""
        async with httpx.AsyncClient() as client:
            # Get PR info
            pr_response = await client.get(
                f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            )
            pr_response.raise_for_status()
            pr_data = pr_response.json()

            # Get diff
            diff_response = await client.get(
                f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.diff",
                },
            )
            diff_response.raise_for_status()
            diff_text = diff_response.text

            # Get changed files
            files_response = await client.get(
                f"{self.GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/files",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
            )
            files_response.raise_for_status()
            files = files_response.json()

            return {
                "pr": pr_data,
                "diff": diff_text,
                "files": files,
                "base_sha": pr_data["base"]["sha"],
                "head_sha": pr_data["head"]["sha"],
            }

    # ============================================================
    # Token Storage
    # ============================================================

    async def store_oauth_token(
        self,
        user_id: str,
        github_user_id: int,
        github_login: str,
        token_response: GitHubTokenResponse,
    ) -> None:
        """Store encrypted OAuth token."""
        async with get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO github_oauth_tokens (
                    user_id, github_user_id, github_login,
                    access_token_encrypted, refresh_token_encrypted,
                    token_type, scope, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, github_user_id) DO UPDATE SET
                    access_token_encrypted = excluded.access_token_encrypted,
                    refresh_token_encrypted = excluded.refresh_token_encrypted,
                    token_type = excluded.token_type,
                    scope = excluded.scope,
                    expires_at = excluded.expires_at,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    user_id,
                    github_user_id,
                    github_login,
                    encrypt_data(token_response.access_token),
                    encrypt_data(token_response.refresh_token) if token_response.refresh_token else None,
                    token_response.token_type,
                    token_response.scope,
                    datetime.now() + timedelta(seconds=token_response.expires_in) if token_response.expires_in else None,
                ),
            )
            await conn.commit()

    async def get_oauth_token(self, user_id: str, github_user_id: int) -> Optional[GitHubTokenResponse]:
        """Get decrypted OAuth token."""
        async with get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM github_oauth_tokens WHERE user_id = ? AND github_user_id = ?",
                (user_id, github_user_id),
            )
            row = await cursor.fetchone()
            if not row:
                return None

            # Check if token is expired
            if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < datetime.now():
                return None

            return GitHubTokenResponse(
                access_token=decrypt_data(row["access_token_encrypted"]),
                token_type=row["token_type"],
                scope=row["scope"],
                expires_in=None,
                refresh_token=decrypt_data(row["refresh_token_encrypted"]) if row["refresh_token_encrypted"] else None,
            )

    async def store_app_installation(
        self,
        user_id: str,
        installation_id: int,
        account_login: str,
        account_type: str,
        repository_selection: str,
        permissions: dict[str, str],
        events: list[str],
    ) -> None:
        """Store GitHub App installation."""
        async with get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO github_app_installations (
                    user_id, installation_id, account_login, account_type,
                    repository_selection, permissions, events
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, installation_id) DO UPDATE SET
                    account_login = excluded.account_login,
                    account_type = excluded.account_type,
                    repository_selection = excluded.repository_selection,
                    permissions = excluded.permissions,
                    events = excluded.events,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    user_id,
                    installation_id,
                    account_login,
                    account_type,
                    repository_selection,
                    json.dumps(permissions),
                    json.dumps(events),
                ),
            )
            await conn.commit()

    async def get_app_installations(self, user_id: str) -> list[dict[str, Any]]:
        """Get user's GitHub App installations."""
        async with get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM github_app_installations WHERE user_id = ?",
                (user_id,),
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


# Singleton instance
_github_service: Optional[GitHubService] = None


def get_github_service() -> GitHubService:
    global _github_service
    if _github_service is None:
        _github_service = GitHubService()
    return _github_service
