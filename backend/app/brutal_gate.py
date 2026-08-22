"""Brutal Mode safety gate.

Every Black Ops endpoint MUST pass through this gate. It enforces, in order:

1. ``BRUTAL_MODE_ENABLED`` environment flag (off by default — global kill switch).
2. The caller is an admin (Private Scope membership is admin-controlled).
3. The target is either the PhantomBank Lab (localhost) or listed in the
   Private Scope table (admin override).
4. The caller explicitly acknowledges ownership / written permission for the
   target when establishing a session; the acknowledgment is recorded in the
   audit trail and the session's subsequent operations re-verify admin role
   and target scope without re-asking for the acknowledgment.

Denials and approvals are written to the ``audit_logs`` table so every
activation is traceable.
"""

import logging
from urllib.parse import urlparse

from app.config import get_settings
from app.database import add_audit_log, find_private_scope, get_or_create_system_scan
from app.services.active_gate import canonicalize_hostname
from app.services.enterprise_access import has_product_admin_access

logger = logging.getLogger("phantomscan.brutal_gate")

LAB_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


class BrutalGateError(Exception):
    """Raised when the Brutal Mode gate denies an operation."""

    def __init__(self, code: str, message: str, http_status: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


class BrutalGate:
    """Server-side enforcement of the Brutal Mode safety contract."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def is_enabled(self) -> bool:
        # Read fresh settings every call so the BRUTAL_MODE_ENABLED kill
        # switch takes effect without a backend restart.
        return bool(get_settings().brutal_mode_enabled)

    def require_enabled(self) -> None:
        if not self.is_enabled():
            raise BrutalGateError(
                "BRUTAL_MODE_DISABLED",
                "Brutal Mode is disabled. Set BRUTAL_MODE_ENABLED=1 in backend/.env to enable.",
            )

    async def require_admin(self, user: dict) -> None:
        if not has_product_admin_access(user):
            raise BrutalGateError(
                "ADMIN_REQUIRED",
                "Brutal Mode requires an admin account (Private Scope is admin-controlled).",
            )

    async def require_target_allowed(self, target_url: str) -> str:
        """Return the canonical hostname if the target is in scope, else deny."""
        hostname = canonicalize_hostname(target_url)
        if hostname in LAB_HOSTNAMES:
            return hostname
        scope = await find_private_scope(hostname)
        if scope is not None:
            return hostname
        raise BrutalGateError(
            "TARGET_NOT_IN_SCOPE",
            f"Target {hostname} is not the PhantomBank Lab and not in Private Scope. "
            "Add it under Settings → Private Scope first.",
        )

    def require_ownership_ack(self, acknowledged: bool) -> None:
        if not acknowledged:
            raise BrutalGateError(
                "OWNERSHIP_ACK_REQUIRED",
                "You must confirm that you own this target or have written permission to test it.",
                http_status=422,
            )

    async def authorize(
        self,
        user: dict,
        target_url: str,
        ownership_ack: bool = False,
        *,
        require_ack: bool = True,
    ) -> str:
        """Run the full gate. Returns the canonical hostname on success."""
        self.require_enabled()
        await self.require_admin(user)
        hostname = await self.require_target_allowed(target_url)
        if require_ack:
            self.require_ownership_ack(ownership_ack)
        await self._log_approval(user["id"], target_url, hostname)
        return hostname

    async def deny(self, user: dict, target_url: str, error: BrutalGateError) -> None:
        """Record a denied gate attempt in the audit trail."""
        try:
            sys_scan_id = await get_or_create_system_scan()
            await add_audit_log(
                sys_scan_id,
                "BrutalGate",
                "brutal_denied",
                f"Brutal Mode denied ({error.code}): {error.message}",
                user_id=user.get("id", "unknown"),
                target=target_url[:2048],
                authorization_status="DENIED",
            )
        except Exception:  # logging must never break the request
            logger.exception("Failed to record brutal gate denial")

    async def _log_approval(self, user_id: str, target_url: str, hostname: str) -> None:
        try:
            sys_scan_id = await get_or_create_system_scan()
            await add_audit_log(
                sys_scan_id,
                "BrutalGate",
                "brutal_authorized",
                f"Brutal Mode authorized for {hostname} (admin override)",
                user_id=user_id,
                target=hostname,
                authorization_status="ADMIN_OVERRIDE",
            )
        except Exception:
            logger.exception("Failed to record brutal gate approval")


def is_lab_target(target_url: str) -> bool:
    """True when the target resolves to the local PhantomBank Lab."""
    try:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        host = (parsed.hostname or "").lower()
    except Exception:
        return False
    return host in LAB_HOSTNAMES
