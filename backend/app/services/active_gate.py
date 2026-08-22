import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse, urlsplit

from app.config import get_settings
from app.database import add_private_scope, find_private_scope, update_private_scope_last_used
from app.services.authorization import TargetAuthorizationService, VerifiedTarget, canonicalize_target

def canonicalize_hostname(target_url: str) -> str:
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    hostname = parsed.hostname or ""
    hostname = hostname.lower().removeprefix("www.").rstrip(".")
    return hostname


@dataclass(frozen=True)
class ActiveTargetDecision:
    allowed: bool
    target_url: str
    target_origin: str
    authorization_status: str
    reason: str
    authorization_id: int | None = None
    verified_target: VerifiedTarget | None = None
    is_lab: bool = False

    def to_context(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "target_url": self.target_url,
            "target_origin": self.target_origin,
            "authorization_status": self.authorization_status,
            "reason": self.reason,
            "authorization_id": self.authorization_id,
            "is_lab": self.is_lab,
        }


class ActiveTargetGate:
    def __init__(self, authorization_service: TargetAuthorizationService | None = None) -> None:
        self.authorization_service = authorization_service or TargetAuthorizationService()

    async def admit(
        self,
        target_url: str,
        user_id: str,
        authorization_id: int | None = None,
        user_role: str = "user",
    ) -> ActiveTargetDecision:
        target = canonicalize_target(target_url)
        parsed = urlsplit(target.url)

        if user_role == "admin":
            hostname = canonicalize_hostname(target_url)
            scope_entry = await find_private_scope(hostname)
            if scope_entry is None:
                await add_private_scope(hostname, added_by=user_id or "admin")
            else:
                await update_private_scope_last_used(hostname)
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="ADMIN_OVERRIDE",
                reason="Admin Full Access (Auto-Whitelisted Target)",
                is_lab=False,
            )

        if self.is_builtin_lab_target(target.url):
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="TRAINING",
                reason="Built-in PhantomBank lab target",
                is_lab=True,
            )
        if self.is_loopback_host(parsed.hostname or ""):
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="ALLOWLIST",
                reason="Local development target",
            )
        if target.origin in self.allowlisted_origins():
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="ALLOWLIST",
                reason="Origin is in ACTIVE_TARGET_ALLOWLIST",
            )
        # Private Scope: admins declare targets here (admin_scope router). A
        # scoped target counts as authorized, so any authenticated user may run
        # pentest scans against it without completing an ownership challenge.
        # Verification via DNS/HTTP ownership remains the fallback below.
        hostname = canonicalize_hostname(target_url)
        scope_entry = await find_private_scope(hostname)
        if scope_entry is not None:
            await update_private_scope_last_used(hostname)
            return ActiveTargetDecision(
                allowed=True,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="ALLOWLIST",
                reason="Target is in Private Scope",
            )
        try:
            verified = await self.authorization_service.require_verified(target.url, user_id, authorization_id)
        except PermissionError:
            return ActiveTargetDecision(
                allowed=False,
                target_url=target.url,
                target_origin=target.origin,
                authorization_status="BLOCKED",
                reason=self.authorization_service.blocked_message(),
            )
        return ActiveTargetDecision(
            allowed=True,
            target_url=target.url,
            target_origin=target.origin,
            authorization_status="VERIFIED",
            reason="Target ownership verification is current",
            authorization_id=verified.id,
            verified_target=verified,
        )

    def allowlisted_origins(self) -> set[str]:
        origins: set[str] = set()
        for item in get_settings().active_target_allowlist.split(","):
            candidate = item.strip()
            if not candidate:
                continue
            try:
                origins.add(canonicalize_target(candidate).origin)
            except ValueError:
                continue
        return origins

    async def can_run_dos(self, target_url: str, user_role: str = "user") -> dict:
        result = await self.admit(target_url, "admin", user_role=user_role)
        return result.to_context()

    @classmethod
    def is_builtin_lab_target(cls, target_url: str) -> bool:
        parsed = urlsplit(target_url)
        return parsed.path.startswith("/lab/phantombank") and cls.is_loopback_host(parsed.hostname or "")

    @staticmethod
    def is_loopback_host(hostname: str) -> bool:
        hostname = hostname.strip("[]").lower().rstrip(".")
        if hostname in {"localhost", "localhost.localdomain"}:
            return True
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False
