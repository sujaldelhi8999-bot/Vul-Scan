import hashlib
import ipaddress
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

import dns.asyncresolver
import httpx

from app.config import get_settings
from app.database import (
    create_authorized_target,
    find_authorized_target,
    get_authorized_target,
    update_authorized_target,
)

logger = logging.getLogger("phantomscan.authorization")


class TargetValidationError(ValueError):
    pass


class TargetNotVerifiedError(PermissionError):
    pass


@dataclass(frozen=True)
class CanonicalTarget:
    url: str
    origin: str
    domain: str


@dataclass(frozen=True)
class VerifiedTarget:
    id: int
    user_id: str
    target: CanonicalTarget
    verification_method: str
    verified_at: datetime
    expires_at: datetime
    status: str = "VERIFIED"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_database_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def to_database_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def canonicalize_target(target_url: str) -> CanonicalTarget:
    candidate = target_url.strip()
    if "://" not in candidate:
        raw_host = candidate.split("/")[0].split(":")[0].lower()
        if raw_host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or raw_host.startswith(("192.168.", "10.", "172.")):
            candidate = f"http://{candidate}"
        else:
            candidate = f"https://{candidate}"
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError("Target must use HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise TargetValidationError("Target URLs cannot contain credentials")
    if not parsed.hostname:
        raise TargetValidationError("Target must include a hostname")
    if parsed.fragment:
        raise TargetValidationError("Target URLs cannot include fragments")

    try:
        domain = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise TargetValidationError("Target hostname is invalid") from exc

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("Target port is invalid") from exc

    default_port = 443 if parsed.scheme.lower() == "https" else 80
    if ":" in domain:
        display_host = f"[{domain}]"
    else:
        display_host = domain
    netloc = display_host if port is None or port == default_port else f"{display_host}:{port}"
    scheme = parsed.scheme.lower()
    origin = f"{scheme}://{netloc}"
    path = parsed.path or "/"
    normalized_url = urlunsplit((scheme, netloc, path, parsed.query, ""))
    return CanonicalTarget(url=normalized_url, origin=origin, domain=domain)


class TargetAuthorizationService:
    def __init__(self, now: Callable[[], datetime] = utc_now) -> None:
        self.settings = get_settings()
        self.now = now

    async def create_challenge(self, target_url: str, user_id: str, method: str) -> dict[str, object]:
        target = canonicalize_target(target_url)
        await self._revoke_other_pending(target.origin, user_id)
        token = secrets.token_urlsafe(32)
        challenge_expires_at = self.now() + timedelta(minutes=self.settings.verification_challenge_minutes)
        authorization_id = await create_authorized_target(
            user_id=user_id,
            domain=target.domain,
            target_origin=target.origin,
            verification_method=method,
            token_hash=hash_token(token),
            challenge_expires_at=to_database_datetime(challenge_expires_at),
        )
        logger.info(
            "Challenge created id=%d for origin=%s method=%s",
            authorization_id, target.origin, method,
        )
        return {
            "id": authorization_id,
            "domain": target.domain,
            "target_origin": target.origin,
            "verification_method": method,
            "token": token,
            "dns_record": f"phantomscan-verification={token}",
            "http_url": f"{target.origin}/.well-known/phantomscan-verification.txt",
            "challenge_expires_at": challenge_expires_at,
            "status": "PENDING",
        }

    async def _revoke_other_pending(self, target_origin: str, user_id: str) -> None:
        record = await find_authorized_target(user_id, target_origin)
        if record is None:
            return
        current_id = int(record["id"])
        if str(record.get("status")) == "PENDING":
            await update_authorized_target(current_id, "REVOKED")
            logger.info("Revoked stale pending challenge id=%d for origin=%s", current_id, target_origin)

    async def verify_challenge(self, authorization_id: int, user_id: str) -> dict[str, object]:
        record = await self._get_owned_record(authorization_id, user_id)
        status = await self._refresh_expiration(record)
        if status == "VERIFIED":
            return await self.status_from_record(record, "TARGET VERIFIED\nPentest capabilities unlocked.")
        if status == "EXPIRED":
            raise TargetNotVerifiedError("Challenge has expired. Create a new challenge and update the verification file.")
        if status != "PENDING":
            raise TargetNotVerifiedError(f"Verification cannot run while target status is {status}")

        method = str(record["verification_method"])
        error_detail: str | None = None
        if method == "dns":
            verified, error_detail = await self._verify_dns(str(record["domain"]), str(record["verification_token_hash"]))
        else:
            verified, error_detail = await self._verify_http(str(record["target_origin"]), str(record["verification_token_hash"]), authorization_id)
        if not verified:
            raise TargetNotVerifiedError(error_detail or "Verification token was not found at the configured location")

        verified_at = self.now()
        expires_at = verified_at + timedelta(days=self.settings.verification_ttl_days)
        await update_authorized_target(
            authorization_id,
            "VERIFIED",
            to_database_datetime(verified_at),
            to_database_datetime(expires_at),
        )
        updated = await get_authorized_target(authorization_id)
        if updated is None:
            raise TargetNotVerifiedError("Verification record disappeared")
        logger.info("Challenge id=%d verified successfully for origin=%s", authorization_id, record.get("target_origin"))
        return await self.status_from_record(updated, "TARGET VERIFIED\nPentest capabilities unlocked.")

    async def get_status(self, target_url: str, user_id: str) -> dict[str, object]:
        target = canonicalize_target(target_url)
        record = await find_authorized_target(user_id, target.origin)
        if record is None:
            return {
                "id": None,
                "domain": target.domain,
                "target_origin": target.origin,
                "verification_method": None,
                "verified_at": None,
                "expires_at": None,
                "status": "PENDING",
                "message": "TARGET NOT VERIFIED",
            }
        status = await self._refresh_expiration(record)
        refreshed = await get_authorized_target(int(record["id"])) if status != record["status"] else record
        return await self.status_from_record(refreshed or record)

    async def revoke(self, authorization_id: int, user_id: str) -> dict[str, object]:
        record = await self._get_owned_record(authorization_id, user_id)
        await update_authorized_target(authorization_id, "REVOKED", record.get("verified_at"), record.get("expires_at"))
        updated = await get_authorized_target(authorization_id)
        return await self.status_from_record(updated or record, "Target authorization revoked.")

    async def require_verified(
        self,
        target_url: str,
        user_id: str,
        authorization_id: int | None = None,
    ) -> VerifiedTarget:
        target = canonicalize_target(target_url)
        record = await get_authorized_target(authorization_id) if authorization_id else await find_authorized_target(user_id, target.origin)
        if record is None or record["user_id"] != user_id or record["target_origin"] != target.origin:
            raise TargetNotVerifiedError(self.blocked_message())
        status = await self._refresh_expiration(record)
        if status != "VERIFIED":
            raise TargetNotVerifiedError(self.blocked_message())
        verified_at = parse_database_datetime(record.get("verified_at"))
        expires_at = parse_database_datetime(record.get("expires_at"))
        if verified_at is None or expires_at is None:
            raise TargetNotVerifiedError(self.blocked_message())
        return VerifiedTarget(
            id=int(record["id"]),
            user_id=user_id,
            target=target,
            verification_method=str(record["verification_method"]),
            verified_at=verified_at,
            expires_at=expires_at,
        )

    async def _get_owned_record(self, authorization_id: int, user_id: str) -> dict[str, object]:
        record = await get_authorized_target(authorization_id)
        if record is None or record["user_id"] != user_id:
            raise TargetNotVerifiedError("Verification record not found")
        return record

    async def _refresh_expiration(self, record: dict[str, object]) -> str:
        status = str(record["status"])
        now = self.now()
        if status == "PENDING":
            challenge_expiry = parse_database_datetime(str(record["challenge_expires_at"]))
            if challenge_expiry is not None and challenge_expiry <= now:
                await update_authorized_target(int(record["id"]), "EXPIRED")
                return "EXPIRED"
        if status == "VERIFIED":
            verified_expiry = parse_database_datetime(str(record.get("expires_at") or ""))
            if verified_expiry is None or verified_expiry <= now:
                await update_authorized_target(
                    int(record["id"]),
                    "EXPIRED",
                    str(record.get("verified_at") or "") or None,
                    str(record.get("expires_at") or "") or None,
                )
                return "EXPIRED"
        return status

    async def _verify_dns(self, domain: str, expected_hash: str) -> tuple[bool, str | None]:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0
        try:
            answers = await resolver.resolve(domain, "TXT")
        except dns.exception.DNSException as exc:
            logger.warning("DNS verification failed for %s: %s", domain, exc)
            return False, f"DNS lookup failed: {exc}"
        except Exception as exc:
            logger.warning("DNS verification failed for %s: unexpected error: %s", domain, exc)
            return False, f"DNS lookup error: {exc}"
        prefix = "phantomscan-verification="
        for answer in answers:
            value = b"".join(getattr(answer, "strings", [])).decode("utf-8", errors="replace")
            if not value:
                value = str(answer).strip('"')
            token = value[len(prefix) :].strip() if value.startswith(prefix) else value
            if secrets.compare_digest(hash_token(token), expected_hash):
                return True, None
        logger.warning("DNS verification failed for %s: token not found in TXT records", domain)
        return False, "DNS TXT record does not contain the expected verification token"

    async def _verify_http(self, target_origin: str, expected_hash: str, authorization_id: int | None = None) -> tuple[bool, str | None]:
        url = f"{target_origin}/.well-known/phantomscan-verification.txt"
        logger.info(
            "Verifying challenge id=%s url=%s",
            authorization_id, url,
        )
        try:
            async with httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                max_redirects=5,
                trust_env=False,
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": "PhantomScan-Ownership-Verification/1.0"},
                )
                if response.status_code != 200:
                    logger.warning(
                        "HTTP verification failed url=%s status=%d location=%s",
                        url, response.status_code,
                        response.headers.get("location", "N/A"),
                    )
                    return False, f"Verification URL returned HTTP {response.status_code} (expected 200)"
                if len(response.content) > 4096:
                    logger.warning("HTTP verification failed url=%s content_too_large size=%d", url, len(response.content))
                    return False, "Verification file is too large (max 4096 bytes)"
        except httpx.TimeoutException:
            logger.warning("HTTP verification timed out url=%s", url)
            return False, "Connection timed out fetching verification file"
        except httpx.HTTPError as exc:
            logger.warning("HTTP verification failed url=%s error=%s", url, exc)
            return False, f"HTTP fetch failed: {exc}"

        content = response.content.decode("utf-8", errors="replace").strip()
        prefix = "phantomscan-verification="
        if not content.startswith(prefix):
            logger.warning(
                "HTTP verification failed url=%s unexpected_format content_prefix=%s",
                url, content[:60],
            )
            return False, (
                f"Verification file does not contain the expected token format. "
                f"The file should start with '{prefix}' but got: {content[:80]}..."
            )
        token = content[len(prefix) :].strip()
        received_hash = hash_token(token)
        match = secrets.compare_digest(received_hash, expected_hash)
        if not match:
            logger.warning(
                "HTTP verification failed url=%s token_hash_mismatch "
                "expected_hash=%s received_token_hash=%s",
                url, expected_hash, received_hash,
            )
            return False, (
                "Verification token in the file does not match the challenge token. "
                "Make sure the file contains the latest token from the Challenge step."
            )
        logger.info("HTTP verification succeeded url=%s", url)
        return True, None

    async def status_from_record(self, record: dict[str, object], message: str | None = None) -> dict[str, object]:
        status = str(record["status"])
        return {
            "id": int(record["id"]),
            "domain": str(record["domain"]),
            "target_origin": str(record["target_origin"]),
            "verification_method": str(record["verification_method"]),
            "verified_at": parse_database_datetime(str(record.get("verified_at") or "")),
            "expires_at": parse_database_datetime(str(record.get("expires_at") or "")),
            "status": status,
            "message": message or ("TARGET VERIFIED" if status == "VERIFIED" else f"Target status: {status}"),
        }

    @staticmethod
    def blocked_message() -> str:
        return (
            "TARGET NOT VERIFIED\n"
            "Active testing blocked.\n\n"
            "Run Defend Scan instead\n"
            "or\n"
            "Verify ownership to unlock Pentest Mode."
        )


def is_ip_address(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False
