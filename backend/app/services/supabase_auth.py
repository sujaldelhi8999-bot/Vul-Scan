"""
Supabase Auth token verification.

Primary path: verify the Supabase access token locally using the project's
public signing keys (JWKS). New-style Supabase projects sign access tokens
with asymmetric keys (ES256 / RS256) published at
``{SUPABASE_URL}/auth/v1/.well-known/jwks.json``. Legacy projects sign with a
shared HS256 secret (SUPABASE_JWT_SECRET). Fallback: call the Supabase
/auth/v1/user endpoint with the Bearer token when local verification is not
possible.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
import jwt

from app.config import get_settings

logger = logging.getLogger("phantomscan.supabase_auth")

_JWKS_CACHE_TTL_SECONDS = 3600
_jwks_client: "jwt.PyJWKClient | None" = None
_jwks_client_fetched_at = 0.0


@dataclass
class SupabaseUser:
    user_id: str
    email: str
    name: str


class SupabaseAuthError(Exception):
    pass


def _get_jwks_client(supabase_url: str) -> "jwt.PyJWKClient":
    """Return a cached JWKS client for the project's public signing keys."""
    global _jwks_client, _jwks_client_fetched_at
    now = time.monotonic()
    if _jwks_client is None or now - _jwks_client_fetched_at > _JWKS_CACHE_TTL_SECONDS:
        _jwks_client = jwt.PyJWKClient(
            f"{supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json",
            cache_keys=True,
        )
        _jwks_client_fetched_at = now
    return _jwks_client


def _decode_jwt(access_token: str, supabase_url: str, jwt_secret: str) -> dict:
    """Decode a Supabase access token using the algorithm declared in its header."""
    header = jwt.get_unverified_header(access_token)
    alg = header.get("alg")

    if alg == "HS256" and jwt_secret:
        return jwt.decode(
            access_token,
            jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )

    if alg in {"ES256", "RS256"} and supabase_url:
        signing_key = _get_jwks_client(supabase_url).get_signing_key_from_jwt(access_token)
        return jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["ES256", "RS256"],
            audience="authenticated",
        )

    raise jwt.InvalidTokenError(f"Unsupported JWT algorithm: {alg!r}")


async def _verify_via_api(access_token: str, supabase_url: str, anon_key: str = "") -> dict:
    """Validate the token against Supabase's /auth/v1/user endpoint."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{supabase_url.rstrip('/')}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "apikey": anon_key or access_token,
            },
        )
        if response.status_code != 200:
            raise SupabaseAuthError(f"Supabase rejected the token (HTTP {response.status_code})")
        return response.json()


async def verify_supabase_token(access_token: str) -> SupabaseUser:
    """Verify a Supabase access token and return the authenticated user.

    Raises SupabaseAuthError when the token is invalid, expired, or missing.
    """
    if not access_token:
        raise SupabaseAuthError("Missing access token")

    settings = get_settings()
    claims: dict = {}

    if settings.supabase_url or settings.supabase_jwt_secret:
        try:
            claims = _decode_jwt(access_token, settings.supabase_url, settings.supabase_jwt_secret)
        except (jwt.InvalidTokenError, ValueError) as exc:
            logger.warning("Supabase JWT decode failed, falling back to API: %s", exc)
            if settings.supabase_url:
                claims = await _verify_via_api(access_token, settings.supabase_url, settings.supabase_anon_key)
            else:
                raise SupabaseAuthError("Invalid Supabase token") from exc
    else:
        raise SupabaseAuthError("Supabase is not configured (SUPABASE_URL / SUPABASE_JWT_SECRET)")

    if not claims:
        raise SupabaseAuthError("Supabase returned no user claims")

    user_id = str(claims.get("sub") or claims.get("id") or "")
    email = str(claims.get("email") or "").lower()
    if not user_id or not email:
        raise SupabaseAuthError("Supabase token is missing user identity")

    # Parse optional expires claim
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
        raise SupabaseAuthError("Supabase token has expired")

    return SupabaseUser(
        user_id=user_id,
        email=email,
        name=str(claims.get("user_metadata", {}).get("name") or claims.get("name") or email),
    )
