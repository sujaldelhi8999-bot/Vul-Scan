import bcrypt
import jwt
import logging
import uuid
from datetime import datetime, timedelta, timezone
from sqlite3 import IntegrityError

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app.auth_middleware import get_current_user, require_platform_admin
from app.config import get_settings
from app.database import (
    create_user,
    get_enterprise_membership,
    get_user_by_email,
    get_user_by_id,
    touch_last_login,
    update_user_name,
    update_user_password,
)
from app.models import SupabaseLoginRequest
from app.services.supabase_auth import SupabaseAuthError, verify_supabase_token

logger = logging.getLogger("phantomscan.auth")
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str | None = Field(default=None, max_length=100)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: str
    email: str
    name: str | None
    role: str
    subscription_tier: str
    subscription_status: str
    created_at: str
    enterprise_id: str | None = None
    enterprise_name: str | None = None
    enterprise_role: str | None = None
    max_severity: str | None = None
    can_request_audit: bool = False
    can_request_fix: bool = False
    can_approve: bool = False
    can_manage_members: bool = False
    allowed_email_domains: list[str] = Field(default_factory=list)


class LoginResponse(BaseModel):
    token: str
    user: UserResponse
    refresh_token: str | None = None
    expires_at: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


ACCESS_TOKEN_TTL_HOURS = 24
REFRESH_TOKEN_TTL_DAYS = 7


def _issue_token(settings, user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "typ": "access",
        "jti": uuid.uuid4().hex,
        "exp": datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_TTL_HOURS),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def _issue_refresh_token(settings, user_id: str) -> str:
    payload = {
        "sub": user_id,
        "typ": "refresh",
        "jti": uuid.uuid4().hex,
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


async def _build_login_response(settings, user: dict) -> LoginResponse:
    token = _issue_token(settings, user["id"], user["role"])
    membership = await get_enterprise_membership(user["id"])
    return LoginResponse(
        token=token,
        refresh_token=_issue_refresh_token(settings, user["id"]),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_TTL_HOURS)).isoformat(),
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            name=user.get("name"),
            role=user["role"],
            subscription_tier=user.get("subscription_tier", "FREE"),
            subscription_status=user.get("subscription_status", "active"),
            created_at=user.get("created_at", ""),
            enterprise_id=membership.get("enterprise_id") if membership else user.get("enterprise_id"),
            enterprise_name=membership.get("enterprise_name") if membership else user.get("enterprise_name"),
            enterprise_role=membership.get("enterprise_role") if membership else user.get("enterprise_role"),
            max_severity="ALL" if membership else user.get("max_severity"),
            can_request_audit=True if membership else bool(user.get("can_request_audit")),
            can_request_fix=True if membership else bool(user.get("can_request_fix")),
            can_approve=True if membership else bool(user.get("can_approve")),
            can_manage_members=membership.get("enterprise_role") == "owner" if membership else bool(user.get("can_manage_members")),
            allowed_email_domains=membership.get("allowed_email_domains", []) if membership else user.get("allowed_email_domains", []),
        ),
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh(req: RefreshRequest):
    """Exchange a valid refresh token for a fresh access token (with rotation).

    The returned refresh token supersedes the presented one. The refresh
    token must carry a ``typ == "refresh"`` claim and belong to a user that
    still exists.
    """
    settings = get_settings()
    if not settings.secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server not configured: SECRET_KEY not set",
        )
    if not req.refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token",
        )
    try:
        payload = jwt.decode(req.refresh_token, settings.secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please log in again.",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from exc

    if payload.get("typ") != "refresh" or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user = await get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists. Please log in again.",
        )
    if user.get("subscription_status") == "canceled":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Subscription canceled",
        )

    return await _build_login_response(settings, user)


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest):
    settings = get_settings()
    
    if not settings.secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server not configured: SECRET_KEY not set",
        )
    
    existing = await get_user_by_email(req.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    
    user_id = uuid.uuid4().hex
    password_hash = _hash_password(req.password)
    await create_user(
        user_id=user_id,
        email=req.email.lower(),
        password_hash=password_hash,
        name=req.name,
        role="user",
    )

    user = {
        "id": user_id,
        "email": req.email.lower(),
        "name": req.name,
        "role": "user",
        "subscription_tier": "FREE",
        "subscription_status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return await _build_login_response(settings, user)


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    settings = get_settings()
    
    if not settings.secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server not configured: SECRET_KEY not set",
        )
    
    user = await get_user_by_email(req.email)
    if not user or not _verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if user.get("is_active") == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deactivated. Contact your administrator.",
        )

    await touch_last_login(user["id"])
    return await _build_login_response(settings, user)


@router.post("/change-password", response_model=UserResponse)
async def change_password(req: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    if not _verify_password(req.current_password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    new_hash = _hash_password(req.new_password)
    await update_user_password(user["id"], new_hash)
    
    updated = await get_user_by_id(user["id"])
    membership = await get_enterprise_membership(user["id"])
    return UserResponse(
        id=updated["id"],
        email=updated["email"],
        name=updated.get("name"),
        role=updated["role"],
        subscription_tier=updated.get("subscription_tier", "FREE"),
        subscription_status=updated.get("subscription_status", "active"),
        created_at=updated.get("created_at", ""),
        enterprise_id=membership.get("enterprise_id") if membership else None,
        enterprise_name=membership.get("enterprise_name") if membership else None,
        enterprise_role=membership.get("enterprise_role") if membership else None,
        max_severity="ALL" if membership else None,
        can_request_audit=bool(membership),
        can_request_fix=bool(membership),
        can_approve=bool(membership),
        can_manage_members=membership.get("enterprise_role") == "owner" if membership else False,
        allowed_email_domains=membership.get("allowed_email_domains", []) if membership else [],
    )


@router.get("/me", response_model=UserResponse)
async def get_me(user: dict = Depends(get_current_user)):
    return UserResponse(
        id=user["id"],
        email=user["email"],
        name=user.get("name"),
        role=user["role"],
        subscription_tier=user.get("subscription_tier", "FREE"),
        subscription_status=user.get("subscription_status", "active"),
        created_at=user.get("created_at", ""),
        enterprise_id=user.get("enterprise_id"),
        enterprise_name=user.get("enterprise_name"),
        enterprise_role=user.get("enterprise_role"),
        max_severity=user.get("max_severity"),
        can_request_audit=bool(user.get("can_request_audit")),
        can_request_fix=bool(user.get("can_request_fix")),
        can_approve=bool(user.get("can_approve")),
        can_manage_members=bool(user.get("can_manage_members")),
        allowed_email_domains=user.get("allowed_email_domains", []),
    )


@router.post("/supabase", response_model=LoginResponse)
async def supabase_login(req: SupabaseLoginRequest):
    """Exchange a Supabase access token (Google / GitHub sign-in) for a session."""
    settings = get_settings()
    try:
        supabase_user = await verify_supabase_token(req.access_token)
    except SupabaseAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Supabase token: {exc}",
        )

    admin_emails = {
        email.strip().lower()
        for email in settings.supabase_admin_emails.split(",")
        if email.strip()
    }
    role = "admin" if supabase_user.email in admin_emails else "user"

    user = await get_user_by_email(supabase_user.email)
    if not user:
        user_id = uuid.uuid4().hex
        try:
            await create_user(
                user_id=user_id,
                email=supabase_user.email,
                password_hash=_hash_password(uuid.uuid4().hex),
                name=supabase_user.name,
                role=role,
            )
        except IntegrityError:
            logger.warning("Supabase user row created concurrently; reusing existing user.")
        user = await get_user_by_email(supabase_user.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not create user",
            )
    elif supabase_user.name and supabase_user.name != user.get("name"):
        await update_user_name(user_id=user["id"], name=supabase_user.name)
        user = {**user, "name": supabase_user.name}

    return await _build_login_response(settings, user)


@router.post("/admin/create", response_model=UserResponse)
async def create_admin_user(req: RegisterRequest, admin: dict = Depends(require_platform_admin)):
    existing = await get_user_by_email(req.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    
    user_id = uuid.uuid4().hex
    password_hash = _hash_password(req.password)
    await create_user(
        user_id=user_id,
        email=req.email.lower(),
        password_hash=password_hash,
        name=req.name,
        role="admin",
    )
    
    created = await get_user_by_id(user_id)
    return UserResponse(
        id=created["id"],
        email=created["email"],
        name=created.get("name"),
        role=created["role"],
        subscription_tier=created.get("subscription_tier", "FREE"),
        subscription_status=created.get("subscription_status", "active"),
        created_at=created.get("created_at", ""),
    )
