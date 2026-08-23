from datetime import datetime, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Header, status

from app.config import get_settings
from app.database import get_enterprise_membership, get_user_by_id
from app.services.enterprise_access import has_product_admin_access, is_platform_admin

settings = get_settings()


async def get_current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not settings.secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: SECRET_KEY is not configured.",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
            )
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc

    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if user.get("is_active") == 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deactivated. Contact your administrator.",
        )
    if user.get("subscription_status") == "canceled":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Subscription canceled",
        )
    membership = await get_enterprise_membership(user_id)
    if membership:
        user.update(
            {
                "enterprise_id": membership["enterprise_id"],
                "enterprise_name": membership["enterprise_name"],
                "enterprise_role": membership["enterprise_role"],
                "max_severity": "ALL",
                "can_request_audit": True,
                "can_request_fix": True,
                "can_approve": membership["enterprise_role"] == "owner",
                "can_manage_members": membership["enterprise_role"] == "owner",
                "allowed_email_domains": membership.get("allowed_email_domains", []),
                "enterprise_membership_active": bool(membership.get("membership_active", 1)),
            }
        )
    return user


def require_tier(required_tier: str):
    tier_order = {"FREE": 0, "PRO": 1, "ENTERPRISE": 2}

    async def dependency(user: dict = Depends(get_current_user)) -> dict:
        if is_platform_admin(user):
            return user
        user_tier = user.get("subscription_tier", "FREE")
        if tier_order.get(user_tier, 0) < tier_order.get(required_tier, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {required_tier} tier or higher",
            )
        return user

    return Depends(dependency)


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if not has_product_admin_access(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or enterprise owner privileges required",
        )
    return user


def require_platform_admin(user: dict = Depends(get_current_user)) -> dict:
    if not is_platform_admin(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform admin privileges required",
        )
    return user
