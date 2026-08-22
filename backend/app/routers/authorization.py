from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth_middleware import get_current_user
from app.config import get_settings
from app.database import get_authorized_target
from app.models import (
    AuthorizationChallengeRequest,
    AuthorizationChallengeResponse,
    AuthorizationStatusResponse,
)
from app.services.authorization import TargetAuthorizationService, TargetNotVerifiedError, TargetValidationError

router = APIRouter(prefix="/api/authorization", tags=["authorization"])
authorization_service = TargetAuthorizationService()
settings = get_settings()


async def _verify_target_ownership(authorization_id: int, user_id: str) -> dict[str, Any]:
    record = await get_authorized_target(authorization_id)
    if not record or record["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization record not found")
    return record


@router.post("/challenge", response_model=AuthorizationChallengeResponse, status_code=status.HTTP_201_CREATED)
async def create_challenge(
    request: AuthorizationChallengeRequest,
    user: dict = Depends(get_current_user),
) -> AuthorizationChallengeResponse:
    try:
        challenge = await authorization_service.create_challenge(
            request.target_url,
            user["id"],
            request.verification_method,
        )
        return AuthorizationChallengeResponse(**challenge)
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.post("/{authorization_id}/verify", response_model=AuthorizationStatusResponse)
async def verify_challenge(
    authorization_id: int,
    user: dict = Depends(get_current_user),
) -> AuthorizationStatusResponse:
    await _verify_target_ownership(authorization_id, user["id"])
    try:
        result = await authorization_service.verify_challenge(authorization_id, user["id"])
        return AuthorizationStatusResponse(**result)
    except TargetNotVerifiedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get("/status", response_model=AuthorizationStatusResponse)
async def authorization_status(
    target_url: str = Query(min_length=4, max_length=2048),
    user: dict = Depends(get_current_user),
) -> AuthorizationStatusResponse:
    try:
        result = await authorization_service.get_status(target_url, user["id"])
        return AuthorizationStatusResponse(**result)
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/{authorization_id}")
async def get_authorization_record(
    authorization_id: int,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    record = await get_authorized_target(authorization_id)
    if record is None or record["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization record not found")
    return {
        "id": record["id"],
        "target_origin": record["target_origin"],
        "domain": record["domain"],
        "verification_method": record["verification_method"],
        "status": record["status"],
        "created_at": record.get("challenge_expires_at"),
        "expires_at": record.get("expires_at"),
        "verification_token_hash": record.get("verification_token_hash"),
    }


@router.post("/{authorization_id}/revoke", response_model=AuthorizationStatusResponse)
async def revoke_authorization(
    authorization_id: int,
    user: dict = Depends(get_current_user),
) -> AuthorizationStatusResponse:
    await _verify_target_ownership(authorization_id, user["id"])
    try:
        result = await authorization_service.revoke(authorization_id, user["id"])
        return AuthorizationStatusResponse(**result)
    except TargetNotVerifiedError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc