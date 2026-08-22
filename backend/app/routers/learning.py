"""Admin-facing Continuous Learning endpoints: insights, apply/dismiss, quality report."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.auth_middleware import require_admin
from app.config import get_settings
from app.models import LearningInsightResponse, LearningInsightUpdateRequest, ScanQualityResponse
from app.services.learning_engine import ContinuousLearningEngine

logger = logging.getLogger("phantomscan.learning")

router = APIRouter(prefix="/api/learning", tags=["learning"])
settings = get_settings()
engine = ContinuousLearningEngine()


@router.get("/insights", response_model=list[LearningInsightResponse])
async def list_insights(
    scan_id: int | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    admin: dict = Depends(require_admin),
) -> list[LearningInsightResponse]:
    rows = await engine.list_insights(scan_id, status_filter)
    return [LearningInsightResponse(**row) for row in rows]


@router.post("/insights/{insight_id}/apply", response_model=LearningInsightResponse)
async def apply_insight(
    insight_id: int,
    request: LearningInsightUpdateRequest | None = None,
    admin: dict = Depends(require_admin),
) -> LearningInsightResponse:
    settings_payload = request.applied_settings if request is not None else None
    row = await engine.apply_insight(insight_id, settings_payload)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Learning insight not found")
    logger.info("Admin applied learning insight %d", insight_id)
    return LearningInsightResponse(**row)


@router.post("/insights/{insight_id}/dismiss", response_model=LearningInsightResponse)
async def dismiss_insight(
    insight_id: int,
    admin: dict = Depends(require_admin),
) -> LearningInsightResponse:
    row = await engine.dismiss_insight(insight_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Learning insight not found")
    logger.info("Admin dismissed learning insight %d", insight_id)
    return LearningInsightResponse(**row)


@router.get("/quality", response_model=ScanQualityResponse)
async def scan_quality(admin: dict = Depends(require_admin)) -> ScanQualityResponse:
    summary = await engine.quality_summary()
    return ScanQualityResponse(**summary)
