import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth_middleware import require_admin
from app.services.attack_planner import AttackPlanner

logger = logging.getLogger("phantomscan.attack_planner")

router = APIRouter(prefix="/api/attack-planner", tags=["Attack Planner"])


class PlanRequest(BaseModel):
    target_url: str = Field(min_length=4, max_length=2048)
    scan_id: int | None = None
    tech_stack: dict | None = None
    open_ports: list[int] | None = None
    findings: list[dict] | None = None
    entry_points: list[dict] | None = None


class QuickScanRequest(BaseModel):
    target_url: str = Field(min_length=4, max_length=2048)


@router.post("/plan")
async def generate_attack_plan(
    req: PlanRequest,
    admin: dict = Depends(require_admin),
):
    """Generate a comprehensive attack plan for a target."""
    if not req.target_url.startswith(("http://", "https://")):
        req.target_url = "https://" + req.target_url

    planner = AttackPlanner()
    plan = await planner.generate_plan(
        target_url=req.target_url,
        scan_id=req.scan_id,
        tech_stack=req.tech_stack,
        open_ports=req.open_ports,
        findings=req.findings,
        entry_points=req.entry_points,
    )
    return {
        "target": plan.target,
        "tech_stack": plan.tech_stack,
        "attack_steps": plan.attack_steps,
        "summary": plan.summary,
        "recommended_chain": plan.recommended_chain,
    }


@router.post("/quick")
async def quick_scan_and_plan(
    req: QuickScanRequest,
    admin: dict = Depends(require_admin),
):
    """Quick scan: detect tech stack and generate attack plan in one call."""
    if not req.target_url.startswith(("http://", "https://")):
        req.target_url = "https://" + req.target_url

    planner = AttackPlanner()
    plan = await planner.generate_plan(target_url=req.target_url)
    return {
        "target": plan.target,
        "tech_stack": plan.tech_stack,
        "attack_steps": plan.attack_steps,
        "summary": plan.summary,
        "recommended_chain": plan.recommended_chain,
    }


@router.get("/health")
async def planner_health():
    return {"status": "ok", "service": "attack_planner"}
