import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.agents.dos import (
    ATTACK_MODES,
    INTENSITY_RPS,
    DoSAgent,
    request_dos_stop,
)
from app.auth_middleware import require_admin
from app.database import get_connection
from app.services.active_gate import ActiveTargetGate, canonicalize_hostname

logger = logging.getLogger("phantomscan.dos")

router = APIRouter(prefix="/api/admin/dos", tags=["Denial of Service"])


class DoSStartRequest(BaseModel):
    target_url: str = Field(min_length=4, max_length=2048)
    intensity: str = "low"
    duration: int = 30
    mode: str = "get_flood"
    endpoint: str | None = None
    override_cap: bool = False


INTENSITY_RULES = {
    "low": {"max_duration": 300, "allowed_outside_lab": True},
    "medium": {"max_duration": 120, "allowed_outside_lab": True},
    "high": {"max_duration": 60, "allowed_outside_lab": True},
    "critical": {"max_duration": 30, "allowed_outside_lab": False},
    "nuclear": {"max_duration": 15, "allowed_outside_lab": False},
}


def _is_lab_target(url: str) -> bool:
    lower = url.lower()
    return (
        "phantombank" in lower
        or "localhost" in lower
        or "127.0.0.1" in lower
        or "::1" in lower
    )


@router.get("/modes")
async def list_attack_modes(
    admin: dict = Depends(require_admin),
):
    """Return available attack modes with their descriptions and limits."""
    return {
        "modes": {
            k: {
                "description": v["description"],
                "default_rps": v["default_rps"],
                "max_rps_lab": v["max_rps_lab"],
                "max_rps_external": v["max_rps_external"],
            }
            for k, v in ATTACK_MODES.items()
        },
        "intensities": {
            k: {"rps": v, "max_duration": INTENSITY_RULES.get(k, {}).get("max_duration", 60)}
            for k, v in INTENSITY_RPS.items()
        },
    }


@router.post("/start")
async def start_dos(
    req: DoSStartRequest,
    admin: dict = Depends(require_admin),
):
    if not req.target_url.startswith(("http://", "https://")):
        req.target_url = "https://" + req.target_url

    if req.intensity not in INTENSITY_RULES:
        req.intensity = "low"

    if req.mode not in ATTACK_MODES:
        req.mode = "get_flood"

    requested_intensity = req.intensity
    requested_mode = req.mode
    rules = INTENSITY_RULES[req.intensity]

    # Downgrade critical/nuclear to high for non-lab targets without override.
    if not rules["allowed_outside_lab"] and not _is_lab_target(req.target_url):
        if not req.override_cap:
            req.intensity = "high"
            rules = INTENSITY_RULES["high"]

    if req.duration > rules["max_duration"]:
        req.duration = rules["max_duration"]

    gate = ActiveTargetGate()
    hostname = canonicalize_hostname(req.target_url)
    decision = await gate.admit(
        target_url=req.target_url,
        user_id="admin",
        authorization_id=None,
        user_role="admin",
    )

    if not decision.allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Target not authorized for DoS testing: {decision.reason}",
        )

    agent = DoSAgent(
        target_url=req.target_url,
        intensity=req.intensity,
        duration=req.duration,
        mode=req.mode,
        endpoint=req.endpoint,
        override_cap=req.override_cap,
        user_id=admin.get("user_id", "admin"),
    )
    result = await agent.start()

    warnings = []
    if requested_intensity != req.intensity:
        warnings.append(
            f"Intensity '{requested_intensity}' auto-downgraded to "
            f"'{req.intensity}' for target {req.target_url}."
        )
    if requested_mode != req.mode:
        warnings.append(
            f"Mode '{requested_mode}' is not available; using '{req.mode}'."
        )
    if warnings:
        result["warning"] = " ".join(warnings)

    # Audit log for override usage.
    if req.override_cap:
        logger.warning(
            "[DoS] Admin %s used intensity override on %s (mode=%s, rps=%d)",
            admin.get("user_id", "admin"),
            req.target_url,
            req.mode,
            agent.rps,
        )

    return result


@router.post("/stop/{job_id}")
async def stop_dos(
    job_id: str,
    admin: dict = Depends(require_admin),
):
    try:
        return await request_dos_stop(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")


@router.get("/status/{job_id}")
async def get_dos_status(
    job_id: str,
    admin: dict = Depends(require_admin),
):
    # Check live agent first.
    from app.agents.dos import ACTIVE_AGENTS

    live_agent = ACTIVE_AGENTS.get(job_id)
    if live_agent is not None:
        return await live_agent.get_status()

    # Fall back to database.
    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM dos_jobs WHERE job_id = ?", (job_id,)
        )
        row = await cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    return dict(row)


@router.get("/history")
async def get_dos_history(
    admin: dict = Depends(require_admin),
):
    async with get_connection() as conn:
        cursor = await conn.execute(
            """
            SELECT job_id, target_url, intensity, status,
                   requests_sent, responses_received, errors,
                   baseline_latency, peak_latency, avg_latency_during, recovery_latency,
                   impact_score, effective, website_status, health_score,
                   p95_latency, p99_latency, jitter_ms, error_rate, throughput_mbps,
                   total_requests, status_2xx, status_3xx, status_4xx, status_5xx,
                   total_data_mb, avg_dns_ms, avg_tcp_ms, avg_tls_ms, avg_ttfb_ms,
                   packet_loss, recovery_ratio, recovered,
                   attack_mode, endpoint, target_class, workers,
                   started_at, stopped_at
            FROM dos_jobs
            ORDER BY started_at DESC
            LIMIT 50
            """
        )
        return [dict(row) for row in await cursor.fetchall()]
