import logging
from typing import Any

from fastapi import APIRouter, Depends

from app.auth_middleware import get_current_user
from app.database import get_execution_status
from app.models import AgentStateDetail, ExecutionStatusResponse
from app.services.execution_status import default_agent_states

logger = logging.getLogger("phantomscan.execution")

router = APIRouter(prefix="/api/execution", tags=["execution"])


@router.get("/status", response_model=ExecutionStatusResponse)
async def execution_status(user: dict = Depends(get_current_user)) -> ExecutionStatusResponse:
    status = await get_execution_status()
    if status is None:
        return ExecutionStatusResponse(
            lifecycle="IDLE",
            agents=[AgentStateDetail(**a) for a in default_agent_states()],
        )
    agents = status.get("agent_states", [])
    return ExecutionStatusResponse(
        execution_type=status.get("execution_type"),
        lifecycle=status.get("lifecycle", "IDLE"),
        job_id=status.get("job_id"),
        scan_id=status.get("scan_id"),
        target_url=status.get("target_url", ""),
        progress_percent=int(status.get("progress_percent", 0)),
        current_module=status.get("current_module"),
        current_phase=status.get("current_phase"),
        surfaces_total=int(status.get("surfaces_total", 0)),
        surfaces_completed=int(status.get("surfaces_completed", 0)),
        findings_count=int(status.get("findings_count", 0)),
        started_at=status.get("started_at"),
        updated_at=status.get("updated_at"),
        completed_at=status.get("completed_at"),
        error_message=status.get("error_message"),
        error_code=status.get("error_code"),
        agents=[AgentStateDetail(**a) for a in agents] if agents else [AgentStateDetail(**a) for a in default_agent_states()],
        is_lab=bool(status.get("is_lab")),
        authorization_status=status.get("authorization_status", ""),
    )