from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.auth_middleware import get_current_user
from app.agents.diagnostic_command import DiagnosticCommandAgent, DiagnosticCommandPolicyError
from app.database import get_audit_logs, get_execution_status, get_latest_scan, get_scan, list_scans
from app.models import AgentStatus
from app.services.jobs import scan_job_manager
from app.services.enterprise_access import enterprise_id_for, require_scan_access

router = APIRouter(prefix="/api/agents", tags=["agents"])

AGENT_NAMES = [
    "Orchestrator Agent",
    "Scanner Agent",
    "Shadow Recon Agent",
    "Recon Agent",
    "Analyzer Agent",
    "CVE Matcher Agent",
    "Authentication Security Agent",
    "Access Control Agent",
    "API Security Agent",
    "Session Security Agent",
    "Injection Analysis Agent",
    "Infrastructure Agent",
    "WebSocket Security Agent",
    "Dependency Agent",
    "Threat Intelligence Agent",
    "Attack Agent",
    "Sandbox Manager Agent",
    "Pentest Agent",
    "Exploit Agent",
    "AI Explainer Agent",
    "AI Security Analyst Agent",
    "Hindi Explainer Agent",
    "Fixer Agent",
    "Report Agent",
    "Notifier Agent",
    "Self Audit Agent",
]

APPLICABILITY_MAP = {
    "IDLE": "idle",
    "QUEUED": "active",
    "RUNNING": "active",
    "WAITING": "idle",
    "COMPLETED": "complete",
    "FAILED": "error",
    "NOT_APPLICABLE": "idle",
}


def known_agents_available() -> bool:
    return bool(AGENT_NAMES) and all(isinstance(name, str) and name.strip() for name in AGENT_NAMES)


@router.get("/status", response_model=list[AgentStatus])
async def agent_statuses(
    scan_id: int | None = Query(default=None, ge=1),
    user: dict = Depends(get_current_user),
) -> list[AgentStatus]:
    exec_status = await get_execution_status()
    if exec_status is not None and exec_status.get("lifecycle") in {"QUEUED", "STARTING", "RUNNING", "PAUSED"}:
        agent_states = exec_status.get("agent_states", [])
        if agent_states:
            name_map = {a["name"]: a["applicability"] for a in agent_states}
            return [
                AgentStatus(name=name, status=APPLICABILITY_MAP.get(name_map.get(name, "IDLE"), "idle"))
                for name in AGENT_NAMES
            ]

    if scan_id is not None:
        scan = await require_scan_access(scan_id, user)
    else:
        scans = await list_scans(user["id"], enterprise_id_for(user))
        scan = scans[0] if scans else None
    if scan is None:
        return [AgentStatus(name=name, status="idle") for name in AGENT_NAMES]

    logs = await get_audit_logs(int(scan["id"]))
    states = {name: "idle" for name in AGENT_NAMES}
    for log in logs:
        name = str(log["agent_name"])
        if name not in states:
            continue
        action = str(log["action"]).lower()
        if action in {"started", "module_started", "sandbox_created"}:
            states[name] = "active"
        elif action in {"completed", "module_completed", "skipped", "delivered", "sandbox_destroyed"}:
            states[name] = "complete"
        elif action in {"error", "failed"}:
            states[name] = "error"
        elif action == "cancelled":
            states[name] = "idle"

    live_job = await scan_job_manager.is_active(int(scan["id"]))
    if live_job and scan["status"] in {"queued", "running", "cancelling"} and all(
        state == "idle" for state in states.values()
    ):
        states["Orchestrator Agent"] = "active"
    self_audit_active = states["Self Audit Agent"] == "active" and scan["status"] in {"running", "cancelling"}
    for name, agent_state in states.items():
        if agent_state != "active":
            continue
        if scan["status"] == "error":
            states[name] = "error"
        elif scan["status"] in {"cancelled", "complete"}:
            states[name] = "idle"
        elif not live_job and not self_audit_active:
            states[name] = "idle"

    return [AgentStatus(name=name, status=states[name]) for name in AGENT_NAMES]


class DiagnosticRequest(BaseModel):
    category: str


@router.post("/diagnostic/{scan_id}")
async def run_diagnostic(
    scan_id: int,
    body: DiagnosticRequest,
    user: dict = Depends(get_current_user),
) -> dict:
    scan = await require_scan_access(scan_id, user)
    agent = DiagnosticCommandAgent()
    try:
        result = await agent.run_diagnostic(
            target_url=scan["target_url"],
            scan_id=scan_id,
            category=body.category,
            user_id=user["id"],
        )
    except DiagnosticCommandPolicyError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    return result
