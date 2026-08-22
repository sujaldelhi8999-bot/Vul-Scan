import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.database import upsert_execution_status, get_execution_status, get_authorized_test_job
from app.config import get_settings

logger = logging.getLogger("phantomscan.execution_status")

AGENT_DEFINITIONS = [
    {"name": "Orchestrator Agent", "responsibility": "Coordinates and executes passive security scans"},
    {"name": "Scanner Agent", "responsibility": "Performs passive reconnaissance and target profiling"},
    {"name": "Shadow Recon Agent", "responsibility": "Discovers subdomains, exposed files, and OSINT data"},
    {"name": "Recon Agent", "responsibility": "Gathers reconnaissance data about the target"},
    {"name": "Analyzer Agent", "responsibility": "Analyzes scanner and recon data for security issues"},
    {"name": "CVE Matcher Agent", "responsibility": "Correlates detected technologies with known CVEs"},
    {"name": "Authentication Security Agent", "responsibility": "Evaluates authentication mechanisms and session security"},
    {"name": "Access Control Agent", "responsibility": "Assesses authorization and access control implementations"},
    {"name": "API Security Agent", "responsibility": "Analyzes API endpoints for security weaknesses"},
    {"name": "Session Security Agent", "responsibility": "Reviews session management and token handling"},
    {"name": "Injection Analysis Agent", "responsibility": "Tests for injection vulnerabilities"},
    {"name": "Infrastructure Agent", "responsibility": "Evaluates infrastructure and network security posture"},
    {"name": "WebSocket Security Agent", "responsibility": "Reviews WebSocket implementations for security issues"},
    {"name": "Dependency Agent", "responsibility": "Analyzes third-party dependencies for vulnerabilities"},
    {"name": "Threat Intelligence Agent", "responsibility": "Gathers threat intelligence data about the target"},
    {"name": "Attack Agent", "responsibility": "Executes authorized attack simulations"},
    {"name": "Sandbox Manager Agent", "responsibility": "Manages sandbox/lab environments for active testing"},
    {"name": "Pentest Agent", "responsibility": "Executes controlled authorized security tests"},
    {"name": "Exploit Agent", "responsibility": "Runs controlled exploit verification modules"},
    {"name": "AI Explainer Agent", "responsibility": "Generates AI-powered explanations of findings"},
    {"name": "AI Security Analyst Agent", "responsibility": "Provides AI-driven security analysis and prioritization"},
    {"name": "Hindi Explainer Agent", "responsibility": "Provides Hindi-language explanations of findings"},
    {"name": "Fixer Agent", "responsibility": "Generates remediation suggestions and markdown reports"},
    {"name": "Report Agent", "responsibility": "Generates security assessment reports"},
    {"name": "Notifier Agent", "responsibility": "Sends notifications about scan results and findings"},
    {"name": "Self Audit Agent", "responsibility": "Performs scheduled security self-assessments of the platform"},
]


def default_agent_states() -> list[dict[str, Any]]:
    return [
        {
            "name": a["name"],
            "applicability": "IDLE",
            "responsibility": a["responsibility"],
            "current_module": None,
            "progress": 0,
            "last_updated": None,
            "detail": "",
        }
        for a in AGENT_DEFINITIONS
    ]


def build_pentest_agent_states(current_module: str | None = None, detail: str = "") -> list[dict[str, Any]]:
    states = default_agent_states()
    now = datetime.now(timezone.utc).isoformat()
    for state in states:
        name = state["name"]
        if name == "Pentest Agent":
            state["applicability"] = "RUNNING"
            state["current_module"] = current_module
            state["detail"] = detail or "Executing authorized security test"
            state["last_updated"] = now
        elif name in ("Sandbox Manager Agent",):
            state["applicability"] = "NOT_APPLICABLE"
            state["detail"] = "Not required for this run"
        elif name == "Self Audit Agent":
            state["applicability"] = "IDLE"
            state["detail"] = "Not running"
        else:
            state["applicability"] = "NOT_APPLICABLE"
            state["detail"] = "Not used in authorized test mode"
    return states


def build_defend_agent_states(scan_status: str, current_phase: str | None = None) -> list[dict[str, Any]]:
    states = default_agent_states()
    now = datetime.now(timezone.utc).isoformat()
    is_running = scan_status in ("queued", "running", "cancelling")
    is_complete = scan_status in ("complete",)
    is_error = scan_status == "error"
    for state in states:
        name = state["name"]
        if name == "Self Audit Agent":
            state["applicability"] = "IDLE"
            state["detail"] = "Next scheduled audit: daily at 02:00 UTC"
            continue
        if is_running:
            state["applicability"] = "RUNNING" if name in (
                "Orchestrator Agent", "Scanner Agent", "Shadow Recon Agent",
                "Analyzer Agent", "CVE Matcher Agent",
            ) else "WAITING"
            state["last_updated"] = now
        elif is_complete:
            state["applicability"] = "COMPLETED"
            state["progress"] = 100
        elif is_error:
            state["applicability"] = "FAILED"
        else:
            state["applicability"] = "IDLE"
    return states


def build_lab_agent_states() -> list[dict[str, Any]]:
    states = default_agent_states()
    now = datetime.now(timezone.utc).isoformat()
    for state in states:
        name = state["name"]
        if name == "Sandbox Manager Agent":
            state["applicability"] = "RUNNING"
            state["detail"] = "Managing lab environment"
            state["last_updated"] = now
        elif name in ("Pentest Agent",):
            state["applicability"] = "RUNNING"
            state["detail"] = "Testing lab surfaces"
            state["last_updated"] = now
        elif name == "Self Audit Agent":
            state["applicability"] = "IDLE"
            state["detail"] = "Not running"
        else:
            state["applicability"] = "NOT_APPLICABLE"
            state["detail"] = "Not used in lab mode"
    return states


def build_self_audit_agent_states(audit_status: str) -> list[dict[str, Any]]:
    states = default_agent_states()
    now = datetime.now(timezone.utc).isoformat()
    for state in states:
        name = state["name"]
        if name == "Self Audit Agent":
            lifecycle_map = {
                "never_run": "IDLE",
                "queued": "QUEUED",
                "running": "RUNNING",
                "complete": "COMPLETED",
                "error": "FAILED",
                "cancelled": "FAILED",
            }
            state["applicability"] = lifecycle_map.get(audit_status, "IDLE")
            state["last_updated"] = now
            state["detail"] = f"Self-audit status: {audit_status}"
        elif name == "Sandbox Manager Agent":
            state["applicability"] = "NOT_APPLICABLE"
            state["detail"] = "Not required for self-audit"
        elif name == "Pentest Agent":
            state["applicability"] = "NOT_APPLICABLE"
            state["detail"] = "Not required for self-audit"
        else:
            state["applicability"] = "NOT_APPLICABLE"
            state["detail"] = "Not used in self-audit mode"
    return states


async def update_authorized_test_execution(
    job_id: str,
    lifecycle: str,
    target_url: str = "",
    progress_percent: int = 0,
    current_module: str | None = None,
    current_phase: str | None = None,
    surfaces_total: int = 0,
    surfaces_completed: int = 0,
    findings_count: int = 0,
    error_message: str | None = None,
    error_code: str | None = None,
    scan_id: int | None = None,
    is_lab: bool = False,
    authorization_status: str = "",
) -> None:
    agent_states = build_pentest_agent_states(current_module=current_module, detail=current_phase or "")
    if is_lab:
        agent_states = build_lab_agent_states()

    await upsert_execution_status(
        execution_type="LAB_OPERATION" if is_lab else "AUTHORIZED_TEST",
        lifecycle=lifecycle,
        job_id=job_id,
        scan_id=scan_id,
        target_url=target_url,
        progress_percent=progress_percent,
        current_module=current_module,
        current_phase=current_phase,
        surfaces_total=surfaces_total,
        surfaces_completed=surfaces_completed,
        findings_count=findings_count,
        agent_states=agent_states,
        error_message=error_message,
        error_code=error_code,
        is_lab=is_lab,
        authorization_status=authorization_status,
    )


_LIFECYCLE_UPPER = {
    "queued": "QUEUED", "running": "RUNNING", "complete": "COMPLETED",
    "failed": "FAILED", "error": "FAILED", "cancelled": "CANCELLED",
    "starting": "STARTING", "paused": "PAUSED", "idle": "IDLE",
}


async def update_defend_scan_execution(
    scan_id: int,
    lifecycle: str,
    target_url: str = "",
    progress_percent: int = 0,
    current_phase: str | None = None,
    findings_count: int = 0,
    error_message: str | None = None,
) -> None:
    db_lc = _LIFECYCLE_UPPER.get(lifecycle.lower(), lifecycle.upper())
    agent_states = build_defend_agent_states(lifecycle.lower(), current_phase=current_phase)
    await upsert_execution_status(
        execution_type="DEFEND_SCAN",
        lifecycle=db_lc,
        scan_id=scan_id,
        target_url=target_url,
        progress_percent=progress_percent,
        current_phase=current_phase,
        findings_count=findings_count,
        agent_states=agent_states,
        error_message=error_message,
    )


async def update_self_audit_execution(
    lifecycle: str,
    scan_id: int | None = None,
    target_url: str = "",
    progress_percent: int = 0,
    findings_count: int = 0,
    error_message: str | None = None,
) -> None:
    agent_states = build_self_audit_agent_states(lifecycle.lower())
    db_lifecycle = _LIFECYCLE_UPPER.get(lifecycle.lower(), lifecycle.upper())
    await upsert_execution_status(
        execution_type="SELF_AUDIT",
        lifecycle=db_lifecycle,
        scan_id=scan_id,
        target_url=target_url,
        progress_percent=progress_percent,
        findings_count=findings_count,
        agent_states=agent_states,
        error_message=error_message,
    )


async def clear_execution() -> None:
    await upsert_execution_status(lifecycle="IDLE")


async def is_any_execution_running() -> bool:
    status = await get_execution_status()
    if status is None:
        return False
    return status.get("lifecycle") in ("QUEUED", "STARTING", "RUNNING", "PAUSED")
