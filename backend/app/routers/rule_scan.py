"""Rule scan API — scan GitHub/uploaded repos with 92 regex rules + AI chat."""

import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.auth_middleware import get_current_user
from app.database import (
    create_scan,
    get_scan,
    create_finding,
    get_findings,
    update_scan_status,
)
from app.services.rule_scanner import RuleScanner
from app.services.enterprise_access import enterprise_id_for, filter_findings_for_user, require_scan_access

logger = logging.getLogger("phantomscan.rule_scan")
router = APIRouter(prefix="/api/rule-scan", tags=["rule-scan"])

_rule_scanner = RuleScanner()


class RuleScanRequest(BaseModel):
    repo_url: str | None = None
    local_path: str | None = None
    sensitivity: str = "medium"
    approval_request_id: int | None = Field(default=None, ge=1)


class RuleScanResponse(BaseModel):
    scan_id: int
    status: str
    findings_count: int
    findings: list[dict[str, Any]]


class RuleScanChatRequest(BaseModel):
    message: str


class RuleScanChatResponse(BaseModel):
    response: str
    scan_id: int


def _clone_repo(url: str, dest: str) -> str:
    """Clone a git repo shallow into dest. Returns the clone directory."""
    clone_dir = os.path.join(dest, "repo")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, clone_dir],
            check=True, capture_output=True, timeout=120,
        )
        return clone_dir
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=400, detail=f"Git clone failed: {exc.stderr.decode()[:500]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=400, detail="Git clone timed out (120s)")


@router.post("/scan", response_model=RuleScanResponse)
async def start_rule_scan(request: RuleScanRequest, user: dict = Depends(get_current_user)):
    """Scan a GitHub repo or local path with 92 regex rules."""
    if not request.repo_url and not request.local_path:
        raise HTTPException(status_code=400, detail="Provide repo_url or local_path")

    scan_id = await create_scan(
        target_url=request.repo_url or request.local_path or "",
        mode="multi_agent",
        selected_tests='["rule_scan"]',
        user_id=user["id"],
        enterprise_id=enterprise_id_for(user),
    )
    await update_scan_status(scan_id, "running")

    scan_path = request.local_path
    temp_dir = None
    try:
        if request.repo_url:
            temp_dir = tempfile.mkdtemp(prefix="rulescan-")
            scan_path = _clone_repo(request.repo_url, temp_dir)

        findings = await _rule_scanner.scan(scan_path, sensitivity=request.sensitivity)

        for f in findings:
            await create_finding(scan_id, {
                "title": f.get("title", "Unknown"),
                "category": f.get("category", "other"),
                "severity": str(f.get("severity", "MEDIUM")).upper(),
                "confidence": "HIGH",
                "target": scan_path or "",
                "endpoint": f.get("file_path", ""),
                "evidence": f.get("matched_text", ""),
                "impact": f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
                "verification": "",
                "agent": "rule_scanner",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": f.get("description", ""),
                "parameter": f.get("rule_id"),
                "module": f.get("owasp_category", ""),
            })

        await update_scan_status(scan_id, "complete")
        return RuleScanResponse(
            scan_id=scan_id,
            status="complete",
            findings_count=len(findings),
            findings=findings,
        )
    except Exception as exc:
        await update_scan_status(scan_id, "error", str(exc)[:500])
        raise HTTPException(status_code=500, detail=str(exc)[:500])
    finally:
        if temp_dir:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("/{scan_id}/findings")
async def get_rule_scan_findings(scan_id: int, user: dict = Depends(get_current_user)):
    """Get all findings from a rule scan."""
    scan = await get_scan(scan_id)
    await require_scan_access(scan_id, user)
    findings = filter_findings_for_user(await get_findings(scan_id), user)
    return {"scan_id": scan_id, "findings": findings}


@router.post("/{scan_id}/chat", response_model=RuleScanChatResponse)
async def rule_scan_chat(scan_id: int, request: RuleScanChatRequest, user: dict = Depends(get_current_user)):
    """Chat about rule scan findings with AI."""
    scan = await get_scan(scan_id)
    await require_scan_access(scan_id, user)

    findings = filter_findings_for_user(await get_findings(scan_id), user)
    from app.services.rule_ai import chat_with_findings
    response = await chat_with_findings(findings, request.message, scan_id)
    return RuleScanChatResponse(response=response, scan_id=scan_id)
