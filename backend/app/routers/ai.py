import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth_middleware import get_current_user
from app.config import get_settings
from app.database import (
    add_audit_log,
    get_audit_logs,
    get_finding,
    get_findings,
    get_previous_scan_for_target,
    get_scan,
    get_scan_artifacts,
    set_scan_artifacts,
)
from app.agents.ai_tutor import create_ai_tutor_agent
from app.models import AITutorRequest, AITutorResponse
from app.services.ai_analyst import AskPhantomScanResponder, create_ai_security_analyst
from app.services.openrouter_client import ai_usage_logger, call_openrouter
from app.services.enterprise_access import enterprise_id_for, filter_findings_for_user, require_scan_access

router = APIRouter(prefix="/api/ai", tags=["ai"])


class AskPhantomScanRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


async def _verify_scan_ownership(scan_id: int, user: dict[str, Any]) -> dict[str, Any]:
    return await require_scan_access(scan_id, user)


async def build_scan_analysis(scan_id: int, user: dict[str, Any], *, refresh: bool = False) -> dict[str, Any]:
    scan = await _verify_scan_ownership(scan_id, user)
    artifacts = await get_scan_artifacts(scan_id)
    if artifacts and artifacts.get("ai_analyst_output") and not refresh:
        return {"scan_id": scan_id, **artifacts["ai_analyst_output"]}

    findings = filter_findings_for_user(await get_findings(scan_id), user)
    previous_scan = await get_previous_scan_for_target(str(scan["target_url"]), scan_id)
    if previous_scan and enterprise_id_for(user) and previous_scan.get("enterprise_id") != enterprise_id_for(user):
        previous_scan = None
    previous_findings = await get_findings(int(previous_scan["id"])) if previous_scan else []
    previous_artifacts = await get_scan_artifacts(int(previous_scan["id"])) if previous_scan else None
    logs = await get_audit_logs(scan_id)
    analysis = await create_ai_security_analyst().analyze(
        scan=scan,
        findings=findings,
        artifacts=artifacts or {},
        previous_scan=previous_scan,
        previous_findings=previous_findings,
        previous_artifacts=previous_artifacts,
        logs=logs,
    )
    await set_scan_artifacts(scan_id, ai_analyst_output=analysis)
    await add_audit_log(
        scan_id,
        "AI Security Analyst Agent",
        "analysis_generated",
        f"Generated AI analyst output with {len(analysis.get('priorities', []))} active priorities",
        user_id=user["id"],
    )
    return {"scan_id": scan_id, **analysis}


@router.get("/scan/{scan_id}/analysis")
async def scan_analysis(
    scan_id: int,
    refresh: bool = Query(default=False),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    return await build_scan_analysis(scan_id, user, refresh=refresh)


@router.post("/scan/{scan_id}/ask")
async def ask_phantomscan(
    scan_id: int,
    payload: AskPhantomScanRequest,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    analysis = await build_scan_analysis(scan_id, user, refresh=False)
    artifacts = await get_scan_artifacts(scan_id)
    findings = filter_findings_for_user(await get_findings(scan_id), user)
    answer = await _ask_openrouter(scan_id, payload.question, analysis, findings)
    ai_note: str | None = None
    citations: list[Any] = []
    if answer:
        pass
    else:
        if not get_settings().openrouter_api_key:
            ai_note = "OpenRouter is not configured. Set OPENROUTER_API_KEY in backend/.env."
        else:
            ai_note = _openrouter_failure_note()
        deterministic = AskPhantomScanResponder().answer(payload.question, analysis, findings, artifacts)
        answer = deterministic["answer"]
        citations = deterministic.get("citations", [])
    await add_audit_log(
        scan_id,
        "AI Security Analyst Agent",
        "question_answered",
        f"Answered Ask PhantomScan question: {payload.question[:200]}" + (f" (AI unavailable: {ai_note})" if ai_note else ""),
        user_id=user["id"],
    )
    return {"scan_id": scan_id, "question": payload.question, "answer": answer, "citations": citations, "grounded": bool(analysis), "can_start_active_test": False, "ai_note": ai_note}


def _openrouter_failure_note() -> str | None:
    # ponytail: reads the global logger's last entry; fine for the local single-user
    # ask flow, revisit if concurrent ask throughput ever matters.
    logs = ai_usage_logger.get_logs()
    if not logs:
        return None
    last = logs[-1]
    status = last.get("response_status", "")
    error = (last.get("error") or "").strip()
    if status.startswith("error_"):
        code = status[len("error_"):]
        if code == "429":
            return "OpenRouter rate limit hit (free daily requests used up). Add credits or wait for the daily reset."
        if code == "401":
            return "OpenRouter rejected the API key (401). Check OPENROUTER_API_KEY."
        return f"OpenRouter request failed (HTTP {code}). {error}".strip()
    if status == "failed":
        return f"OpenRouter request failed after retries. {error}".strip()
    if status == "success":
        return "OpenRouter returned an empty response."
    return None


async def _ask_openrouter(
    scan_id: int, question: str, analysis: dict[str, Any], findings: list[dict[str, Any]]
) -> str:
    if not get_settings().openrouter_api_key:
        return ""
    evidence = {
        "target_url": analysis.get("target_url"),
        "security_summary": analysis.get("security_summary"),
        "priorities": [
            {"title": p.get("title"), "endpoint": p.get("endpoint"), "severity": p.get("severity"), "recommended_action": p.get("recommended_action")}
            for p in analysis.get("priorities", [])
        ][:10],
        "root_causes": [
            {"category": rc.get("category"), "findings": [f.get("title") for f in rc.get("findings", [])]}
            for rc in analysis.get("root_causes", [])
        ],
        "remediation_plan": analysis.get("remediation_plan"),
        "findings": [
            {"title": f.get("title"), "severity": f.get("severity"), "endpoint": f.get("endpoint"), "recommendation": f.get("recommendation") or f.get("fix")}
            for f in findings
        ][:15],
    }
    system_prompt = (
        "You are PhantomScan's remediation advisor. Based ONLY on the provided scan evidence, "
        "answer the user's question directly and concretely: state exactly what to update/fix, "
        "ordered by priority, citing endpoints, files, or config keys where available. "
        "Do not invent findings that are not in the evidence. Keep it under 300 words."
    )
    prompt = f"SCAN EVIDENCE:\n{json.dumps(evidence, default=str, ensure_ascii=False)}\n\nQUESTION: {question}"
    # ponytail: free models have small context windows; cap prompt to avoid empty responses.
    max_prompt_chars = 8000
    if len(prompt) > max_prompt_chars:
        prompt = prompt[:max_prompt_chars] + f"\n\n[ evidence truncated for context limit ]\n\nQUESTION: {question}"
    return await call_openrouter(prompt, system_prompt=system_prompt, max_tokens=600, scan_id=scan_id)


@router.get("/findings/{finding_id}/explain")
async def explain_finding(
    finding_id: int,
    language: Literal["en", "hi"] = Query(default="en"),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    finding = await get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    # Verify ownership via scan
    scan = await _verify_scan_ownership(int(finding["scan_id"]), user)
    if not filter_findings_for_user([finding], user):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    explanation = await create_ai_security_analyst().explain_finding_cached(finding, language=language)
    return {"finding_id": finding_id, "language": language, **explanation, "can_start_active_test": False}


@router.post("/tutor/chat", response_model=AITutorResponse)
async def tutor_chat(
    request: AITutorRequest,
    user: dict = Depends(get_current_user),
) -> AITutorResponse:
    """Chat with the AI tutor about a finding (or general security question)."""
    finding_context: dict[str, Any] = dict(request.context or {})
    scan_id: int | None = None

    if request.finding_id is not None:
        finding = await get_finding(request.finding_id)
        if finding is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        scan = await _verify_scan_ownership(int(finding["scan_id"]), user)
        if not filter_findings_for_user([finding], user):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        scan_id = finding.get("scan_id")
        finding_context.setdefault("title", finding.get("title", ""))
        finding_context.setdefault("category", finding.get("category", ""))
        finding_context.setdefault("severity", finding.get("severity", ""))
        finding_context.setdefault("evidence", finding.get("evidence", ""))
        finding_context.setdefault("recommendation", finding.get("recommendation", "") or finding.get("fix", ""))
        finding_context.setdefault("file_path", finding.get("file_path", ""))
        finding_context.setdefault("code_snippet", finding.get("code_snippet", ""))

    result = await create_ai_tutor_agent().run(
        finding_id=request.finding_id or 0,
        question=request.question,
        context=finding_context,
        scan_id=scan_id,
        user_level=request.user_level,
    )

    if scan_id is not None:
        await add_audit_log(
            scan_id,
            "AI Tutor Agent",
            "tutor_chat",
            f"Answered tutor question: {request.question[:200]}",
            user_id=user["id"],
        )

    return AITutorResponse(
        answer=result.get("answer", ""),
        explanation=result.get("explanation"),
        code_examples=result.get("code_examples", []),
        references=result.get("references", []),
        follow_up_questions=result.get("follow_up_questions", []),
        confidence=result.get("confidence", 0.0),
    )
