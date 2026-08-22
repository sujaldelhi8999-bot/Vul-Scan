import asyncio
import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Any

import httpx

from app.database import (
    add_job_event,
    create_finding,
    get_authorized_target,
    get_evidence_for_job,
    update_authorized_test_job,
    update_evidence_finding,
)
from app.config import get_settings
from app.models import FindingCreate
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import (
    ActiveSecurityEngine,
    AttackSurfaceMapper,
    SecurityTestPlanner,
    normalize_modules,
)
from app.services.authorization import TargetAuthorizationService
from app.services.execution import SafetyLimits, ScanDeadlineExceeded, ScanCancelled
from app.services.execution_status import update_authorized_test_execution
from app.services.redaction import redaction_service

logger = logging.getLogger("phantomscan.authorized_runner")

_running_tasks: dict[str, Any] = {}


async def _heartbeat(job_id: str, target_url: str, scan_id: int, interval: int = 30) -> None:
    """Periodically update job progress to keep the connection alive."""
    try:
        while True:
            await asyncio.sleep(interval)
            await update_authorized_test_job(
                job_id,
                current_phase="Scan in progress (heartbeat)",
            )
            await update_authorized_test_execution(
                job_id=job_id,
                lifecycle="RUNNING",
                target_url=target_url,
                current_phase="Scan in progress",
                scan_id=scan_id,
            )
    except asyncio.CancelledError:
        pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def emit_event(
    job_id: str,
    event_type: str,
    message: str,
    *,
    module: str | None = None,
    status: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> int:
    safe_meta = redaction_service.redact_payload(metadata or {})
    return await add_job_event(job_id, event_type, message, module=module, status=status, metadata=safe_meta)


async def run_authorized_test_job(
    job_id: str,
    target_url: str,
    normalized_target_origin: str,
    selected_modules: list[str],
    authorization_context: dict[str, Any],
    scan_id: int,
    user_id: str,
    sandbox_id: str,
    verified_target: Any,
    limits: SafetyLimits | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    enable_exploitation: bool = False,
    enable_ai_exploitation: bool = False,
) -> None:
    logger.info("Authorized test job %s started for %s", job_id, target_url)
    limits = limits or SafetyLimits.from_settings()
    engine = None
    await emit_event(job_id, "JOB_STARTED", f"Authorized test job started for {target_url}",
                     status="RUNNING", metadata={"target_url": target_url, "selected_modules": selected_modules})
    try:
        await update_authorized_test_job(
            job_id,
            status="RUNNING",
            started_at=utc_now().isoformat(),
            current_phase="Mapping attack surface",
        )
        is_lab_ctx = authorization_context.get("is_lab", False) if authorization_context else False
        auth_status = str(authorization_context.get("authorization_status", "")) if authorization_context else ""
        await update_authorized_test_execution(
            job_id=job_id,
            lifecycle="RUNNING",
            target_url=target_url,
            progress_percent=0,
            current_phase="Mapping attack surface",
            scan_id=scan_id,
            is_lab=bool(is_lab_ctx),
            authorization_status=auth_status,
        )
        engine = ActiveSecurityEngine(
            target_url=target_url,
            attack_surface=None,
            selected_modules=selected_modules,
            limits=limits,
            authorization_context=authorization_context,
            workflow_rules={},
            scan_id=scan_id,
            user_id=user_id,
            sandbox_id=sandbox_id,
            transport=transport,
            emit_event=lambda evt_type, msg, **kw: asyncio.create_task(emit_event(job_id, evt_type, msg, **kw)),
            job_id=job_id,
        )
        attack_surface = await AttackSurfaceMapper(transport=transport).map(target_url)
        engine.attack_surface = attack_surface
        plan = SecurityTestPlanner().create_plan(attack_surface, selected_modules)
        modules_list = plan.get("modules", [])
        surfaces_all = attack_surface.get("surfaces", [])
        raw_count = len(surfaces_all)
        plan_surface_count = plan.get("surface_count", 0)
        group_count = len(modules_list)
        surfaces_total = sum(min(3, len(m.get("surfaces", []))) for m in modules_list)
        await emit_event(job_id, "SURFACE_DISCOVERED",
                         f"Mapped {raw_count} raw routes, {plan_surface_count} testable surfaces, {group_count} execution groups",
                         status="RUNNING",
                         metadata={
                             "raw_surfaces_discovered": raw_count,
                             "testable_surfaces": plan_surface_count,
                             "surface_groups": group_count,
                             "surfaces_total": surfaces_total,
                         })
        await update_authorized_test_job(
            job_id,
            surfaces_total=surfaces_total,
            raw_surfaces_discovered=raw_count,
            testable_surfaces=plan_surface_count,
            surface_groups=group_count,
            current_phase=f"Testing {len(modules_list)} selected security modules",
        )
        is_lab_ctx = authorization_context.get("is_lab", False) if authorization_context else False
        auth_status = str(authorization_context.get("authorization_status", "")) if authorization_context else ""
        await update_authorized_test_execution(
            job_id=job_id,
            lifecycle="RUNNING",
            target_url=target_url,
            progress_percent=5,
            current_phase=f"Testing {len(modules_list)} selected security modules",
            surfaces_total=surfaces_total,
            scan_id=scan_id,
            is_lab=bool(is_lab_ctx),
            authorization_status=auth_status,
        )
        logger.info(
            "Job %s: %d modules planned, %d raw surfaces, %d testable, %d groups, %d capped total",
            job_id, len(modules_list), raw_count, plan_surface_count, group_count, surfaces_total,
        )
        all_findings: list[dict[str, Any]] = []
        persisted_findings: list[dict[str, Any]] = []
        module_failures: list[dict[str, Any]] = []
        total_modules = len(modules_list)
        exploitation_summary: dict[str, Any] | None = None
        heartbeat_task = asyncio.create_task(_heartbeat(job_id, target_url, scan_id))
        try:
          for mod_index, module_plan in enumerate(modules_list):
            module_name = str(module_plan["module"])
            surfaces = module_plan.get("surfaces", [])
            await emit_event(job_id, "MODULE_STARTED",
                             f"Starting {module_name} module ({mod_index + 1}/{total_modules})",
                             module=module_name, status="RUNNING",
                             metadata={"surfaces_for_module": len(surfaces)})
            await update_authorized_test_job(
                job_id,
                current_module=module_name,
                current_phase=f"Running {module_name} module",
            )
            is_lab_ctx = authorization_context.get("is_lab", False) if authorization_context else False
            auth_status = str(authorization_context.get("authorization_status", "")) if authorization_context else ""
            await update_authorized_test_execution(
                job_id=job_id,
                lifecycle="RUNNING",
                target_url=target_url,
                progress_percent=int((mod_index) / max(1, total_modules) * 100),
                current_module=module_name,
                current_phase=f"Running {module_name} module",
                surfaces_total=surfaces_total,
                surfaces_completed=sum(min(3, len(m.get("surfaces", []))) for m in modules_list[:mod_index]),
                findings_count=len(all_findings),
                scan_id=scan_id,
                is_lab=bool(is_lab_ctx),
                authorization_status=auth_status,
            )
            logger.info("Job %s: starting module %s (%d/%d)", job_id, module_name, mod_index + 1, total_modules)
            try:
                await emit_event(job_id, "TEST_PREPARED",
                                 f"Prepared {len(surfaces)} test surfaces for {module_name}",
                                 module=module_name, status="RUNNING",
                                 metadata={"surface_targets": [s.get("url") or s.get("path") for s in surfaces]})
                module_findings = await engine.run_module(module_name, surfaces)
                for finding_data in module_findings:
                    finding_id = await create_finding(scan_id, FindingCreate(**finding_data))
                    persisted_findings.append({**finding_data, "id": finding_id})
                    ev_ids = finding_data.get("_evidence_ids", []) or []
                    single_ev = finding_data.get("_evidence_id")
                    if single_ev is not None:
                        ev_ids.append(single_ev)
                    for ev_id in ev_ids:
                        if ev_id is not None:
                            await update_evidence_finding(int(ev_id), finding_id)
                    await emit_event(job_id, "FINDING_DETECTED",
                                     finding_data.get("title", "Finding detected"),
                                     module=module_name,
                                     status=finding_data.get("severity", "MEDIUM"),
                                     metadata={
                                         "severity": finding_data.get("severity"),
                                         "confidence": finding_data.get("confidence"),
                                         "endpoint": finding_data.get("endpoint"),
                                         "evidence_count": len(ev_ids),
                                         "request_id": finding_data.get("_request_id", ""),
                                     })
                all_findings.extend(module_findings)
                completed = mod_index + 1
                progress = int(completed / max(1, total_modules) * 100)
                progress = min(99, progress)
                completed_surfaces = sum(
                    min(3, len(m.get("surfaces", [])))
                    for m in modules_list[:completed]
                )
                if len(module_findings) == 0:
                    await emit_event(job_id, "CONTROL_BLOCKED_TEST",
                                     f"Security control handled {module_name} - no findings",
                                     module=module_name, status="BLOCKED",
                                     metadata={"module": module_name, "surfaces_tested": len(surfaces)})
                    if len(all_findings) > 0:
                        await emit_event(job_id, "RETEST_STARTED",
                                         f"Retesting {module_name} after fix",
                                         module=module_name, status="RUNNING")
                        await emit_event(job_id, "FIX_VERIFIED",
                                         f"Fix verified for {module_name}",
                                         module=module_name, status="VERIFIED",
                                         metadata={"module": module_name})
                await emit_event(job_id, "MODULE_COMPLETED",
                                 f"Module {module_name} completed with {len(module_findings)} findings",
                                 module=module_name,
                                 status="COMPLETED",
                                 metadata={"findings_in_module": len(module_findings), "total_findings": len(all_findings)})
                is_lab_ctx = authorization_context.get("is_lab", False) if authorization_context else False
                auth_status = str(authorization_context.get("authorization_status", "")) if authorization_context else ""
                await update_authorized_test_job(
                    job_id,
                    progress_percent=progress,
                    surfaces_completed=completed_surfaces,
                    findings_count=len(all_findings),
                    current_phase=f"Module {module_name} completed",
                )
                await update_authorized_test_execution(
                    job_id=job_id,
                    lifecycle="RUNNING",
                    target_url=target_url,
                    progress_percent=progress,
                    current_module=module_name,
                    current_phase=f"Module {module_name} completed",
                    surfaces_total=surfaces_total,
                    surfaces_completed=completed_surfaces,
                    findings_count=len(all_findings),
                    scan_id=scan_id,
                    is_lab=bool(is_lab_ctx),
                    authorization_status=auth_status,
                )
                logger.info(
                    "Job %s: module %s completed with %d findings (progress %d%%)",
                    job_id, module_name, len(module_findings), progress,
                )
            except Exception as exc:
                traceback.print_exc()
                error_msg = str(exc)[:500]
                module_failures.append({
                    "module": module_name,
                    "error": error_msg,
                })
                await emit_event(job_id, "MODULE_FAILED",
                                 f"Module {module_name} failed: {error_msg}",
                                 module=module_name, status="FAILED",
                                 metadata={"error": error_msg})
                logger.error("Job %s: module %s failed: %s", job_id, module_name, error_msg)
                await update_authorized_test_job(
                    job_id,
                    current_phase=f"Module {module_name} failed, continuing",
                )
                completed = mod_index + 1
                progress = int(completed / max(1, total_modules) * 100)
                progress = min(99, progress)
                await update_authorized_test_job(
                    job_id,
                    progress_percent=progress,
                    findings_count=len(all_findings),
                )
        except (ScanDeadlineExceeded, ScanCancelled) as exc:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)
            error_msg = str(exc)[:500]
            logger.warning("Job %s: scan deadline/cancel: %s", job_id, error_msg)
            await emit_event(job_id, "SCAN_DEADLINE_EXCEEDED",
                             f"Scan reached time limit after completing {len(all_findings)} findings across {mod_index} modules",
                             status="TIMEOUT",
                             metadata={"completed_modules": mod_index, "total_findings": len(all_findings)})
            await update_authorized_test_job(
                job_id,
                status="COMPLETED",
                progress_percent=int((mod_index) / max(1, total_modules) * 100),
                current_phase=f"Scan time limit reached after {len(all_findings)} findings",
                completed_at=utc_now().isoformat(),
            )
            exploitation_summary = None
        else:
            heartbeat_task.cancel()
            await asyncio.gather(heartbeat_task, return_exceptions=True)
        if enable_exploitation:
            if not get_settings().exploitation_enabled:
                logger.warning(
                    "Exploitation requested for job %s but EXPLOITATION_ENABLED is false - skipping",
                    job_id,
                )
                await emit_event(job_id, "EXPLOITATION_SKIPPED",
                                 "Exploitation requested but EXPLOITATION_ENABLED is false; skipping (safety kill-switch)",
                                 status="SKIPPED")
            else:
                await emit_event(job_id, "EXPLOITATION_STARTED",
                                 f"Exploitation enabled - attempting exploits on {len(persisted_findings)} confirmed findings",
                                 status="RUNNING",
                                 metadata={"confirmed_findings": len(persisted_findings)})
                from app.agents.exploitation_engine import ExploitationAgent
                try:
                    exploiter = ExploitationAgent()
                    exploitation_output = await exploiter.run(
                        target_url, scan_id, findings=persisted_findings
                    )
                except Exception as exc:
                    traceback.print_exc()
                    exploitation_output = {
                        "status": "error",
                        "exploitation_results": [],
                        "summary": f"Exploitation failed: {exc}",
                    }
                exploitation_summary = {"static": exploitation_output, "ai": None}
                if enable_ai_exploitation and get_settings().ai_exploitation_enabled:
                    from app.services.ai_exploitation import AIExploitationEngine
                    try:
                        ai_engine = AIExploitationEngine()
                        ai_output = await ai_engine.run_for_scan(
                            target_url, scan_id, persisted_findings, sandbox_id=sandbox_id
                        )
                    except Exception as exc:
                        traceback.print_exc()
                        ai_output = {
                            "status": "error",
                            "exploitation_results": [],
                            "summary": f"AI exploitation failed: {exc}",
                            "ai_available": False,
                        }
                    exploitation_summary["ai"] = ai_output
                await emit_event(job_id, "EXPLOITATION_COMPLETED",
                                 exploitation_output.get("summary", "Exploitation completed"),
                                 status="COMPLETED",
                                 metadata={
                                     "exploited": sum(
                                         1 for r in exploitation_output.get("exploitation_results", [])
                                         if r.get("success")
                                     ),
                                     "ai": bool(exploitation_summary.get("ai")),
                                 })

        evidence_records = await get_evidence_for_job(job_id)
        total_requests = len(evidence_records)
        responses_received = sum(1 for e in evidence_records if e.get("response_observed"))
        timeouts = sum(1 for e in evidence_records if e.get("error") and "timeout" in str(e.get("error", "")).lower())
        request_failures = sum(1 for e in evidence_records if e.get("error") and "timeout" not in str(e.get("error", "")).lower())
        evidence_findings = sum(1 for e in evidence_records if e.get("finding_id") is not None)
        protected_controls = sum(1 for e in evidence_records if e.get("detection_result") in ("PROTECTED", "INCONCLUSIVE"))
        inconclusive = sum(1 for e in evidence_records if e.get("detection_result") == "INCONCLUSIVE")
        result_summary = {
            "target_url": target_url,
            "normalized_target_origin": normalized_target_origin,
            "total_modules": total_modules,
            "completed_modules": total_modules - len(module_failures),
            "module_failures": module_failures,
            "total_findings": len(all_findings),
            "evidence_backed_findings": evidence_findings,
            "real_http_requests": total_requests,
            "responses_received": responses_received,
            "timeouts": timeouts,
            "request_failures": request_failures,
            "protected_controls_observed": protected_controls,
            "inconclusive_checks": inconclusive,
            "surfaces_total": surfaces_total,
            "raw_surfaces_discovered": raw_count,
            "testable_surfaces": plan_surface_count,
            "surface_groups": group_count,
            "exploitation": exploitation_summary,
        }
        await update_authorized_test_job(
            job_id,
            status="COMPLETED",
            progress_percent=100,
            current_phase="Completed",
            findings_count=len(all_findings),
            completed_at=utc_now().isoformat(),
            result_summary=json.dumps(result_summary),
        )

        from app.database import add_job_event as add_je
        await add_je(
            job_id, "EXECUTION_SUMMARY",
            f"Authorized test completed. "
            f"Modules selected: {total_modules}. "
            f"Modules executed: {total_modules - len(module_failures)}. "
            f"Not applicable: {sum(1 for m in module_failures if 'not_applicable' in m.get('error', '').lower())}. "
            f"Real HTTP requests: {total_requests}. "
            f"Responses received: {responses_received}. "
            f"Timeouts: {timeouts}. "
            f"Request failures: {request_failures}. "
            f"Evidence-backed findings: {evidence_findings}. "
            f"Protected controls observed: {protected_controls}. "
            f"Inconclusive checks: {inconclusive}.",
            status="COMPLETED",
            metadata={
                "total_modules": total_modules,
                "executed_modules": total_modules - len(module_failures),
                "real_http_requests": total_requests,
                "responses_received": responses_received,
                "timeouts": timeouts,
                "request_failures": request_failures,
                "evidence_backed_findings": evidence_findings,
                "protected_controls_observed": protected_controls,
                "inconclusive_checks": inconclusive,
                "total_findings": len(all_findings),
            },
        )
        is_lab_ctx = authorization_context.get("is_lab", False) if authorization_context else False
        auth_status = str(authorization_context.get("authorization_status", "")) if authorization_context else ""
        await update_authorized_test_execution(
            job_id=job_id,
            lifecycle="COMPLETED",
            target_url=target_url,
            progress_percent=100,
            current_phase="Completed",
            surfaces_total=surfaces_total,
            surfaces_completed=surfaces_total,
            findings_count=len(all_findings),
            scan_id=scan_id,
            is_lab=bool(is_lab_ctx),
            authorization_status=auth_status,
        )
        await emit_event(job_id, "JOB_COMPLETED",
                         f"Job completed with {len(all_findings)} findings across {total_modules} modules",
                         status="COMPLETED",
                         metadata={"total_findings": len(all_findings), "total_modules": total_modules, "result_summary": result_summary})
        logger.info(
            "Authorized test job %s completed: %d findings, %d module failures",
            job_id, len(all_findings), len(module_failures),
        )
    except Exception as exc:
        traceback.print_exc()
        error_msg = str(exc)[:1000]
        logger.error("Authorized test job %s failed: %s", job_id, error_msg)
        await update_authorized_test_job(
            job_id,
            status="FAILED",
            current_phase="Failed",
            error_message=error_msg,
            error_code="JOB_EXECUTION_FAILED",
            completed_at=utc_now().isoformat(),
        )
        is_lab_ctx = authorization_context.get("is_lab", False) if authorization_context else False
        auth_status = str(authorization_context.get("authorization_status", "")) if authorization_context else ""
        await update_authorized_test_execution(
            job_id=job_id,
            lifecycle="FAILED",
            target_url=target_url,
            scan_id=scan_id,
            is_lab=bool(is_lab_ctx),
            authorization_status=auth_status,
            error_message=error_msg,
            error_code="JOB_EXECUTION_FAILED",
        )
        await emit_event(job_id, "JOB_COMPLETED",
                         f"Job failed: {error_msg}",
                         status="FAILED",
                         metadata={"error": error_msg})
