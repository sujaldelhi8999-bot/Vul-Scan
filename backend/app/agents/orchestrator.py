import asyncio
import json
import logging
import os
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.agents import Agent
from app.agents.ai_explainer import AIExplainerAgent
from app.agents.ai_security_analyst import AISecurityAnalystAgent
from app.agents.analyzer import AnalyzerAgent
from app.agents.browser_security import BrowserSecurityAgent
from app.agents.cve_matcher import CVEMatcherAgent
from app.agents.exploitation.sqli import SQLIExploitationAgent
from app.agents.exploitation_engine import ExploitationAgent
from app.agents.fixer import FixerAgent
from app.agents.multi_agent_orchestrator import MultiAgentOrchestrator, SharedContext
from app.agents.notifier import NotifierAgent
from app.agents.sandbox_manager import SandboxManagerAgent
from app.agents.scanner import ScannerAgent
from app.agents.security_assessment import (
    AccessControlAgent,
    ApiSecurityAgent,
    AuthSecurityAgent,
    DependencyAgent,
    InfrastructureAgent,
    InjectionAnalysisAgent,
    SessionSecurityAgent,
    ThreatIntelligenceAgent,
    WebSocketSecurityAgent,
)
from app.agents.shadow_recon import ShadowReconAgent
from app.agents.source_coordinator import SourceCoordinatorAgent
from app.database import (
    add_audit_log,
    create_finding,
    create_scan,
    get_audit_logs,
    get_findings,
    get_previous_scan_for_target,
    get_scan_artifacts,
    list_applied_tunings,
    safe_int,
    set_scan_artifacts,
    update_evidence_finding,
    update_finding,
    update_scan_progress,
    update_scan_status,
)
from app.models import FindingCreate, ScanRequest, MultiSourceScanRequest
from app.config import get_settings
from app.services.active_gate import ActiveTargetGate
from app.services.adaptive_scan_planner import AdaptiveScanPlanner
from app.services.ai_decision_maker import AIDecisionMaker
from app.services.ai_exploitation import AIExploitationEngine
from app.services.ai.exploit_generator import generate_poc_with_retry
from app.services.ai.sandbox_executor import run_poc
from app.services.attack_graph.builder import AttackGraphBuilder
from app.services.attack_graph.sandbox_tester import SandboxTester
from app.services.attack_graph.guide_generator import HackGuideGenerator
from app.services.attack_graph.builder import AttackGraphBuilder, build_attack_graph_from_findings
from app.services.attack_graph.validator import AttackPathValidator
from app.services.authorization import TargetAuthorizationService, VerifiedTarget, canonicalize_target
from app.services.execution import SafetyLimits
from app.services.openrouter_client import call_openrouter
from app.services.reporting.context_filter import apply_context_filter
from app.services.reporting.report_generator import generate_report
from app.security import redact_sensitive
from app.services.tci import TargetComplexityIndex
from app.websockets import scan_event_broker

logger = logging.getLogger("phantomscan.orchestrator")


def _safe_timestamp(value: Any) -> datetime:
    """Parse a finding timestamp, falling back to now on failure."""
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except Exception as e:
        logger.debug("Failed to parse timestamp %r: %s", value, e)
        return datetime.now(timezone.utc)


class OrchestratorAgent(Agent):
    def __init__(self, limits: SafetyLimits | None = None) -> None:
        super().__init__("Orchestrator Agent")
        self.limits = limits or SafetyLimits.from_settings()
        self._finding_lock = asyncio.Lock()
        self._progress_lock = asyncio.Lock()
        self._progress_by_scan: dict[int, int] = {}

    async def run(
        self,
        scan_request: ScanRequest,
        scan_id: int | None = None,
        *,
        verified_target: VerifiedTarget | None = None,
        user_id: str = "local-user",
        user_role: str = "user",
        authorization_context: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        settings = get_settings()
        target = canonicalize_target(scan_request.target_url)
        scan_request = scan_request.model_copy(update={"target_url": target.url})
        verified_target, authorization_context = await self.validate_execution(
            scan_request,
            verified_target,
            user_id,
            user_role,
            authorization_context,
        )

        if scan_id is None:
            scan_id = await create_scan(
                target_url=target.url,
                mode=scan_request.mode,
                intensity=scan_request.intensity,
                selected_tests=json.dumps(scan_request.selected_tests, separators=(",", ":")),
                user_id=user_id,
                authorization_id=verified_target.id if verified_target is not None else None,
                authorization_confirmed=scan_request.authorization_confirmed,
            )

        self.scan_id = scan_id
        self.status = "active"
        await update_scan_status(scan_id, "running")
        await self.set_progress(scan_id, 2, "orchestration_started")
        await self.log_action("started", f"Orchestrating {scan_request.mode}/{scan_request.profile or scan_request.scan_depth} scan for {target.url}")
        await self.publish(scan_id, "orchestrator", {"status": "running", "progress": 2})

        try:
            if scan_request.mode == "multi_agent":
                return await self.run_multi_agent(
                    scan_request,
                    scan_id,
                    target.url,
                    user_id,
                    authorization_context,
                )

            scanner = ScannerAgent()
            shadow_recon = ShadowReconAgent()
            scanner_event, shadow_event = await self.gather_agents(
                self.run_agent("scanner", scanner.name, lambda: scanner.run(target.url, scan_id), scan_id),
                self.run_agent(
                    "shadow_recon",
                    shadow_recon.name,
                    lambda: shadow_recon.run(target.url, scan_id, scan_depth=scan_request.scan_depth),
                    scan_id,
                ),
                scan_id=scan_id,
                phase="reconnaissance_running",
                start_progress=2,
                end_progress=30,
            )
            scanner_output = scanner_event["result"]
            shadow_output = shadow_event["result"]
            await set_scan_artifacts(
                scan_id,
                scanner_output=scanner_output,
                shadow_recon_output=shadow_output,
            )
            await self.set_progress(scan_id, 30, "reconnaissance_complete")

            # Phase 2: Vulnerability Detection
            print(f"[DEBUG] scan_id={scan_id} – entering vulnerability phase")
            await self.set_progress(scan_id, 35, "vulnerability_scanning_started")
            print(f"[DEBUG] scan_id={scan_id} – set progress to 35")
            vuln_profile = str(getattr(scan_request, "scan_depth", "quick") or "quick").lower()
            if vuln_profile not in {"quick", "standard", "deep", "stealth"}:
                vuln_profile = "quick"
            # Stealth maps to deep-level modules with evasion enabled
            effective_profile = "deep" if vuln_profile == "stealth" else vuln_profile
            is_stealth = vuln_profile == "stealth" and settings.stealth_enabled
            module_timeout = {"quick": 8.0, "standard": 20.0, "deep": 45.0, "stealth": 45.0}[vuln_profile]
            from app.services.vuln_detectors import sqli_detector, xss_detector, lfi_detector, \
                cmd_injection_detector, ssrf_detector, xxe_detector, idor_detector, \
                csrf_detector, rate_limiting_detector, cors_detector, header_detector, \
                tls_detector, business_logic_detector, file_upload_detector
            from app.services.parameter_discoverer import discover_parameters
            from app.services.js_analyzer import analyze_js_files
            import bs4

            # Get HTML for parameter and JS analysis – use stealth client when in stealth mode
            print(f"[DEBUG] scan_id={scan_id} – fetching HTML for JS/param analysis (stealth={is_stealth})")
            try:
                if is_stealth:
                    from app.evasion.probe import fetch_with_stealth
                    _stealth_resp = await fetch_with_stealth(scan_request.target_url)
                    html = _stealth_resp.text
                else:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.get(scan_request.target_url)
                        html = resp.text
                print(f"[DEBUG] scan_id={scan_id} – HTML fetched ({len(html)} chars)")
            except Exception as exc:
                print(f"[DEBUG] scan_id={scan_id} – HTML fetch failed: {exc}")
                html = ""

            # Discover parameters and JS files
            params_data = discover_parameters(html)
            js_urls = [link.get('src') for link in bs4.BeautifulSoup(html, 'html.parser').find_all('script', src=True)]
            js_findings = []
            if vuln_profile != "quick":
                js_limit = 5 if vuln_profile == "standard" else len(js_urls)
                try:
                    js_findings = await asyncio.wait_for(
                        analyze_js_files(scan_request.target_url, js_urls[:js_limit]),
                        timeout=module_timeout,
                    )
                except asyncio.TimeoutError:
                    print(f"[DEBUG] scan_id={scan_id} – JS analysis TIMED OUT after {module_timeout:g}s")
            print(f"[DEBUG] scan_id={scan_id} – params={len(params_data.get('params',[]))}, js_urls={len(js_urls)}")

            # Run vulnerability detectors with profile-specific scope and budgets.
            all_params = params_data.get('params', [])
            param_limit = {"quick": 3, "standard": 8, "deep": 12, "stealth": 12}[vuln_profile]
            params = all_params[:param_limit]
            print(f"[DEBUG] scan_id={scan_id} – profile={vuln_profile}, testing {len(params)}/{len(all_params)} params, timeout={module_timeout:g}s")
            if effective_profile == "quick":
                modules = [
                    ("Security Headers", lambda: header_detector.scan_headers(scan_request.target_url, params, mode=effective_profile)),
                    ("CORS", lambda: cors_detector.scan_cors(scan_request.target_url, params, mode=effective_profile)),
                    ("TLS", lambda: tls_detector.scan_tls(scan_request.target_url, params, mode=effective_profile)),
                    ("Basic SQLi", lambda: sqli_detector.scan_sqli(scan_request.target_url, params, mode=effective_profile, limit=2)),
                    ("Basic XSS", lambda: xss_detector.scan_xss(scan_request.target_url, params, html=html, mode=effective_profile, limit=2)),
                    ("Basic LFI", lambda: lfi_detector.scan_lfi(scan_request.target_url, params, mode=effective_profile, limit=2)),
                ]
            elif effective_profile == "standard":
                modules = [
                    ("SQL Injection", lambda: sqli_detector.scan_sqli(scan_request.target_url, params, mode=effective_profile)),
                    ("XSS", lambda: xss_detector.scan_xss(scan_request.target_url, params, html=html, mode=effective_profile)),
                    ("LFI", lambda: lfi_detector.scan_lfi(scan_request.target_url, params, mode=effective_profile)),
                    ("Command Injection", lambda: cmd_injection_detector.scan_cmd(scan_request.target_url, params, mode=effective_profile)),
                    ("SSRF", lambda: ssrf_detector.scan_ssrf(scan_request.target_url, params, mode=effective_profile)),
                    ("IDOR", lambda: idor_detector.scan_idor(scan_request.target_url, params, mode=effective_profile)),
                    ("CSRF", lambda: csrf_detector.scan_csrf(scan_request.target_url, params, mode=effective_profile)),
                    ("Headers", lambda: header_detector.scan_headers(scan_request.target_url, params, mode=effective_profile)),
                    ("CORS", lambda: cors_detector.scan_cors(scan_request.target_url, params, mode=effective_profile)),
                    ("Rate Limiting", lambda: rate_limiting_detector.scan_rate_limiting(scan_request.target_url, params, mode=effective_profile)),
                ]
            else:
                modules = [
                    ("SQL Injection", lambda: sqli_detector.scan_sqli(scan_request.target_url, params, mode=effective_profile)),
                    ("XSS", lambda: xss_detector.scan_xss(scan_request.target_url, params, html=html, mode=effective_profile)),
                    ("LFI", lambda: lfi_detector.scan_lfi(scan_request.target_url, params, mode=effective_profile)),
                    ("Command Injection", lambda: cmd_injection_detector.scan_cmd(scan_request.target_url, params, mode=effective_profile)),
                    ("SSRF", lambda: ssrf_detector.scan_ssrf(scan_request.target_url, params, mode=effective_profile)),
                    ("IDOR", lambda: idor_detector.scan_idor(scan_request.target_url, params, mode=effective_profile)),
                    ("CSRF", lambda: csrf_detector.scan_csrf(scan_request.target_url, params, mode=effective_profile)),
                    ("Headers", lambda: header_detector.scan_headers(scan_request.target_url, params, mode=effective_profile)),
                    ("CORS", lambda: cors_detector.scan_cors(scan_request.target_url, params, mode=effective_profile)),
                    ("Rate Limiting", lambda: rate_limiting_detector.scan_rate_limiting(scan_request.target_url, params, mode=effective_profile)),
                    ("XXE", lambda: xxe_detector.scan_xxe(scan_request.target_url, mode=effective_profile)),
                    ("Business Logic", lambda: business_logic_detector.scan_business_logic(scan_request.target_url, params, html=html, mode=effective_profile)),
                    ("File Upload", lambda: file_upload_detector.scan_file_upload(scan_request.target_url, params, html=html, mode=effective_profile)),
                ]
            total = len(modules)
            findings = []
            print(f"[DEBUG] scan_id={scan_id} – starting {total} {vuln_profile} vulnerability modules (stealth={is_stealth})")
            for idx, (name, func) in enumerate(modules):
                # Stealth mode: add random delays between modules to mimic human browsing
                if is_stealth:
                    from app.core.http_client import stealth_delay
                    await stealth_delay(settings.evasion_delay_min, settings.evasion_delay_max)
                progress = 35 + int((idx / total) * 30)  # 35% → 65%
                print(f"[DEBUG] scan_id={scan_id} – [{idx+1}/{total}] {name} at {progress}%")
                await self.set_progress(scan_id, progress, f"vuln_{name.lower().replace(' ', '_')}_running")
                print(f"[DEBUG] scan_id={scan_id} – progress {progress}% published for {name}")
                try:
                    result = await asyncio.wait_for(
                        func(),
                        timeout=module_timeout,
                    )
                    if isinstance(result, list):
                        findings.extend(result)
                        print(f"[DEBUG] scan_id={scan_id} – {name} returned {len(result)} findings")
                    else:
                        findings.append(result)
                        print(f"[DEBUG] scan_id={scan_id} – {name} returned 1 finding")
                except asyncio.TimeoutError:
                    print(f"[DEBUG] scan_id={scan_id} – {name} TIMED OUT after {module_timeout:g}s")
                    await self.set_progress(scan_id, progress, f"vuln_{name.lower().replace(' ', '_')}_timed_out")
                except Exception as e:
                    print(f"[DEBUG] scan_id={scan_id} – {name} ERROR: {type(e).__name__}: {str(e)[:200]}")
                    await self.set_progress(scan_id, progress, f"vuln_{name.lower().replace(' ', '_')}_error")
            print(f"[DEBUG] scan_id={scan_id} – all modules done, setting progress to 65")
            await self.set_progress(scan_id, 65, "vulnerability_scanning_complete")

            # Add JS analysis findings
            for jf in js_findings:
                findings.append({
                    "type": "JS Info Leak",
                    "severity": "LOW",
                    "detail": jf,
                    "confidence": 50
                })

            # Apply context-aware filtering
            tech_stack = scanner_output.get("tech_stack", {})
            filtered_findings = apply_context_filter(
                findings, tech_stack, params_data['params'],
                scanner_output.get("subdomains", [])
            )

            # Phase 3: AI Verification intensity follows the scan profile.
            await self.set_progress(scan_id, 70, "ai_verification_started" if effective_profile != "quick" else "ai_verification_skipped")
            verified_findings = []
            verification_severities = {
                "quick": set(),
                "standard": {"CRITICAL"},
                "deep": {"CRITICAL", "HIGH"},
            }[effective_profile]
            verification_retries = {"standard": 1, "deep": 3}.get(effective_profile, 0)
            for finding in filtered_findings:
                severity = str(finding.get("severity", "")).upper()
                if effective_profile == "quick":
                    finding["verified"] = False
                    finding["confidence"] = 60
                elif severity in verification_severities:
                    try:
                        poc_script = await generate_poc_with_retry(finding, max_retries=verification_retries)
                        if poc_script:
                            verdict = await run_poc(poc_script)
                            finding["verified"] = verdict["success"]
                            finding["confidence"] = 95 if verdict["success"] else 50
                            finding["poc"] = poc_script if verdict["success"] else None
                    except Exception as e:
                        finding["verified"] = False
                        finding["confidence"] = 30
                else:
                    finding["verified"] = False
                verified_findings.append(finding)
            # Phase 4: Attack Graph Generation
            await self.set_progress(scan_id, 85, "attack_graph_generation")

            # Build attack graph from verified findings
            attack_graph_builder = AttackGraphBuilder()
            for f in verified_findings:
                finding = type('Finding', (), {
                    'id': f.get('id', 0),
                    'type': f.get('type', ''),
                    'severity': f.get('severity', ''),
                    'target': f.get('target', ''),
                    'param': f.get('param', ''),
                    'payload': f.get('payload', ''),
                    'evidence': f.get('evidence', '')
                })()
                attack_graph_builder.add_finding(finding)

            graph = attack_graph_builder.build()

            # Find attack paths
            all_paths = attack_graph_builder.find_all_paths()

            # Validate attack paths
            validator = AttackPathValidator(
                lambda finding: any(
                    marker in (finding.get('evidence') or '').lower()
                    for marker in ['vuln_true', 'confirmed', 'verified']
                )
            )

            validated_paths = await validator.validate_all_paths(all_paths)

            # Store attack graph and paths in artifacts
            await set_scan_artifacts(
                scan_id,
                attack_graph=graph,
                attack_paths=all_paths,
                path_validations=validated_paths,
            )

            await self.set_progress(scan_id, 90, "attack_analysis_complete")


            # Store findings in database
            await set_scan_artifacts(
                scan_id,
                vuln_findings=filtered_findings,
                verified_findings=verified_findings,
            )

            await self.set_progress(scan_id, 80, "verification_complete")

            complexity = TargetComplexityIndex().analyze_recon(scanner_output)
            await set_scan_artifacts(scan_id, tci_output=complexity)
            await self.publish(
                scan_id,
                "tci_computed",
                {
                    "score": complexity["score"],
                    "band": complexity["band"],
                    "band_label": complexity["band_label"],
                },
            )

            adaptive_plan = None
            if scan_request.mode == "pentest":
                planner = AdaptiveScanPlanner()
                adaptive_plan = planner.plan(
                    complexity,
                    scan_request,
                    self.limits,
                    await list_applied_tunings(),
                )
                self.limits = replace(self.limits, **adaptive_plan["limits"])
                await self.publish(
                    scan_id,
                    "adaptive_plan_computed",
                    {
                        "band": adaptive_plan["band"],
                        "score": adaptive_plan["score"],
                        "requests_per_second": adaptive_plan["requests_per_second"],
                        "modules": adaptive_plan["modules"],
                        "excluded_modules": adaptive_plan["excluded_modules"],
                        "rationale": adaptive_plan["rationale"],
                    },
                )
                await self.log_action(
                    "adaptive_plan",
                    f"TCI {complexity['score']}/100 ({complexity['band']}) -> "
                    f"{adaptive_plan['requests_per_second']:g} req/s, "
                    f"{len(adaptive_plan['modules'])} module(s)",
                )

            ai_decision: list[str] | None = None
            if scan_request.mode == "pentest":
                ai_decision = await self.run_ai_decision_maker(
                    target.url,
                    scan_id,
                    scanner_output,
                    scan_request.selected_tests,
                )

            analyzer = AnalyzerAgent()
            cve_matcher = CVEMatcherAgent()
            browser_security = BrowserSecurityAgent(limits=self.limits)
            analysis_timeout = max(1.0, float(getattr(get_settings(), "analysis_module_timeout", 20.0)))
            analysis_tasks = [
                self.run_agent(
                    "analyzer",
                    analyzer.name,
                    lambda: analyzer.run(target.url, scan_id, scanner_output),
                    scan_id,
                    max_retries=0,
                    timeout=analysis_timeout,
                    timeout_result={},
                    live_findings_target=target.url,
                ),
                self.run_agent(
                    "cve_matcher",
                    cve_matcher.name,
                    lambda: cve_matcher.run(scanner_output.get("tech_stack", {}), scan_id),
                    scan_id,
                    max_retries=0,
                    timeout=analysis_timeout,
                    timeout_result={"cve_matches": [], "provider_errors": [{"provider": "NVD", "error_type": "DEPENDENCY_UNAVAILABLE", "message": f"CVE matcher timed out after {analysis_timeout:g}s"}]},
                    live_findings_target=target.url,
                ),
                self.run_agent(
                    "browser_security",
                    browser_security.name,
                    lambda: browser_security.run(
                        target.url,
                        scan_id,
                        mode=scan_request.mode,
                        authorization_context=authorization_context,
                    ),
                    scan_id,
                    max_retries=0,
                    timeout=analysis_timeout,
                    timeout_result={},
                    live_findings_target=target.url,
                ),
            ]
            assessment_agents = [
                ("authentication", AuthSecurityAgent()),
                ("access_control", AccessControlAgent()),
                ("api_security", ApiSecurityAgent()),
                ("session_security", SessionSecurityAgent()),
                ("injection_analysis", InjectionAnalysisAgent()),
                ("infrastructure", InfrastructureAgent()),
                ("websocket_security", WebSocketSecurityAgent()),
                ("dependency", DependencyAgent()),
                ("threat_intelligence", ThreatIntelligenceAgent()),
            ]
            for event_name, agent in assessment_agents:
                analysis_tasks.append(
                    self.run_agent(
                        event_name,
                        agent.name,
                        lambda agent=agent: agent.run(target.url, scan_id, scanner_output, shadow_output),
                        scan_id,
                        max_retries=0,
                        timeout=analysis_timeout,
                        timeout_result={},
                        live_findings_target=target.url,
                    )
                )

            if scan_request.mode == "pentest":
                sandbox = SandboxManagerAgent(limits=self.limits)
                business_logic_tests = [item.model_dump(mode="json") for item in scan_request.business_logic_tests]
                planned_modules = (
                    adaptive_plan["modules"]
                    if adaptive_plan is not None and not scan_request.selected_tests and not ai_decision
                    else None
                )
                active_payload = {
                    "engine": "active_security",
                    "scan_id": scan_id,
                    "target_url": target.url,
                    "intensity": adaptive_plan["intensity"] if adaptive_plan is not None else scan_request.intensity,
                    "selected_modules": ai_decision or scan_request.selected_tests or planned_modules or [],
                    "selected_tests": scan_request.selected_tests,
                    "business_logic_tests": business_logic_tests,
                    "workflow_rules": {"business_logic_tests": business_logic_tests, "confidence_profile": scan_request.confidence_profile},
                    "user_id": user_id,
                    "authorization_id": authorization_context.get("authorization_id"),
                    "authorization_context": authorization_context,
                }
                analysis_tasks.append(
                    self.run_agent(
                        "sandbox_manager",
                        sandbox.name,
                        lambda: sandbox.run_active_scan(active_payload, scan_id),
                        scan_id,
                        max_retries=0,
                        live_findings_target=target.url,
                    )
                )

            analysis_events = await self.gather_agents(
                *analysis_tasks,
                scan_id=scan_id,
                phase="analysis_running",
                start_progress=30,
                end_progress=65,
            )
            active_result = next(
                (
                    event["result"]
                    for event in analysis_events
                    if event.get("agent") == "sandbox_manager" and isinstance(event.get("result"), dict)
                ),
                None,
            )
            if active_result:
                await set_scan_artifacts(scan_id, active_security_output=active_result)
                for active_event in active_result.get("events", [])[:250]:
                    if not isinstance(active_event, dict):
                        continue
                    event_name = str(active_event.get("event") or "active_security_event")
                    await self.publish(
                        scan_id,
                        event_name,
                        {
                            "details": active_event.get("details"),
                            "selected_module": active_event.get("selected_module"),
                            "result": active_event.get("result"),
                            "request_count": active_event.get("request_count"),
                            "sandbox_id": active_event.get("sandbox_id"),
                        },
                    )
            browser_result = next(
                (
                    event["result"]
                    for event in analysis_events
                    if event.get("agent") == "browser_security" and isinstance(event.get("result"), dict)
                ),
                None,
            )
            if browser_result:
                await set_scan_artifacts(scan_id, browser_security_output=browser_result)
                await self.publish(
                    scan_id,
                    "browser_observation_completed",
                    {
                        "pages": len(browser_result.get("pages", [])),
                        "network_events": len(browser_result.get("network_events", [])),
                        "apis": len(browser_result.get("api_inventory", [])),
                        "findings": len(browser_result.get("findings", [])),
                    },
                )
            request_count = max(
                (count for event in analysis_events if (count := safe_int(event["result"].get("request_count"))) is not None),
                default=0,
            )
            sandbox_id = next(
                (
                    str(event["result"]["sandbox_id"])
                    for event in analysis_events
                    if event["result"].get("sandbox_id")
                ),
                None,
            )
            await self.set_progress(
                scan_id,
                65,
                "analysis_complete",
                request_count=request_count,
                sandbox_id=sandbox_id,
            )
            findings = self.collect_findings(analysis_events, target.url)
            findings = self._apply_ml_prioritization(findings)

            critical_findings = [f for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"]
            if critical_findings:
                alert_notifier = NotifierAgent()
                for cf in critical_findings:
                    asyncio.create_task(alert_notifier.send_critical_alert(cf, target.url, scan_id))

            ai_explainer = AIExplainerAgent()
            try:
                ai_event = await self.run_agent(
                    "ai_explainer",
                    ai_explainer.name,
                    lambda: ai_explainer.run(findings, scan_id),
                    scan_id,
                    max_retries=0,
                    timeout=20.0,
                )
                enriched_findings = ai_event["result"].get("findings", findings)
            except asyncio.TimeoutError:
                await self.log_action("ai_explainer_timeout", "AI explainer timed out; continuing with deterministic findings")
                await self.publish(scan_id, "ai_explainer_timeout", {"status": "timeout", "message": "AI explainer timed out; using fallback findings", "progress": 78})
                enriched_findings = findings
            except Exception as exc:
                await self.log_action("ai_explainer_error", str(exc)[:2000])
                await self.publish(scan_id, "ai_explainer_error", {"status": "error", "message": "AI explainer failed; using fallback findings", "error": str(exc)[:500], "progress": 78})
                enriched_findings = findings
            await self.set_progress(scan_id, 78, "explanations_complete", request_count=request_count)

            persisted_findings = await self.persist_findings(scan_id, enriched_findings, target.url)
            await self.set_progress(scan_id, 86, "findings_persisted", request_count=request_count)

            exploitation_requested = (
                scan_request.enable_exploitation and scan_request.mode == "pentest"
            )
            if exploitation_requested and not settings.exploitation_enabled:
                logger.warning(
                    "Exploitation requested for scan %d but EXPLOITATION_ENABLED is false - skipping",
                    scan_id,
                )
                await add_audit_log(
                    scan_id,
                    "Exploitation Engine",
                    "exploitation",
                    "Exploitation requested but EXPLOITATION_ENABLED is false; skipping (safety kill-switch)",
                )
                exploitation_requested = False

            exploitation_result = None
            if exploitation_requested:
                await self.set_progress(scan_id, 87, "exploitation_started", request_count=request_count)
                exploiter = ExploitationAgent()
                expl_event = await self.run_agent(
                    "exploitation",
                    exploiter.name,
                    lambda: exploiter.run(target.url, scan_id, findings=persisted_findings),
                    scan_id,
                )
                exploitation_result = expl_event.get("result")
                if exploitation_result and exploitation_result.get("exploitation_results"):
                    await set_scan_artifacts(scan_id, exploitation_output=exploitation_result)
                await self.set_progress(scan_id, 89, "exploitation_complete", request_count=request_count)

            if exploitation_requested and exploitation_result:
                await self.run_sqli_exploitation(target.url, scan_id, persisted_findings)

            ai_exploitation_result = None
            ai_requested = exploitation_requested and scan_request.enable_ai_exploitation
            if ai_requested and not settings.ai_exploitation_enabled:
                logger.warning(
                    "AI exploitation requested for scan %d but AI_EXPLOITATION_ENABLED is false - skipping",
                    scan_id,
                )
                await add_audit_log(
                    scan_id,
                    "AIExploitationEngine",
                    "exploitation",
                    "AI exploitation requested but AI_EXPLOITATION_ENABLED is false; skipping",
                )
                ai_requested = False
            if ai_requested:
                ai_exploitation_result = await self.run_ai_exploitation(
                    target.url, scan_id, persisted_findings, sandbox_id=sandbox_id
                )

            fixer = FixerAgent()
            try:
                fixer_event = await self.run_agent(
                    "fixer",
                    fixer.name,
                    lambda: fixer.run(persisted_findings, scan_id),
                    scan_id,
                    max_retries=0,
                    timeout=20.0,
                )
                markdown_report = str(fixer_event["result"].get("markdown_report", ""))
            except asyncio.TimeoutError:
                await self.log_action("fixer_timeout", "Fixer report generation timed out; continuing with fallback report")
                await self.publish(scan_id, "fixer_timeout", {"status": "timeout", "message": "Report generation timed out; using fallback report", "progress": 93})
                markdown_report = f"# PhantomScan Report\n\nScan completed with {len(persisted_findings)} findings. AI report generation timed out."
            except Exception as exc:
                await self.log_action("fixer_error", str(exc)[:2000])
                await self.publish(scan_id, "fixer_error", {"status": "error", "message": "Report generation failed; using fallback report", "error": str(exc)[:500], "progress": 93})
                markdown_report = f"# PhantomScan Report\n\nScan completed with {len(persisted_findings)} findings. Report generation failed."
            if active_result and active_result.get("final_report"):
                markdown_report = f"{markdown_report}\n\n{active_result['final_report']}" if markdown_report else str(active_result["final_report"])
            if browser_result:
                browser_report = self.browser_report(browser_result)
                markdown_report = f"{markdown_report}\n\n{browser_report}" if markdown_report else browser_report
            await set_scan_artifacts(scan_id, markdown_report=markdown_report)
            await self.set_progress(scan_id, 93, "report_complete", request_count=request_count)

            artifact_context = {
                "scanner_output": scanner_output,
                "shadow_recon_output": shadow_output,
                "markdown_report": markdown_report,
                "active_security_output": active_result,
                "browser_security_output": browser_result,
            }
            ai_analyst_output = await self.run_ai_security_analyst(
                scan_id=scan_id,
                target_url=target.url,
                mode=scan_request.mode,
                intensity=scan_request.intensity,
                findings=persisted_findings,
                artifacts=artifact_context,
                request_count=request_count,
            )
            await set_scan_artifacts(scan_id, ai_analyst_output=ai_analyst_output)
            await self.set_progress(scan_id, 95, "ai_analysis_complete", request_count=request_count)

            sev_counts = {}
            for f in persisted_findings:
                s = str(f.get("severity", "INFO")).upper()
                sev_counts[s] = sev_counts.get(s, 0) + 1
            consultation = None
            try:
                consultation = await asyncio.wait_for(
                    call_openrouter(
                        json.dumps({
                            "target": target.url,
                            "total_findings": len(persisted_findings),
                            "severity_breakdown": sev_counts,
                            "top_findings": [
                                {"title": f.get("title"), "severity": f.get("severity"), "category": f.get("category"), "endpoint": f.get("endpoint")}
                                for f in persisted_findings[:20]
                            ],
                        }, default=str),
                        system_prompt=(
                            "You are PhantomScan's senior security consultant. Analyze the scan results "
                            "and provide: 1) Risk prioritization (what to fix first and why), "
                            "2) Attack chain analysis (how vulnerabilities chain together), "
                            "3) Executive summary (2-3 sentences for leadership)."
                        ),
                        max_tokens=1500,
                        scan_id=scan_id,
                        json_response=True,
                        timeout=15.0,
                        retry_limit=1,
                    ),
                    timeout=16.0,
                )
            except asyncio.TimeoutError:
                await self.log_action("ai_consultation_timeout", "AI consultation timed out; continuing without consultation")
                await self.publish(scan_id, "ai_consultation_timeout", {"status": "timeout", "message": "AI consultation timed out; deterministic report remains available", "progress": 95})
            except Exception as exc:
                await self.log_action("ai_consultation_error", str(exc)[:2000])
                await self.publish(scan_id, "ai_consultation_error", {"status": "error", "message": "AI consultation failed; deterministic report remains available", "error": str(exc)[:500], "progress": 95})
            ai_consultation = None
            if consultation:
                try:
                    ai_consultation = json.loads(consultation) if isinstance(consultation, str) else consultation
                except (json.JSONDecodeError, TypeError):
                    ai_consultation = {"raw": consultation}
                await set_scan_artifacts(scan_id, ai_consultation=ai_consultation)
                await self.publish(scan_id, "ai_consultation", {"summary": ai_consultation})
            sqli_exploitation_results = [
                f.get("exploitation_result") for f in persisted_findings
                if f.get("exploited") and f.get("exploitation_result")
            ]
            summary = {
                "scan_id": scan_id,
                "target_url": target.url,
                "mode": scan_request.mode,
                "intensity": scan_request.intensity,
                "scanner": scanner_output,
                "shadow_recon": shadow_output,
                "findings": persisted_findings,
                "markdown_report": markdown_report,
                "active_security": active_result,
                "browser_security": browser_result,
                "ai_decision": ai_decision,
                "complexity": complexity,
                "adaptive_plan": adaptive_plan,
                "ai_analyst_output": ai_analyst_output,
                "exploitation_results": sqli_exploitation_results if sqli_exploitation_results else None,
                "ai_exploitation": ai_exploitation_result,
                "ai_consultation": ai_consultation,
            }
            await self._write_report_files(summary, scan_id, target.url, markdown_report, scanner_output, shadow_output, active_result)
            notifier = NotifierAgent()
            notifier_event = await self.run_agent(
                "notifier",
                notifier.name,
                lambda: notifier.run(summary, scan_id),
                scan_id,
            )
            notification_result = notifier_event["result"]
            summary["notification"] = notification_result
            summary["status"] = "complete"
            await set_scan_artifacts(scan_id, notification_result=notification_result)
            await self.set_progress(scan_id, 97, "notification_complete", request_count=request_count)

            await update_scan_status(scan_id, "complete")
            await self.run_learning(scan_id)
            self.status = "complete"
            await self.log_action("completed", f"Scan completed with {len(persisted_findings)} findings")
            await self.publish(scan_id, "scan_complete", {"status": "complete", "progress": 100})
            return summary
        except asyncio.CancelledError:
            self.status = "cancelled"
            await update_scan_status(scan_id, "cancelled")
            await self.log_action("cancelled", "Scan was cancelled")
            await self.publish(scan_id, "scan_cancelled", {"status": "cancelled", "progress": 0})
            raise
        except Exception as exc:
            traceback.print_exc()
            self.status = "error"
            await update_scan_status(scan_id, "error", str(exc)[:1000])
            await self.log_action("error", str(exc)[:2000])
            await self.publish(scan_id, "scan_failed", {"status": "error", "error": str(exc)})
            return {"scan_id": scan_id, "status": "error", "error": str(exc)}

    async def run_multi_agent(
        self,
        scan_request: ScanRequest,
        scan_id: int,
        target_url: str,
        user_id: str = "local-user",
        authorization_context: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        """Run the multi-agent workflow (Recon -> Attack -> Exploit -> Report)."""
        context = SharedContext(
            target_url=target_url,
            scan_id=scan_id,
            scan_request=scan_request,
            host=self,
            user_id=user_id,
            authorization_context=authorization_context,
        )
        multi = MultiAgentOrchestrator(limits=self.limits, host=self)
        summary = await multi.run(context)
        await update_scan_status(scan_id, "complete")
        await self.run_learning(scan_id)
        self.status = "complete"
        await self.log_action(
            "completed", f"Multi-agent scan completed with {len(summary.get('findings', []))} findings"
        )
        await self.publish(scan_id, "scan_complete", {"status": "complete", "progress": 100})
        return summary

    async def run_multi_source(
        self,
        scan_request: MultiSourceScanRequest,
        scan_id: int | None = None,
        *,
        verified_target: VerifiedTarget | None = None,
        user_id: str = "local-user",
        user_role: str = "user",
        authorization_context: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        """Run a multi-source coordinated scan (SAST + DAST + SCA + IaC + Secrets)."""
        target_url = "multi-source://scan"
        if scan_request.sources:
            for source in scan_request.sources:
                if source.type == "live":
                    target_url = source.target_url
                    break
            if target_url == "multi-source://scan":
                for source in scan_request.sources:
                    if source.type in {"local", "github", "gitlab", "bitbucket"}:
                        target_url = f"code-source://{source.type}"
                        break

        if scan_id is None:
            scan_id = await create_scan(
                target_url=target_url,
                mode="multi_agent",
                intensity=scan_request.intensity,
                selected_tests=json.dumps([s.type for s in scan_request.sources]),
                user_id=user_id,
                authorization_id=None,
                authorization_confirmed=False,
            )

        self.scan_id = scan_id
        self.status = "active"
        await update_scan_status(scan_id, "running")
        await self.set_progress(scan_id, 2, "multi_source_started")
        await self.log_action("started", f"Coordinating multi-source scan: {scan_request.name}")
        await self.publish(scan_id, "orchestrator", {"status": "running", "progress": 2})

        try:
            coordinator = SourceCoordinatorAgent()
            result = await coordinator.run(
                scan_request=scan_request,
                scan_id=scan_id,
                user_id=user_id,
                authorization_context=authorization_context,
            )

            all_findings = []
            for sr in result.get("source_results", []):
                if sr.get("status") == "completed" and "result" in sr:
                    findings = sr["result"].get("findings", [])
                    for f in findings:
                        f["_source_type"] = sr.get("source_type", "unknown")
                    all_findings.extend(findings)

            persisted_findings = await self.persist_findings(scan_id, all_findings, target_url)

            await self.set_progress(scan_id, 90, "reports_generation")
            fixer = FixerAgent()
            try:
                fixer_event = await self.run_agent(
                    "fixer",
                    fixer.name,
                    lambda: fixer.run(persisted_findings, scan_id),
                    scan_id,
                    max_retries=0,
                    timeout=20.0,
                )
                markdown_report = str(fixer_event["result"].get("markdown_report", ""))
            except asyncio.TimeoutError:
                await self.log_action("fixer_timeout", "Fixer report generation timed out; continuing with fallback report")
                await self.publish(scan_id, "fixer_timeout", {"status": "timeout", "message": "Report generation timed out; using fallback report", "progress": 93})
                markdown_report = f"# PhantomScan Report\n\nScan completed with {len(persisted_findings)} findings. AI report generation timed out."
            except Exception as exc:
                await self.log_action("fixer_error", str(exc)[:2000])
                await self.publish(scan_id, "fixer_error", {"status": "error", "message": "Report generation failed; using fallback report", "error": str(exc)[:500], "progress": 93})
                markdown_report = f"# PhantomScan Report\n\nScan completed with {len(persisted_findings)} findings. Report generation failed."
            await set_scan_artifacts(scan_id, markdown_report=markdown_report)

            await self.set_progress(scan_id, 93, "ai_analysis")
            artifact_context = {
                "markdown_report": markdown_report,
                "source_results": result.get("source_results", []),
            }
            ai_analyst_output = await self.run_ai_security_analyst(
                scan_id=scan_id,
                target_url=target_url,
                mode="multi_agent",
                intensity=scan_request.intensity,
                findings=persisted_findings,
                artifacts=artifact_context,
                request_count=0,
            )
            await set_scan_artifacts(scan_id, ai_analyst_output=ai_analyst_output)

            notifier = NotifierAgent()
            await self.run_agent(
                "notifier",
                notifier.name,
                lambda: notifier.run({
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "mode": "multi_agent",
                    "intensity": scan_request.intensity,
                    "findings": persisted_findings,
                    "source_results": result.get("source_results", []),
                    "markdown_report": markdown_report,
                }, scan_id),
                scan_id,
            )

            await update_scan_status(scan_id, "complete")
            await self._cleanup_uploaded_sources(scan_request)
            await self.run_learning(scan_id)
            self.status = "complete"
            await self.log_action("completed", f"Multi-source scan completed with {len(persisted_findings)} findings, {result.get('correlated_findings', 0)} correlations")
            await self.publish(scan_id, "scan_complete", {"status": "complete", "progress": 100})

            return {
                "scan_id": scan_id,
                "target_url": target_url,
                "mode": "multi_agent",
                "intensity": scan_request.intensity,
                "findings": persisted_findings,
                "source_results": result.get("source_results", []),
                "total_findings": result.get("total_findings", 0),
                "correlated_findings": result.get("correlated_findings", 0),
                "markdown_report": markdown_report,
                "ai_analyst_output": ai_analyst_output,
                "status": "complete",
            }

        except asyncio.CancelledError:
            self.status = "cancelled"
            await self._cleanup_uploaded_sources(scan_request)
            await update_scan_status(scan_id, "cancelled")
            await self.log_action("cancelled", "Multi-source scan was cancelled")
            await self.publish(scan_id, "scan_cancelled", {"status": "cancelled", "progress": 0})
            raise
        except Exception as exc:
            traceback.print_exc()
            self.status = "error"
            await self._cleanup_uploaded_sources(scan_request)
            await update_scan_status(scan_id, "error", str(exc)[:1000])
            await self.log_action("error", str(exc)[:2000])
            await self.publish(scan_id, "scan_failed", {"status": "error", "error": str(exc)})
            return {"scan_id": scan_id, "status": "error", "error": str(exc)}

    async def _cleanup_uploaded_sources(self, scan_request: Any) -> None:
        """Delete extracted upload-* temp dirs for local sources once the scan has finished.
        Never raises; findings already embed code snippets, so evidence is not lost."""
        try:
            import shutil
            import tempfile as _tempfile

            tmp_root = os.path.normpath(_tempfile.gettempdir())
            for source in getattr(scan_request, "sources", []) or []:
                if getattr(source, "type", None) != "local":
                    continue
                path = getattr(source, "path", None)
                if not path:
                    continue
                norm = os.path.normpath(str(path))
                if not norm.startswith(tmp_root + os.sep):
                    continue
                parts = norm[len(tmp_root) + 1:].split(os.sep)
                upload_idx = next((i for i, p in enumerate(parts) if p.startswith("upload-")), None)
                if upload_idx is None:
                    continue
                root = os.path.join(tmp_root, *parts[: upload_idx + 1])
                shutil.rmtree(root, ignore_errors=True)
                logger.info("Cleaned up uploaded codebase temp dir: %s", root)
        except Exception:
            logger.debug("Uploaded source cleanup skipped", exc_info=True)

    async def run_learning(self, scan_id: int) -> None:
        """Run the ContinuousLearningEngine post-scan pass. Never fails the scan."""
        try:
            from app.services.learning_engine import ContinuousLearningEngine

            engine = ContinuousLearningEngine()
            insights = await engine.process_scan(scan_id)
            await add_audit_log(
                scan_id,
                "Learning Engine",
                "learning_insights_generated",
                f"{len(insights)} insight(s) recorded for scan {scan_id}",
                user_id="local-user",
            )
            await self.publish(
                scan_id,
                "learning_completed",
                {"status": "complete", "insight_count": len(insights)},
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Learning engine failed for scan %d", scan_id)
            try:
                await add_audit_log(
                    scan_id,
                    "Learning Engine",
                    "learning_failed",
                    str(exc)[:1000],
                    user_id="local-user",
                )
            except Exception as e:
                logger.debug("Failed to log learning failure for scan %d: %s", scan_id, e)
            await self.publish(
                scan_id,
                "learning_failed",
                {"status": "error", "error": str(exc)[:500]},
            )

    async def run_ai_decision_maker(
        self,
        target_url: str,
        scan_id: int,
        scanner_output: dict[str, Any],
        selected_tests: list[str],
    ) -> list[str] | None:
        """Ask the AI Decision Maker for a prioritized module plan.

        Uses the scanner's fingerprint (no duplicate HTTP work). Returns None
        on failure so the caller keeps the existing full-module behavior.
        """
        try:
            recon_context = {
                "tech_stack": scanner_output.get("tech_stack") or {},
                "technologies_detailed": scanner_output.get("technologies_detailed") or [],
                "http_headers": scanner_output.get("http_headers") or {},
                "waf_detected": scanner_output.get("waf_detected"),
                "cdn_detected": scanner_output.get("cdn_detected"),
                "open_ports": scanner_output.get("open_ports") or [],
            }
            decision_maker = AIDecisionMaker()
            recommended = await asyncio.wait_for(
                decision_maker.recommend_modules(
                    target_url,
                    recon_context,
                    scan_id=scan_id,
                    manual_selection=selected_tests or None,
                ),
                timeout=20.0,
            )
            if selected_tests and recommended:
                source = "merged"
            elif not recommended:
                source = "fallback"
            else:
                source = "ai"
            await self.publish(
                scan_id,
                "ai_decision",
                {
                    "status": "complete" if recommended else "fallback",
                    "source": source,
                    "selected_modules": recommended,
                    "module_count": len(recommended),
                },
            )
            await self.log_action(
                "ai_decision",
                f"{source}: selected {len(recommended)} modules: {recommended[:12]}",
            )
            return recommended
        except asyncio.TimeoutError:
            logger.warning("AI decision maker timed out for %s", target_url)
            try:
                await self.log_action("ai_decision_timeout", "AI decision maker timed out; using selected/default modules")
                await self.publish(
                    scan_id,
                    "ai_decision_timeout",
                    {"status": "timeout", "source": "fallback", "selected_modules": selected_tests, "module_count": len(selected_tests)},
                )
            except Exception as e:
                logger.debug("Failed to log AI decision timeout: %s", e)
            return selected_tests or None
        except Exception as exc:
            logger.exception("AI decision maker failed for %s", target_url)
            try:
                await self.log_action("ai_decision_error", str(exc)[:2000])
            except Exception as e:
                logger.debug("Failed to log AI decision error: %s", e)
            return None

    async def run_sqli_exploitation(
        self,
        target_url: str,
        scan_id: int,
        findings: list[dict[str, Any]],
    ) -> None:
        sqli_findings = [
            f for f in findings
            if f.get("category", "").lower() in ("sql_injection", "injection")
        ]
        if not sqli_findings:
            return

        await self.publish(scan_id, "sqli_exploitation_started", {
            "message": f"🔓 Exploiting {len(sqli_findings)} SQL injection vulnerabilities...",
        })

        for finding in sqli_findings[:3]:
            target_url = finding.get("endpoint") or finding.get("target", "")
            param = finding.get("parameter") or "id"
            payload = finding.get("evidence", "")[:100] or ""

            try:
                agent = SQLIExploitationAgent(
                    scan_id=scan_id,
                    target_url=target_url,
                    param=param,
                    payload=payload,
                )
                result = await agent.exploit()

                finding["exploitation_result"] = result
                finding["exploited"] = True

                tables_count = len(result.get("tables", []))
                data_count = sum(len(d.get("rows", [])) for d in result.get("data", []))
                await self.publish(scan_id, "sqli_exploitation_result", {
                    "finding_id": finding.get("id"),
                    "param": param,
                    "database_type": result.get("database_type"),
                    "tables": result.get("tables", []),
                    "tables_count": tables_count,
                    "data_count": data_count,
                    "message": (
                        f"🔓 Exploited SQL Injection on {param}: "
                        f"DB={result.get('database_type')}, "
                        f"{tables_count} tables, {data_count} rows extracted"
                    ),
                })

                await add_audit_log(
                    scan_id,
                    "SQLIExploitationAgent",
                    "sqli_exploited",
                    f"Exploited SQLi on param={param}, DB={result.get('database_type')}, "
                    f"tables={tables_count}, rows={data_count}",
                )
            except Exception as exc:
                await self.publish(scan_id, "sqli_exploitation_error", {
                    "message": f"SQLi exploitation failed: {exc}",
                })
                traceback.print_exc()

    async def run_ai_exploitation(
        self,
        target_url: str,
        scan_id: int,
        findings: list[dict[str, Any]],
        *,
        sandbox_id: str | None = None,
    ) -> dict[str, Any]:
        engine = AIExploitationEngine()
        try:
            await self.publish(scan_id, "ai_exploitation_started", {
                "message": "AI exploitation engine started: generating and validating PoCs...",
            })
            result = await asyncio.wait_for(
                engine.run_for_scan(target_url, scan_id, findings, sandbox_id=sandbox_id),
                timeout=30.0,
            )
            await self.publish(scan_id, "ai_exploitation_result", {
                "exploitation_results": result.get("exploitation_results", []),
                "summary": result.get("summary", ""),
                "ai_available": result.get("ai_available", False),
            })
            await self.log_action("ai_exploitation", result.get("summary", ""))
            return result
        except asyncio.TimeoutError:
            logger.warning("AI exploitation timed out for %s", target_url)
            await self.publish(scan_id, "ai_exploitation_timeout", {"status": "timeout", "message": "AI exploitation timed out; continuing without AI exploitation results"})
            try:
                await self.log_action("ai_exploitation_timeout", "AI exploitation timed out; continuing without AI exploitation results")
            except Exception as e:
                logger.debug("Failed to log AI exploitation timeout: %s", e)
            return {
                "status": "timeout",
                "exploitation_results": [],
                "summary": "AI exploitation timed out; deterministic scan results remain available.",
                "ai_available": False,
            }
        except Exception as exc:
            logger.exception("AI exploitation failed for %s", target_url)
            try:
                await self.log_action("ai_exploitation_error", str(exc)[:2000])
            except Exception as e:
                logger.debug("Failed to log AI exploitation error: %s", e)
            return {
                "status": "error",
                "exploitation_results": [],
                "summary": f"AI exploitation failed: {exc}",
                "ai_available": False,
            }

    async def run_ai_security_analyst(
        self,
        *,
        scan_id: int,
        target_url: str,
        mode: str,
        intensity: str,
        findings: list[dict[str, Any]],
        artifacts: dict[str, Any],
        request_count: int,
    ) -> dict[str, Any]:
        fallback = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ai_available": False,
            "ai_status": "AI Security Analyst unavailable - deterministic scan output remains available",
            "safety": {"grounded_in_scan_evidence": True, "can_start_active_test": False, "active_tests": "recommend_only"},
            "security_summary": {
                "overall_security_posture": "Unavailable",
                "most_important_risks": [],
                "immediate_attention": "AI analyst did not complete; use persisted findings and reports.",
                "recommended_next_action": "Review persisted findings by severity and confidence.",
            },
            "priorities": [],
            "related_security_chains": [],
            "root_causes": [],
            "remediation_plan": {"IMMEDIATE": [], "TODAY": [], "THIS_WEEK": []},
            "grounding": {"source": "scanner-generated evidence only"},
        }
        try:
            previous_scan = await get_previous_scan_for_target(target_url, scan_id)
            previous_findings = await get_findings(int(previous_scan["id"])) if previous_scan else []
            previous_artifacts = await get_scan_artifacts(int(previous_scan["id"])) if previous_scan else None
            logs = await get_audit_logs(scan_id)
            analyst = AISecurityAnalystAgent()
            event = await self.run_agent(
                "ai_security_analyst",
                analyst.name,
                lambda: analyst.run(
                    scan={"id": scan_id, "target_url": target_url, "mode": mode, "intensity": intensity},
                    findings=findings,
                    artifacts=artifacts,
                    previous_scan=previous_scan,
                    previous_findings=previous_findings,
                    previous_artifacts=previous_artifacts,
                    logs=logs,
                ),
                scan_id,
                max_retries=0,
                timeout=20.0,
            )
            return event["result"]
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            traceback.print_exc()
            await add_audit_log(
                scan_id,
                "AI Security Analyst Agent",
                "skipped",
                f"AI analyst failed without failing the scan: {exc}"[:2000],
                request_count=request_count,
            )
            return {**fallback, "error": str(exc)[:500]}

    async def gather_agents(
        self,
        *operations: Awaitable[dict[str, Any]],
        scan_id: int | None = None,
        phase: str = "agents_running",
        start_progress: int | None = None,
        end_progress: int | None = None,
    ) -> list[dict[str, Any]]:
        tasks = [asyncio.create_task(operation) for operation in operations]
        results: list[dict[str, Any] | None] = [None] * len(tasks)
        task_indexes = {task: i for i, task in enumerate(tasks)}
        completed = 0

        while task_indexes:
            done, _ = await asyncio.wait(task_indexes.keys(), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                index = task_indexes.pop(task)
                completed += 1
                try:
                    result = task.result()
                except BaseException as exc:
                    logger.error("Agent task %d raised: %s", index, exc)
                    result = {"error": str(exc)[:500], "result": {}}
                results[index] = result

                if scan_id is not None and start_progress is not None and end_progress is not None and tasks:
                    progress = start_progress + int((completed / len(tasks)) * (end_progress - start_progress))
                    agent_name = str(result.get("agent_name") or result.get("agent") or f"agent {index + 1}")
                    status_value = str(result.get("status") or "complete")
                    bounded_progress = min(end_progress, progress)
                    effective_progress = await self.set_progress(
                        scan_id,
                        bounded_progress,
                        phase,
                        publish_event=False,
                    )
                    payload = {
                        "phase": phase,
                        "status": "running",
                        "progress": effective_progress,
                        "completed_agents": completed,
                        "total_agents": len(tasks),
                        "agent_name": agent_name,
                        "message": f"{agent_name} {status_value}; {completed}/{len(tasks)} analysis agents complete",
                    }
                    await self.publish(scan_id, "scan_progress", payload)
                    await self.publish(scan_id, phase, payload)

        return [result or {"error": "Agent did not return a result", "result": {}} for result in results]

    async def validate_execution(
        self,
        request: ScanRequest,
        verified_target: VerifiedTarget | None,
        user_id: str,
        user_role: str = "user",
        authorization_context: dict[str, object] | None = None,
    ) -> tuple[VerifiedTarget | None, dict[str, object]]:
        target = canonicalize_target(request.target_url)
        if request.mode == "defend":
            if request.selected_tests or request.business_logic_tests:
                raise PermissionError("Defend mode cannot invoke active test modules")
            if verified_target is not None or request.authorization_confirmed or request.authorization_id is not None:
                raise PermissionError("Defend mode cannot receive active-test authorization")
            return None, {
                "allowed": True,
                "target_url": target.url,
                "target_origin": target.origin,
                "authorization_status": "NOT_REQUIRED",
                "reason": "Passive defend scan",
                "authorization_id": None,
                "is_lab": False,
            }

        if not request.selected_tests:
            raise PermissionError("Pentest execution requires at least one selected test module")
        if request.business_logic_tests and "business_logic" not in request.selected_tests:
            raise PermissionError("Business logic definitions require the business_logic module")
        decision = await ActiveTargetGate(TargetAuthorizationService()).admit(target.url, user_id, request.authorization_id, user_role=user_role)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        if decision.authorization_status == "VERIFIED" and not request.authorization_confirmed:
            raise PermissionError("Verified external pentest targets require manual authorization confirmation")
        if verified_target is not None and decision.verified_target is not None and verified_target.id != decision.verified_target.id:
            raise PermissionError("Pentest authorization does not match the requested target")
        return decision.verified_target, decision.to_context()

    async def run_agent(
        self,
        event_name: str,
        agent_name: str,
        operation: Callable[[], Awaitable[dict[str, Any]]],
        scan_id: int,
        *,
        max_retries: int = 1,
        timeout: float | None = None,
        timeout_result: dict[str, Any] | None = None,
        live_findings_target: str | None = None,
    ) -> dict[str, Any]:
        await self.publish(
            scan_id,
            event_name,
            {"agent": event_name, "agent_name": agent_name, "status": "active"},
        )
        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                op = operation()
                if timeout is not None:
                    result = await asyncio.wait_for(op, timeout=timeout)
                else:
                    result = await op
                event = {
                    "agent": event_name,
                    "agent_name": agent_name,
                    "status": "complete",
                    "result": result,
                    "attempt": attempt + 1,
                }
                await self.publish(scan_id, event_name, event)
                if live_findings_target is not None:
                    live_findings = self.collect_findings([event], live_findings_target)
                    if live_findings:
                        await self.persist_findings(
                            scan_id,
                            self._apply_ml_prioritization(live_findings),
                            live_findings_target,
                        )
                return event
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError as exc:
                last_exc = exc
                await add_audit_log(scan_id, agent_name, "timeout", f"Attempt {attempt + 1} timed out after {timeout}s")
                await self.publish(
                    scan_id,
                    event_name,
                    {"agent": event_name, "agent_name": agent_name, "status": "timeout", "attempt": attempt + 1},
                )
                if attempt >= max_retries and timeout_result is not None:
                    return {
                        "agent": event_name,
                        "agent_name": agent_name,
                        "status": "timeout",
                        "result": timeout_result,
                        "attempt": attempt + 1,
                    }
            except Exception as exc:
                last_exc = exc
                traceback.print_exc()
                await add_audit_log(scan_id, agent_name, "error", f"Attempt {attempt + 1}: {str(exc)[:2000]}")
                await self.publish(
                    scan_id,
                    event_name,
                    {"agent": event_name, "agent_name": agent_name, "status": "error", "attempt": attempt + 1, "error": str(exc)},
                )
                if attempt < max_retries:
                    await asyncio.sleep(1)
                    continue
                await self.log_action("agent_error", f"{agent_name} failed after {attempt + 1} attempts: {exc}"[:2000])
                raise
        raise last_exc or RuntimeError(f"{agent_name} failed")

    def _apply_ml_prioritization(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not findings:
            return findings
        try:
            from app.ml.risk_prioritizer import RiskPrioritizer

            return RiskPrioritizer().prioritize(findings)
        except Exception as exc:
            logger.warning("ML prioritization failed: %s", exc)
            return findings

    def collect_findings(self, events: list[dict[str, Any]], target_url: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for event in events:
            result = event.get("result", {})
            default_agent = str(event.get("agent_name") or "Orchestrator Agent")
            for finding in result.get("findings", []):
                if isinstance(finding, dict):
                    findings.append({"agent": default_agent, **finding})
            findings.extend(self.cve_matches_to_findings(result.get("cve_matches", []), target_url))
            findings.extend(self.pentest_responses_to_findings(result.get("abnormal_responses", []), target_url))
        return self._deduplicate_findings(findings)

    def _deduplicate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not findings:
            return findings

        seen: dict[str, dict[str, Any]] = {}
        deduplicated: list[dict[str, Any]] = []

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        for finding in findings:
            dedup_key = self._runtime_dedup_key(finding)

            if dedup_key in seen:
                existing = seen[dedup_key]
                existing_sev = severity_order.get(str(existing.get("severity", "INFO")).upper(), 4)
                new_sev = severity_order.get(str(finding.get("severity", "INFO")).upper(), 4)

                if new_sev < existing_sev:
                    finding["corroborating_agents"] = list(existing.get("corroborating_agents") or [])
                    seen[dedup_key] = finding
                    dedup_idx = None
                    for i, d in enumerate(deduplicated):
                        d_key = self._runtime_dedup_key(d)
                        if d_key == dedup_key:
                            dedup_idx = i
                            break
                    if dedup_idx is not None:
                        deduplicated[dedup_idx] = finding

                    existing = finding

                if existing.get("agent") != finding.get("agent"):
                    existing_agents = existing.get("corroborating_agents", [])
                    if not isinstance(existing_agents, list):
                        existing_agents = []
                    if finding.get("agent") and finding["agent"] not in existing_agents:
                        existing_agents.append(finding["agent"])
                    existing["corroborating_agents"] = existing_agents
            else:
                seen[dedup_key] = finding
                deduplicated.append(finding)

        return deduplicated

    @staticmethod
    def _runtime_dedup_key(finding: dict[str, Any]) -> str:
        fields = (
            "title",
            "category",
            "endpoint",
            "parameter",
            "module",
            "file_path",
            "line_number",
            "cve_id",
        )
        return "|".join(str(finding.get(field, "")).lower().strip() for field in fields)

    def cve_matches_to_findings(
        self,
        cve_matches: list[dict[str, Any]],
        target_url: str,
    ) -> list[dict[str, Any]]:
        findings = []
        for match in cve_matches:
            score = match.get("cvss_score")
            cve_id = match.get("cve_id") or "Unknown CVE"
            technology = match.get("affected_component") or match.get("technology") or "detected technology"
            cwe_list = match.get("cwe", [])
            version_affected = match.get("version_affected")
            cwe_str = ", ".join(cwe_list) if cwe_list else ""
            version_str = f" (versions: {version_affected})" if version_affected else ""
            findings.append(
                {
                    "title": f"Known vulnerability in {technology}: {cve_id}",
                    "severity": self.cvss_to_severity(score),
                    "confidence": "POTENTIAL",
                    "category": "CVE",
                    "target": target_url,
                    "endpoint": target_url,
                    "description": match.get("description") or "NVD reported a matching CVE for detected technology.",
                    "how_exploited": f"A reachable affected version{version_str} may be targeted with the techniques documented for this CVE.",
                    "fix": "Upgrade the affected package or service to a vendor-supported version that remediates the CVE.",
                    "verification": "Confirm the deployed version is outside the affected range and rerun dependency detection.",
                    "agent": "CVE Matcher Agent",
                    "cve_id": match.get("cve_id"),
                    "cvss_score": score,
                    "cwe": cwe_str or None,
                    "version_affected": version_affected,
                }
            )
        return findings

    def pentest_responses_to_findings(
        self,
        abnormal_responses: list[dict[str, Any]],
        target_url: str,
    ) -> list[dict[str, Any]]:
        findings = []
        for response in abnormal_responses:
            test = response.get("test", "Pentest check")
            findings.append(
                {
                    "title": f"Abnormal response during {test}",
                    "severity": "HIGH" if test in {"SQL Injection", "Open Redirect", "Auth Bypass"} else "MEDIUM",
                    "confidence": "MEDIUM",
                    "category": "Pentest",
                    "target": target_url,
                    "endpoint": response.get("url") or target_url,
                    "description": f"The endpoint responded abnormally to {test}.",
                    "how_exploited": "An attacker may replay the observed request pattern to probe the abnormal behavior.",
                    "fix": "Validate inputs and enforce authorization on every protected route.",
                    "verification": "Repeat the authorized request after remediation and confirm the abnormal response is absent.",
                    "agent": "Pentest Agent",
                    "cve_id": None,
                    "cvss_score": None,
                }
            )
        return findings

    @staticmethod
    def cvss_to_severity(score: Any) -> str:
        if score is None:
            return "MEDIUM"
        try:
            score_value = float(score)
        except (TypeError, ValueError):
            return "MEDIUM"
        if score_value >= 9.0:
            return "CRITICAL"
        if score_value >= 7.0:
            return "HIGH"
        if score_value >= 4.0:
            return "MEDIUM"
        return "LOW"

    async def persist_findings(
        self,
        scan_id: int,
        findings: list[dict[str, Any]],
        target_url: str,
    ) -> list[dict[str, Any]]:
        async with self._finding_lock:
            existing = await get_findings(scan_id)
            seen: dict[tuple[Any, ...], dict[str, Any]] = {}
            for row in existing:
                try:
                    key = self.finding_key(
                        FindingCreate(**{name: row.get(name) for name in FindingCreate.model_fields})
                    )
                except Exception:
                    # DB rows may predate optional FindingCreate fields (exploited, sources,
                    # patch, ...) — build the key from present non-None values only.
                    data = {name: row.get(name) for name in FindingCreate.model_fields if row.get(name) is not None}
                    if not data:
                        continue
                    key = self.finding_key(FindingCreate(**data))
                seen[key] = row
            for finding in findings:
                try:
                    normalized = self.normalize_finding(finding, target_url)
                except ValueError as exc:
                    await add_audit_log(scan_id, self.name, "finding_skipped", str(exc)[:2000])
                    continue
                key = self.finding_key(normalized)
                existing_row = seen.get(key)
                if existing_row is not None:
                    await self.update_existing_finding(scan_id, existing_row, normalized)
                    continue
                finding_id = await create_finding(scan_id, normalized)
                evidence_ids = list(finding.get("_evidence_ids") or [])
                if finding.get("_evidence_id") and finding.get("_evidence_id") not in evidence_ids:
                    evidence_ids.append(finding.get("_evidence_id"))
                for evidence_id in evidence_ids:
                    try:
                        await update_evidence_finding(int(evidence_id), finding_id)
                    except (TypeError, ValueError):
                        continue
                current_findings = [self.live_finding_payload(row) for row in await get_findings(scan_id)]
                created_finding = next((row for row in current_findings if int(row.get("id") or 0) == finding_id), None)
                finding_message = (
                    f"Verified finding: {normalized.title}"
                    if created_finding and created_finding.get("verified")
                    else f"Finding detected: {normalized.title}"
                )
                await self.publish(
                    scan_id,
                    "finding_created",
                    {
                        "finding_id": finding_id,
                        "title": normalized.title,
                        "severity": normalized.severity,
                        "status": "running",
                        "message": finding_message,
                        "finding": created_finding,
                        "findings": current_findings,
                    },
                )
                if created_finding is not None:
                    seen[key] = created_finding
            return await get_findings(scan_id)

    async def update_existing_finding(
        self,
        scan_id: int,
        existing: dict[str, Any],
        normalized: FindingCreate,
    ) -> None:
        finding_id = int(existing.get("id") or 0)
        if finding_id <= 0:
            return
        data = normalized.model_dump(mode="json")
        updatable = {
            "title", "category", "severity", "confidence", "target", "endpoint",
            "evidence", "impact", "recommendation", "verification", "agent",
            "cve_id", "cvss_score", "cwe", "version_affected", "file_path",
            "line_number", "code_snippet", "fix_recommendation", "parameter",
            "module", "recommended_fix", "verification_status", "request_id",
            "confidence_score", "confidence_label", "reproduction_command",
            "request_response_diff", "verification_hash", "verification_method",
            "verification_stage", "verification_result", "source_correlation",
        }
        updates: dict[str, Any] = {}
        for name in updatable:
            value = data.get(name)
            if value in (None, ""):
                continue
            if existing.get(name) != value:
                updates[name] = value
        if not updates:
            return
        await update_finding(finding_id, **updates)
        current_findings = [self.live_finding_payload(row) for row in await get_findings(scan_id)]
        updated_finding = next((row for row in current_findings if int(row.get("id") or 0) == finding_id), None)
        await self.publish(
            scan_id,
            "finding_updated",
            {
                "finding_id": finding_id,
                "title": data.get("title"),
                "severity": data.get("severity"),
                "status": "running",
                "message": f"Finding updated: {data.get('title')}",
                "finding": updated_finding,
                "findings": current_findings,
            },
        )

    @staticmethod
    def live_finding_payload(finding: dict[str, Any]) -> dict[str, Any]:
        payload = dict(finding)
        confidence = str(payload.get("confidence") or "").upper()
        verification_status = str(payload.get("verification_status") or "").upper()
        verified = confidence == "CONFIRMED" or verification_status == "ISSUE_STILL_PRESENT"
        payload["verified"] = verified
        score = payload.get("confidence_score")
        try:
            payload["confidence_percent"] = round(float(score) * 100) if score is not None else {
                "CONFIRMED": 100,
                "HIGH": 85,
                "MEDIUM": 65,
                "LOW": 40,
                "POTENTIAL": 25,
            }.get(confidence, 0)
        except (TypeError, ValueError):
            payload["confidence_percent"] = 0
        return payload

    @staticmethod
    def normalize_finding(finding: dict[str, Any], target_url: str) -> FindingCreate:
        def first_text(*names: str, default: str = "") -> str:
            for name in names:
                value = finding.get(name)
                if value is not None and str(value).strip():
                    return str(value).strip()
            return default

        def first_int(*names: str) -> int | None:
            for name in names:
                value = finding.get(name)
                if value is None or value == "":
                    continue
                try:
                    parsed = int(value)
                except (TypeError, ValueError):
                    continue
                if parsed > 0:
                    return parsed
            return None

        severity = str(finding.get("severity") or "INFO").upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "INFO"
        confidence = str(finding.get("confidence") or "MEDIUM").upper()
        if confidence not in {"CONFIRMED", "HIGH", "MEDIUM", "LOW", "POTENTIAL"}:
            confidence = "POTENTIAL"
        remediation_status = str(finding.get("remediation_status") or "OPEN").upper()
        if remediation_status not in {"OPEN", "IN_PROGRESS", "RESOLVED"}:
            remediation_status = "OPEN"
        verification_status = str(finding.get("verification_status") or "NOT_VERIFIED").upper()
        if verification_status not in {"NOT_VERIFIED", "FIX_VERIFIED", "ISSUE_STILL_PRESENT", "VERIFY_FAILED"}:
            verification_status = "NOT_VERIFIED"
        risk_status = str(finding.get("risk_status") or "ACTIVE").upper()
        if risk_status not in {"ACTIVE", "FALSE_POSITIVE", "ACCEPTED_RISK"}:
            risk_status = "ACTIVE"

        type_label = str(finding.get("type") or "").lower()
        tool = first_text("tool")
        type_labels = {"sast": "SAST", "secret": "Secrets", "sca": "SCA", "iac": "IaC"}
        category = first_text("category", "module", default="") or type_labels.get(type_label, type_label or "Security")
        if tool and tool != "semgrep" and not first_text("category"):
            category = f"{category} · {tool}"
        category = category[:120]

        title = first_text(
            "title", "name", "issue", "vulnerability",
            "rule_name", "rule_id", "misconfiguration_type", "detector_name",
        )
        if not title:
            package = first_text("package_name")
            if package:
                vuln_id = first_text("vulnerability_id")
                title = f"Vulnerable dependency: {package}" + (f" ({vuln_id})" if vuln_id else "")
        if not title:
            title = first_text("secret_type", "message")[:140] or None
        if not title:
            raise ValueError("Finding is missing a title")
        agent = first_text("agent", "source", default="Orchestrator Agent")

        evidence = first_text(
            "evidence", "description", "details", "message", "code_snippet", "matched_content", "matched_text",
        )
        location = first_text("file_path")
        line_number = first_int("line_number", "line_start", "start_line", "line_end")
        if location:
            evidence_parts = [evidence, f"Location: {location}" + (f":{line_number}" if line_number else "")]
            evidence = "\n".join(p for p in evidence_parts if p)
        if not evidence:
            evidence = first_text("advisory_url")

        code_snippet = redact_sensitive(first_text("code_snippet", "matched_text", "matched_content", "context")[:12000]) or None
        recommendation = first_text("recommendation", "fix_recommendation", "fix", "remediation")
        if not recommendation:
            fixed_version = first_text("fixed_version")
            if fixed_version:
                recommendation = f"Upgrade the dependency to a fixed version (e.g. {fixed_version})."
        impact = first_text("impact", "how_exploited", "risk")
        if not impact and first_text("message"):
            impact = first_text("message")[:2000]

        cve_id = str(finding["cve_id"])[:40] if finding.get("cve_id") else None
        if not cve_id and type_label == "sca":
            vuln_id = first_text("vulnerability_id")
            if vuln_id:
                cve_id = vuln_id[:40]

        cwe_value = finding.get("cwe")
        if not cwe_value and finding.get("cwe_ids"):
            cwe_list = [c for c in finding["cwe_ids"] if isinstance(c, str)]
            cwe_value = ", ".join(cwe_list)
        if cwe_value:
            cwe_value = str(cwe_value)[:200]
        else:
            cwe_value = None

        if not finding.get("severity") and type_label in {"secret", "sca"}:
            if type_label == "secret":
                severity = "HIGH" if finding.get("verified") else "MEDIUM"
            else:
                severity = "HIGH"

        module_value = first_text("module", "selected_module", "tool")[:120] or None

        return FindingCreate(
            title=str(title)[:300],
            category=category,
            severity=severity,
            confidence=confidence,
            target=first_text("target", "target_url", default=target_url)[:2048],
            endpoint=first_text("endpoint", "url", "path", "file_path", default=target_url)[:2048],
            evidence=redact_sensitive(evidence[:12000]),
            impact=impact[:4000],
            recommendation=recommendation[:6000],
            verification=first_text(
                "verification",
                default="Rerun the relevant PhantomScan analysis after remediation and confirm the evidence is absent.",
            )[:4000],
            agent=agent[:120],
            timestamp=_safe_timestamp(finding.get("timestamp")),
            cve_id=cve_id,
            cvss_score=finding.get("cvss_score"),
            cwe=cwe_value,
            version_affected=str(finding.get("version_affected"))[:500] if finding.get("version_affected") else None,
            file_path=location[:2048] or None,
            line_number=line_number,
            code_snippet=code_snippet,
            fix_recommendation=first_text("fix_recommendation", "recommendation", "fix", default=recommendation)[:6000] or None,
            parameter=first_text("parameter", default="")[:200] or None,
            module=module_value,
            recommended_fix=first_text("recommended_fix", "recommendation", "fix", default=recommendation)[:6000] or None,
            remediation_status=remediation_status,
            verification_status=verification_status,
            risk_status=risk_status,
            request_id=first_text("request_id", "_request_id", default="")[:80] or None,
            confidence_score=finding.get("confidence_score"),
            confidence_label=first_text("confidence_label", default="")[:20] or None,
            reproduction_command=first_text("reproduction_command", default="")[:4000] or None,
            request_response_diff=first_text("request_response_diff", default="")[:12000] or None,
            verification_hash=first_text("verification_hash", default="")[:128] or None,
            verification_method=first_text("verification_method", default="")[:120] or None,
            verification_stage=first_text("verification_stage", default="")[:120] or None,
            verification_result=finding.get("verification_result") if isinstance(finding.get("verification_result"), dict) else None,
            source_correlation=finding.get("source_correlation") if isinstance(finding.get("source_correlation"), dict) else None,
        )

    @staticmethod
    def finding_key(finding: FindingCreate) -> tuple[Any, ...]:
        data = finding.model_dump(mode="json")
        # Dedup on stable identity fields only — derived/optional fields
        # (recommended_fix, sources, remediation_status, ...) differ between
        # DB rows and freshly normalized findings and would cause duplicates
        # to be re-inserted. All identity fields are plain strings or None,
        # so the tuple is always hashable.
        identity = ("title", "category", "target", "endpoint", "file_path", "line_number", "parameter", "module", "cve_id")
        return tuple(data[name] for name in identity)

    async def set_progress(
        self,
        scan_id: int,
        progress: int,
        phase: str,
        *,
        request_count: int | None = None,
        sandbox_id: str | None = None,
        publish_event: bool = True,
    ) -> int:
        async with self._progress_lock:
            previous = self._progress_by_scan.get(scan_id, 0)
            effective_progress = max(previous, max(0, min(int(progress), 100)))
            self._progress_by_scan[scan_id] = effective_progress
        await update_scan_progress(
            scan_id,
            effective_progress,
            request_count=request_count,
            sandbox_id=sandbox_id,
        )
        payload: dict[str, Any] = {"progress": effective_progress, "phase": phase, "status": "running"}
        if request_count is not None:
            payload["request_count"] = request_count
        if sandbox_id is not None:
            payload["sandbox_id"] = sandbox_id
        if publish_event:
            await self.publish(scan_id, "scan_progress", payload)
        return effective_progress

    async def publish(self, scan_id: int, event: str, payload: dict[str, Any]) -> None:
        payload = dict(payload)
        raw_progress = payload.get("progress")
        normalized_progress = safe_int(raw_progress)
        if normalized_progress is not None:
            async with self._progress_lock:
                previous = self._progress_by_scan.get(scan_id, 0)
                effective_progress = max(previous, max(0, min(normalized_progress, 100)))
                self._progress_by_scan[scan_id] = effective_progress
            payload["progress"] = effective_progress
        print(f"[DEBUG] scan_id={scan_id} – publish event={event} payload_progress={payload.get('progress', '?')}")
        try:
            await scan_event_broker.publish(
                scan_id,
                {"event": event, "type": event, "payload": payload},
            )
            print(f"[DEBUG] scan_id={scan_id} – publish OK for event={event}")
        except Exception as exc:
            print(f"[DEBUG] scan_id={scan_id} – publish FAILED for event={event}: {exc}")

    async def _write_report_files(
        self, summary: dict[str, Any], scan_id: int, target_url: str,
        markdown_report: str,
        scanner_output: dict[str, Any], shadow_output: dict[str, Any],
        active_result: dict[str, Any] | None
    ) -> None:
        reports_dir = Path(__file__).resolve().parent.parent.parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_target = target_url.replace("://", "_").replace("/", "_").replace(".", "_")[:60]

        json_path = reports_dir / f"{safe_target}_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str, ensure_ascii=False)

        md_path = reports_dir / f"{safe_target}_{timestamp}.md"
        findings = summary.get("findings", [])
        lines = [f"# PhantomScan Report: {target_url}", f"**Scan ID:** {scan_id}", f"**Time:** {timestamp}", ""]
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = str(f.get("severity", "INFO")).upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        lines.append("## Summary")
        lines.append(f"- Total findings: {len(findings)}")
        for sev, cnt in sev_counts.items():
            if cnt:
                lines.append(f"- {sev}: {cnt}")
        lines.append(f"- Subdomains: {len(scanner_output.get('subdomains', []))}")
        lines.append(f"- Open ports: {len(scanner_output.get('open_ports', []))}")
        lines.append(f"- WAF: {scanner_output.get('waf_detected', 'none')}")
        lines.append("")
        lines.append("## Findings")
        for f in findings:
            lines.append(f"### [{f.get('severity')}] {f.get('title')}")
            lines.append(f"- Category: {f.get('category', 'General')}")
            lines.append(f"- Endpoint: {f.get('endpoint', target_url)}")
            lines.append(f"- Evidence: {f.get('evidence', 'N/A')}")
            lines.append(f"- Impact: {f.get('impact', 'N/A')}")
            lines.append(f"- Fix: {f.get('fix', 'N/A')}")
            if f.get("cwe"):
                lines.append(f"- CWE: {f.get('cwe')}")
            if f.get("version_affected"):
                lines.append(f"- Affected Versions: {f.get('version_affected')}")
            if f.get("exploited") and f.get("exploitation_result"):
                er = f["exploitation_result"]
                lines.append("- **Exploited:** True")
                lines.append(f"- Database Type: {er.get('database_type', 'Unknown')}")
                lines.append(f"- Tables ({len(er.get('tables', []))}): {', '.join(er.get('tables', []))}")
                for td in er.get("data", []):
                    lines.append(f"  - Table: {td['table']} ({len(td.get('rows', []))} rows)")
            lines.append("")
        lines.append("")
        if any(f.get("exploited") for f in findings):
            lines.append("## Exploitation Summary")
            exploited = [f for f in findings if f.get("exploited")]
            lines.append(f"- Total exploited vulnerabilities: {len(exploited)}")
            for f in exploited:
                er = f.get("exploitation_result", {})
                lines.append(f"- {f.get('title', 'Finding')}: {er.get('database_type', 'Unknown')} - {len(er.get('tables', []))} tables")
            lines.append("")
        if markdown_report:
            lines.append("## Remediation Checklist")
            lines.append(markdown_report if markdown_report.startswith("#") else f"```\n{markdown_report}\n```")
            lines.append("")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        rem_path = reports_dir / f"{safe_target}_remediation_{timestamp}.md"
        with open(rem_path, "w", encoding="utf-8") as f:
            f.write(markdown_report or "# PhantomScan Remediation Checklist\nNo findings.")

        recon_path = reports_dir / f"{safe_target}_recon_{timestamp}.md"
        recon_lines = ["# PhantomScan Shadow Recon", f"## Target: {target_url}", ""]
        recon_lines.append("### WHOIS")
        whois_data = shadow_output.get("whois", {})
        if whois_data:
            for k, v in whois_data.items():
                recon_lines.append(f"- {k}: {v}")
        else:
            recon_lines.append("- WHOIS unavailable")
        recon_lines.append("")
        recon_lines.append("### Google Dorks")
        for dork in shadow_output.get("dork_urls", []):
            recon_lines.append(f"- `{dork}`")
        recon_lines.append("")
        recon_lines.append("### Disallowed Paths (robots.txt)")
        for p in shadow_output.get("disallowed_paths", []):
            recon_lines.append(f"- {p}")
        recon_lines.append("")
        recon_lines.append("### Sitemap URLs")
        for u in shadow_output.get("sitemap_urls", []):
            https = "HTTPS" if u.get("https") else "HTTP"
            recon_lines.append(f"- [{https}] {u.get('url')}")
        recon_lines.append("")
        recon_lines.append("### Exposed Files")
        for ef in shadow_output.get("exposed_files", []):
            recon_lines.append(f"- {ef.get('path')} ({ef.get('status_code')})")
        recon_lines.append("")
        recon_lines.append("### Leaked Emails")
        for e in shadow_output.get("leaked_emails", []):
            recon_lines.append(f"- {e}")
        recon_lines.append("")
        recon_lines.append("### JS Source Maps")
        for sm in shadow_output.get("js_sourcemaps", []):
            recon_lines.append(f"- {sm}")
        recon_lines.append("")
        recon_lines.append("### Internal IPs Found")
        for ip in shadow_output.get("internal_ips", []):
            recon_lines.append(f"- {ip}")
        recon_lines.append("")
        recon_lines.append("### Wayback Machine URLs")
        for u in shadow_output.get("wayback_urls", []):
            recon_lines.append(f"- [{u.get('timestamp', '')}] {u.get('url', '')} ({u.get('status_code', '')})")
        recon_lines.append("")
        recon_lines.append("### crt.sh Subdomains")
        for s in shadow_output.get("crtsh_subdomains", []):
            recon_lines.append(f"- {s.get('subdomain', '')} (valid: {s.get('not_before', '')} to {s.get('not_after', '')})")
        recon_lines.append("")
        recon_lines.append("### All Discovered Subdomains")
        for s in shadow_output.get("all_subdomains", []):
            recon_lines.append(f"- {s}")
        with open(recon_path, "w", encoding="utf-8") as f:
            f.write("\n".join(recon_lines))

        pentest_log_path = reports_dir / f"{safe_target}_pentest_log_{timestamp}.json"
        pentest_data = {}
        if active_result:
            pentest_data = {
                "probe_log": active_result.get("probe_log", []),
                "findings": active_result.get("findings", []),
                "request_count": active_result.get("request_count", 0),
            }
        with open(pentest_log_path, "w", encoding="utf-8") as f:
            json.dump(pentest_data, f, indent=2, default=str)

        await self.log_action("reports_written", f"Reports saved to {reports_dir}")

    @staticmethod
    def browser_report(browser_result: dict[str, Any]) -> str:
        safety = browser_result.get("safety", {})
        lines = [
            "# Browser Observation Report",
            f"Engine: {browser_result.get('browser_engine', 'unknown')}",
            f"Pages visited: {len(browser_result.get('pages', []))}",
            f"Network events: {len(browser_result.get('network_events', []))}",
            f"APIs discovered: {len(browser_result.get('api_inventory', []))}",
            f"Console events: {len(browser_result.get('console_events', []))}",
            f"WebSockets: {len(browser_result.get('websockets', []))}",
            f"Safety pause: {safety.get('pause_reason') or 'none'}",
        ]
        for finding in browser_result.get("findings", [])[:10]:
            lines.append(f"- [{finding.get('severity')}/{finding.get('confidence')}] {finding.get('title')}")
        return "\n".join(lines)
