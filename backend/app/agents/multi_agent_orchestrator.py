"""Multi-agent orchestration: a dependency graph of collaborating role agents.

The MultiAgentOrchestrator arranges four specialized agents (Recon, Attack,
Exploit, Report) into a workflow graph with the dependency chain
Recon -> Attack -> Exploit -> Report. Ready nodes run concurrently and every
agent execution is logged to the ``agent_runs`` ledger. Agents share state
through a :class:`SharedContext` passed between stages.
"""

import asyncio
import logging
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.agents import Agent
from app.agents.ai_explainer import AIExplainerAgent
from app.agents.ai_security_analyst import AISecurityAnalystAgent
from app.agents.analyzer import AnalyzerAgent
from app.agents.browser_security import BrowserSecurityAgent
from app.agents.cve_matcher import CVEMatcherAgent
from app.agents.exploitation_engine import ExploitationAgent
from app.agents.fixer import FixerAgent
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
from app.database import (
    add_audit_log,
    complete_agent_run,
    list_applied_tunings,
    safe_int,
    set_scan_artifacts,
    start_agent_run,
)
from app.models import ScanRequest
from app.services.adaptive_scan_planner import AdaptiveScanPlanner
from app.services.execution import SafetyLimits
from app.services.tci import TargetComplexityIndex

logger = logging.getLogger("phantomscan.multi_agent_orchestrator")


@dataclass
class SharedContext:
    """Shared state carried through the multi-agent workflow.

    Each stage writes its outputs into :attr:`stages` so downstream agents can
    consume them without direct coupling.
    """

    target_url: str
    scan_id: int
    scan_request: ScanRequest
    host: Any
    user_id: str = "local-user"
    authorization_context: dict[str, object] | None = None
    stages: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)


class WorkflowNode:
    def __init__(
        self,
        name: str,
        operation: Callable[[SharedContext], Awaitable[Any]],
        dependencies: list[str] | None = None,
    ) -> None:
        self.name = name
        self.operation = operation
        self.dependencies = list(dependencies or [])


class WorkflowGraph:
    """Minimal DAG scheduler: executes ready nodes concurrently in levels."""

    def __init__(self) -> None:
        self._nodes: list[WorkflowNode] = []

    def add_node(
        self,
        name: str,
        operation: Callable[[SharedContext], Awaitable[Any]],
        dependencies: list[str] | None = None,
    ) -> None:
        self._nodes.append(WorkflowNode(name, operation, dependencies))

    async def execute(self, context: SharedContext) -> dict[str, Any]:
        results: dict[str, Any] = {}
        pending = list(self._nodes)
        while pending:
            ready = [
                node
                for node in pending
                if all(dependency in results for dependency in node.dependencies)
            ]
            if not ready:
                names = [node.name for node in pending]
                raise RuntimeError(f"Workflow stalled on unresolved dependencies: {names}")
            tasks = [asyncio.create_task(node.operation(context)) for node in ready]
            try:
                outcomes = await asyncio.gather(*tasks)
            except BaseException:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            for node, outcome in zip(ready, outcomes):
                results[node.name] = outcome
                pending.remove(node)
        return results


class ReconAgent(Agent):
    """Discovers the attack surface: technologies, endpoints, infrastructure.

    Runs the Scanner and Shadow Recon agents in parallel and merges their
    outputs into the shared context for downstream agents.
    """

    def __init__(self, runner: "MultiAgentOrchestrator") -> None:
        super().__init__("Recon Agent")
        self.runner = runner

    async def run(self, context: SharedContext) -> dict[str, Any]:
        self.scan_id = context.scan_id
        await self.log_action("started", f"Recon started for {context.target_url}")
        scanner = ScannerAgent()
        shadow_recon = ShadowReconAgent()
        scanner_event, shadow_event = await self.runner.gather_agents(
            self.runner.run_agent(
                "scanner",
                scanner.name,
                lambda: scanner.run(context.target_url, context.scan_id),
                context.scan_id,
            ),
            self.runner.run_agent(
                "shadow_recon",
                shadow_recon.name,
                lambda: shadow_recon.run(
                    context.target_url,
                    context.scan_id,
                    scan_depth=context.scan_request.scan_depth,
                ),
                context.scan_id,
            ),
        )
        scanner_output = scanner_event["result"]
        shadow_output = shadow_event["result"]
        await set_scan_artifacts(
            context.scan_id,
            scanner_output=scanner_output,
            shadow_recon_output=shadow_output,
        )
        complexity = TargetComplexityIndex().analyze_recon(scanner_output)
        await set_scan_artifacts(context.scan_id, tci_output=complexity)
        await context.host.publish(
            context.scan_id,
            "tci_computed",
            {
                "score": complexity["score"],
                "band": complexity["band"],
                "band_label": complexity["band_label"],
            },
        )
        stage = {
            "scanner_output": scanner_output,
            "shadow_output": shadow_output,
            "complexity": complexity,
        }
        context.stages["recon"] = stage
        await context.host.set_progress(context.scan_id, 30, "reconnaissance_complete")
        await self.log_action("completed", f"Recon complete: {len(scanner_output.get('findings', []))} observations")
        return stage


class AttackAgent(Agent):
    """Plans and executes vulnerability tests across parallel engines.

    Uses the recon fingerprint to prioritize modules (AI Decision Maker) and
    runs the analyzer, CVE matcher, browser security, assessment and (for
    active scans) sandbox engines in parallel. Enriches and persists findings.
    """

    def __init__(self, runner: "MultiAgentOrchestrator") -> None:
        super().__init__("Attack Agent")
        self.runner = runner

    async def run(self, context: SharedContext) -> dict[str, Any]:
        self.scan_id = context.scan_id
        await self.log_action("started", f"Attack started for {context.target_url}")
        scan_id = context.scan_id
        target_url = context.target_url
        recon = context.stages["recon"]
        scanner_output = recon["scanner_output"]
        shadow_output = recon["shadow_output"]
        scan_request = context.scan_request

        ai_decision: list[str] | None = None
        if scan_request.mode in ("pentest", "multi_agent"):
            ai_decision = await context.host.run_ai_decision_maker(
                target_url,
                scan_id,
                scanner_output,
                scan_request.selected_tests,
            )

        analyzer = AnalyzerAgent()
        cve_matcher = CVEMatcherAgent()
        browser_security = BrowserSecurityAgent(limits=self.runner.limits)
        attack_tasks = [
            self.runner.run_agent(
                "analyzer",
                analyzer.name,
                lambda: analyzer.run(target_url, scan_id, scanner_output),
                scan_id,
            ),
            self.runner.run_agent(
                "cve_matcher",
                cve_matcher.name,
                lambda: cve_matcher.run(scanner_output.get("tech_stack", {}), scan_id),
                scan_id,
            ),
            self.runner.run_agent(
                "browser_security",
                browser_security.name,
                lambda: browser_security.run(
                    target_url,
                    scan_id,
                    mode="pentest",
                    authorization_context=context.authorization_context,
                ),
                scan_id,
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
            attack_tasks.append(
                self.runner.run_agent(
                    event_name,
                    agent.name,
                    lambda agent=agent: agent.run(target_url, scan_id, scanner_output, shadow_output),
                    scan_id,
                )
            )

        if scan_request.mode in ("pentest", "multi_agent"):
            sandbox = SandboxManagerAgent(limits=self.runner.limits)
            business_logic_tests = [item.model_dump(mode="json") for item in scan_request.business_logic_tests]
            complexity = recon.get("complexity")
            planned_modules = None
            if complexity is not None:
                plan = AdaptiveScanPlanner().plan(
                    complexity,
                    scan_request,
                    self.runner.limits,
                    await list_applied_tunings(),
                )
                planned_modules = (
                    plan["modules"]
                    if not scan_request.selected_tests and not ai_decision
                    else None
                )
                context.stages["adaptive_plan"] = plan
                await context.host.publish(
                    scan_id,
                    "adaptive_plan_computed",
                    {
                        "band": plan["band"],
                        "score": plan["score"],
                        "requests_per_second": plan["requests_per_second"],
                        "modules": plan["modules"],
                        "rationale": plan["rationale"],
                    },
                )
            active_payload = {
                "engine": "active_security",
                "scan_id": scan_id,
                "target_url": target_url,
                "intensity": scan_request.intensity,
                "selected_modules": ai_decision or scan_request.selected_tests or planned_modules or [],
                "selected_tests": scan_request.selected_tests,
                "business_logic_tests": business_logic_tests,
                "workflow_rules": {"business_logic_tests": business_logic_tests, "confidence_profile": scan_request.confidence_profile},
                "user_id": context.user_id,
                "authorization_id": (context.authorization_context or {}).get("authorization_id"),
                "authorization_context": context.authorization_context,
            }
            attack_tasks.append(
                self.runner.run_agent(
                    "sandbox_manager",
                    sandbox.name,
                    lambda: sandbox.run_active_scan(active_payload, scan_id),
                    scan_id,
                )
            )

        attack_events = await self.runner.gather_agents(
            *attack_tasks,
            scan_id=scan_id,
            phase="analysis_running",
            start_progress=30,
            end_progress=65,
        )
        active_result = next(
            (
                event["result"]
                for event in attack_events
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
                await context.host.publish(
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
                for event in attack_events
                if event.get("agent") == "browser_security" and isinstance(event.get("result"), dict)
            ),
            None,
        )
        if browser_result:
            await set_scan_artifacts(scan_id, browser_security_output=browser_result)
            await context.host.publish(
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
            (count for event in attack_events if (count := safe_int(event["result"].get("request_count"))) is not None),
            default=0,
        )
        sandbox_id = next(
            (
                str(event["result"]["sandbox_id"])
                for event in attack_events
                if event["result"].get("sandbox_id")
            ),
            None,
        )
        await context.host.set_progress(
            scan_id,
            65,
            "analysis_complete",
            request_count=request_count,
            sandbox_id=sandbox_id,
        )
        findings = context.host.collect_findings(attack_events, target_url)

        ai_explainer = AIExplainerAgent()
        try:
            ai_event = await self.runner.run_agent(
                "ai_explainer",
                ai_explainer.name,
                lambda: ai_explainer.run(findings, scan_id),
                scan_id,
                max_retries=0,
                timeout=20.0,
            )
            enriched_findings = ai_event["result"].get("findings", findings)
        except asyncio.TimeoutError:
            await context.host.log_action("ai_explainer_timeout", "AI explainer timed out; continuing with deterministic findings")
            await context.host.publish(scan_id, "ai_explainer_timeout", {"status": "timeout", "message": "AI explainer timed out; using fallback findings", "progress": 78})
            enriched_findings = findings
        except Exception as exc:
            await context.host.log_action("ai_explainer_error", str(exc)[:2000])
            await context.host.publish(scan_id, "ai_explainer_error", {"status": "error", "message": "AI explainer failed; using fallback findings", "error": str(exc)[:500], "progress": 78})
            enriched_findings = findings
        await context.host.set_progress(scan_id, 78, "explanations_complete", request_count=request_count)

        persisted_findings = await context.host.persist_findings(scan_id, enriched_findings, target_url)
        await context.host.set_progress(scan_id, 86, "findings_persisted", request_count=request_count)

        stage = {
            "findings": findings,
            "enriched_findings": enriched_findings,
            "persisted_findings": persisted_findings,
            "active_result": active_result,
            "browser_result": browser_result,
            "ai_decision": ai_decision,
            "request_count": request_count,
            "sandbox_id": sandbox_id,
        }
        context.stages["attack"] = stage
        await self.log_action("completed", f"Attack complete: {len(persisted_findings)} findings persisted")
        return stage


class ExploitAgent(Agent):
    """Validates confirmed findings with PoCs.

    Runs the exploitation engine, SQLi exploitation and AI exploitation on
    the persisted findings when exploitation is enabled for the scan.
    """

    def __init__(self, runner: "MultiAgentOrchestrator") -> None:
        super().__init__("Exploit Agent")
        self.runner = runner

    async def run(self, context: SharedContext) -> dict[str, Any]:
        self.scan_id = context.scan_id
        await self.log_action("started", f"Exploit started for {context.target_url}")
        scan_id = context.scan_id
        target_url = context.target_url
        attack = context.stages["attack"]
        persisted_findings = attack["persisted_findings"]
        request_count = safe_int(attack.get("request_count"), 0) or 0

        exploitation_result = None
        ai_exploitation_result = None
        if context.scan_request.enable_exploitation:
            await context.host.set_progress(scan_id, 87, "exploitation_started", request_count=request_count)
            exploiter = ExploitationAgent()
            expl_event = await self.runner.run_agent(
                "exploitation",
                exploiter.name,
                lambda: exploiter.run(target_url, scan_id, findings=persisted_findings),
                scan_id,
            )
            exploitation_result = expl_event.get("result")
            if exploitation_result and exploitation_result.get("exploitation_results"):
                await set_scan_artifacts(scan_id, exploitation_output=exploitation_result)
            await context.host.set_progress(scan_id, 89, "exploitation_complete", request_count=request_count)

            if exploitation_result:
                await context.host.run_sqli_exploitation(target_url, scan_id, persisted_findings)

            ai_exploitation_result = await context.host.run_ai_exploitation(
                target_url, scan_id, persisted_findings, sandbox_id=attack.get("sandbox_id")
            )

        stage = {
            "exploitation_result": exploitation_result,
            "ai_exploitation": ai_exploitation_result,
            "sqli_results": [
                f.get("exploitation_result")
                for f in persisted_findings
                if f.get("exploited") and f.get("exploitation_result")
            ],
        }
        context.stages["exploit"] = stage
        await self.log_action("completed", "Exploit stage complete")
        return stage


class ReportAgent(Agent):
    """Generates comprehensive reports from all stages.

    Produces the markdown report, AI security analyst output, report files
    and delivers the notification, then assembles the scan summary.
    """

    def __init__(self, runner: "MultiAgentOrchestrator") -> None:
        super().__init__("Report Agent")
        self.runner = runner

    async def run(self, context: SharedContext) -> dict[str, Any]:
        self.scan_id = context.scan_id
        await self.log_action("started", f"Report started for {context.target_url}")
        scan_id = context.scan_id
        target_url = context.target_url
        recon = context.stages["recon"]
        attack = context.stages["attack"]
        exploit = context.stages["exploit"]
        persisted_findings = attack["persisted_findings"]
        request_count = safe_int(attack.get("request_count"), 0) or 0
        active_result = attack["active_result"]
        browser_result = attack["browser_result"]

        fixer = FixerAgent()
        fixer_event = await self.runner.run_agent(
            "fixer",
            fixer.name,
            lambda: fixer.run(persisted_findings, scan_id),
            scan_id,
        )
        markdown_report = str(fixer_event["result"].get("markdown_report", ""))
        if active_result and active_result.get("final_report"):
            markdown_report = (
                f"{markdown_report}\n\n{active_result['final_report']}" if markdown_report else str(active_result["final_report"])
            )
        if browser_result:
            browser_report = context.host.browser_report(browser_result)
            markdown_report = f"{markdown_report}\n\n{browser_report}" if markdown_report else browser_report
        await set_scan_artifacts(scan_id, markdown_report=markdown_report)
        await context.host.set_progress(scan_id, 93, "report_complete", request_count=request_count)

        artifact_context = {
            "scanner_output": recon["scanner_output"],
            "shadow_recon_output": recon["shadow_output"],
            "markdown_report": markdown_report,
            "active_security_output": active_result,
            "browser_security_output": browser_result,
        }
        ai_analyst_output = await context.host.run_ai_security_analyst(
            scan_id=scan_id,
            target_url=target_url,
            mode=context.scan_request.mode,
            intensity=context.scan_request.intensity,
            findings=persisted_findings,
            artifacts=artifact_context,
            request_count=request_count,
        )
        await set_scan_artifacts(scan_id, ai_analyst_output=ai_analyst_output)
        await context.host.set_progress(scan_id, 95, "ai_analysis_complete", request_count=request_count)

        summary = {
            "scan_id": scan_id,
            "target_url": target_url,
            "mode": context.scan_request.mode,
            "intensity": context.scan_request.intensity,
            "scanner": recon["scanner_output"],
            "shadow_recon": recon["shadow_output"],
            "findings": persisted_findings,
            "markdown_report": markdown_report,
            "active_security": active_result,
            "browser_security": browser_result,
            "ai_decision": attack["ai_decision"],
            "ai_analyst_output": ai_analyst_output,
            "exploitation_results": exploit["sqli_results"] if exploit["sqli_results"] else None,
            "ai_exploitation": exploit["ai_exploitation"],
        }
        await context.host._write_report_files(
            summary,
            scan_id,
            target_url,
            markdown_report,
            recon["scanner_output"],
            recon["shadow_output"],
            active_result,
        )
        notifier = NotifierAgent()
        notifier_event = await self.runner.run_agent(
            "notifier",
            notifier.name,
            lambda: notifier.run(summary, scan_id),
            scan_id,
        )
        notification_result = notifier_event["result"]
        summary["notification"] = notification_result
        summary["status"] = "complete"
        await set_scan_artifacts(scan_id, notification_result=notification_result)
        await context.host.set_progress(scan_id, 97, "notification_complete", request_count=request_count)
        context.summary = summary
        await self.log_action("completed", f"Report complete for {len(persisted_findings)} findings")
        return summary


class MultiAgentOrchestrator:
    """Runs the Recon -> Attack -> Exploit -> Report workflow on a scan."""

    def __init__(self, limits: SafetyLimits | None = None, host: Any | None = None) -> None:
        self.limits = limits or SafetyLimits.from_settings()
        self.host = host

    async def run(self, context: SharedContext) -> dict[str, Any]:
        if self.host is None:
            raise RuntimeError("MultiAgentOrchestrator requires a host (OrchestratorAgent)")
        graph = WorkflowGraph()
        graph.add_node(
            "recon",
            self._role_operation("recon", ReconAgent(self), context),
            dependencies=[],
        )
        graph.add_node(
            "attack",
            self._role_operation("attack", AttackAgent(self), context),
            dependencies=["recon"],
        )
        graph.add_node(
            "exploit",
            self._role_operation("exploit", ExploitAgent(self), context),
            dependencies=["attack"],
        )
        graph.add_node(
            "report",
            self._role_operation("report", ReportAgent(self), context),
            dependencies=["exploit"],
        )
        await graph.execute(context)
        return context.summary

    def _role_operation(
        self,
        event_name: str,
        agent: Agent,
        context: SharedContext,
    ) -> Callable[[SharedContext], Awaitable[dict[str, Any]]]:
        async def operation(_context: SharedContext) -> dict[str, Any]:
            return await self.run_agent(
                event_name,
                agent.name,
                lambda: agent.run(context),
                context.scan_id,
            )

        return operation

    async def run_agent(
        self,
        event_name: str,
        agent_name: str,
        operation: Callable[[], Awaitable[dict[str, Any]]],
        scan_id: int,
        *,
        max_retries: int = 1,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Run one agent execution and log it to the agent_runs ledger."""
        run_id = await start_agent_run(scan_id, agent_name)
        started = asyncio.get_running_loop().time()
        await self.host.publish(
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
                await complete_agent_run(
                    run_id,
                    status="completed",
                    execution_time=asyncio.get_running_loop().time() - started,
                    attempts=attempt + 1,
                )
                event = {
                    "agent": event_name,
                    "agent_name": agent_name,
                    "status": "complete",
                    "result": result,
                    "attempt": attempt + 1,
                }
                await self.host.publish(scan_id, event_name, event)
                return event
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError as exc:
                last_exc = exc
                await add_audit_log(scan_id, agent_name, "timeout", f"Attempt {attempt + 1} timed out after {timeout}s")
                await self.host.publish(
                    scan_id,
                    event_name,
                    {"agent": event_name, "agent_name": agent_name, "status": "timeout", "attempt": attempt + 1},
                )
            except Exception as exc:
                last_exc = exc
                traceback.print_exc()
                await add_audit_log(scan_id, agent_name, "error", f"Attempt {attempt + 1}: {str(exc)[:2000]}")
                await self.host.publish(
                    scan_id,
                    event_name,
                    {
                        "agent": event_name,
                        "agent_name": agent_name,
                        "status": "error",
                        "attempt": attempt + 1,
                        "error": str(exc),
                    },
                )
                if attempt < max_retries:
                    await asyncio.sleep(1)
                    continue
                await complete_agent_run(
                    run_id,
                    status="failed",
                    execution_time=asyncio.get_running_loop().time() - started,
                    error_message=str(exc)[:1000],
                    attempts=attempt + 1,
                )
                await self.host.log_action("agent_error", f"{agent_name} failed after {attempt + 1} attempts: {exc}"[:2000])
                raise
        await complete_agent_run(
            run_id,
            status="failed",
            execution_time=asyncio.get_running_loop().time() - started,
            error_message=str(last_exc)[:1000] if last_exc else None,
            attempts=max_retries + 1,
        )
        raise last_exc or RuntimeError(f"{agent_name} failed")

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
                    await self.host.publish(
                        scan_id,
                        phase,
                        {
                            "phase": phase,
                            "status": "running",
                            "progress": min(end_progress, progress),
                            "completed_agents": completed,
                            "total_agents": len(tasks),
                            "agent_name": agent_name,
                            "message": f"{agent_name} {status_value}; {completed}/{len(tasks)} analysis agents complete",
                        },
                    )

        return [result or {"error": "Agent did not return a result", "result": {}} for result in results]
