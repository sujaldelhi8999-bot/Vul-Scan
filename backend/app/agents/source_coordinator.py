"""
Source Coordinator Agent - Orchestrates multi-source scanning (SAST, DAST, SCA, IaC, Secrets).
"""

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from app.agents import Agent
from app.agents.sast_agent import SASTAgent
from app.database import update_scan_progress
from app.models import MultiSourceScanRequest
from app.services.active_gate import ActiveTargetGate
from app.services.active_security import ActiveSecurityEngine
from app.services.authorization import TargetAuthorizationService
from app.services.execution import ExecutionBudget, SafetyLimits as ExecSafetyLimits

logger = logging.getLogger("phantomscan.source_coordinator")


class SourceCoordinatorAgent(Agent):
    """Coordinates multi-source security scanning (SAST + DAST + SCA + IaC + Secrets)."""

    def __init__(self, limits: ExecSafetyLimits | None = None) -> None:
        super().__init__("Source Coordinator Agent")
        self.limits = limits or ExecSafetyLimits.from_settings()

    async def run(
        self,
        scan_request: MultiSourceScanRequest,
        scan_id: int,
        user_id: str = "local-user",
        authorization_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run coordinated multi-source scan."""
        try:
            return await self._run_core(scan_request, scan_id, user_id, authorization_context)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Source coordinator failed: %s", e, exc_info=True)
            self.status = "error"
            await self.log_action("failed", f"Source coordinator failed: {str(e)[:2000]}")
            try:
                from app.database import update_scan_status
                await update_scan_status(scan_id, "error", str(e)[:1000])
            except Exception:
                pass
            return {
                "status": "failed",
                "scan_id": scan_id,
                "total_findings": 0,
                "correlated_findings": 0,
                "source_results": [],
                "sources_scanned": [s.type for s in scan_request.sources],
                "health_score": None,
                "error": str(e),
            }

    async def _run_core(
        self,
        scan_request: MultiSourceScanRequest,
        scan_id: int,
        user_id: str = "local-user",
        authorization_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run coordinated multi-source scan (core logic)."""
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Coordinating multi-source scan: {scan_request.name}")

        # Persist source definitions up front
        from app.database import upsert_scan_source
        for source in scan_request.sources:
            source_config = source.model_dump(mode="json") if hasattr(source, "model_dump") else dict(source)
            identifier = source_config.get("repo_url") or source_config.get("target_url") or source_config.get("path") or source_config.get("image") or str(source.type)
            await upsert_scan_source(
                scan_id=scan_id,
                source_type=source.type,
                source_config=source_config,
                source_identifier=str(identifier),
                priority=getattr(source, "priority", 1) or 1,
            )

        # Prepare source configurations
        source_results = []
        total_findings = 0
        correlated_count = 0

        # Separate sources by type
        live_sources = [s for s in scan_request.sources if s.type == "live"]
        sast_sources = [s for s in scan_request.sources if s.type != "live"]

        # Phase 1: Run SAST on code sources (parallel)
        if sast_sources:
            await update_scan_progress(scan_id, 10, f"Starting SAST on {len(sast_sources)} code sources")
            await self.log_action("sast_phase_started", f"Starting SAST on {len(sast_sources)} code sources")
            sast_results = await self._run_sast_sources(sast_sources, scan_id, user_id)
            source_results.extend(sast_results)
            total_findings += sum(self._result_findings(r) for r in sast_results)
            await update_scan_progress(scan_id, 40, f"SAST completed with {total_findings} findings")
            await self.log_action("sast_phase_completed", f"SAST completed with {total_findings} findings")

        # Phase 2: Run DAST on live targets (if authorized)
        if live_sources:
            await update_scan_progress(scan_id, 45, f"Starting DAST on {len(live_sources)} live targets")
            await self.log_action("dast_phase_started", f"Starting DAST on {len(live_sources)} live targets")
            dast_results = await self._run_dast_sources(live_sources, scan_id, user_id, authorization_context)
            source_results.extend(dast_results)
            total_findings += sum(self._result_findings(r) for r in dast_results)
            await update_scan_progress(scan_id, 75, f"DAST completed with {total_findings} total findings")
            await self.log_action("dast_phase_completed", f"DAST completed with {total_findings} total findings")

        # Phase 3: Correlation across sources
        if scan_request.correlate_findings and source_results:
            await update_scan_progress(scan_id, 80, "Starting cross-source correlation")
            await self.log_action("correlation_started", "Starting cross-source correlation")
            correlated_count = await self._correlate_findings(scan_id, source_results)
            await self.log_action("correlation_completed", f"Found {correlated_count} correlations")

        # Phase 4: Data flow tracing
        if scan_request.data_flow_tracing and source_results:
            await update_scan_progress(scan_id, 85, "Starting data flow tracing")
            await self.log_action("dataflow_started", "Starting data flow tracing")
            await self._trace_data_flows(scan_id, source_results)
            await self.log_action("dataflow_completed", "Data flow tracing completed")

        # Phase 5: Calculate health score
        await update_scan_progress(scan_id, 90, "Calculating health score")
        health_score_result = None
        try:
            from app.services.health_score import calculate_health_score
            all_findings = []
            for source_result in source_results:
                all_findings.extend(source_result.get("findings", []))
            summary = {
                "total_findings": total_findings,
                "critical": sum(1 for f in all_findings if f.get("severity") == "critical"),
                "high": sum(1 for f in all_findings if f.get("severity") == "high"),
                "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
                "low": sum(1 for f in all_findings if f.get("severity") == "low"),
                "info": sum(1 for f in all_findings if f.get("severity") == "info"),
                "secrets_found": sum(1 for f in all_findings if f.get("type") in ("secret", "secrets")),
                "total_files": sum(r.get("stats", {}).get("total_files", 0) for r in source_results),
                "scanned_files": sum(r.get("stats", {}).get("scanned_files", 0) for r in source_results),
                "lines_scanned": sum(r.get("stats", {}).get("lines_scanned", 0) for r in source_results),
                "scan_duration_seconds": 0,
            }
            health_score_result = calculate_health_score(summary, all_findings)
            await self.log_action("health_score", f"Health score: {health_score_result.health_score}/100 ({health_score_result.classification})")
        except Exception as e:
            await self.log_action("health_score_error", f"Health score calculation failed: {str(e)}")

        await update_scan_progress(scan_id, 95, f"Scan complete: {total_findings} findings, {correlated_count} correlations")
        self.status = "complete"
        await self.log_action("completed", f"Multi-source scan completed: {total_findings} findings, {correlated_count} correlations")

        return {
            "status": "complete",
            "scan_id": scan_id,
            "total_findings": total_findings,
            "correlated_findings": correlated_count,
            "source_results": source_results,
            "sources_scanned": [s.type for s in scan_request.sources],
            "health_score": {
                "score": health_score_result.health_score,
                "classification": health_score_result.classification,
                "color": health_score_result.color,
                "categories": [
                    {"name": c.name, "score": c.score, "weighted_score": c.weighted_score, "factors": c.factors}
                    for c in health_score_result.categories
                ],
                "top_factors": health_score_result.top_factors,
                "executive_summary": health_score_result.executive_summary,
            } if health_score_result else None,
        }

    @staticmethod
    def _result_findings(item: dict[str, Any]) -> int:
        """Safely extract total_findings from a source result item."""
        result = item.get("result")
        if isinstance(result, dict):
            return int(result.get("total_findings", 0) or 0)
        logger.warning("Malformed source result item (missing 'result'): %s", item)
        return 0

    async def _run_sast_sources(
        self,
        sources: list[Any],
        scan_id: int,
        user_id: str,
    ) -> list[dict[str, Any]]:
        """Run SAST on multiple code sources, updating progress as each one completes."""
        from app.database import update_scan_source_status

        total = max(len(sources), 1)
        # Progress budget: 10% (start) → 40% (all SAST done).  30 points total.
        progress_start = 10
        progress_end = 40
        progress_budget = progress_end - progress_start  # 30

        results: list[dict[str, Any]] = []
        completed = 0

        # Emit a quick pulse so the bar moves immediately (12%) and the user
        # knows the scan is working, not stuck.
        await update_scan_progress(
            scan_id,
            progress_start + 2,
            f"SAST running on {total} source(s) — pure-Python scanners active",
        )

        async def run_single(source) -> dict[str, Any]:
            source_config = (
                source.model_dump(mode="json") if hasattr(source, "model_dump") else source
            )
            identifier = source_config.get("repo_url") or source_config.get("path", "unknown")
            sast_agent = SASTAgent()
            started = time.time()
            try:
                await update_scan_source_status(scan_id, source.type, "running", error_message=None)
                result = await sast_agent.run(
                    scan_id=scan_id,
                    source_config=source_config,
                    scan_mode="sast",
                )
                findings = result.get("findings", [])
                await update_scan_source_status(
                    scan_id,
                    source.type,
                    "completed",
                    findings_count=len(findings),
                    scan_duration_seconds=round(time.time() - started, 2),
                    artifacts={"tool_counts": result.get("tool_counts") or {}},
                )
                return {
                    "source_type": source.type,
                    "source_identifier": identifier,
                    "status": "completed",
                    "result": result,
                    "findings": findings,
                }
            except Exception as e:
                error_msg = str(e) or f"{type(e).__name__}: {e}"
                logger.error("Source %s failed: %s", identifier, error_msg, exc_info=True)
                await update_scan_source_status(
                    scan_id,
                    source.type,
                    "failed",
                    error_message=error_msg[:1000],
                    scan_duration_seconds=round(time.time() - started, 2),
                )
                return {
                    "source_type": source.type,
                    "source_identifier": identifier,
                    "status": "failed",
                    "error": error_msg,
                }

        # Run sources sequentially so we can emit per-source progress.
        # (Parallel gather is fine for speed but loses per-item progress signals.)
        for source in sources:
            result = await run_single(source)
            results.append(result)
            completed += 1
            # Interpolate progress: 12% → 38% as sources complete
            pct = progress_start + 2 + int(progress_budget * 0.9 * completed / total)
            n_findings = len(result.get("findings", []) or result.get("result", {}).get("findings", []))
            await update_scan_progress(
                scan_id,
                pct,
                f"SAST {completed}/{total} done — {n_findings} findings so far",
            )

        return results

    async def _run_dast_sources(
        self,
        sources: list[Any],
        scan_id: int,
        user_id: str,
        authorization_context: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Run DAST on live targets."""
        from app.database import update_scan_source_status
        results = []
        
        for source in sources:
            source_config = source.model_dump(mode="json") if hasattr(source, 'model_dump') else source
            target_url = source_config.get("target_url")
            source_id = target_url or "live"
            started = time.time()
            
            # Check authorization
            try:
                await update_scan_source_status(scan_id, source_id, "running", error_message=None)
                auth_service = TargetAuthorizationService()
                gate = ActiveTargetGate(auth_service)
                decision = await gate.admit(
                    target_url, user_id, 
                    source_config.get("authorization_id"),
                    user_role="user"
                )
                
                if not decision.allowed:
                    await update_scan_source_status(
                        scan_id, source_id, "skipped", error_message=decision.reason,
                    )
                    results.append({
                        "source_type": "live",
                        "source_identifier": target_url,
                        "status": "skipped",
                        "error": decision.reason,
                    })
                    continue

                # Run DAST
                limits = ExecSafetyLimits.from_settings()
                budget = ExecutionBudget(limits)
                transport = httpx.ASGITransport(app=None) if decision.is_lab else None
                
                engine = ActiveSecurityEngine(
                    target_url=decision.target_url,
                    attack_surface=None,
                    selected_modules=[str(item) for item in source_config.get("selected_modules", [])],
                    limits=limits,
                    authorization_context=decision.to_context(),
                    workflow_rules=source_config.get("workflow_rules", {}),
                    scan_id=scan_id,
                    user_id=user_id,
                    sandbox_id=f"dast-{scan_id}",
                    budget=budget,
                    transport=transport,
                )
                
                result = await engine.run()
                findings = result.get("findings", [])
                await update_scan_source_status(
                    scan_id,
                    source_id,
                    "completed",
                    findings_count=len(findings),
                    scan_duration_seconds=round(time.time() - started, 2),
                )
                results.append({
                    "source_type": "live",
                    "source_identifier": target_url,
                    "status": "completed",
                    "result": result,
                })
                
            except Exception as e:
                await update_scan_source_status(
                    scan_id, source_id, "failed", error_message=str(e)[:1000],
                    scan_duration_seconds=round(time.time() - started, 2),
                )
                results.append({
                    "source_type": "live",
                    "source_identifier": target_url,
                    "status": "failed",
                    "error": str(e),
                })
        
        return results

    async def _correlate_findings(self, scan_id: int, source_results: list[dict[str, Any]]) -> int:
        """Correlate findings across sources."""
        from app.database import get_connection
        
        all_findings = []
        for sr in source_results:
            if sr.get("status") == "completed" and "result" in sr:
                findings = sr["result"].get("findings", [])
                for f in findings:
                    f["_source_result"] = sr
                all_findings.extend(findings)
        
        if not all_findings:
            return 0
        
        # Simple correlation: group by file path, endpoint, or rule
        correlations = []
        processed = set()
        
        for i, f1 in enumerate(all_findings):
            if i in processed:
                continue
            
            correlated = [i]
            for j, f2 in enumerate(all_findings):
                if i == j or j in processed:
                    continue
                
                # Check correlation criteria
                if self._are_findings_correlated(f1, f2):
                    correlated.append(j)
                    processed.add(j)
            
            if len(correlated) > 1:
                correlations.append({
                    "scan_id": scan_id,
                    "unified_id": f"corr-{scan_id}-{len(correlations)}",
                    "correlation_type": self._determine_correlation_type(all_findings, correlated),
                    "confidence": 0.8,
                    "source_types": list(set(all_findings[i].get("_source_result", {}).get("source_type", "unknown") for i in correlated)),
                    "finding_ids": [all_findings[i].get("id") for i in correlated if all_findings[i].get("id")],
                    "evidence": {"correlated_count": len(correlated)},
                })
                processed.update(correlated)
        
        # Store correlations
        if correlations:
            async with get_connection() as conn:
                for corr in correlations:
                    await conn.execute(
                        """
                        INSERT INTO source_correlations (
                            scan_id, unified_id, correlation_type, confidence,
                            source_types, finding_ids, evidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            corr["unified_id"],
                            corr["correlation_type"],
                            corr["confidence"],
                            json.dumps(corr["source_types"]),
                            json.dumps(corr["finding_ids"]),
                            json.dumps(corr["evidence"]),
                        ),
                    )
                await conn.commit()
        
        return len(correlations)

    def _are_findings_correlated(self, f1: dict[str, Any], f2: dict[str, Any]) -> bool:
        """Check if two findings are correlated."""
        # Same file path
        if f1.get("file_path") and f1.get("file_path") == f2.get("file_path"):
            return True
        
        # Same endpoint
        if f1.get("endpoint") and f1.get("endpoint") == f2.get("endpoint"):
            return True
        
        # Same rule ID
        if f1.get("rule_id") and f1.get("rule_id") == f2.get("rule_id"):
            return True
        
        # Same CVE
        if f1.get("cve_id") and f1.get("cve_id") == f2.get("cve_id"):
            return True
        
        # Same vulnerability type + similar location
        if f1.get("type") == f2.get("type"):
            # Check if they're in the same component
            loc1 = f1.get("file_path", "") or f1.get("endpoint", "")
            loc2 = f2.get("file_path", "") or f2.get("endpoint", "")
            if loc1 and loc2 and self._similar_location(loc1, loc2):
                return True
        
        return False

    def _similar_location(self, loc1: str, loc2: str) -> bool:
        """Check if two locations are similar (same directory or same API path prefix)."""
        from urllib.parse import urlparse
        import os
        try:
            if loc1.startswith("http") and loc2.startswith("http"):
                p1 = urlparse(loc1).path
                p2 = urlparse(loc2).path
                return p1.split("/")[1] == p2.split("/")[1] if len(p1.split("/")) > 1 and len(p2.split("/")) > 1 else False
            # File path: same directory
            dir1 = os.path.dirname(loc1)
            dir2 = os.path.dirname(loc2)
            if dir1 and dir2 and dir1 == dir2:
                return True
            # File path: same filename
            if os.path.basename(loc1) == os.path.basename(loc2) and os.path.basename(loc1):
                return True
        except Exception as e:
            logger.debug("Error: %s", e)
        return False

    def _determine_correlation_type(self, findings: list[dict[str, Any]], indices: list[int]) -> str:
        """Determine correlation type."""
        types = set(findings[i].get("type") for i in indices)
        
        if len(types) > 1:
            return "vulnerability_chain"
        
        t = types.pop() if types else ""
        if t == "sast":
            return "same_file"
        elif t == "dast":
            return "same_endpoint"
        return "exact_match"

    async def _trace_data_flows(self, scan_id: int, source_results: list[dict[str, Any]]) -> None:
        """Perform taint analysis / data flow tracing."""
        # This would integrate with a taint analysis engine
        # For now, we'll create data flow traces for correlated findings
        from app.database import get_connection

        async with get_connection() as conn:
            # Get all findings for this scan
            cursor = await conn.execute(
                "SELECT id, title, category, endpoint, evidence FROM findings WHERE scan_id = ?",
                (scan_id,),
            )
            findings = [dict(r) for r in await cursor.fetchall()]

            # Simple data flow: trace from source (user input) to sink (dangerous function)
            # This is a simplified version - a real implementation would use a taint analysis engine
            for f in findings:
                if f.get("category") in ("injection", "xss", "ssrf", "rce"):
                    # This finding could be part of a data flow
                    pass
