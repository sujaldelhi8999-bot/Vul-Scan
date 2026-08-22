import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.agents import Agent
from app.agents.notifier import NotifierAgent
from app.agents.orchestrator import OrchestratorAgent
from app.config import get_settings
from app.database import (
    add_audit_log, create_scan, get_findings, set_scan_artifacts,
    update_scan_status, get_or_create_system_user,
)
from app.services.execution_status import update_self_audit_execution
from app.models import ScanRequest
from app.services.authorization import canonicalize_target

logger = logging.getLogger("phantomscan.self_audit")


BASE_DIR = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = BASE_DIR / "reports"
SELF_AUDIT_LOG = BASE_DIR / "reports" / "self_audit_log.json"


class SelfAuditAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Self Audit Agent")
        self.settings = get_settings()
        REPORTS_DIR.mkdir(exist_ok=True)

    async def run(
        self, target_url: str = "http://localhost:8000",
        scan_id: int | None = None
    ) -> dict[str, Any]:
        target = canonicalize_target(target_url)

        if scan_id is None:
            system_user_id = await get_or_create_system_user()
            scan_id = await create_scan(
                target_url=target.url, mode="defend", intensity="low",
                selected_tests="[]", user_id=system_user_id,
            )

        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", "Running PhantomScan self-audit")
        await update_self_audit_execution(lifecycle="running", scan_id=scan_id, target_url=target.url)

        try:
            orchestrator = OrchestratorAgent()
            request = ScanRequest(target_url=target.url, mode="defend", intensity="low")
            result = await orchestrator.run(request, scan_id)

            if result.get("status") == "error":
                self.status = "error"
                await self.log_action("error", str(result.get("error", ""))[:2000])
                return result

            findings = await get_findings(scan_id)
            critical_high = [
                f for f in findings
                if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
            ]

            configuration_issues = self._detect_configuration_issues()
            dependency_issues = self._scan_dependencies()

            previous = self._load_previous()
            new_critical = self._diff_findings(critical_high, previous)

            notification_result: dict[str, Any] | None = None
            if critical_high or configuration_issues or dependency_issues:
                await add_audit_log(
                    scan_id, self.name, "ALERT",
                    f"New Critical/High findings: {len(critical_high)}, Config issues: {len(configuration_issues)}, Dep issues: {len(dependency_issues)}",
                )
                notifier = NotifierAgent()
                notification_result = await notifier.run(
                    {
                        "findings": critical_high,
                        "target_url": target.url,
                        "configuration_issues": configuration_issues,
                        "dependency_issues": dependency_issues,
                    },
                    scan_id, webhook_url=self.settings.self_audit_webhook,
                )

            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            report = {
                "scan_id": scan_id,
                "date": today,
                "target": target.url,
                "total_findings": len(findings),
                "critical_high": len(critical_high),
                "new_since_last_audit": len(new_critical),
                "configuration_issues": len(configuration_issues),
                "dependency_issues": len(dependency_issues),
                "findings": [
                    {"title": f.get("title"), "severity": f.get("severity"),
                     "category": f.get("category")}
                    for f in findings
                ],
                "configuration_details": configuration_issues,
                "dependency_details": dependency_issues,
                "notification_delivered": notification_result.get("delivered", False)
                if notification_result else False,
            }

            report_path = REPORTS_DIR / f"self_audit_{today}.json"
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2, default=str)

            self._save_previous(critical_high)

            self.status = "complete"
            await self.log_action(
                "completed",
                f"Self-audit: {len(findings)} findings, "
                f"{len(critical_high)} critical/high, "
                f"{len(new_critical)} new, "
                f"{len(configuration_issues)} config issues, "
                f"{len(dependency_issues)} dependency issues"
            )
            await update_self_audit_execution(
                lifecycle="complete", scan_id=scan_id,
                findings_count=len(findings),
            )
            return {
                "scan_id": scan_id, "status": "complete",
                "findings": findings,
                "critical_high": critical_high,
                "new_critical": new_critical,
                "configuration_issues": configuration_issues,
                "dependency_issues": dependency_issues,
                "notification": notification_result,
                "report_path": str(report_path),
            }

        except asyncio.CancelledError:
            await update_scan_status(scan_id, "cancelled")
            raise
        except Exception as exc:
            self.status = "error"
            await update_scan_status(scan_id, "error", str(exc)[:1000])
            await self.log_action("error", str(exc)[:2000])
            await update_self_audit_execution(
                lifecycle="error", scan_id=scan_id,
                error_message=str(exc)[:1000],
            )
            raise

    def _load_previous(self) -> list[dict[str, Any]]:
        try:
            if SELF_AUDIT_LOG.exists():
                with open(SELF_AUDIT_LOG) as f:
                    return json.load(f)
        except Exception as e:
            logger.debug("Error: %s", e)
            pass
        return []

    def _save_previous(self, findings: list[dict[str, Any]]) -> None:
        try:
            with open(SELF_AUDIT_LOG, "w") as f:
                json.dump(findings, f, indent=2, default=str)
        except Exception as e:
            logger.debug("Error: %s", e)
            pass

    def _diff_findings(
        self, current: list[dict[str, Any]],
        previous: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        prev_titles = {f.get("title", "") for f in previous}
        return [f for f in current if f.get("title", "") not in prev_titles]
