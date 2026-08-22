from typing import Any

from app.agents import Agent
from app.services.ai_analyst import create_ai_security_analyst


class AISecurityAnalystAgent(Agent):
    def __init__(self) -> None:
        super().__init__("AI Security Analyst Agent")

    async def run(
        self,
        *,
        scan: dict[str, Any],
        findings: list[dict[str, Any]],
        artifacts: dict[str, Any] | None,
        previous_scan: dict[str, Any] | None = None,
        previous_findings: list[dict[str, Any]] | None = None,
        previous_artifacts: dict[str, Any] | None = None,
        logs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self.scan_id = int(scan.get("id") or scan.get("scan_id") or 0)
        self.status = "active"
        await self.log_action("started", f"Analyzing {len(findings)} evidence-backed findings")
        analyst = create_ai_security_analyst()
        result = await analyst.analyze(
            scan=scan,
            findings=findings,
            artifacts=artifacts,
            previous_scan=previous_scan,
            previous_findings=previous_findings,
            previous_artifacts=previous_artifacts,
            logs=logs,
        )
        self.status = "complete"
        await self.log_action("completed", f"Generated {len(result.get('priorities', []))} priorities and {len(result.get('root_causes', []))} root-cause groups")
        return result
