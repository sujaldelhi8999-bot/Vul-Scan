import asyncio
from typing import Literal

from app.database import add_audit_log

AgentStatus = Literal["idle", "active", "complete", "error"]


class Agent:
    def __init__(self, name: str) -> None:
        self.name = name
        self.status: AgentStatus = "idle"
        self.scan_id: int | None = None

    async def run(self, target_url: str, scan_id: int) -> dict[str, str]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Started agent run for {target_url}")
        await asyncio.sleep(0)
        self.status = "complete"
        await self.log_action("completed", f"Completed agent run for {target_url}")
        return {"name": self.name, "status": self.status}

    async def log_action(self, action: str, details: str) -> int:
        if self.scan_id is None:
            raise RuntimeError("Agent must be assigned to a scan before writing audit logs")
        return await add_audit_log(
            scan_id=self.scan_id,
            agent_name=self.name,
            action=action,
            details=details,
        )
