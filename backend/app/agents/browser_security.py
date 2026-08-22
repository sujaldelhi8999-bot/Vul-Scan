from typing import Any

import httpx

from app.agents import Agent
from app.config import get_settings
from app.services.browser_observation import BrowserObservationEngine
from app.services.execution import ExecutionBudget, SafetyLimits


class BrowserSecurityAgent(Agent):
    def __init__(self, limits: SafetyLimits | None = None, transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__("Browser Security Agent")
        self.limits = limits or SafetyLimits.from_settings()
        self.transport = transport

    async def run(
        self,
        target_url: str,
        scan_id: int,
        *,
        mode: str = "defend",
        authorization_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("browser_observation_started", f"Starting browser observation for {target_url}")
        transport = self.transport
        if transport is None and mode == "pentest" and (authorization_context or {}).get("is_lab"):
            from main import app as fastapi_app

            transport = httpx.ASGITransport(app=fastapi_app)
        engine = BrowserObservationEngine(
            target_url=target_url,
            mode=mode,
            authorization_context=authorization_context or {},
            limits=self.limits,
            scan_id=scan_id,
            budget=ExecutionBudget(self.limits),
            transport=transport,
            max_pages=get_settings().browser_page_limit,
        )
        result = await engine.run()
        self.status = "complete" if result.get("status") == "complete" else "error"
        await self.log_action(
            "browser_observation_completed",
            f"Browser observation completed with {len(result.get('network_events', []))} network events, "
            f"{len(result.get('api_inventory', []))} APIs, and {len(result.get('findings', []))} findings",
        )
        return result
