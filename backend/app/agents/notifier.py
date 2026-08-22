import logging
from typing import Any

import httpx

from app.agents import Agent
from app.config import get_settings

logger = logging.getLogger("phantomscan.notifier")


class NotifierAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Notifier Agent")
        self.settings = get_settings()

    async def run(
        self, scan_summary: dict[str, Any], scan_id: int,
        webhook_url: str | None = None
    ) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        dest = webhook_url or self.settings.notification_webhook_url
        await self.log_action("started", "Preparing notification")

        if not dest:
            self.status = "complete"
            await self.log_action("skipped", "No webhook configured")
            return {"delivered": False, "status_code": None, "message": "No webhook URL"}

        findings = scan_summary.get("findings", [])
        critical_count = len([f for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"])
        high_count = len([f for f in findings if str(f.get("severity", "")).upper() == "HIGH"])
        top_critical = ""
        for f in findings:
            if str(f.get("severity", "")).upper() == "CRITICAL":
                top_critical = str(f.get("title", "Unknown"))
                break

        scan_time = str(scan_summary.get("scan_time", 0))

        payload = {
            "text": f"PhantomScan completed: {scan_summary.get('target_url', 'unknown')}",
            "attachments": [{
                "color": "#ff0000" if critical_count > 0 else "#ffa500",
                "fields": [
                    {"title": "Critical", "value": str(critical_count), "short": True},
                    {"title": "High", "value": str(high_count), "short": True},
                    {"title": "Scan Time", "value": f"{scan_time}s", "short": True},
                    {"title": "Top Finding", "value": top_critical or "None", "short": False},
                ]
            }]
        }

        if critical_count > 0 or high_count > 0:
            payload["attachments"][0]["fields"].insert(
                0, {"title": "🚨 ALERT 🚨", "value": f"{critical_count} Critical + {high_count} High findings", "short": False}
            )

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                r = await client.post(dest, json=payload)
                delivered = 200 <= r.status_code < 300
                self.status = "complete" if delivered else "error"
                await self.log_action("delivered" if delivered else "failed", f"HTTP {r.status_code}")
                return {"delivered": delivered, "status_code": r.status_code, "message": r.text[:500]}
            except httpx.HTTPError as exc:
                self.status = "error"
                await self.log_action("failed", str(exc))
                return {"delivered": False, "status_code": None, "message": str(exc)}

    async def send_critical_alert(
        self, finding: dict[str, Any], target_url: str, scan_id: int,
        webhook_url: str | None = None
    ) -> dict[str, Any]:
        self.scan_id = scan_id
        dest = webhook_url or self.settings.notification_webhook_url
        if not dest:
            return {"delivered": False, "status_code": None, "message": "No webhook"}

        payload = {
            "text": f"🚨 CRITICAL FINDING DURING SCAN: {target_url}",
            "attachments": [{
                "color": "#ff0000",
                "fields": [
                    {"title": "Finding", "value": str(finding.get("title", "")), "short": False},
                    {"title": "Severity", "value": str(finding.get("severity", "")), "short": True},
                    {"title": "Endpoint", "value": str(finding.get("endpoint", "")), "short": True},
                ]
            }]
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                r = await client.post(dest, json=payload)
                return {"delivered": 200 <= r.status_code < 300, "status_code": r.status_code}
            except Exception as e:
                logger.debug("Error: %s", e)
                return {"delivered": False, "status_code": None}
