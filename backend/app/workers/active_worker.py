import asyncio
import json
import sys
from typing import Any

import httpx

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from app.agents.pentest import PentestAgent
from app.models import BusinessLogicTest
from app.services.authorization import TargetAuthorizationService
from app.services.active_security import ActiveSecurityEngine
from app.services.execution import ExecutionBudget, SafetyLimits


async def execute(payload: dict[str, Any]) -> dict[str, Any]:
    limits = SafetyLimits(**payload["limits"])
    budget = ExecutionBudget(limits)
    if payload.get("engine") == "active_security":
        workflow_rules = dict(payload.get("workflow_rules") or {})
        if "business_logic_tests" not in workflow_rules:
            workflow_rules["business_logic_tests"] = payload.get("business_logic_tests", [])
        authorization_context = dict(payload.get("authorization_context") or {})
        transport = None
        if authorization_context.get("is_lab"):
            from main import app as fastapi_app

            transport = httpx.ASGITransport(app=fastapi_app)
        engine = ActiveSecurityEngine(
            target_url=str(payload["target_url"]),
            attack_surface=payload.get("attack_surface"),
            selected_modules=[str(item) for item in payload.get("selected_modules") or payload.get("selected_tests", [])],
            limits=limits,
            authorization_context=authorization_context,
            workflow_rules=workflow_rules,
            scan_id=int(payload["scan_id"]),
            user_id=str(payload["user_id"]),
            sandbox_id=str(payload["sandbox_id"]),
            budget=budget,
            transport=transport,
        )
        result = await engine.run()
        return {"status": "complete", "result": result}

    authorization_service = TargetAuthorizationService()
    agent = PentestAgent(
        authorization_service=authorization_service,
        budget=budget,
        user_id=str(payload["user_id"]),
        authorization_id=int(payload["authorization_id"]),
        sandbox_id=str(payload["sandbox_id"]),
    )
    business_tests = [BusinessLogicTest(**item) for item in payload.get("business_logic_tests", [])]
    result = await agent.run(
        target_url=str(payload["target_url"]),
        scan_id=int(payload["scan_id"]),
        mode="pentest",
        intensity=str(payload["intensity"]),
        selected_tests=[str(item) for item in payload["selected_tests"]],
        business_logic_tests=business_tests,
    )
    return {"status": "complete", "result": result}


def main() -> None:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = asyncio.run(execute(payload))
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
    except BaseException as exc:
        sys.stdout.write(json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":")))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
