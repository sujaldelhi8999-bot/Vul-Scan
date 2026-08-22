import asyncio
import traceback
import uuid
from typing import Any

from app.agents.orchestrator import OrchestratorAgent
from app.database import add_audit_log, get_scan, update_scan_status
from app.models import ScanRequest
from app.services.authorization import VerifiedTarget
from app.services.execution import SafetyLimits
from app.websockets import scan_event_broker


class ScanCapacityError(RuntimeError):
    pass


class ScanNotRunningError(RuntimeError):
    pass


class ScanJobManager:
    def __init__(self, limits: SafetyLimits | None = None) -> None:
        self.limits = limits or SafetyLimits.from_settings()
        self._tasks: dict[int, asyncio.Task[dict[str, Any]]] = {}
        self._reservations: set[str] = set()
        self._lock = asyncio.Lock()

    async def reserve_slot(self) -> str:
        async with self._lock:
            self._remove_completed()
            if len(self._tasks) + len(self._reservations) >= self.limits.max_concurrent_scans:
                raise ScanCapacityError("Maximum concurrent scan limit reached")
            reservation = uuid.uuid4().hex
            self._reservations.add(reservation)
            return reservation

    async def release_slot(self, reservation: str) -> None:
        async with self._lock:
            self._reservations.discard(reservation)

    async def submit(
        self,
        reservation: str,
        scan_id: int,
        request: ScanRequest,
        verified_target: VerifiedTarget | None,
        user_id: str,
        authorization_context: dict[str, object] | None = None,
        user_role: str = "user",
    ) -> None:
        async with self._lock:
            if reservation not in self._reservations:
                raise ScanCapacityError("Scan capacity reservation is invalid or expired")
            self._reservations.remove(reservation)
            task = asyncio.create_task(
                self._execute(scan_id, request, verified_target, user_id, authorization_context, user_role),
                name=f"phantomscan-{scan_id}",
            )
            self._tasks[scan_id] = task

    async def _execute(
        self,
        scan_id: int,
        request: ScanRequest,
        verified_target: VerifiedTarget | None,
        user_id: str,
        authorization_context: dict[str, object] | None = None,
        user_role: str = "user",
    ) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(
                OrchestratorAgent(limits=self.limits).run(
                    request,
                    scan_id,
                    verified_target=verified_target,
                    user_id=user_id,
                    user_role=user_role,
                    authorization_context=authorization_context,
                ),
                timeout=self.limits.max_scan_duration + 5,
            )
        except asyncio.TimeoutError:
            await update_scan_status(scan_id, "error", "Scan exceeded the configured duration limit")
            await add_audit_log(scan_id, "Job Manager", "scan_timeout", "Scan terminated by the hard duration limit")
            scan = await get_scan(scan_id)
            await scan_event_broker.publish(
                scan_id,
                {
                    "type": "scan_failed",
                    "progress": int(scan["progress"]) if scan is not None else 0,
                    "error": "Scan time limit exceeded",
                },
            )
            return {"scan_id": scan_id, "status": "error"}
        except asyncio.CancelledError:
            await update_scan_status(scan_id, "cancelled")
            await add_audit_log(scan_id, "Job Manager", "scan_cancelled", "Scan cancelled by user request")
            scan = await get_scan(scan_id)
            await scan_event_broker.publish(
                scan_id,
                {"type": "scan_cancelled", "progress": int(scan["progress"]) if scan is not None else 0},
            )
            raise
        except Exception as exc:
            traceback.print_exc()
            await update_scan_status(scan_id, "error", str(exc)[:1000])
            await add_audit_log(scan_id, "Job Manager", "scan_failed", str(exc)[:2000])
            scan = await get_scan(scan_id)
            await scan_event_broker.publish(
                scan_id,
                {
                    "type": "scan_failed",
                    "progress": int(scan["progress"]) if scan is not None else 0,
                    "error": str(exc),
                },
            )
            return {"scan_id": scan_id, "status": "error", "error": str(exc)}
        finally:
            async with self._lock:
                self._tasks.pop(scan_id, None)

    async def stop(self, scan_id: int) -> str:
        scan = await get_scan(scan_id)
        if scan is None:
            raise KeyError(scan_id)
        if scan["status"] in {"cancelling", "cancelled", "complete", "error"}:
            raise ScanNotRunningError(f"Scan is already {scan['status']}")
        async with self._lock:
            task = self._tasks.get(scan_id)
            if task is not None and task.done():
                self._tasks.pop(scan_id, None)
                task = None
            current = await get_scan(scan_id)
            if current is None:
                raise KeyError(scan_id)
            if current["status"] in {"cancelling", "cancelled", "complete", "error"}:
                raise ScanNotRunningError(f"Scan is already {current['status']}")
            await update_scan_status(scan_id, "cancelling")
            await add_audit_log(scan_id, "Job Manager", "cancellation_requested", "Immediate scan cancellation requested")
            await scan_event_broker.publish(
                scan_id,
                {"type": "scan_cancelling", "progress": int(current["progress"])},
            )
            if task is not None:
                task.cancel()
            else:
                await update_scan_status(scan_id, "cancelled")
                await add_audit_log(scan_id, "Job Manager", "scan_cancelled", "Queued scan cancelled before execution")
                await scan_event_broker.publish(
                    scan_id,
                    {"type": "scan_cancelled", "progress": int(current["progress"])},
                )
        return "cancelling" if task is not None else "cancelled"

    async def is_active(self, scan_id: int) -> bool:
        async with self._lock:
            self._remove_completed()
            task = self._tasks.get(scan_id)
            return task is not None and not task.done()

    async def register_task(self, scan_id: int, task: asyncio.Task[dict[str, Any]]) -> None:
        async with self._lock:
            self._tasks[scan_id] = task

    async def shutdown(self) -> None:
        async with self._lock:
            tasks = list(self._tasks.values())
            for task in tasks:
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _remove_completed(self) -> None:
        for scan_id, task in list(self._tasks.items()):
            if task.done():
                self._tasks.pop(scan_id, None)


scan_job_manager = ScanJobManager()
