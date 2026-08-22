import asyncio
import time
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from app.config import get_settings
from app.database import add_audit_log
from app.security import redact_sensitive, redact_url
from app.services.authorization import TargetAuthorizationService, canonicalize_target


class ExecutionLimitError(RuntimeError):
    pass


class RequestLimitExceeded(ExecutionLimitError):
    pass


class ScanDeadlineExceeded(ExecutionLimitError):
    pass


class ScanCancelled(ExecutionLimitError):
    pass


@dataclass(frozen=True)
class SafetyLimits:
    max_scan_duration: int
    max_requests_per_second: float
    max_total_requests: int
    max_concurrent_scans: int
    max_redirect_depth: int
    max_response_size: int

    @classmethod
    def from_settings(cls) -> "SafetyLimits":
        settings = get_settings()
        return cls(
            max_scan_duration=max(10, settings.max_scan_duration),
            max_requests_per_second=max(0.1, settings.max_requests_per_second),
            max_total_requests=max(1, settings.max_total_requests),
            max_concurrent_scans=max(1, settings.max_concurrent_scans),
            max_redirect_depth=max(0, settings.max_redirect_depth),
            max_response_size=max(1024, settings.max_response_size),
        )


class ExecutionBudget:
    def __init__(self, limits: SafetyLimits) -> None:
        self.limits = limits
        self.started_at = time.monotonic()
        self.cancelled = asyncio.Event()
        self.request_count = 0
        self._request_times: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def reserve_request(self) -> int:
        async with self._lock:
            self.check()
            if self.request_count >= self.limits.max_total_requests:
                raise RequestLimitExceeded(f"Request budget exhausted at {self.limits.max_total_requests} requests")

            now = time.monotonic()
            while self._request_times and now - self._request_times[0] >= 1.0:
                self._request_times.popleft()
            rate_window = max(1, int(self.limits.max_requests_per_second))
            if len(self._request_times) >= rate_window:
                wait_for = 1.0 - (now - self._request_times[0])
                if wait_for > 0:
                    await asyncio.sleep(wait_for)
                    self.check()
                    now = time.monotonic()
                    while self._request_times and now - self._request_times[0] >= 1.0:
                        self._request_times.popleft()

            self.request_count += 1
            self._request_times.append(time.monotonic())
            return self.request_count

    def check(self) -> None:
        if self.cancelled.is_set():
            raise ScanCancelled("Scan cancellation requested")
        if time.monotonic() - self.started_at >= self.limits.max_scan_duration:
            raise ScanDeadlineExceeded(f"Scan exceeded {self.limits.max_scan_duration} seconds")

    def cancel(self) -> None:
        self.cancelled.set()


class BudgetedTargetClient:
    def __init__(
        self,
        *,
        scan_id: int,
        user_id: str,
        authorization_id: int,
        target_url: str,
        sandbox_id: str,
        authorization_service: TargetAuthorizationService,
        budget: ExecutionBudget,
    ) -> None:
        self.scan_id = scan_id
        self.user_id = user_id
        self.authorization_id = authorization_id
        self.target = canonicalize_target(target_url)
        self.sandbox_id = sandbox_id
        self.authorization_service = authorization_service
        self.budget = budget

    async def request(
        self,
        module: str,
        method: str,
        url_or_path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        await self.authorization_service.require_verified(
            self.target.url,
            self.user_id,
            self.authorization_id,
        )
        self.budget.check()
        url = urljoin(f"{self.target.origin}/", url_or_path) if url_or_path.startswith("/") else url_or_path
        candidate = canonicalize_target(url)
        if candidate.origin != self.target.origin:
            raise ExecutionLimitError("Active requests cannot leave the verified target origin")
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
            raise ExecutionLimitError(f"HTTP method {method} is not allowed by the active-test sandbox")
        request_number = await self.budget.reserve_request()
        await add_audit_log(
            self.scan_id,
            "Pentest Agent",
            "active_request",
            f"{method} {redact_url(candidate.url)}",
            user_id=self.user_id,
            target=self.target.origin,
            authorization_status="VERIFIED",
            selected_module=module,
            request_count=request_number,
            sandbox_id=self.sandbox_id,
        )

        timeout = min(10.0, max(1.0, self.budget.limits.max_scan_duration / 4))
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "PhantomScan-Authorized-Pentest/1.0"},
            ) as client:
                async with client.stream(method, candidate.url, headers=headers, json=json_body) as response:
                    body = bytearray()
                    truncated = False
                    async for chunk in response.aiter_bytes():
                        remaining = self.budget.limits.max_response_size - len(body)
                        if remaining <= 0:
                            truncated = True
                            break
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break
                    decoded = body.decode(response.encoding or "utf-8", errors="replace")
                    return {
                        "url": candidate.url,
                        "status_code": response.status_code,
                        "headers": {key.lower(): value for key, value in response.headers.items()},
                        "body": redact_sensitive(decoded, self.budget.limits.max_response_size),
                        "truncated": truncated,
                    }
        except httpx.HTTPError as exc:
            return {
                "url": candidate.url,
                "status_code": None,
                "headers": {},
                "body": "",
                "truncated": False,
                "error": str(exc),
            }
