import asyncio
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from typing import Any

import psutil

from app.agents import Agent
from app.security import redact_sensitive
from app.services.active_gate import ActiveTargetGate
from app.services.authorization import canonicalize_target
from app.services.execution import SafetyLimits


class DiagnosticCommandPolicyError(PermissionError):
    pass


@dataclass(frozen=True)
class DiagnosticCommandSpec:
    category: str
    argv: list[str]
    timeout: int
    output_limit: int = 12000


class DiagnosticCommandPolicy:
    ALLOWED_CATEGORIES = {"dns_lookup", "http_headers", "tls_certificate", "container_health", "dependency_inspection"}
    FORBIDDEN_TOKENS = {"sh", "bash", "powershell", "cmd", "nc", "netcat", "ssh", "scp", "curl|sh", "rm", "del"}

    async def authorize(self, target_url: str, user_id: str, authorization_id: int | None = None, user_role: str = "user") -> dict[str, Any]:
        decision = await ActiveTargetGate().admit(target_url, user_id, authorization_id, user_role=user_role)
        if not decision.allowed:
            raise DiagnosticCommandPolicyError(decision.reason)
        return decision.to_context()

    def build(self, category: str, target_url: str, limits: SafetyLimits) -> DiagnosticCommandSpec:
        if category not in self.ALLOWED_CATEGORIES:
            raise DiagnosticCommandPolicyError("Diagnostic command category is not allowlisted")
        target = canonicalize_target(target_url)
        timeout = min(10, max(1, limits.max_scan_duration // 6))
        if category == "dns_lookup":
            argv = [sys.executable, "-c", "import socket,sys; print(socket.getaddrinfo(sys.argv[1], None)[0][4][0])", target.domain]
        elif category == "http_headers":
            argv = [sys.executable, "-c", "import http.client,urllib.parse,sys; u=urllib.parse.urlsplit(sys.argv[1]); c=(http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection)(u.netloc, timeout=5); c.request('HEAD', u.path or '/'); r=c.getresponse(); print(r.status); [print(k+': '+v) for k,v in r.getheaders()]", target.url]
        elif category == "tls_certificate":
            argv = [sys.executable, "-c", "import ssl,socket,sys; host=sys.argv[1]; ctx=ssl.create_default_context(); s=ctx.wrap_socket(socket.create_connection((host,443),timeout=5),server_hostname=host); print(s.version()); print(s.getpeercert().get('notAfter',''))", target.domain]
        elif category == "container_health":
            argv = [sys.executable, "-c", "import os,platform; print(platform.platform()); print('pid', os.getpid())"]
        else:
            argv = [sys.executable, "-m", "pip", "check"]
        self.validate_argv(argv)
        return DiagnosticCommandSpec(category=category, argv=argv, timeout=timeout)

    def validate_argv(self, argv: list[str]) -> None:
        arguments = " ".join(argv[1:]).lower()
        tokens = set(re.findall(r"[a-z0-9_.|/-]+", arguments))
        if tokens & self.FORBIDDEN_TOKENS:
            raise DiagnosticCommandPolicyError("Forbidden diagnostic command token")
        if not argv or argv[0] != sys.executable:
            raise DiagnosticCommandPolicyError("Diagnostic commands must run through the local Python interpreter sandbox")


class DiagnosticCommandAgent(Agent):
    def __init__(self, limits: SafetyLimits | None = None, memory_limit_mb: int = 128) -> None:
        super().__init__("Diagnostic Command Agent")
        self.limits = limits or SafetyLimits.from_settings()
        self.policy = DiagnosticCommandPolicy()
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024

    async def run_diagnostic(
        self,
        target_url: str,
        scan_id: int,
        category: str,
        *,
        user_id: str = "local-user",
        user_role: str = "user",
        authorization_id: int | None = None,
    ) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        authorization = await self.policy.authorize(target_url, user_id, authorization_id, user_role=user_role)
        spec = self.policy.build(category, target_url, self.limits)
        await self.log_action("diagnostic_started", f"{category} for {target_url}")
        with tempfile.TemporaryDirectory(prefix="phantomscan-diagnostic-") as directory:
            process = await asyncio.create_subprocess_exec(
                *spec.argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=directory,
                env=self.restricted_environment(),
            )
            monitor = asyncio.create_task(self.monitor_memory(process))
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=spec.timeout)
            except asyncio.TimeoutError:
                await self.terminate(process)
                stdout, stderr = b"", b"diagnostic timeout"
            finally:
                monitor.cancel()
                await asyncio.gather(monitor, return_exceptions=True)
        self.status = "complete" if process.returncode == 0 else "error"
        result = {
            "category": category,
            "authorization": authorization,
            "returncode": process.returncode,
            "stdout": redact_sensitive(stdout.decode("utf-8", errors="replace"), spec.output_limit),
            "stderr": redact_sensitive(stderr.decode("utf-8", errors="replace"), spec.output_limit),
            "timeout": spec.timeout,
            "output_limit": spec.output_limit,
        }
        await self.log_action("diagnostic_completed", f"{category} completed with return code {process.returncode}")
        return result

    @staticmethod
    def restricted_environment() -> dict[str, str]:
        allowed = {"PATH", "SYSTEMROOT", "WINDIR", "PYTHONIOENCODING", "PYTHONUTF8"}
        environment = {name: value for name, value in os.environ.items() if name in allowed}
        environment.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"})
        return environment

    async def monitor_memory(self, process: asyncio.subprocess.Process) -> None:
        while process.returncode is None:
            try:
                usage = psutil.Process(process.pid).memory_info().rss
                if usage > self.memory_limit_bytes:
                    await self.terminate(process)
                    return
            except psutil.Error:
                return
            await asyncio.sleep(0.2)

    @staticmethod
    async def terminate(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            psutil.Process(process.pid).kill()
        except psutil.Error:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()
