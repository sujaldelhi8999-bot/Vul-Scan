"""PoC execution sandbox: runs ``poc_worker`` in a restricted environment.

Two execution modes:
- ``subprocess``: resource-limited child process (RLIMIT on POSIX, restricted
  environment, memory monitor) mirroring ``SandboxManagerAgent``.
- ``docker``: ephemeral ``python:3.12-slim`` container with memory/CPU caps,
  no host state (single read-only file mount), spec passed via stdin.

``EXPLOIT_SANDBOX=auto`` (default) picks Docker when the CLI and daemon are
available, falling back to the subprocess path otherwise.
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from app.agents.sandbox_manager import SandboxExecutionError, apply_unix_resource_limits
from app.config import BASE_DIR
from app.services.execution import SafetyLimits

logger = logging.getLogger("phantomscan.poc_sandbox")

DEFAULT_MEMORY_LIMIT_MB = 256
DEFAULT_CPU_LIMIT = 0.5
DOCKER_CHECK_TTL_SECONDS = 60.0
POC_WORKER = str(BASE_DIR / "app" / "workers" / "poc_worker.py")

_ALLOWED_ENV_NAMES = {
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "PYTHONIOENCODING",
    "PYTHONUTF8",
}


class PoCSandboxRunner:
    """Executes a single PoC validation spec inside the sandbox."""

    def __init__(
        self,
        *,
        limits: SafetyLimits | None = None,
        memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
        cpu_limit: float = DEFAULT_CPU_LIMIT,
        mode: str | None = None,
        docker_image: str | None = None,
    ) -> None:
        self.limits = limits or SafetyLimits.from_settings()
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        self.cpu_limit = float(cpu_limit)
        self.mode = (mode or os.getenv("EXPLOIT_SANDBOX", "auto")).lower()
        self.docker_image = docker_image or os.getenv("EXPLOIT_DOCKER_IMAGE", "python:3.12-slim")
        self._docker_available: bool | None = None
        self._docker_checked_at = 0.0

    async def run(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Validate a PoC spec; returns the worker's JSON result dict."""
        if not Path(POC_WORKER).is_file():
            raise SandboxExecutionError("poc_worker.py not found")
        if self.mode == "auto":
            if await self.docker_available():
                return await self._run_docker(spec)
            return await self._run_subprocess(spec)
        if self.mode == "docker":
            if not await self.docker_available():
                raise SandboxExecutionError("EXPLOIT_SANDBOX=docker but Docker is not available")
            return await self._run_docker(spec)
        return await self._run_subprocess(spec)

    async def docker_available(self) -> bool:
        if self._docker_available is not None and time.monotonic() - self._docker_checked_at < DOCKER_CHECK_TTL_SECONDS:
            return self._docker_available
        docker_path = shutil.which("docker")
        available = bool(docker_path)
        if available:
            try:
                process = await asyncio.create_subprocess_exec(
                    docker_path,
                    "info",
                    "--format",
                    "{{.ServerVersion}}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(process.communicate(), timeout=10.0)
                available = process.returncode == 0
            except Exception:
                available = False
        self._docker_available = available
        self._docker_checked_at = time.monotonic()
        logger.info("PoC sandbox Docker availability: %s", available)
        return available

    def restricted_environment(self) -> dict[str, str]:
        environment = {name: value for name, value in os.environ.items() if name in _ALLOWED_ENV_NAMES}
        environment.update(
            {
                "PYTHONPATH": str(BASE_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "PHANTOMSCAN_SANDBOX": "1",
            }
        )
        return environment

    async def _run_subprocess(self, spec: dict[str, Any]) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="phantomscan-poc-") as workdir:
            kwargs: dict[str, Any] = {}
            if os.name != "nt":
                kwargs["preexec_fn"] = lambda: apply_unix_resource_limits(
                    self.memory_limit_bytes,
                    int(self.limits.max_scan_duration),
                )
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                POC_WORKER,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workdir,
                env=self.restricted_environment(),
                **kwargs,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(json.dumps(spec).encode("utf-8")),
                    timeout=self.limits.max_scan_duration,
                )
            except asyncio.TimeoutError:
                process.kill()
                raise SandboxExecutionError("PoC worker exceeded the execution time limit") from None
        if process.returncode != 0:
            error_text = stderr.decode("utf-8", errors="replace")[:2000]
            raise SandboxExecutionError(f"PoC worker failed: {error_text or 'unknown worker error'}")
        try:
            result = json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise SandboxExecutionError("PoC worker returned invalid structured output") from exc
        if not isinstance(result, dict):
            raise SandboxExecutionError("PoC worker returned non-object output")
        return result

    async def _run_docker(self, spec: dict[str, Any]) -> dict[str, Any]:
        docker_path = shutil.which("docker")
        if not docker_path:
            raise SandboxExecutionError("docker CLI not found")
        command = [
            docker_path,
            "run",
            "--rm",
            "-i",
            "--memory",
            f"{self.memory_limit_bytes // (1024 * 1024)}m",
            "--cpus",
            str(self.cpu_limit),
            "-e",
            "PHANTOMSCAN_SANDBOX=1",
            "-v",
            f"{POC_WORKER}:/poc_worker.py:ro",
            self.docker_image,
            "python",
            "/poc_worker.py",
        ]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(json.dumps(spec).encode("utf-8")),
                timeout=self.limits.max_scan_duration,
            )
        except asyncio.TimeoutError:
            process.kill()
            raise SandboxExecutionError("Docker PoC worker exceeded the execution time limit") from None
        if process.returncode != 0:
            error_text = stderr.decode("utf-8", errors="replace")[:2000]
            raise SandboxExecutionError(f"Docker PoC worker failed: {error_text or 'unknown worker error'}")
        try:
            result = json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise SandboxExecutionError("Docker PoC worker returned invalid structured output") from exc
        if not isinstance(result, dict):
            raise SandboxExecutionError("Docker PoC worker returned non-object output")
        return result
