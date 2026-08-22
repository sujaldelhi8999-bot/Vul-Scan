import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

import psutil

from app.agents import Agent
from app.config import BASE_DIR
from app.services.execution import SafetyLimits

logger = logging.getLogger("phantomscan.sandbox_manager")


class SandboxExecutionError(RuntimeError):
    pass


def apply_unix_resource_limits(memory_limit_bytes: int, cpu_seconds: int) -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    except (ImportError, OSError, ValueError):
        return


class SandboxManagerAgent(Agent):
    def __init__(self, limits: SafetyLimits | None = None, memory_limit_mb: int = 256) -> None:
        super().__init__("Sandbox Manager Agent")
        self.limits = limits or SafetyLimits.from_settings()
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024
        self.process: asyncio.subprocess.Process | None = None
        self.sandbox_id: str | None = None
        self._memory_exceeded = False

    async def run_active_scan(self, payload: dict[str, Any], scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        self.sandbox_id = f"sandbox-{uuid.uuid4().hex[:12]}"
        payload = {
            **payload,
            "sandbox_id": self.sandbox_id,
            "limits": {
                "max_scan_duration": self.limits.max_scan_duration,
                "max_requests_per_second": self.limits.max_requests_per_second,
                "max_total_requests": self.limits.max_total_requests,
                "max_concurrent_scans": self.limits.max_concurrent_scans,
                "max_redirect_depth": self.limits.max_redirect_depth,
                "max_response_size": self.limits.max_response_size,
            },
        }
        await self.log_action("sandbox_created", self.sandbox_id)

        try:
            result = await self._run_subprocess(payload)
        except NotImplementedError:
            # asyncio.create_subprocess_exec raises NotImplementedError when the
            # running event loop does not support subprocesses (e.g. a Selector
            # loop on Windows, or a third-party loop such as uvloop). Fall back
            # to executing the active worker in-process so scans still complete.
            logger.warning(
                "asyncio subprocess unsupported on this platform/loop; running active worker in-process (scan_id=%s)",
                scan_id,
            )
            result = await self._run_inline(payload)
        return await self._finalize(result)

    async def _run_subprocess(self, payload: dict[str, Any]) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="phantomscan-") as sandbox_directory:
            environment = self.restricted_environment()
            kwargs: dict[str, Any] = {}
            if os.name != "nt":
                kwargs["preexec_fn"] = lambda: apply_unix_resource_limits(
                    self.memory_limit_bytes,
                    self.limits.max_scan_duration,
                )
            self.process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "app.workers.active_worker",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=sandbox_directory,
                env=environment,
                **kwargs,
            )
            monitor = asyncio.create_task(self.monitor_memory(self.process))
            try:
                stdout, stderr = await asyncio.wait_for(
                    self.process.communicate(json.dumps(payload).encode("utf-8")),
                    timeout=self.limits.max_scan_duration,
                )
            except asyncio.TimeoutError as exc:
                await self.terminate()
                raise SandboxExecutionError("Active worker exceeded the scan time limit") from exc
            except asyncio.CancelledError:
                await self.terminate()
                raise SandboxExecutionError("Active worker exceeded the scan time limit")
            finally:
                monitor.cancel()
                await asyncio.gather(monitor, return_exceptions=True)

        if self._memory_exceeded:
            raise SandboxExecutionError("Active worker exceeded its memory limit")
        if self.process.returncode != 0:
            error_text = stderr.decode("utf-8", errors="replace")[:2000]
            raise SandboxExecutionError(f"Active worker failed: {error_text or 'unknown worker error'}")
        try:
            result = json.loads(stdout.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise SandboxExecutionError("Active worker returned invalid structured output") from exc
        if not isinstance(result, dict):
            raise SandboxExecutionError("Active worker returned invalid structured output")
        return result

    async def _run_inline(self, payload: dict[str, Any]) -> dict[str, Any]:
        from app.workers.active_worker import execute

        result = await execute(payload)
        if not isinstance(result, dict):
            raise SandboxExecutionError("Active worker returned invalid structured output")
        return result

    async def _finalize(self, result: dict[str, Any]) -> dict[str, Any]:
        if result.get("status") != "complete":
            raise SandboxExecutionError(str(result.get("error", "Active worker did not complete")))
        self.status = "complete"
        await self.log_action("sandbox_destroyed", self.sandbox_id)
        return {
            **result["result"],
            "sandbox_id": self.sandbox_id,
        }

    async def apply_patch(self, patch: str, file_path: str, scan_id: int, target_root: str | None = None) -> dict[str, Any]:
        """
        Apply a unified diff patch to a file in the sandbox.
        
        Args:
            patch: Unified diff patch content
            file_path: Relative path to the file to patch
            scan_id: Scan ID for logging
            target_root: Optional root directory (defaults to temp dir)
            
        Returns:
            Dict with success status, applied changes, and any errors
        """
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("patch_apply_started", f"Applying patch to {file_path}")
        
        try:
            with tempfile.TemporaryDirectory(prefix="phantomscan-patch-") as work_dir:
                src_file: Path | None = None
                # If target_root provided, copy the target file there
                if target_root:
                    root = Path(target_root).resolve()
                    src_file = (root / file_path).resolve()
                    if root != src_file and root not in src_file.parents:
                        return {"success": False, "file_path": file_path, "error": "File path escapes the source workspace"}
                    dst_file = (Path(work_dir) / file_path).resolve()
                    if Path(work_dir).resolve() not in dst_file.parents:
                        return {"success": False, "file_path": file_path, "error": "File path escapes the patch workspace"}
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    if src_file.exists():
                        shutil.copy2(src_file, dst_file)
                    else:
                        # Create empty file if it doesn't exist
                        dst_file.write_text("")
                else:
                    # Create file structure in work_dir
                    dst_file = Path(work_dir) / file_path
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    if not dst_file.exists():
                        dst_file.write_text("")
                
                # Write patch to a temporary file
                patch_file = Path(work_dir) / "patch.diff"
                patch_file.write_text(patch)
                
                # Apply patch using git apply or patch command
                result = await self._apply_patch_command(patch_file, dst_file, work_dir)
                
                if result["success"]:
                    # Read the patched file content
                    patched_content = dst_file.read_text() if dst_file.exists() else ""
                    if src_file is not None:
                        src_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(dst_file, src_file)
                    
                    await self.log_action("patch_applied", f"Successfully patched {file_path}")
                    self.status = "complete"
                    return {
                        "success": True,
                        "file_path": file_path,
                        "patched_content": patched_content,
                        "target_root": str(Path(target_root).resolve()) if target_root else None,
                        "changes": result.get("changes", []),
                    }
                else:
                    await self.log_action("patch_failed", f"Failed to patch {file_path}: {result.get('error')}")
                    self.status = "error"
                    return {
                        "success": False,
                        "file_path": file_path,
                        "error": result.get("error", "Patch application failed"),
                        "stdout": result.get("stdout", ""),
                        "stderr": result.get("stderr", ""),
                    }
                    
        except Exception as e:
            await self.log_action("patch_error", f"Exception applying patch to {file_path}: {e}")
            self.status = "error"
            return {
                "success": False,
                "file_path": file_path,
                "error": str(e),
            }

    async def _apply_patch_command(self, patch_file: Path, target_file: Path, work_dir: str) -> dict[str, Any]:
        """Apply patch using git apply or patch command."""
        # Try git apply first (more reliable for unified diffs)
        for cmd in [
            ["git", "apply", "--whitespace=nowarn", str(patch_file)],
            ["patch", "-p1", "-i", str(patch_file)],
        ]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=work_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                
                if proc.returncode == 0:
                    return {
                        "success": True,
                        "changes": stdout.decode().strip().split("\n") if stdout else [],
                        "stdout": stdout.decode(),
                        "stderr": stderr.decode(),
                    }
            except FileNotFoundError:
                continue
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "stdout": "",
                    "stderr": "",
                }
        
        return {
            "success": False,
            "error": "Neither 'git apply' nor 'patch' command available",
            "stdout": "",
            "stderr": "",
        }

    def restricted_environment(self) -> dict[str, str]:
        allowed_names = {
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "DATABASE_URL",
            "ACTIVE_TARGET_ALLOWLIST",
            "PYTHONIOENCODING",
            "PYTHONUTF8",
        }
        environment = {name: value for name, value in os.environ.items() if name in allowed_names}
        environment.update(
            {
                "PYTHONPATH": str(BASE_DIR),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "PHANTOMSCAN_SANDBOX": "1",
            }
        )
        return environment

    async def monitor_memory(self, process: asyncio.subprocess.Process) -> None:
        while process.returncode is None:
            try:
                parent = psutil.Process(process.pid)
                rss = parent.memory_info().rss + sum(child.memory_info().rss for child in parent.children(recursive=True))
                if rss > self.memory_limit_bytes:
                    self._memory_exceeded = True
                    await self.terminate()
                    return
            except psutil.Error:
                return
            await asyncio.sleep(0.25)

    async def terminate(self) -> None:
        if self.process is None or self.process.returncode is not None:
            return
        try:
            parent = psutil.Process(self.process.pid)
            children = parent.children(recursive=True)
            for process in children:
                try:
                    process.kill()
                except psutil.Error:
                    continue
            try:
                parent.kill()
            except psutil.Error:
                pass
            await asyncio.to_thread(psutil.wait_procs, [parent, *children], 3)
        except psutil.Error:
            try:
                self.process.kill()
            except ProcessLookupError:
                pass
        try:
            await self.process.wait()
        except ProcessLookupError:
            return
