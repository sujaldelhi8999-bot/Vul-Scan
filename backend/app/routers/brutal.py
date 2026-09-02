"""Brutal Mode (Black Ops) REST + WebSocket API.

Every endpoint passes through :class:`app.brutal_gate.BrutalGate` which
enforces: BRUTAL_MODE_ENABLED flag, admin role, Private Scope / Lab target,
and an explicit ownership acknowledgment. All actions are persisted to the
``brutal_ops`` table.
"""

import logging
import os
from typing import Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel, ConfigDict, Field

from app.auth_middleware import get_current_user
from app.agents.ai_payload import AIPayloadGenerator
from app.agents.exfil import ExfiltrationAgent, decrypt_to_temp, resolve_archive
from app.agents.brutal_exploit import ExploitationEngine, SUPPORTED_CATEGORIES
from app.agents.lateral_movement import LateralMovementAgent
from app.agents.post_exploit import PostExploitationAgent, install_persistence
from app.agents.simulation_intel import SimulationIntel
from app.brutal_gate import BrutalGate, BrutalGateError
from app.brutal_sessions import BrutalSessionManager
from app.config import get_settings
from app.database import get_enterprise_membership, get_user_by_id, list_brutal_ops
from app.services.enterprise_access import has_product_admin_access, is_platform_admin
from app.services.reverse_shell import (
    PayloadFactory,
    ShellSessionManager,
    run_command,
)

logger = logging.getLogger("phantomscan.brutal_router")

router = APIRouter(prefix="/api/brutal", tags=["brutal-mode"])
settings = get_settings()
gate = BrutalGate()


class OwnershipAckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    ownership_ack: bool


class SessionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    ownership_ack: bool
    name: str | None = Field(default=None, max_length=120)
    simulation: bool = False


class ExploitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str = Field(min_length=2, max_length=80)
    finding: dict[str, Any] | None = None


class ShellCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    os_hint: str = Field(default="auto", max_length=40)


class ExecRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1, max_length=2000)


class PersistRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(default="cron", max_length=40)
    command: str = Field(default="", max_length=2000)


class PayloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_type: str = Field(min_length=2, max_length=60)
    os: str = Field(default="linux", max_length=40)
    hint: str = Field(default="", max_length=500)


def _deny(exc: BrutalGateError) -> HTTPException:
    return HTTPException(status_code=exc.http_status, detail={"code": exc.code, "message": exc.message})


def _simulation_readonly() -> HTTPException:
    """Refuse fabricated operations on a simulation session (passive intel only)."""
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            "Simulation sessions collect passive intel only (DNS + one HTTP request). "
            "Run Brutal Mode against the PhantomBank Lab, or enable real exploitation "
            "(EXPLOITATION_ENABLED=true) for Private Scope targets."
        ),
    )


def _session_or_404(session_id: str) -> Any:
    try:
        return BrutalSessionManager.require(session_id)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brutal session not found")


def _shell_or_404(shell_id: str) -> Any:
    shell = ShellSessionManager.get(shell_id)
    if shell is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shell session not found")
    return shell


async def _gate_session(user: dict, session_id: str, ack: bool = True) -> Any:
    session = _session_or_404(session_id)
    if session.actor != user.get("id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your Brutal session")
    try:
        await gate.authorize(user, session.target_url, ack, require_ack=ack)
    except BrutalGateError as exc:
        raise _deny(exc) from exc
    return session


# -- status & consent -------------------------------------------------------


@router.get("/status")
async def brutal_status(user: dict = Depends(get_current_user)) -> dict[str, Any]:
    admin = has_product_admin_access(user)
    return {
        "enabled": gate.is_enabled(),
        "admin": admin,
        "requirements": {
            "env_flag": gate.is_enabled(),
            "admin_role": admin,
            "private_scope_target": True,
            "ownership_ack": True,
        },
        "supported_categories": SUPPORTED_CATEGORIES,
    }


@router.post("/ack")
async def record_ownership_ack(request: OwnershipAckRequest, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Record an explicit ownership / permission acknowledgment for a target."""
    try:
        hostname = await gate.authorize(user, request.target_url, request.ownership_ack)
    except BrutalGateError as exc:
        raise _deny(exc) from exc
    return {"success": True, "target": hostname, "message": "Ownership acknowledgment recorded in audit trail"}


# -- sessions ---------------------------------------------------------------


@router.post("/sessions", status_code=status.HTTP_201_CREATED)
async def create_session(request: SessionCreateRequest, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    try:
        hostname = await gate.authorize(user, request.target_url, request.ownership_ack)
    except BrutalGateError as exc:
        await gate.deny(user, request.target_url, exc)
        raise _deny(exc) from exc
    session = BrutalSessionManager.create(request.target_url, user["id"], simulation=request.simulation)
    await session.save_new()
    if request.simulation:
        intel = await SimulationIntel(request.target_url).gather_intel()
        session.sim_intel = intel
        await session.log_op(
            "intel_gathered",
            "success",
            f"Passive intel gathered for {hostname} — tech_stack={intel.get('tech_stack')} ip={intel.get('ip')}",
            output=f"tech_stack={intel.get('tech_stack')} ip={intel.get('ip')}",
        )
    else:
        from app.database import get_findings_by_target

        findings = await get_findings_by_target(hostname)
        if findings:
            session.findings = findings
            await session.log_op(
                "findings_loaded",
                "success",
                f"Loaded {len(findings)} scanner findings for {hostname} into session",
            )
    await session.log_op(
        "session_established",
        "success",
        f"Brutal session established for {hostname} ({'simulation' if request.simulation else 'lab'} mode)",
        output=f"ownership acknowledged by {user.get('email') or user['id']}",
    )
    return session.serialize(with_loot=False)


@router.get("/sessions")
async def list_sessions(user: dict = Depends(get_current_user)) -> list[dict[str, Any]]:
    if not has_product_admin_access(user):
        return []
    sessions = BrutalSessionManager.list()
    if not is_platform_admin(user):
        sessions = [session for session in sessions if session.actor == user.get("id")]
    return [s.serialize(with_loot=False) for s in sessions]


@router.get("/sessions/{session_id}")
async def session_detail(session_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    return session.serialize(with_loot=True)


# -- exploitation -----------------------------------------------------------


@router.post("/sessions/{session_id}/exploit")
async def run_exploit(
    session_id: str,
    request: ExploitRequest,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    if session.simulation:
        raise _simulation_readonly()
    engine = ExploitationEngine(session)
    return await engine.exploit(request.category, request.finding)


# -- shell ------------------------------------------------------------------


@router.post("/sessions/{session_id}/shell", status_code=status.HTTP_201_CREATED)
async def open_shell(
    session_id: str,
    request: ShellCreateRequest | None = None,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    os_hint = request.os_hint if request is not None else "auto"
    if session.simulation:
        raise _simulation_readonly()
    shell = ShellSessionManager.create(session_id, session.target_url, user["id"], os_hint)
    await session.log_op(
        "shell_opened",
        "success",
        f"Interactive shell session {shell.shell_id} opened",
        output=f"payloads available for {os_hint or 'auto'}",
    )
    return ShellSessionManager.serialize(shell)


@router.get("/shell/{shell_id}")
async def shell_info(shell_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    shell = _shell_or_404(shell_id)
    await _gate_session(user, shell.session_id, ack=False)
    return ShellSessionManager.serialize(shell)


@router.post("/shell/{shell_id}/exec")
async def shell_exec(shell_id: str, request: ExecRequest, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    shell = _shell_or_404(shell_id)
    await _gate_session(user, shell.session_id, ack=False)
    return await run_command(shell, request.command)


@router.delete("/shell/{shell_id}")
async def close_shell(shell_id: str, user: dict = Depends(get_current_user)) -> dict[str, str]:
    shell = _shell_or_404(shell_id)
    await _gate_session(user, shell.session_id, ack=False)
    ShellSessionManager.close(shell_id)
    return {"status": "closed"}


@router.get("/shell/{shell_id}/payloads")
async def shell_payloads(shell_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    shell = _shell_or_404(shell_id)
    await _gate_session(user, shell.session_id, ack=False)
    return {
        "reverse_shell": PayloadFactory.reverse_shell_payloads(),
        "bind_shell": PayloadFactory.bind_shell_payloads(),
    }


# -- post-exploitation / lateral / persistence ------------------------------


async def _require_open_shell(session_id: str) -> Any:
    shells = ShellSessionManager.list(session_id)
    for shell in shells:
        if not shell.closed:
            return shell
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Open a shell session first (POST /api/brutal/sessions/{id}/shell)",
    )


@router.post("/sessions/{session_id}/post-exploit")
async def post_exploit(session_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    if session.simulation:
        raise _simulation_readonly()
    shell = await _require_open_shell(session_id)
    agent = PostExploitationAgent(session, shell)
    enumeration = await agent.enumerate_system()
    privesc = await agent.check_privesc()
    return {"summary": "Post-exploitation complete", "enumeration": enumeration, "privesc": privesc}


@router.post("/sessions/{session_id}/lateral")
async def lateral_movement(session_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    if session.simulation:
        raise _simulation_readonly()
    shell = await _require_open_shell(session_id)
    agent = LateralMovementAgent(session, shell)
    return await agent.run()


@router.post("/sessions/{session_id}/persist")
async def persist(session_id: str, request: PersistRequest, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    if session.simulation:
        raise _simulation_readonly()
    shell = await _require_open_shell(session_id)
    return await install_persistence(session, shell, request.kind, request.command)


# -- exfiltration -----------------------------------------------------------


@router.post("/sessions/{session_id}/exfil")
async def exfil(session_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    if session.simulation:
        raise _simulation_readonly()
    agent = ExfiltrationAgent(session)
    try:
        result = await agent.pack()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return result


@router.get("/exfil/{file_id}")
async def download_exfil(file_id: str, user: dict = Depends(get_current_user)) -> FileResponse:
    if not has_product_admin_access(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    path = resolve_archive(file_id)
    if path is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found")
    if path.suffix.lower() == ".enc":
        tmp = decrypt_to_temp(file_id)
        if tmp is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decrypt archive")
        return FileResponse(
            tmp,
            media_type="application/zip",
            filename=f"{path.stem}.zip",
            background=BackgroundTask(os.unlink, tmp),
        )
    return FileResponse(path, media_type="application/zip", filename=path.name)


# -- AI payloads ------------------------------------------------------------


@router.post("/sessions/{session_id}/payload")
async def generate_payload(
    session_id: str,
    request: PayloadRequest,
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    session = await _gate_session(user, session_id, ack=False)
    generator = AIPayloadGenerator(session)
    return await generator.generate(request.vuln_type, request.os, request.hint)


# -- audit trail ------------------------------------------------------------


@router.get("/ops")
async def brutal_ops(
    session_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    user: dict = Depends(get_current_user),
) -> list[dict[str, Any]]:
    if not has_product_admin_access(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return await list_brutal_ops(session_id, limit)


# -- WebSocket interactive console ------------------------------------------
#
# NOTE: this handler is registered directly on the FastAPI app in main.py
# (``app.add_api_websocket_route("/ws/brutal/shell/{shell_id}", ...)``) rather
# than with ``@router.websocket`` because this router carries the
# ``/api/brutal`` prefix, which would otherwise turn the path into
# ``/api/brutal/ws/brutal/shell/{shell_id}`` and break the frontend.


async def brutal_shell_ws(websocket: WebSocket, shell_id: str) -> None:
    """Interactive shell console. Each client message is one command; the
    server replies with one output frame."""
    protocol_header = websocket.headers.get("sec-websocket-protocol") or ""
    ticket = next((part.strip().removeprefix("ticket.") for part in protocol_header.split(",") if part.strip().startswith("ticket.")), "")
    token = ticket or websocket.query_params.get("wst", "") or websocket.query_params.get("token", "")
    user: dict | None = None
    expired = False
    if token:
        try:
            if ticket:
                payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"], audience="phantomscan-ws")
                if payload.get("typ") != "ws-ticket" or payload.get("scope") != "brutal":
                    raise jwt.InvalidTokenError("invalid websocket ticket scope")
            else:
                payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
            user = await get_user_by_id(payload.get("sub", ""))
            membership = await get_enterprise_membership(user["id"]) if user else None
            if user and membership:
                user["enterprise_id"] = membership["enterprise_id"]
                user["enterprise_membership_active"] = bool(membership.get("membership_active", 1))
        except jwt.ExpiredSignatureError:
            expired = True
            logger.warning("Brutal shell WS rejected: token expired")
        except Exception:
            user = None
    if user is None or not has_product_admin_access(user):
        # 4001 (token expired) lets the client refresh and reconnect;
        # 1008 means the credential is genuinely invalid.
        await websocket.close(code=4001 if expired else 1008)
        return

    shell = ShellSessionManager.get(shell_id)
    if shell is None:
        await websocket.close(code=1008)
        return
    try:
        await gate.authorize(user, shell.target_url, False, require_ack=False)
    except BrutalGateError:
        await websocket.close(code=1008)
        return

    offered = {part.strip() for part in protocol_header.split(",")}
    await websocket.accept(subprotocol="phantomscan.ws-ticket" if "phantomscan.ws-ticket" in offered else None)
    await websocket.send_text("__ready__")
    try:
        while True:
            command = await websocket.receive_text()
            if not command.strip():
                continue
            if command.strip().lower() in ("exit", "quit"):
                ShellSessionManager.close(shell_id)
                await websocket.send_text("__closed__")
                break
            result = await run_command(shell, command)
            await websocket.send_text(
                result.get("output", result.get("error", "")) or "(no output)"
            )
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("Brutal shell WS error: %s", exc)
        try:
            await websocket.send_text(f"[console error: {exc}]")
        except Exception:
            pass
