import asyncio
import logging
import sys

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phantomscan")
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.agents.self_audit import SelfAuditAgent
from app.config import get_settings
from app.database import (
    add_audit_log,
    database_is_available,
    get_audit_logs,
    get_findings,
    get_or_create_system_scan,
    get_scan,
    get_enterprise_membership,
    initialize_database,
)
from app.models import HealthResponse
from app.routers import active, admin_scope, agents, ai, auth, attack_planner, authorization, brutal, dos, enterprise, execution, findings, github, intelligence, lab, learning, logs, multi_source, rule_scan, sast, scan, self_audit
from app.services.jobs import scan_job_manager
from app.services.openrouter_client import get_ai_status
from app.websockets import scan_event_broker
from app.services.enterprise_access import filter_findings_for_user, require_scan_access

class TimeoutMiddleware(BaseHTTPMiddleware):
    """Simple request timeout middleware (replaces removed starlette TimeoutMiddleware)."""

    def __init__(self, app, timeout: int = 300):
        super().__init__(app)
        self.timeout = timeout

    async def dispatch(self, request: Request, call_next) -> Response:
        import asyncio
        from fastapi.responses import JSONResponse as _JSONResponse
        try:
            return await asyncio.wait_for(call_next(request), timeout=self.timeout)
        except asyncio.TimeoutError:
            return _JSONResponse(status_code=504, content={"detail": "Request timed out"})


settings = get_settings()
TERMINAL_SCAN_STATUSES = {"cancelled", "complete", "error"}

# WebSocket close codes (see RFC 6455; 3000-4999 are application-defined).
# 1008 (policy violation) means the credential itself is invalid — the client
# must log in again. 4001 means the access token merely expired — the client
# can refresh and reconnect. 4044 means the requested scan no longer exists.
WS_CLOSE_AUTH_FAILED = 1008
WS_CLOSE_TOKEN_EXPIRED = 4001
WS_CLOSE_SCAN_NOT_FOUND = 4044

# Security
security = HTTPBearer(auto_error=False)


async def get_current_user_ws(websocket: WebSocket) -> tuple[dict | None, int | None]:
    """Validate WebSocket connection via token in query params or headers.

    Returns ``(user, close_code)`` where ``close_code`` is ``None`` on success
    and the close code to use on rejection. Does NOT call ``websocket.close()``
    — the caller must handle acceptance/rejection.
    """
    # When WebSocket auth is disabled, allow all connections
    if not settings.require_auth_on_websocket:
        return {"id": "ws-anonymous", "role": "user"}, None

    token = websocket.query_params.get("token")
    if not token:
        # Try Authorization header
        auth_header = websocket.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        logger.warning("WebSocket connection rejected: no token provided")
        return None, WS_CLOSE_AUTH_FAILED

    # API key mode: accept the configured API key value
    if settings.api_key_enabled and settings.api_key_value and token == settings.api_key_value:
        return {"id": "ws-user", "role": "user"}, None

    # Secret key mode: accept matching secret_key (development / simple auth)
    if settings.secret_key and token == settings.secret_key:
        return {"id": "ws-user", "role": "user"}, None

    # JWT mode: decode and validate normal JWT
    if settings.secret_key:
        try:
            import jwt
            from app.database import get_user_by_id
            payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
            user_id = payload.get("sub")
            if user_id:
                exp = payload.get("exp")
                if not exp or datetime.fromtimestamp(exp, tz=timezone.utc) >= datetime.now(timezone.utc):
                    user = await get_user_by_id(user_id)
                    if user and user.get("subscription_status") != "canceled":
                        membership = await get_enterprise_membership(user_id)
                        if membership:
                            user.update(
                                {
                                    "enterprise_id": membership["enterprise_id"],
                                    "enterprise_role": membership["enterprise_role"],
                                    "max_severity": membership.get("max_severity", "LOW"),
                                    "enterprise_membership_active": bool(membership.get("membership_active", 1)),
                                }
                            )
                        return user, None
                    logger.warning("WebSocket connection rejected: token did not match any credential")
                else:
                    logger.warning("WebSocket connection rejected: token expired for user %s", user_id)
                    return None, WS_CLOSE_TOKEN_EXPIRED
            else:
                logger.warning("WebSocket connection rejected: token missing subject claim")
        except jwt.ExpiredSignatureError as exc:
            logger.warning("WebSocket connection rejected: token expired (%s)", exc)
            return None, WS_CLOSE_TOKEN_EXPIRED
        except jwt.InvalidTokenError as exc:
            logger.warning("WebSocket connection rejected: invalid token (%s)", exc)

    logger.warning("WebSocket connection rejected: token did not match any credential")
    return None, WS_CLOSE_AUTH_FAILED


async def verify_health_auth(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    """Verify authentication for health endpoint."""
    if not settings.require_auth_on_health:
        return True
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authentication")
    # In production, verify JWT token
    # For now, check against secret_key or API key
    if settings.api_key_enabled and settings.api_key_value and credentials.credentials == settings.api_key_value:
        return True
    if settings.secret_key and credentials.credentials == settings.secret_key:
        return True
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@asynccontextmanager
async def lifespan(application: FastAPI):
    await initialize_database()
    system_scan_id = await get_or_create_system_scan()
    await add_audit_log(system_scan_id, "System", "backend_started", "PhantomScan backend started")

    from app.brutal_sessions import BrutalSessionManager
    restored = await BrutalSessionManager.restore()
    logger.info("Restored %d persisted Brutal sessions", restored)

    from app.database import get_connection as _recovery_conn
    try:
        async with _recovery_conn() as _conn:
            _cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
            _cur = await _conn.execute(
                "SELECT id, target_url, scan_id FROM authorized_test_jobs WHERE status IN ('QUEUED', 'RUNNING') AND updated_at < ?",
                (_cutoff,),
            )
            _stuck_rows = await _cur.fetchall()
            for _row in _stuck_rows:
                _jid = str(_row["id"])
                try:
                    await _conn.execute(
                        "UPDATE authorized_test_jobs SET status = 'FAILED', error_message = ?, error_code = ?, completed_at = ? WHERE id = ?",
                        ("Backend restart interrupted execution", "BACKEND_RESTART", datetime.now(timezone.utc).isoformat(), _jid),
                    )
                    await _conn.commit()
                    _turl = str(_row["target_url"]) if _row["target_url"] else ""
                    from app.services.active_gate import ActiveTargetGate
                    _ilab = ActiveTargetGate.is_builtin_lab_target(_turl) if _turl else False
                    from app.services.execution_status import update_authorized_test_execution as _recover_exec
                    await _recover_exec(
                        job_id=_jid,
                        lifecycle="FAILED",
                        target_url=_turl,
                        scan_id=_row["scan_id"],
                        is_lab=_ilab,
                        error_message="Backend restart interrupted execution",
                        error_code="BACKEND_RESTART",
                    )
                    logger.warning("Recovery: marked job %s as FAILED (backend restart)", _jid)
                except Exception as _exc:
                    logger.error("Recovery: failed to mark job %s: %s", _jid, _exc)
    except Exception as _exc:
        logger.error("Recovery: could not check for stuck jobs: %s", _exc)

    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        SelfAuditAgent().run,
        "cron",
        hour=2,
        minute=0,
        id="phantomscan_self_audit",
        replace_existing=True,
    )
    scheduler.start()
    application.state.scheduler = scheduler
    try:
        yield
    finally:
        if scheduler.running:
            scheduler.shutdown(wait=False)
        await scan_job_manager.shutdown()
        from app.database import _db_connection as _shared_conn
        if _shared_conn is not None:
            await _shared_conn.close()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
logger.info("CORS allowed origins: %s", settings.cors_origins)

# Add timeout middleware to prevent hanging requests (5 minutes)
app.add_middleware(
    TimeoutMiddleware,
    timeout=300,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

app.include_router(scan.router)
app.include_router(active.router)
app.include_router(admin_scope.router)
app.include_router(auth.router)
app.include_router(ai.router)
app.include_router(authorization.router)
app.include_router(dos.router)
app.include_router(agents.router)
app.include_router(logs.router)
app.include_router(findings.router)
app.include_router(self_audit.router)
app.include_router(lab.router)
app.include_router(execution.router)
app.include_router(intelligence.router)
app.include_router(learning.router)
app.include_router(github.router)
app.include_router(multi_source.router)
app.include_router(sast.router)
app.include_router(brutal.router)
app.include_router(attack_planner.router)
app.include_router(rule_scan.router)
app.include_router(enterprise.router)

# The brutal router carries the /api/brutal prefix, so its WebSocket console is
# registered here at the /ws/* path the frontend connects to.
app.add_api_websocket_route("/ws/brutal/shell/{shell_id}", brutal.brutal_shell_ws)


def scheduler_state() -> str:
    scheduler = getattr(app.state, "scheduler", None)
    if scheduler is None:
        return "unavailable"
    return "running" if scheduler.running else "stopped"


async def health_snapshot() -> HealthResponse:
    database_available = await database_is_available()
    current_scheduler_state = scheduler_state()
    agents_available = agents.known_agents_available()
    ai_status_info = get_ai_status()
    return HealthResponse(
        status=(
            "ok"
            if database_available and current_scheduler_state == "running" and agents_available
            else "degraded"
        ),
        service="phantomscan",
        database="available" if database_available else "unavailable",
        scheduler=current_scheduler_state,
        agents="available" if agents_available else "unavailable",
        ai_provider=ai_status_info["provider"],
        ai_model=ai_status_info["model"],
        ai_status="connected" if ai_status_info["configured"] else "offline",
    )


@app.get("/api/health", response_model=HealthResponse)
async def health_check(_: bool = Depends(verify_health_auth)) -> HealthResponse:
    return await health_snapshot()


def event_envelope(scan_id: int, event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("event") or event.get("type") or "message")
    raw_payload = event.get("payload")
    if isinstance(raw_payload, dict):
        payload = dict(raw_payload)
    else:
        payload = {
            key: value
            for key, value in event.items()
            if key not in {"event", "type", "payload", "scan_id"}
        }
    return {
        "event": event_name,
        "type": event_name,
        "scan_id": scan_id,
        "payload": payload,
        **payload,
    }


async def scan_snapshot(scan_id: int, scan_record: dict[str, Any], user: dict[str, Any] | None = None) -> dict[str, Any]:
    return event_envelope(
        scan_id,
        {
            "event": "snapshot",
            "payload": {
                "status": scan_record["status"],
                "progress": int(scan_record["progress"]),
                "request_count": int(scan_record["request_count"]),
                "findings": filter_findings_for_user(await get_findings(scan_id), user or {}),
                "logs": await get_audit_logs(scan_id),
            },
        },
    )


@app.websocket("/ws/status")
async def global_status(websocket: WebSocket) -> None:
    # Accept the connection first to complete the HTTP upgrade
    # (prevents "Pending" state in browser when auth fails)
    await websocket.accept()
    user, close_code = await get_current_user_ws(websocket)
    if not user:
        reason = "Token expired" if close_code == WS_CLOSE_TOKEN_EXPIRED else "Authentication failed"
        await websocket.close(code=close_code or status.WS_1008_POLICY_VIOLATION, reason=reason)
        return

    logger.info("WebSocket /ws/status connected (user=%s)", user.get("id"))
    event_name = "status"
    try:
        while True:
            health = await health_snapshot()
            payload = {
                "api": "available",
                **health.model_dump(mode="json"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await websocket.send_json(
                {
                    "event": event_name,
                    "type": event_name,
                    "payload": payload,
                    **payload,
                }
            )
            event_name = "heartbeat"
            await asyncio.sleep(5)
    except (WebSocketDisconnect, RuntimeError):
        logger.debug("WebSocket /ws/status disconnected")
        return


@app.websocket("/ws/scan/{scan_id}")
async def scan_updates(websocket: WebSocket, scan_id: int) -> None:
    # Accept the connection first to complete the HTTP upgrade
    await websocket.accept()
    user, close_code = await get_current_user_ws(websocket)
    if not user:
        reason = "Token expired" if close_code == WS_CLOSE_TOKEN_EXPIRED else "Authentication failed"
        await websocket.close(code=close_code or status.WS_1008_POLICY_VIOLATION, reason=reason)
        return

    logger.debug("WebSocket /ws/scan/%d connected (user=%s)", scan_id, user.get("id"))
    queue = None
    try:
        scan_record = await get_scan(scan_id)
        if scan_record is None:
            await websocket.send_json(event_envelope(scan_id, {"event": "error", "payload": {"error": "Scan not found"}}))
            await websocket.close(code=WS_CLOSE_SCAN_NOT_FOUND, reason="Scan not found")
            return

        try:
            await require_scan_access(scan_id, user)
        except HTTPException:
            await websocket.send_json(event_envelope(scan_id, {"event": "error", "payload": {"error": "Scan not found"}}))
            await websocket.close(code=WS_CLOSE_SCAN_NOT_FOUND, reason="Scan not found")
            return

        queue = await scan_event_broker.subscribe(scan_id)
        await websocket.send_json(await scan_snapshot(scan_id, scan_record, user))
        if scan_record["status"] in TERMINAL_SCAN_STATUSES:
            await websocket.close(code=1000)
            return

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=2)
                await websocket.send_json(event_envelope(scan_id, event))
            except asyncio.TimeoutError:
                scan_record = await get_scan(scan_id)
                if scan_record is None:
                    await websocket.send_json(
                        event_envelope(scan_id, {"event": "error", "payload": {"error": "Scan not found"}})
                    )
                    await websocket.close(code=WS_CLOSE_SCAN_NOT_FOUND, reason="Scan not found")
                    return
                await websocket.send_json(await scan_snapshot(scan_id, scan_record, user))

            scan_record = await get_scan(scan_id)
            if scan_record is None:
                await websocket.close(code=WS_CLOSE_SCAN_NOT_FOUND, reason="Scan not found")
                return
            if scan_record["status"] in TERMINAL_SCAN_STATUSES:
                await websocket.send_json(await scan_snapshot(scan_id, scan_record, user))
                await websocket.close(code=1000)
                return
    except (WebSocketDisconnect, RuntimeError):
        logger.debug("WebSocket /ws/scan/%d disconnected", scan_id)
        return
    except Exception as exc:
        logger.error("WebSocket /ws/scan/%d error: %s", scan_id, exc, exc_info=True)
        try:
            await websocket.close(code=1011, reason="Internal error")
        except Exception:
            pass
    finally:
        if queue is not None:
            await scan_event_broker.unsubscribe(scan_id, queue)
