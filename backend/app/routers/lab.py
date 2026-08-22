import json
from html import escape
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.lab import (
    FAKE_USERS,
    LAB_SCENARIOS,
    is_vulnerable,
    lab_manifest,
    render_dashboard,
    scenario_status,
    set_many_scenario_states,
    set_scenario_state,
)

router = APIRouter(tags=["phantombank-lab"])


class LabScenarioRequest(BaseModel):
    state: str | None = Field(default=None, pattern="^(VULNERABLE|PATCHED|vulnerable|patched)$")
    scenario: str | None = None
    states: dict[str, str] = Field(default_factory=dict)


def lab_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Cache-Control": "no-store"}
    if is_vulnerable("security_headers_cors"):
        headers["Access-Control-Allow-Origin"] = "*"
        headers["Access-Control-Allow-Credentials"] = "true"
        return headers
    headers.update(
        {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
    )
    return headers


def html_response(content: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(content, status_code=status_code, headers=lab_headers())


def json_response(content: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content, status_code=status_code, headers=lab_headers())


@router.get("/api/lab/status")
async def lab_status() -> dict[str, Any]:
    return {
        "name": "PhantomBank Lab",
        "default_state": "VULNERABLE",
        "scenario_state": scenario_status(),
        "scenarios": LAB_SCENARIOS,
    }


@router.post("/api/lab/scenario")
async def switch_lab_scenario(request: LabScenarioRequest) -> dict[str, Any]:
    try:
        if request.states:
            state = set_many_scenario_states(request.states)
        elif request.state:
            state = set_scenario_state(request.state, request.scenario)
        else:
            raise ValueError("Provide state or states")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"scenario_state": state}


@router.post("/api/lab/reset")
async def reset_lab() -> dict[str, Any]:
    return {"scenario_state": set_scenario_state("VULNERABLE")}


@router.get("/api/lab/manifest")
async def api_lab_manifest(request: Request) -> dict[str, Any]:
    return lab_manifest(str(request.base_url).rstrip("/"))


@router.get("/lab/phantombank", response_class=HTMLResponse)
@router.get("/lab/phantombank/", response_class=HTMLResponse)
async def phantom_bank_home() -> HTMLResponse:
    return html_response(render_dashboard())


@router.get("/lab/phantombank/manifest")
async def phantom_bank_manifest(request: Request) -> dict[str, Any]:
    return lab_manifest(str(request.base_url).rstrip("/"))


@router.get("/lab/phantombank/login", response_class=HTMLResponse)
async def phantom_bank_login() -> HTMLResponse:
    content = """
    <html><body>
      <h1>PhantomBank Login</h1>
      <form action="/lab/phantombank/login" method="post">
        <input name="username" value="alice">
        <input name="password" type="password" value="demo-password">
        <button type="submit">Sign in</button>
      </form>
    </body></html>
    """
    response = html_response(content)
    if not is_vulnerable("authentication_rate_limiting_session"):
        response.headers["RateLimit-Limit"] = "5"
        response.headers["RateLimit-Remaining"] = "4"
        response.headers.append("Set-Cookie", "phantombank_session=demo; HttpOnly; Secure; SameSite=Lax; Path=/lab/phantombank")
    return response


@router.post("/lab/phantombank/login")
async def phantom_bank_login_post() -> JSONResponse:
    response = json_response({"status": "ok", "user": "alice", "training_only": True})
    if not is_vulnerable("authentication_rate_limiting_session"):
        response.headers["RateLimit-Limit"] = "5"
        response.headers.append("Set-Cookie", "phantombank_session=demo; HttpOnly; Secure; SameSite=Lax; Path=/lab/phantombank")
    return response


@router.get("/lab/phantombank/search", response_class=HTMLResponse)
async def phantom_bank_search(q: str = "") -> HTMLResponse:
    rendered = q if is_vulnerable("input_validation_output_encoding") else escape(q)
    return html_response(f"<html><body><h1>Search</h1><p>Results for {rendered}</p></body></html>")


@router.post("/lab/phantombank/api/profile")
async def update_profile(request: Request) -> JSONResponse:
    body = await safe_json(request)
    age = body.get("age")
    display_name = str(body.get("display_name", ""))
    if is_vulnerable("input_validation_output_encoding"):
        return json_response({"accepted": True, "message": f"accepted invalid input: {display_name or age}"})
    if not isinstance(age, int) or age < 18 or age > 120:
        return json_response({"accepted": False, "error": "age must be a realistic integer"}, 400)
    return json_response({"accepted": True, "display_name": escape(display_name)})


@router.get("/lab/phantombank/api/accounts")
async def accounts(customer: str = "alice") -> JSONResponse:
    if is_vulnerable("access_control_api") and "PHANTOMSCAN_DATA_PROBE" in customer:
        return json_response({"error": "demo data layer error near controlled marker", "marker": "PHANTOMSCAN_DATA_PROBE"}, 500)
    account = FAKE_USERS.get(customer, FAKE_USERS["alice"])
    return json_response({"account": account, "training_only": True})


@router.options("/lab/phantombank/api/accounts")
@router.options("/lab/phantombank/api/transfer")
async def api_options() -> Response:
    allow = "GET, POST, PUT, DELETE, OPTIONS" if is_vulnerable("access_control_api") else "GET, POST, OPTIONS"
    return Response(status_code=204, headers={**lab_headers(), "Allow": allow})


@router.get("/lab/phantombank/api/admin/users")
async def admin_users() -> JSONResponse:
    if is_vulnerable("access_control_api"):
        return json_response({"users": list(FAKE_USERS.values()), "note": "fake admin data"})
    return json_response({"error": "admin authentication required"}, 403)


@router.get("/lab/phantombank/transfer", response_class=HTMLResponse)
async def transfer_page() -> HTMLResponse:
    return html_response(render_dashboard())


@router.post("/lab/phantombank/api/transfer")
async def transfer(request: Request) -> JSONResponse:
    body = await safe_json(request)
    amount = parse_amount(body.get("amount"))
    if is_vulnerable("business_logic") and amount <= 0:
        return json_response({"accepted": True, "message": "demo transfer accepted with invalid amount"})
    if amount <= 0:
        return json_response({"accepted": False, "error": "amount must be positive"}, 400)
    if is_vulnerable("csrf") and not request.headers.get("x-csrf-token"):
        return json_response({"accepted": True, "message": "demo transfer accepted without CSRF token"})
    if not request.headers.get("x-csrf-token"):
        return json_response({"accepted": False, "error": "csrf token required"}, 403)
    return json_response({"accepted": True, "training_only": True})


@router.get("/lab/phantombank/upload", response_class=HTMLResponse)
async def upload_page() -> HTMLResponse:
    extra = "<p>Filenames are stored as provided in this vulnerable scenario.</p>" if is_vulnerable("file_handling_path_handling") else "<p>Filenames are normalized and validated.</p>"
    return html_response(
        f"""
        <html><body><h1>Upload Statement</h1>{extra}
        <form action="/lab/phantombank/upload" method="post" enctype="multipart/form-data">
          <input type="file" name="statement">
          <input name="filename" value="statement.pdf">
          <button type="submit">Upload</button>
        </form></body></html>
        """
    )


@router.post("/lab/phantombank/upload")
async def upload_simulation(request: Request) -> JSONResponse:
    body = await safe_json(request)
    filename = str(body.get("filename") or request.query_params.get("filename") or "statement.pdf")
    if is_vulnerable("file_handling_path_handling") and (".." in filename or filename.endswith(".html")):
        return json_response({"accepted": True, "stored_as": filename, "training_only": True})
    if ".." in filename or filename.endswith(".html"):
        return json_response({"accepted": False, "error": "unsafe filename rejected"}, 400)
    return json_response({"accepted": True, "stored_as": "normalized-demo-statement.pdf"})


@router.get("/lab/phantombank/download")
async def download(file: str = "statement-alice.txt") -> PlainTextResponse:
    if is_vulnerable("file_handling_path_handling") and ".." in file:
        return PlainTextResponse(
            "PHANTOMBANK INTERNAL DEMO STATEMENT\nAlice -> Bob: $10.00\nNo real files were read.",
            headers=lab_headers(),
        )
    if ".." in file or file.startswith("/"):
        return PlainTextResponse("unsafe path rejected", status_code=400, headers=lab_headers())
    return PlainTextResponse("Alice demo statement: $10.00 training transaction", headers=lab_headers())


@router.post("/lab/phantombank/graphql")
async def graphql(request: Request) -> JSONResponse:
    body = await safe_json(request)
    query = str(body.get("query", ""))
    if "__schema" in query and is_vulnerable("graphql"):
        return json_response({"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "DemoAccount"}]}}})
    if "__schema" in query:
        return json_response({"errors": [{"message": "introspection disabled in lab patched mode"}]}, 403)
    return json_response({"data": {"viewer": "alice"}})


@router.get("/lab/phantombank/redirect")
async def lab_redirect(next: str = "/lab/phantombank") -> Response:
    if is_vulnerable("redirect"):
        return RedirectResponse(next, status_code=302, headers=lab_headers())
    if next.startswith("/lab/phantombank") and not next.startswith("//"):
        return RedirectResponse(next, status_code=302, headers=lab_headers())
    return json_response({"error": "external redirect rejected"}, 400)


@router.get("/lab/phantombank/api/session")
async def session() -> JSONResponse:
    if is_vulnerable("authentication_rate_limiting_session"):
        return json_response(
            {
                "token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImxhYiI6dHJ1ZX0.demoSignature",
                "token_config": {"alg": "none", "storage": "localStorage"},
            }
        )
    response = json_response({"session": "cookie", "token_config": {"alg": "RS256", "storage": "HttpOnly cookie"}})
    response.headers.append("Set-Cookie", "phantombank_session=demo; HttpOnly; Secure; SameSite=Lax; Path=/lab/phantombank")
    return response


@router.get("/lab/phantombank/api/debug")
async def debug() -> JSONResponse:
    if is_vulnerable("sensitive_exposure"):
        return json_response(
            {
                "debug": True,
                "api_key": "DEMO_KEY_DO_NOT_USE_123456",
                "note": "fake lab diagnostic data only",
            }
        )
    return json_response({"error": "debug endpoint disabled"}, 404)


@router.websocket("/lab/phantombank/ws/prices")
async def prices_websocket(websocket: WebSocket) -> None:
    if not is_vulnerable("websocket_exposure"):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    await websocket.send_text(json.dumps({"symbol": "PHB-DEMO", "price": "101.25", "training_only": True}))
    await websocket.close(code=1000)


# ---------------------------------------------------------------------------
# Brutal Mode lab simulation.
#
# These endpoints simulate the "compromised host / internal network" side of
# an engagement. They only ever return FAKE training data, never touch real
# files, processes, or network targets. Scenario-aware: when the lab is in
# PATCHED state the simulated vulnerabilities are blocked, so the
# exploit → patched → re-exploit-fails demo works.
# ---------------------------------------------------------------------------

LAB_INTERNAL_NETWORK = {
    "hosts": [
        {
            "hostname": "db-01",
            "ip": "10.0.0.2",
            "ports": [22, 3306, 6379],
            "services": ["ssh", "mysql", "redis"],
            "os": "Ubuntu 22.04",
        },
        {
            "hostname": "backup-01",
            "ip": "10.0.0.3",
            "ports": [22, 8080],
            "services": ["ssh", "jenkins"],
            "os": "Debian 11",
        },
        {
            "hostname": "app-01",
            "ip": "10.0.0.4",
            "ports": [22, 80, 443],
            "services": ["ssh", "nginx"],
            "os": "Ubuntu 22.04",
        },
    ],
    "training_only": True,
}

LAB_SIM_CREDS = {
    "root": "toor",
    "alice": "demo-password",
    "bob": "P@ssw0rd!2024",
    "backup": "backup-secret-01",
}

LAB_SIM_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
lab-service:x:1000:1000:PhantomBank App:/home/lab-service:/bin/bash
alice:x:1001:1001:Alice:/home/alice:/bin/bash
backup:x:1002:1002:Backup:/home/backup:/bin/bash"""

LAB_SIM_DB_USERS = [
    {"id": 1, "username": "alice", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    {"id": 2, "username": "bob", "password_hash": "e10adc3949ba59abbe56e057f20f883e"},
    {"id": 3, "username": "admin", "password_hash": "21232f297a57a5a743894a0e4a801fc3"},
    {"id": 4, "username": "backup_service", "password_hash": "1a2b3c4d5e6f7a8b9c0d"},
]

LAB_SIM_CONFIG = """<?php
$db_host = '10.0.0.2';
$db_user = 'phb_app';
$db_pass = 'PhantomBank!DB_Secret_2024';
$redis_host = '10.0.0.2';
$redis_port = 6379;
$debug_mode = true;
$aws_access_key = 'AKIAIOSFODNN7EXAMPLE';
$aws_secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
?>"""


def _lab_sim_open() -> bool:
    return is_vulnerable("file_handling_path_handling") or is_vulnerable("injection")


def _sim_command_output(cmd: str) -> tuple[str, int]:
    """Map a command to canned simulated output. Returns (output, exit_code)."""
    first = cmd.strip().split(" ")[0].lower()
    if first in ("whoami", "id"):
        return "lab-service\nuid=1000(lab-service) gid=1000(lab-service) groups=1000(lab-service)", 0
    if first in ("uname",):
        return "Linux db-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux", 0
    if first in ("ifconfig", "ip"):
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.4  netmask 255.255.255.0", 0
    if first in ("hostname",):
        return "app-01", 0
    if first in ("netstat", "ss"):
        return "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN", 0
    if first in ("ls", "dir"):
        return "app.py  config.php  uploads/  static/  .env  backup/", 0
    if first in ("pwd",):
        return "/opt/phantombank", 0
    if first in ("cat",):
        lowered = cmd.lower()
        if "passwd" in lowered:
            return LAB_SIM_PASSWD, 0
        if "config" in lowered or "env" in lowered:
            return LAB_SIM_CONFIG, 0
        return "simulated file content (training only)", 0
    if first in ("env",):
        return "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nDB_HOST=10.0.0.2\nDB_USER=phb_app\nREDIS_HOST=10.0.0.2", 0
    if first in ("ps",):
        return "PID TTY          TIME CMD\n1 ? 00:00:00 systemd\n420 ? 00:00:12 mysqld\n523 ? 00:00:03 redis-server\n", 0
    if first in ("find",):
        return "/usr/bin/passwd\n/usr/bin/sudo\n/opt/phantombank/backup/backup.sh", 0
    if first in ("crontab", "schtasks"):
        return "0 2 * * * /opt/phantombank/backup/backup.sh", 0
    if first in ("sudo",):
        return "User lab-service may run the following commands on app-01:\n    (ALL) NOPASSWD: /opt/phantombank/backup/backup.sh", 0
    if first in ("help", "?"):
        return "simulated shell: whoami, id, uname, hostname, ifconfig, netstat, ls, cat /etc/passwd, cat config.php, env, ps, find, crontab, sudo -l, exit", 0
    return f"sh: {first}: command not found (simulated)", 127


@router.post("/api/lab/brutal/exec")
async def lab_brutal_exec(request: Request) -> JSONResponse:
    """Simulated RCE / command injection target."""
    body = await safe_json(request)
    cmd = str(body.get("cmd") or body.get("command") or "")
    if not _lab_sim_open():
        return json_response({"error": "command execution blocked (patched scenario)", "simulated": True}, 403)
    if not cmd:
        return json_response({"error": "cmd is required"}, 400)
    output, code = _sim_command_output(cmd)
    return json_response({"output": output, "exit_code": code, "simulated": True})


@router.post("/api/lab/brutal/sqli")
async def lab_brutal_sqli(request: Request) -> JSONResponse:
    """Simulated SQL injection target (UNION-based dump)."""
    body = await safe_json(request)
    query = str(body.get("query") or "")
    if not _lab_sim_open():
        return json_response({"error": "SQL execution blocked (patched scenario)", "simulated": True}, 403)
    if "union" in query.lower():
        return json_response({"rows": LAB_SIM_DB_USERS, "columns": ["id", "username", "password_hash"], "simulated": True})
    if "os-shell" in query.lower():
        return json_response({"os_shell": True, "hint": "Use /api/lab/brutal/exec for commands", "simulated": True})
    return json_response({"rows": [], "simulated": True})


@router.post("/api/lab/brutal/lfi")
async def lab_brutal_lfi(request: Request) -> JSONResponse:
    """Simulated LFI target."""
    body = await safe_json(request)
    path = str(body.get("path") or "")
    if not _lab_sim_open():
        return json_response({"error": "file read blocked (patched scenario)", "simulated": True}, 403)
    if "passwd" in path:
        return json_response({"content": LAB_SIM_PASSWD, "path": path, "simulated": True})
    if "config" in path or "env" in path:
        return json_response({"content": LAB_SIM_CONFIG, "path": path, "simulated": True})
    if "log" in path:
        return json_response(
            {"content": "simulated apache access log with PHP markers", "log_poisoning": True, "simulated": True}
        )
    return json_response({"content": "no such file (simulated)", "path": path, "simulated": True})


@router.post("/api/lab/brutal/ssrf")
async def lab_brutal_ssrf(request: Request) -> JSONResponse:
    """Simulated SSRF target (internal service probing)."""
    body = await safe_json(request)
    url = str(body.get("url") or "")
    if not _lab_sim_open():
        return json_response({"error": "internal fetch blocked (patched scenario)", "simulated": True}, 403)
    if "metadata" in url:
        return json_response(
            {
                "content": '{"accountId":"112233","accessKeyId":"ASIAEXAMPLE","secretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}',
                "service": "cloud-metadata",
                "simulated": True,
            }
        )
    if "redis" in url:
        return json_response({"content": "Redis 6.2.6 banner - NOAUTH Authentication required", "service": "redis", "simulated": True})
    if "elastic" in url or "9200" in url:
        return json_response({"content": '{"name":"es-01","version":{"number":"7.17.9"}}', "service": "elasticsearch", "simulated": True})
    return json_response({"content": "connection refused (simulated)", "simulated": True})


@router.get("/api/lab/brutal/network")
async def lab_brutal_network() -> JSONResponse:
    """Simulated internal network map for lateral movement."""
    if not _lab_sim_open():
        return json_response({"error": "network map blocked (patched scenario)", "simulated": True}, 403)
    return json_response(LAB_INTERNAL_NETWORK)


@router.post("/api/lab/brutal/ssh-login")
async def lab_brutal_ssh_login(request: Request) -> JSONResponse:
    """Simulated SSH login attempt against an internal host."""
    body = await safe_json(request)
    username = str(body.get("username") or "")
    password = str(body.get("password") or "")
    key = str(body.get("key") or "")
    host = str(body.get("host") or "10.0.0.2")
    if not _lab_sim_open():
        return json_response({"error": "ssh blocked (patched scenario)", "simulated": True}, 403)
    if key and "BEGIN OPENSSH PRIVATE KEY" in key:
        return json_response({"authenticated": True, "host": host, "method": "key", "username": "backup", "simulated": True})
    if LAB_SIM_CREDS.get(username) == password:
        return json_response({"authenticated": True, "host": host, "method": "password", "username": username, "simulated": True})
    return json_response({"authenticated": False, "host": host, "error": "permission denied", "simulated": True}, 403)


@router.post("/api/lab/brutal/persist")
async def lab_brutal_persist(request: Request) -> JSONResponse:
    """Simulated persistence installation (cron / systemd / scheduled task)."""
    body = await safe_json(request)
    kind = str(body.get("kind") or "cron")
    command = str(body.get("command") or "")
    if not _lab_sim_open():
        return json_response({"error": "persistence blocked (patched scenario)", "simulated": True}, 403)
    if kind == "cron":
        return json_response({"installed": True, "mechanism": "crontab", "entry": f"@reboot {command}", "simulated": True})
    if kind == "systemd":
        return json_response({"installed": True, "mechanism": "systemd unit", "entry": f"[Service] ExecStart={command}", "simulated": True})
    if kind == "registry":
        return json_response({"installed": True, "mechanism": "HKCU Run key", "entry": f"Run -> {command}", "simulated": True})
    return json_response({"installed": True, "mechanism": kind, "entry": command, "simulated": True})


@router.post("/api/lab/brutal/upload-shell")
async def lab_brutal_upload_shell(request: Request) -> JSONResponse:
    """Simulated webshell deployment via vulnerable file upload."""
    body = await safe_json(request)
    filename = str(body.get("filename") or "shell.php")
    if not _lab_sim_open():
        return json_response({"error": "upload blocked (patched scenario)", "simulated": True}, 403)
    if filename.endswith((".php", ".jsp", ".asp", ".aspx")):
        return json_response(
            {
                "deployed": True,
                "url": f"/lab/phantombank/uploads/{filename}",
                "note": "simulated webshell deployed — combine with /api/lab/brutal/exec for interactive access",
                "simulated": True,
            }
        )
    return json_response({"deployed": False, "error": "extension not allowed", "simulated": True}, 400)


@router.post("/api/lab/brutal/xss-steal")
async def lab_brutal_xss_steal(request: Request) -> JSONResponse:
    """Simulated session theft via persistent XSS."""
    body = await safe_json(request)
    cookie = str(body.get("cookie") or "")
    if not _lab_sim_open():
        return json_response({"error": "session theft blocked (patched scenario)", "simulated": True}, 403)
    if cookie:
        return json_response(
            {
                "stolen": True,
                "session": "eyJzdWIiOiJhbGljZSIsImxhYiI6dHJ1ZX0.demoSignature",
                "user": "alice",
                "hijackable": True,
                "simulated": True,
            }
        )
    return json_response({"stolen": False, "error": "no cookie captured", "simulated": True}, 400)


async def safe_json(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        return dict(request.query_params)
    return data if isinstance(data, dict) else {}


def parse_amount(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
