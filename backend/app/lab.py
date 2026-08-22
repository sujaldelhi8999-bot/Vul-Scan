from copy import deepcopy
from html import escape
from typing import Any


LAB_SCENARIOS = {
    "input_validation_output_encoding": ["input_security", "xss"],
    "authentication_rate_limiting_session": ["auth_session", "jwt"],
    "access_control_api": ["access_control", "api_security"],
    "csrf": ["csrf"],
    "file_handling_path_handling": ["file_upload", "path_handling"],
    "graphql": ["graphql"],
    "websocket_exposure": ["websocket"],
    "redirect": ["redirect"],
    "security_headers_cors": ["security_headers", "cors", "tls_https"],
    "sensitive_exposure": ["sensitive_exposure"],
    "business_logic": ["business_logic"],
}

VALID_LAB_STATES = {"VULNERABLE", "PATCHED"}
_scenario_state = {name: "VULNERABLE" for name in LAB_SCENARIOS}

FAKE_USERS = {
    "alice": {"id": "acct_alice_demo", "name": "Alice Demo", "balance": 1250.00, "role": "customer"},
    "bob": {"id": "acct_bob_demo", "name": "Bob Demo", "balance": 640.50, "role": "customer"},
    "admin": {"id": "acct_admin_demo", "name": "Admin Demo", "balance": 0.00, "role": "admin"},
}


def scenario_status() -> dict[str, str]:
    return dict(_scenario_state)


def set_scenario_state(state: str, scenario: str | None = None) -> dict[str, str]:
    normalized = state.upper()
    if normalized not in VALID_LAB_STATES:
        raise ValueError("Lab scenario state must be VULNERABLE or PATCHED")
    if scenario is None or scenario == "all":
        for name in _scenario_state:
            _scenario_state[name] = normalized
        return scenario_status()
    if scenario not in _scenario_state:
        raise ValueError(f"Unknown lab scenario: {scenario}")
    _scenario_state[scenario] = normalized
    return scenario_status()


def set_many_scenario_states(states: dict[str, str]) -> dict[str, str]:
    for scenario, state in states.items():
        set_scenario_state(state, scenario)
    return scenario_status()


def is_vulnerable(scenario: str) -> bool:
    return _scenario_state.get(scenario, "VULNERABLE") == "VULNERABLE"


def scenario_for_module(module: str) -> str | None:
    for scenario, modules in LAB_SCENARIOS.items():
        if module in modules:
            return scenario
    return None


def lab_manifest(base_url: str = "") -> dict[str, Any]:
    def url(path: str) -> str:
        return f"{base_url.rstrip('/')}{path}" if base_url else path

    surfaces = [
        {
            "id": "search_query",
            "type": "query",
            "method": "GET",
            "path": "/lab/phantombank/search",
            "url": url("/lab/phantombank/search"),
            "parameters": ["q"],
            "module_hints": ["input_security", "xss"],
            "scenario": "input_validation_output_encoding",
            "description": "Demo search accepts a query string and renders results.",
        },
        {
            "id": "accounts_api",
            "type": "api",
            "method": "GET",
            "path": "/lab/phantombank/api/accounts",
            "url": url("/lab/phantombank/api/accounts"),
            "parameters": ["customer"],
            "module_hints": ["injection", "api_security"],
            "scenario": "access_control_api",
            "description": "Fake account lookup API.",
        },
        {
            "id": "profile_update",
            "type": "api",
            "method": "POST",
            "path": "/lab/phantombank/api/profile",
            "url": url("/lab/phantombank/api/profile"),
            "parameters": ["display_name", "age"],
            "module_hints": ["input_security"],
            "scenario": "input_validation_output_encoding",
            "description": "Profile update endpoint with simple input validation behavior.",
        },
        {
            "id": "login",
            "type": "form",
            "method": "POST",
            "path": "/lab/phantombank/login",
            "url": url("/lab/phantombank/login"),
            "parameters": ["username", "password"],
            "module_hints": ["auth_session", "jwt"],
            "scenario": "authentication_rate_limiting_session",
            "description": "Fake login form for rate-limit and session checks.",
        },
        {
            "id": "admin_users",
            "type": "api",
            "method": "GET",
            "path": "/lab/phantombank/api/admin/users",
            "url": url("/lab/phantombank/api/admin/users"),
            "parameters": [],
            "module_hints": ["access_control", "api_security"],
            "auth_required": True,
            "scenario": "access_control_api",
            "description": "Admin-only fake user listing.",
        },
        {
            "id": "transfer_form",
            "type": "form",
            "method": "POST",
            "path": "/lab/phantombank/api/transfer",
            "url": url("/lab/phantombank/api/transfer"),
            "parameters": ["from_account", "to_account", "amount"],
            "module_hints": ["csrf", "business_logic"],
            "scenario": "csrf",
            "description": "Demo transfer workflow with fake balances only.",
        },
        {
            "id": "upload_form",
            "type": "form",
            "method": "POST",
            "path": "/lab/phantombank/upload",
            "url": url("/lab/phantombank/upload"),
            "parameters": ["filename"],
            "module_hints": ["file_upload"],
            "scenario": "file_handling_path_handling",
            "description": "Upload simulation; no files are stored.",
        },
        {
            "id": "statement_download",
            "type": "api",
            "method": "GET",
            "path": "/lab/phantombank/download",
            "url": url("/lab/phantombank/download"),
            "parameters": ["file"],
            "module_hints": ["path_handling"],
            "scenario": "file_handling_path_handling",
            "description": "Statement download simulation using hardcoded content.",
        },
        {
            "id": "graphql",
            "type": "api",
            "method": "POST",
            "path": "/lab/phantombank/graphql",
            "url": url("/lab/phantombank/graphql"),
            "parameters": ["query"],
            "module_hints": ["graphql"],
            "scenario": "graphql",
            "description": "GraphQL demo endpoint with optional introspection.",
        },
        {
            "id": "websocket_prices",
            "type": "websocket",
            "method": "WEBSOCKET",
            "path": "/lab/phantombank/ws/prices",
            "url": url("/lab/phantombank/ws/prices"),
            "parameters": [],
            "module_hints": ["websocket"],
            "auth_required": False,
            "scenario": "websocket_exposure",
            "description": "Fake market-price channel for WebSocket discovery.",
        },
        {
            "id": "redirect",
            "type": "redirect",
            "method": "GET",
            "path": "/lab/phantombank/redirect",
            "url": url("/lab/phantombank/redirect"),
            "parameters": ["next"],
            "module_hints": ["redirect"],
            "scenario": "redirect",
            "description": "Demo post-login redirect target.",
        },
        {
            "id": "root_headers",
            "type": "page",
            "method": "GET",
            "path": "/lab/phantombank",
            "url": url("/lab/phantombank"),
            "parameters": [],
            "module_hints": ["security_headers", "cors", "tls_https"],
            "scenario": "security_headers_cors",
            "description": "Main demo banking page and headers.",
        },
        {
            "id": "session_api",
            "type": "api",
            "method": "GET",
            "path": "/lab/phantombank/api/session",
            "url": url("/lab/phantombank/api/session"),
            "parameters": [],
            "module_hints": ["jwt", "auth_session"],
            "scenario": "authentication_rate_limiting_session",
            "description": "Fake session metadata endpoint.",
        },
        {
            "id": "debug_api",
            "type": "api",
            "method": "GET",
            "path": "/lab/phantombank/api/debug",
            "url": url("/lab/phantombank/api/debug"),
            "parameters": [],
            "module_hints": ["sensitive_exposure"],
            "scenario": "sensitive_exposure",
            "description": "Fake diagnostic data endpoint.",
        },
        {
            "id": "transfer_business_rule",
            "type": "api",
            "method": "POST",
            "path": "/lab/phantombank/api/transfer",
            "url": url("/lab/phantombank/api/transfer"),
            "parameters": ["from_account", "to_account", "amount"],
            "module_hints": ["business_logic"],
            "scenario": "business_logic",
            "description": "Transfer amount and workflow-state validation.",
        },
    ]
    for surface in surfaces:
        surface["state"] = _scenario_state.get(str(surface.get("scenario")), "VULNERABLE")
        surface["vulnerable"] = surface["state"] == "VULNERABLE"
    return {
        "name": "PhantomBank Lab",
        "base_path": "/lab/phantombank",
        "users": deepcopy(FAKE_USERS),
        "scenario_state": scenario_status(),
        "scenarios": deepcopy(LAB_SCENARIOS),
        "surfaces": surfaces,
    }


def render_dashboard() -> str:
    user = FAKE_USERS["alice"]
    csrf_input = "" if is_vulnerable("csrf") else '<input type="hidden" name="csrf_token" value="demo-csrf-token">'
    websocket_hint = "ws://demo/lab/phantombank/ws/prices" if is_vulnerable("websocket_exposure") else "authenticated price stream"
    return f"""
    <html>
      <head><title>PhantomBank Lab</title></head>
      <body>
        <h1>PhantomBank Lab</h1>
        <p>Training-only bank for fake users Alice, Bob, and Admin.</p>
        <section id="account">
          <h2>{escape(user['name'])}</h2>
          <p>Balance: ${user['balance']:.2f}</p>
        </section>
        <nav>
          <a href="/lab/phantombank/search?q=alice">Search</a>
          <a href="/lab/phantombank/login">Login</a>
          <a href="/lab/phantombank/upload">Upload statement</a>
          <a href="/lab/phantombank/api/debug">Diagnostics</a>
        </nav>
        <form action="/lab/phantombank/api/transfer" method="post">
          {csrf_input}
          <input name="from_account" value="alice">
          <input name="to_account" value="bob">
          <input name="amount" value="10.00">
          <button type="submit">Transfer</button>
        </form>
        <script>window.phantomBankPriceStream = "{websocket_hint}";</script>
      </body>
    </html>
    """
