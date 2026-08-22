import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parents[2]
BACKEND_URL = "http://127.0.0.1:8012"
TARGET = f"{BACKEND_URL}/lab/phantombank"


def wait_for_health(timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BACKEND_URL}/api/health", timeout=1) as response:
                if response.status == 200:
                    return
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"Backend did not become healthy: {last_error}")


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def wait_scan(client: httpx.Client, scan_id: int, headers: dict, timeout: float = 120.0) -> dict:
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        try:
            response = client.get(f"/api/scan/{scan_id}", headers=headers)
            response.raise_for_status()
            last = response.json()
        except httpx.TimeoutException:
            time.sleep(1)
            continue
        if last["status"] in {"complete", "error", "cancelled"}:
            return last
        time.sleep(1)
    raise RuntimeError(f"Timed out waiting for scan {scan_id}; last={last}")


def start_scan(client: httpx.Client, payload: dict, headers: dict) -> int:
    response = client.post("/api/scan/start", json=payload, headers=headers)
    response.raise_for_status()
    return int(response.json()["scan_id"])


def auth_headers(client: httpx.Client) -> dict:
    """Register a test user and return Authorization headers."""
    email = f"e2e_{time.time_ns()}@example.com"
    password = "E2ETestPass123!"
    reg = client.post("/api/auth/register", json={"email": email, "password": password, "name": "E2E Test User"})
    if reg.status_code != 201:
        login = client.post("/api/auth/login", json={"email": email, "password": password})
        if login.status_code == 200:
            return {"Authorization": f"Bearer {login.json()['token']}"}
        raise RuntimeError(f"Auth failed: {reg.text} / {login.text}")
    return {"Authorization": f"Bearer {reg.json()['token']}"}


def main() -> int:
    env = os.environ.copy()
    env["MAX_SCAN_DURATION"] = "120"
    env["MAX_REQUESTS_PER_SECOND"] = "100"
    env["MAX_TOTAL_REQUESTS"] = "220"
    env["BROWSER_PAGE_LIMIT"] = "8"
    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8012"],
        cwd=ROOT / "backend",
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_health()
        with httpx.Client(base_url=BACKEND_URL, timeout=120.0) as client:
            headers = auth_headers(client)
            client.post("/api/lab/scenario", json={"state": "VULNERABLE"}, headers=headers).raise_for_status()
            manifest = client.get("/api/lab/manifest", headers=headers)
            manifest.raise_for_status()
            assert len(manifest.json()["surfaces"]) >= 10, "lab surfaces missing"

            mapped = client.post("/api/active/map", json={"target_url": TARGET, "selected_modules": ["xss", "access_control", "csrf"]}, headers=headers)
            mapped.raise_for_status()
            assert mapped.json()["gate"]["authorization_status"] == "TRAINING", "lab active gate failed"
            assert mapped.json()["plan"]["modules"], "active planner produced no modules"
            print("E2E PASS attack surface map")

            defend_id = start_scan(client, {"target_url": TARGET, "mode": "defend", "intensity": "low"}, headers)
            defend = wait_scan(client, defend_id, headers)
            assert defend["status"] == "complete", defend
            defend_artifacts = client.get(f"/api/scan/{defend_id}/artifacts", headers=headers).json()
            assert defend_artifacts.get("browser_security_output"), "defend browser artifact missing"
            assert defend_artifacts.get("ai_analyst_output"), "defend AI analyst artifact missing"
            browser_engine = defend_artifacts["browser_security_output"].get("browser_engine")
            assert browser_engine in {"playwright_chromium", "http_fallback", "http_observer"}, browser_engine
            print(f"E2E PASS defend scan browser={browser_engine}")

            modules = ["xss", "access_control", "csrf", "security_headers", "sensitive_exposure"]
            pentest_id = start_scan(client, {"target_url": TARGET, "mode": "pentest", "intensity": "low", "selected_tests": modules}, headers)
            pentest = wait_scan(client, pentest_id, headers)
            assert pentest["status"] == "complete", pentest
            pentest_artifacts = client.get(f"/api/scan/{pentest_id}/artifacts", headers=headers).json()
            active = pentest_artifacts.get("active_security_output") or {}
            assert active.get("status") == "complete", active
            assert active.get("findings"), "authorized lab pentest produced no active findings"
            print("E2E PASS authorized lab pentest")

            persisted_findings = client.get("/api/findings", params={"scan_id": pentest_id}, headers=headers).json()
            verify_candidate = next((item for item in persisted_findings if item.get("module") == "xss"), persisted_findings[0])
            client.post("/api/lab/scenario", json={"state": "PATCHED"}, headers=headers).raise_for_status()
            verify = client.post(f"/api/findings/{verify_candidate['id']}/verify", headers=headers)
            verify.raise_for_status()
            assert verify.json()["status"] == "FIX_VERIFIED", verify.text
            print("E2E PASS verify fix")

            second_id = start_scan(client, {"target_url": TARGET, "mode": "pentest", "intensity": "low", "selected_tests": ["xss"]}, headers)
            second = wait_scan(client, second_id, headers)
            assert second["status"] == "complete", second
            comparison = client.get(f"/api/ai/scan/{second_id}/analysis", headers=headers).json().get("scan_comparison", {})
            assert comparison.get("previous_scan_id") is not None, comparison
            print("E2E PASS scan comparison")

            client.post("/api/lab/scenario", json={"state": "VULNERABLE"}, headers=headers).raise_for_status()
            stop_id = start_scan(client, {"target_url": TARGET, "mode": "pentest", "intensity": "low", "selected_tests": ["xss", "access_control", "csrf", "security_headers", "sensitive_exposure"]}, headers)
            stop_response = client.post(f"/api/scan/{stop_id}/stop", headers=headers)
            assert stop_response.status_code in {200, 409}, stop_response.text
            stopped = wait_scan(client, stop_id, headers, timeout=30.0)
            assert stopped["status"] in {"cancelled", "complete"}, stopped
            print(f"E2E PASS stop path status={stopped['status']}")

        print("FULL E2E DEMO: PASS")
        return 0
    finally:
        stop(backend)


if __name__ == "__main__":
    raise SystemExit(main())
