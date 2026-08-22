import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import psutil
from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[2]
BACKEND_URL = "http://127.0.0.1:8011"
FRONTEND_URL = "http://127.0.0.1:5174"


def wait_for(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status < 500:
                    return
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        parent = psutil.Process(process.pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except psutil.Error:
                pass
        parent.kill()
        psutil.wait_procs([parent, *children], timeout=5)
    except psutil.Error:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> int:
    backend: subprocess.Popen[str] | None = None
    frontend: subprocess.Popen[str] | None = None
    try:
        backend_env = os.environ.copy()
        backend_env["FRONTEND_URL"] = FRONTEND_URL
        backend = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8011",
                "--no-access-log",
            ],
            cwd=ROOT / "backend",
            env=backend_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        frontend_env = os.environ.copy()
        frontend_env["VITE_API_BASE_URL"] = BACKEND_URL
        frontend_env["VITE_WS_BASE_URL"] = BACKEND_URL.replace("http", "ws")
        npm = shutil.which("npm.cmd") or shutil.which("npm") or "npm"
        frontend = subprocess.Popen(
            [npm, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5174", "--strictPort"],
            cwd=ROOT / "frontend",
            env=frontend_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for(f"{BACKEND_URL}/api/health")
        wait_for(FRONTEND_URL)
        routes = [
            "/",
            "/scan",
            "/findings",
            "/assets",
            "/cve",
            "/remediation",
            "/agents",
            "/history",
            "/audit-logs",
            "/self-audit",
            "/notifications",
            "/system-health",
            "/settings",
            "/authorized-testing",
        ]
        errors: list[str] = []
        diagnostics: list[str] = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.on("console", lambda message: errors.append(f"console:{message.type}:{message.text}") if message.type == "error" else None)
            page.on("pageerror", lambda error: errors.append(f"pageerror:{error}"))
            page.on("requestfailed", lambda request: diagnostics.append(f"requestfailed:{request.url}:{request.failure}" ) if "/api/" in request.url or "/ws/" in request.url else None)
            page.on("response", lambda response: diagnostics.append(f"api-response:{response.status}:{response.url}") if ("/api/" in response.url and response.status >= 400) else None)
            for route in routes:
                response = page.goto(f"{FRONTEND_URL}{route}", wait_until="domcontentloaded", timeout=20_000)
                if response is None or response.status >= 500:
                    errors.append(f"route:{route}:status:{response.status if response else 'none'}")
                    continue
                page.wait_for_timeout(600)
                body = page.locator("body").inner_text(timeout=5_000).strip()
                if not body:
                    errors.append(f"route:{route}:blank body")
                print(f"ROUTE PASS {route}")
            page.goto(FRONTEND_URL, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(3_000)
            body = page.locator("body").inner_text(timeout=5_000)
            if "Systems Online" not in body:
                errors.append("global-status: Systems Online not shown while backend health is passing")
            page.get_by_text("Ask", exact=True).first.click(timeout=5_000)
            page.get_by_text("Ask PhantomScan", exact=True).wait_for(timeout=5_000)
            page.get_by_label("Close drawer").click(timeout=5_000)
            page.get_by_label("Notifications").click(timeout=5_000)
            page.get_by_role("heading", name="Notifications").wait_for(timeout=5_000)
            page.get_by_label("Close drawer").click(timeout=5_000)
            page.keyboard.press("Control+K")
            page.get_by_text("Open Dashboard", exact=True).wait_for(timeout=5_000)
            page.mouse.click(10, 10)
            page.goto(FRONTEND_URL, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_timeout(35_000)
            try:
                page.get_by_text("Orchestrator Agent", exact=True).wait_for(timeout=15_000)
            except Exception:
                print("DASHBOARD BODY")
                print(page.locator("body").inner_text(timeout=5_000)[:3000])
                print("CAPTURED DIAGNOSTICS")
                print("\n".join([*errors, *diagnostics][-30:]))
                raise
            page.get_by_placeholder("Search PhantomScan...").fill("Scanner")
            page.get_by_role("button", name="Scanner Agent idle").wait_for(timeout=10_000)
            print("GLOBAL CONTROLS PASS")
            browser.close()
        if errors:
            print("FRONTEND ERRORS")
            for error in errors:
                print(error)
            return 1
        print("FRONTEND ROUTE SMOKE: PASS")
        return 0
    finally:
        if frontend is not None:
            stop(frontend)
        if backend is not None:
            stop(backend)


if __name__ == "__main__":
    raise SystemExit(main())
