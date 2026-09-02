import os
import shutil
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

_test_db_dir: str | None = None
_test_db_path: Path | None = None


def _sqlite_files(path: Path) -> list[Path]:
    return [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]


def pytest_configure(config):
    """Set required env vars before any test imports app.

    Tests always run against an isolated SQLite database, regardless of any
    developer or CI DATABASE_URL value. This prevents test runs from touching a
    local PhantomScan database and matches the active runtime storage layer.
    """
    global _test_db_dir, _test_db_path
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only-123456789012345678901234")
    configured_url = os.environ.get("PHANTOMSCAN_TEST_DATABASE_URL")
    if configured_url:
        if not configured_url.startswith("sqlite:///"):
            raise RuntimeError("PHANTOMSCAN_TEST_DATABASE_URL must use sqlite:/// for the current test runtime")
        _test_db_path = Path(configured_url.replace("sqlite:///", "")).resolve()
        _test_db_path.parent.mkdir(parents=True, exist_ok=True)
        for file_path in _sqlite_files(_test_db_path):
            file_path.unlink(missing_ok=True)
        os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"
        return

    _test_db_dir = tempfile.mkdtemp(prefix="phantomscan-tests-")
    _test_db_path = Path(_test_db_dir) / "test.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"


def pytest_unconfigure(config):
    """Remove isolated SQLite test database files."""
    try:
        import asyncio
        from app.database import close_database
        asyncio.run(close_database())
    except Exception:
        pass
    if _test_db_path is not None:
        for file_path in _sqlite_files(_test_db_path):
            try:
                file_path.unlink(missing_ok=True)
            except PermissionError:
                # On Windows, SQLite handles can briefly remain locked after a
                # failed async TestClient run. Do not mask the real test result.
                pass
    if _test_db_dir:
        shutil.rmtree(_test_db_dir, ignore_errors=True)


def create_auth_headers(client: TestClient, email: str = None, password: str = "TestPass123!") -> dict:
    """Register a user and return Authorization headers."""
    if email is None:
        email = f"test_{os.urandom(4).hex()}@example.com"
    reg = client.post("/api/auth/register", json={"email": email, "password": password, "name": "Test User"})
    if reg.status_code != 201:
        # User might already exist, try login
        login = client.post("/api/auth/login", json={"email": email, "password": password})
        if login.status_code == 200:
            token = login.json()["token"]
            return {"Authorization": f"Bearer {token}"}
        raise AssertionError(f"Failed to register/login: {reg.text} / {login.text}")
    token = reg.json()["token"]
    return {"Authorization": f"Bearer {token}"}


async def promote_to_admin(user_id: str):
    """Promote user to admin via direct DB update."""
    import aiosqlite
    from app.config import get_settings
    settings = get_settings()
    db_path = settings.database_url.replace("sqlite:///", "")
    async with aiosqlite.connect(db_path) as db:
        await db.execute("UPDATE users SET role = 'admin', subscription_tier = 'PRO' WHERE id = ?", (user_id,))
        await db.commit()


async def create_admin_headers(client: TestClient, email: str = None, password: str = "AdminPass123!") -> dict:
    """Register a user, promote to admin, and return admin Authorization headers."""
    if email is None:
        email = f"admin_{os.urandom(4).hex()}@example.com"
    reg = client.post("/api/auth/register", json={"email": email, "password": password, "name": "Admin User"})
    if reg.status_code != 201:
        login = client.post("/api/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200, login.text
        user_id = login.json()["user"]["id"]
    else:
        user_id = reg.json()["user"]["id"]
    await promote_to_admin(user_id)
    login = client.post("/api/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    token = login.json()["token"]
    return {"Authorization": f"Bearer {token}"}
