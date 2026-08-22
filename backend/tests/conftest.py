import os
import pytest
from fastapi.testclient import TestClient


def pytest_configure(config):
    """Set required env vars before any test imports app."""
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only-123456789012345678901234")


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