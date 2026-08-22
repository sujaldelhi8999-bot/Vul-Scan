#!/usr/bin/env python3
"""Promote an existing account to an Enterprise owner.

Usage:
    python backend/scripts/enterprise_promote_admin.py --email owner@example.com
    python backend/scripts/enterprise_promote_admin.py --email owner@example.com \
        --name "Acme Security" --allowed-domain acme.com
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional for the standalone script
    load_dotenv = None


def _load_env() -> None:
    if load_dotenv:
        load_dotenv(BACKEND_DIR / ".env")
        load_dotenv(ROOT_DIR / ".env")


async def promote(email: str, name: str | None, domains: list[str]) -> dict[str, str]:
    from app.database import get_connection, initialize_database

    await initialize_database()
    normalized_email = email.strip().lower()
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT id, email, name FROM users WHERE lower(email) = ? LIMIT 1",
            (normalized_email,),
        )
        user = await cursor.fetchone()
        if user is None:
            raise LookupError(f"No account exists for {normalized_email}")

        cursor = await connection.execute(
            "SELECT enterprise_id FROM enterprise_memberships WHERE user_id = ? LIMIT 1",
            (user["id"],),
        )
        membership = await cursor.fetchone()
        enterprise_id = str(membership["enterprise_id"]) if membership else f"ent_{uuid.uuid4().hex}"
        enterprise_name = (name or user["name"] or normalized_email.split("@", 1)[0]).strip()
        clean_domains = sorted({str(domain).strip().lower().lstrip("@") for domain in domains if str(domain).strip()})

        await connection.execute(
            """
            INSERT INTO enterprises (id, name, allowed_email_domains, is_active, created_by)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                allowed_email_domains = excluded.allowed_email_domains,
                is_active = 1,
                updated_at = CURRENT_TIMESTAMP
            """,
            (enterprise_id, enterprise_name, json.dumps(clean_domains), user["id"]),
        )
        await connection.execute(
            """
            INSERT INTO enterprise_memberships (
                enterprise_id, user_id, role, max_severity,
                can_request_audit, can_request_fix, can_approve, can_manage_members, is_active
            ) VALUES (?, ?, 'owner', 'ALL', 1, 1, 1, 1, 1)
            ON CONFLICT(user_id) DO UPDATE SET
                enterprise_id = excluded.enterprise_id,
                role = 'owner',
                max_severity = 'ALL',
                can_request_audit = 1,
                can_request_fix = 1,
                can_approve = 1,
                can_manage_members = 1,
                is_active = 1,
                updated_at = CURRENT_TIMESTAMP
            """,
            (enterprise_id, user["id"]),
        )
        await connection.execute(
            """
            UPDATE users
            SET subscription_tier = 'ENTERPRISE',
                subscription_status = 'active', is_active = 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (user["id"],),
        )
        await connection.commit()

    return {"user_id": str(user["id"]), "email": str(user["email"]), "enterprise_id": enterprise_id, "name": enterprise_name}


async def _run_promote(email: str, name: str | None, domains: list[str]) -> dict[str, str]:
    try:
        return await promote(email, name, domains)
    finally:
        from app import database

        if database._db_connection is not None:
            await database._db_connection.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Promote an existing account to an Enterprise owner")
    parser.add_argument("--email", required=True, help="Existing account email")
    parser.add_argument("--name", help="Enterprise display name")
    parser.add_argument("--allowed-domain", action="append", default=[], help="Allowed employee email domain; repeatable")
    return parser


def main() -> int:
    _load_env()
    args = _parser().parse_args()
    try:
        result = asyncio.run(_run_promote(args.email, args.name, args.allowed_domain))
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        f"Enterprise owner ready: {result['email']} "
        f"(enterprise_id={result['enterprise_id']}, name={result['name']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
