"""In-memory Brutal Mode engagement sessions (persisted to the DB).

A session tracks one target across the full kill chain: exploitation →
shell → post-exploitation → lateral movement → persistence → exfiltration.
Every event is appended to the session timeline AND persisted to the
``brutal_ops`` table for the audit trail. The session itself is snapshotted
to ``brutal_sessions`` on every ``log_op`` so it survives backend restarts
(loot is written on the next ``log_op``; every exploit/post-exploit flow
ends with one).
"""

import time
import uuid
from dataclasses import dataclass, field

from app.database import (
    create_brutal_op,
    create_brutal_session_row,
    load_brutal_sessions,
    save_brutal_session_row,
)


@dataclass
class BrutalSession:
    """One engagement against one authorized target."""

    session_id: str
    target_url: str
    actor: str
    created_at: float
    status: str = "established"
    timeline: list[dict] = field(default_factory=list)
    loot: list[dict] = field(default_factory=list)
    op_ids: list[int] = field(default_factory=list)
    simulation: bool = False
    sim_intel: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    scan_id: int | None = None

    def add_event(self, action: str, status: str, detail: str, payload: str | None = None) -> None:
        self.timeline.append(
            {
                "ts": time.time(),
                "action": action,
                "status": status,
                "detail": detail,
            }
        )

    async def save_new(self) -> None:
        await create_brutal_session_row(
            self.session_id,
            self.target_url,
            self.actor,
            self.created_at,
            status=self.status,
            simulation=self.simulation,
            findings=self.findings,
            sim_intel=self.sim_intel,
            timeline=self.timeline,
            loot=self.loot,
        )

    async def save(self) -> None:
        await save_brutal_session_row(
            self.session_id,
            target_url=self.target_url,
            actor=self.actor,
            created_at=self.created_at,
            simulation=self.simulation,
            status=self.status,
            timeline=self.timeline,
            loot=self.loot,
            findings=self.findings,
            sim_intel=self.sim_intel,
        )

    async def log_op(
        self,
        action: str,
        status: str,
        detail: str,
        *,
        payload: str | None = None,
        output: str | None = None,
        scan_id: int | None = None,
    ) -> int:
        op_id = await create_brutal_op(
            self.session_id,
            self.target_url,
            self.actor,
            action,
            scan_id=scan_id,
            status=status,
            detail=detail,
            payload=payload,
            output=output,
        )
        self.op_ids.append(op_id)
        self.add_event(action, status, detail)
        await self.save()
        return op_id

    def add_loot(self, kind: str, name: str, content: str, source: str) -> None:
        self.loot.append(
            {
                "kind": kind,
                "name": name,
                "content": content[:200_000],
                "source": source,
                "ts": time.time(),
            }
        )

    def serialize(self, with_loot: bool = False) -> dict:
        return {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "actor": self.actor,
            "created_at": self.created_at,
            "status": self.status,
            "simulation": self.simulation,
            "sim_intel": self.sim_intel if self.simulation else None,
            "findings_count": len(self.findings),
            "findings": self.findings if with_loot else self.findings[:5],
            "timeline": self.timeline,
            "loot_count": len(self.loot),
            "loot": self.loot if with_loot else [{"kind": l["kind"], "name": l["name"], "source": l["source"]} for l in self.loot],
        }


class BrutalSessionManager:
    """Singleton registry of active Brutal Mode sessions."""

    _sessions: dict[str, BrutalSession] = {}

    @classmethod
    def create(cls, target_url: str, actor: str, *, simulation: bool = False) -> BrutalSession:
        session = BrutalSession(
            session_id=uuid.uuid4().hex[:16],
            target_url=target_url,
            actor=actor,
            created_at=time.time(),
            simulation=simulation,
        )
        cls._sessions[session.session_id] = session
        return session

    @classmethod
    def get(cls, session_id: str) -> BrutalSession | None:
        return cls._sessions.get(session_id)

    @classmethod
    def list(cls) -> list[BrutalSession]:
        return sorted(cls._sessions.values(), key=lambda s: s.created_at, reverse=True)

    @classmethod
    def require(cls, session_id: str) -> BrutalSession:
        session = cls.get(session_id)
        if session is None:
            raise KeyError(f"Brutal session {session_id} not found")
        return session

    @classmethod
    async def restore(cls) -> int:
        """Reload persisted sessions into memory (called at startup). Returns count."""
        cls._sessions = {}
        for row in await load_brutal_sessions():
            session = BrutalSession(
                session_id=row["session_id"],
                target_url=row["target_url"],
                actor=row["actor"],
                created_at=float(row["created_at"]),
                status=row.get("status") or "established",
                simulation=bool(row.get("simulation")),
                findings=row.get("findings") or [],
                sim_intel=row.get("sim_intel") or {},
                timeline=row.get("timeline") or [],
                loot=row.get("loot") or [],
            )
            cls._sessions[session.session_id] = session
        return len(cls._sessions)
