import asyncio
from collections import defaultdict
from typing import Any


class ScanEventBroker:
    def __init__(self) -> None:
        self._subscribers: dict[int, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)

    async def subscribe(self, scan_id: int) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers[scan_id].add(queue)
        return queue

    async def unsubscribe(self, scan_id: int, queue: asyncio.Queue[dict[str, Any]]) -> None:
        subscribers = self._subscribers.get(scan_id)
        if subscribers is None:
            return
        subscribers.discard(queue)
        if not subscribers:
            self._subscribers.pop(scan_id, None)

    async def publish(self, scan_id: int, event: dict[str, Any]) -> None:
        subscribers = list(self._subscribers.get(scan_id, set()))
        for queue in subscribers:
            await queue.put(event)

    def cleanup_stale(self) -> None:
        empty_ids = [sid for sid, subs in self._subscribers.items() if not subs]
        for sid in empty_ids:
            self._subscribers.pop(sid, None)


scan_event_broker = ScanEventBroker()
