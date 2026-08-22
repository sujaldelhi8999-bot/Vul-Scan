import asyncio
import json
import uuid
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Callable, Optional

import redis.asyncio as redis
from redis.asyncio import Redis

from app.config import get_settings
from app.database_orm import get_db_session
from app.models import ScanRequest

logger = logging.getLogger("phantomscan.distributed_queue")


@dataclass
class ScanJob:
    """Represents a scan job in the distributed queue."""
    id: str
    scan_id: int
    scan_request: ScanRequest
    user_id: str
    authorization_context: Optional[dict] = None
    user_role: str = "user"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    priority: int = 1
    attempts: int = 0
    max_attempts: int = 3


class DistributedScanQueue:
    """
    Redis-backed distributed scan job queue.
    
    Features:
    - Priority queue (higher priority = processed first)
    - Worker registration and heartbeat
    - Job acknowledgment and retry logic
    - Dead letter queue for failed jobs
    - Horizontal scaling support
    """
    
    # Redis key prefixes
    QUEUE_KEY = "phantomscan:queue:scan_jobs"
    PROCESSING_KEY = "phantomscan:processing:scan_jobs"
    DEAD_LETTER_KEY = "phantomscan:dead_letter:scan_jobs"
    WORKERS_KEY = "phantomscan:workers"
    WORKER_HEARTBEAT_TTL = 30  # seconds
    
    def __init__(self, redis_client: Optional[Redis] = None):
        self.settings = get_settings()
        self._redis = redis_client
        self._worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
    
    async def initialize(self) -> None:
        """Initialize Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(
                self.settings.redis_url,
                max_connections=self.settings.redis_max_connections,
                socket_timeout=self.settings.redis_socket_timeout,
                socket_connect_timeout=self.settings.redis_socket_connect_timeout,
                decode_responses=True,
            )
        # Test connection
        await self._redis.ping()
        logger.info("Distributed scan queue initialized")
    
    async def close(self) -> None:
        """Close Redis connection."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        if self._redis:
            await self._redis.close()
    
    # -----------------------------------------------------------------------
    # Job Queue Operations
    # -----------------------------------------------------------------------
    
    async def enqueue(self, job: ScanJob) -> None:
        """Add a job to the priority queue."""
        job_data = {
            "id": job.id,
            "scan_id": job.scan_id,
            "scan_request": job.scan_request.model_dump(),
            "user_id": job.user_id,
            "authorization_context": job.authorization_context,
            "user_role": job.user_role,
            "created_at": job.created_at.isoformat(),
            "priority": job.priority,
            "attempts": job.attempts,
            "max_attempts": job.max_attempts,
        }
        # Use negative priority for max-heap behavior (higher priority first)
        await self._redis.zadd(
            self.QUEUE_KEY,
            {json.dumps(job_data): -job.priority}
        )
        logger.info(f"Enqueued job {job.id} with priority {job.priority}")
    
    async def dequeue(self, worker_id: str, count: int = 1) -> list[ScanJob]:
        """
        Atomically move jobs from queue to processing.
        Uses Lua script for atomicity.
        """
        lua_script = """
        local jobs = redis.call('ZRANGE', KEYS[1], 0, ARGV[1]-1)
        if #jobs > 0 then
            redis.call('ZREM', KEYS[1], unpack(jobs))
            redis.call('ZADD', KEYS[2], ARGV[2], unpack(jobs))
        end
        return jobs
        """
        script = self._redis.register_script(lua_script)
        
        timestamp = datetime.now(timezone.utc).timestamp()
        job_datas = await script(
            keys=[self.QUEUE_KEY, self.PROCESSING_KEY],
            args=[count, timestamp]
        )
        
        jobs = []
        for job_data in job_datas:
            data = json.loads(job_data)
            scan_request = ScanRequest(**data.pop("scan_request"))
            job = ScanJob(
                scan_request=scan_request,
                **data
            )
            jobs.append(job)
        
        if jobs:
            logger.info(f"Worker {worker_id} dequeued {len(jobs)} job(s)")
        
        return jobs
    
    async def acknowledge(self, job_id: str) -> bool:
        """Mark job as successfully completed."""
        # Remove from processing set
        removed = await self._redis.zrem(self.PROCESSING_KEY, job_id)
        if removed:
            logger.info(f"Job {job_id} acknowledged")
        return bool(removed)
    
    async def requeue(self, job: ScanJob) -> None:
        """Requeue job for retry (increment attempts)."""
        job.attempts += 1
        if job.attempts >= job.max_attempts:
            await self.move_to_dead_letter(job, "Max attempts exceeded")
        else:
            await self.enqueue(job)
            logger.warning(f"Job {job.id} requeued (attempt {job.attempts}/{job.max_attempts})")
    
    async def move_to_dead_letter(self, job: ScanJob, reason: str) -> None:
        """Move failed job to dead letter queue."""
        job_data = {
            "id": job.id,
            "scan_id": job.scan_id,
            "scan_request": job.scan_request.model_dump(),
            "user_id": job.user_id,
            "authorization_context": job.authorization_context,
            "user_role": job.user_role,
            "created_at": job.created_at.isoformat(),
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "failure_reason": reason,
            "attempts": job.attempts,
        }
        await self._redis.zadd(
            self.DEAD_LETTER_KEY,
            {json.dumps(job_data): datetime.now(timezone.utc).timestamp()}
        )
        await self._redis.zrem(self.PROCESSING_KEY, job.id)
        logger.error(f"Job {job.id} moved to dead letter: {reason}")
    
    # -----------------------------------------------------------------------
    # Worker Management
    # -----------------------------------------------------------------------
    
    async def register_worker(self, capabilities: Optional[list[str]] = None) -> None:
        """Register this worker."""
        worker_data = {
            "id": self._worker_id,
            "capabilities": capabilities or ["scan"],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "idle",
        }
        await self._redis.hset(
            self.WORKERS_KEY,
            self._worker_id,
            json.dumps(worker_data)
        )
        await self._redis.expire(self.WORKERS_KEY, self.WORKER_HEARTBEAT_TTL * 2)
        logger.info(f"Worker {self._worker_id} registered")
    
    async def heartbeat(self, status: str = "idle", current_job: Optional[str] = None) -> None:
        """Send worker heartbeat."""
        worker_data = {
            "id": self._worker_id,
            "status": status,
            "current_job": current_job,
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        }
        await self._redis.hset(
            self.WORKERS_KEY,
            self._worker_id,
            json.dumps(worker_data)
        )
        await self._redis.expire(self.WORKERS_KEY, self.WORKER_HEARTBEAT_TTL * 2)
    
    async def start_heartbeat(self, interval: int = 10) -> None:
        """Start periodic heartbeat."""
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(interval))
    
    async def _heartbeat_loop(self, interval: int) -> None:
        while self._running:
            try:
                await self.heartbeat()
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(interval)
    
    async def get_workers(self) -> list[dict]:
        """Get all registered workers."""
        workers = await self._redis.hgetall(self.WORKERS_KEY)
        return [json.loads(w) for w in workers.values()]
    
    async def cleanup_stale_workers(self, max_age: int = 60) -> int:
        """Remove workers that haven't sent heartbeat."""
        workers = await self.get_workers()
        removed = 0
        now = datetime.now(timezone.utc)
        for worker in workers:
            last_hb = datetime.fromisoformat(worker.get("last_heartbeat", worker.get("started_at", "")))
            if (now - last_hb).total_seconds() > max_age:
                await self._redis.hdel(self.WORKERS_KEY, worker["id"])
                removed += 1
        return removed
    
    # -----------------------------------------------------------------------
    # Monitoring
    # -----------------------------------------------------------------------
    
    async def get_queue_stats(self) -> dict:
        """Get queue statistics."""
        queued = await self._redis.zcard(self.QUEUE_KEY)
        processing = await self._redis.zcard(self.PROCESSING_KEY)
        dead_letter = await self._redis.zcard(self.DEAD_LETTER_KEY)
        workers = len(await self.get_workers())
        
        return {
            "queued": queued,
            "processing": processing,
            "dead_letter": dead_letter,
            "workers": workers,
        }
    
    async def get_dead_letter_jobs(self, limit: int = 100) -> list[dict]:
        """Get jobs from dead letter queue."""
        jobs = await self._redis.zrange(self.DEAD_LETTER_KEY, 0, limit - 1)
        return [json.loads(j) for j in jobs]
    
    async def retry_dead_letter_job(self, job_id: str) -> bool:
        """Retry a job from dead letter queue."""
        jobs = await self._redis.zrange(self.DEAD_LETTER_KEY, 0, -1)
        for job_data in jobs:
            data = json.loads(job_data)
            if data["id"] == job_id:
                await self._redis.zrem(self.DEAD_LETTER_KEY, job_data)
                job = ScanJob(
                    id=data["id"],
                    scan_id=data["scan_id"],
                    scan_request=ScanRequest(**data["scan_request"]),
                    user_id=data["user_id"],
                    authorization_context=data.get("authorization_context"),
                    user_role=data.get("user_role", "user"),
                    created_at=datetime.fromisoformat(data["created_at"]),
                    priority=1,
                    attempts=0,
                    max_attempts=3,
                )
                await self.enqueue(job)
                return True
        return False


# Global queue instance
scan_queue: Optional[DistributedScanQueue] = None


@asynccontextmanager
async def get_scan_queue() -> AsyncGenerator[DistributedScanQueue, None]:
    """FastAPI dependency for scan queue."""
    global scan_queue
    if scan_queue is None:
        scan_queue = DistributedScanQueue()
        await scan_queue.initialize()
    try:
        yield scan_queue
    finally:
        pass  # Don't close here, close on shutdown


async def initialize_scan_queue() -> DistributedScanQueue:
    """Initialize the global scan queue."""
    global scan_queue
    scan_queue = DistributedScanQueue()
    await scan_queue.initialize()
    return scan_queue


async def shutdown_scan_queue() -> None:
    """Shutdown the global scan queue."""
    global scan_queue
    if scan_queue:
        await scan_queue.close()
        scan_queue = None
