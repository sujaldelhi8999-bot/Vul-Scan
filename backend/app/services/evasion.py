"""Advanced evasion helpers for Brutal Mode operations.

Provides user-agent rotation, randomized request jitter, and payload
obfuscation so automated exploitation traffic resembles real browsing activity
and avoids tripping naive rate-limit / WAF rules. All of it is opt-in per
request via :class:`EvasionStrategy`.
"""

import asyncio
import base64
import random
import time
from urllib.parse import quote

from app.config import get_settings

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/126.0.2592.61",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]


class EvasionStrategy:
    """Per-operation evasion knobs.

    ``obfuscate`` and ``slow_scan`` default to the BRUTAL_EVASION_* env
    toggles (OFF by default so canned lab keyword-matching still works).
    """

    def __init__(
        self,
        *,
        rotate_user_agent: bool = True,
        jitter_min: float = 0.3,
        jitter_max: float = 2.5,
        obfuscate: bool | None = None,
        slow_scan: bool | None = None,
    ) -> None:
        settings = get_settings()
        self.rotate_user_agent = rotate_user_agent
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.obfuscate = settings.brutal_evasion_obfuscate if obfuscate is None else obfuscate
        self.slow_scan = settings.brutal_evasion_slow_scan if slow_scan is None else slow_scan

    def headers(self) -> dict[str, str]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.7,de;q=0.3"]),
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        if self.rotate_user_agent:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        return headers

    async def jitter_delay(self) -> None:
        """Sleep a randomized delay to keep request cadence human-like.

        No-op unless the BRUTAL_EVASION_SLOW_SCAN toggle is on.
        """
        if not self.slow_scan:
            return
        await asyncio.sleep(random.uniform(self.jitter_min, self.jitter_max))

    def obfuscate_payload(self, payload: str, mode: str | None = None) -> str:
        """Obfuscate a payload to bypass naive signature filters."""
        if not self.obfuscate:
            return payload
        mode = mode or random.choice(["base64", "unicode", "mixed"])
        if mode == "base64":
            encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
            return f"echo {encoded} | base64 -d | bash"
        if mode == "unicode":
            return quote(payload, safe="")
        if mode == "mixed":
            return "".join(ch if i % 3 else chr(ord(ch) + 0xFEE0) for i, ch in enumerate(payload))
        return payload


def slow_scan(delay: float = 1.0) -> None:
    """Compatibility helper for callers that want a plain blocking sleep."""
    time.sleep(delay)