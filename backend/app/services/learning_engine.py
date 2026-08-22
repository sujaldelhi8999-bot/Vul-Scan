"""ContinuousLearningEngine.

Post-scan learning: classifies persisted findings into true/false positives
using their risk/verification status, aggregates them per test module, asks the
LLM (with deterministic heuristic fallback) for a tuning recommendation, and
persists ``learning_insights`` rows. Admin can apply or dismiss insights; applied
insights become tunings consumed by the AdaptiveScanPlanner on future scans.
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from app.database import (
    get_ai_cache,
    get_findings,
    get_scan,
    list_applied_tunings,
    list_learning_insights,
    scan_quality_summary,
    set_ai_cache,
    update_learning_insight_status,
    upsert_learning_insights,
)
from app.services.openrouter_client import ai_usage_logger, call_openrouter

logger = logging.getLogger("phantomscan.learning")

SCAN_LEVEL_MODULE = "*"

TRUE_POSITIVE_RISK_STATUSES = {"ACTIVE", "ACCEPTED_RISK"}
TRUE_POSITIVE_VERIFICATION_STATUSES = {"FIX_VERIFIED", "ISSUE_STILL_PRESENT"}
FALSE_POSITIVE_RISK_STATUS = "FALSE_POSITIVE"

SYSTEM_PROMPT = (
    "You are PhantomScan's Continuous Learning Engine. Given the true/false "
    "positive statistics of findings from an authorized security scan, "
    "recommend how the module should be tuned on future scans. Respond ONLY "
    "with JSON in this exact shape: "
    '{"action": "disable" | "tune" | "review" | "keep", '
    '"rationale": "one sentence"}. "disable" only when the module is a '
    "consistent noise source (very high false positive rate), \"tune\" when "
    "it produces meaningful signal but excessive false positives, \"review\" "
    "when it reports nothing despite findings being rated, otherwise \"keep\"."
)


def classify_finding(finding: dict[str, Any]) -> str:
    risk_status = str(finding.get("risk_status") or "").upper()
    verification_status = str(finding.get("verification_status") or "").upper()
    if risk_status == FALSE_POSITIVE_RISK_STATUS:
        return "fp"
    if (
        risk_status in TRUE_POSITIVE_RISK_STATUSES
        or verification_status in TRUE_POSITIVE_VERIFICATION_STATUSES
    ):
        return "tp"
    return "unrated"


def aggregate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, int]] = {}
    for finding in findings:
        module = str(finding.get("module") or "unmapped")
        bucket = buckets.setdefault(module, {"total": 0, "tp": 0, "fp": 0, "unrated": 0})
        bucket["total"] += 1
        bucket[classify_finding(finding)] += 1
    return [
        {
            "module": module,
            "total_count": counts["total"],
            "true_positives": counts["tp"],
            "false_positives": counts["fp"],
            "unrated_count": counts["unrated"],
            "true_positive_rate": round(counts["tp"] / max(1, counts["total"]), 3),
            "false_positive_rate": round(counts["fp"] / max(1, counts["total"]), 3),
        }
        for module, counts in buckets.items()
    ]


def heuristic_recommendation(stats: dict[str, Any]) -> tuple[str, str]:
    fp_rate = float(stats["false_positive_rate"])
    tp_rate = float(stats["true_positive_rate"])
    total = int(stats["total_count"])
    if total > 0 and tp_rate == 0 and fp_rate < 0.5:
        return "review", "Module produced no confirmed true positives; detection quality needs review"
    if fp_rate >= 0.8:
        return "disable", f"{fp_rate * 100:.0f}% of findings were false positives; disable to cut noise"
    if fp_rate >= 0.5:
        return "tune", f"{fp_rate * 100:.0f}% false positive rate; tune signatures for precision"
    return "keep", "Acceptable true/false positive balance"


class ContinuousLearningEngine:
    """Post-scan learning pass and admin-facing insight management."""

    def __init__(
        self,
        *,
        llm: Callable[..., Any] | None = None,
        cache_ttl_seconds: float = 3600.0,
    ) -> None:
        self._llm = llm
        self._cache_ttl_seconds = float(cache_ttl_seconds)

    async def process_scan(self, scan_id: int) -> list[dict[str, Any]]:
        scan = await get_scan(scan_id)
        if scan is None:
            return []
        findings = await get_findings(scan_id)
        stats = aggregate_findings(findings)
        if not stats:
            stats = [
                {
                    "module": SCAN_LEVEL_MODULE,
                    "total_count": 0,
                    "true_positives": 0,
                    "false_positives": 0,
                    "unrated_count": 0,
                    "true_positive_rate": 0.0,
                    "false_positive_rate": 0.0,
                }
            ]

        rows: list[dict[str, Any]] = []
        for module_stats in stats:
            module = module_stats["module"]
            action, rationale = await self._recommend(scan_id, module, module_stats)
            recommendation_data = {
                "action": action,
                "rationale": rationale,
                "fp_rate": module_stats["false_positive_rate"],
                "tp_rate": module_stats["true_positive_rate"],
                "sample_count": module_stats["total_count"],
            }
            rows.append(
                {
                    **module_stats,
                    "kind": "module",
                    "recommendation": rationale,
                    "recommendation_data": recommendation_data,
                }
            )

        total = sum(int(row["total_count"]) for row in rows)
        if scan.get("mode") == "pentest":
            rows.append(
                {
                    "module": SCAN_LEVEL_MODULE,
                    "kind": "scan",
                    "total_count": total,
                    "true_positives": sum(int(row["true_positives"]) for row in rows),
                    "false_positives": sum(int(row["false_positives"]) for row in rows),
                    "unrated_count": sum(int(row["unrated_count"]) for row in rows),
                    "true_positive_rate": round(
                        sum(int(row["true_positives"]) for row in rows) / max(1, total), 3
                    ),
                    "false_positive_rate": round(
                        sum(int(row["false_positives"]) for row in rows) / max(1, total), 3
                    ),
                    "recommendation": f"Scan produced {total} rated finding(s) across "
                    f"{max(1, len([r for r in rows if r['module'] != SCAN_LEVEL_MODULE]))} module(s)",
                    "recommendation_data": {},
                }
            )

        await upsert_learning_insights(scan_id, rows)
        return rows

    async def list_insights(
        self,
        scan_id: int | None = None,
        status_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        return await list_learning_insights(scan_id, status_filter)

    async def apply_insight(
        self,
        insight_id: int,
        applied_settings: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        settings = applied_settings
        if settings is None:
            from app.database import get_learning_insight

            insight = await get_learning_insight(insight_id)
            if insight is None:
                return None
            data = insight.get("recommendation_data") or {}
            settings = {
                "action": data.get("action", "keep"),
                "fp_rate": data.get("fp_rate", 0.0),
                "sample_count": data.get("sample_count", 0),
            }
        return await update_learning_insight_status(insight_id, "applied", settings)

    async def dismiss_insight(self, insight_id: int) -> dict[str, Any] | None:
        return await update_learning_insight_status(insight_id, "dismissed")

    async def quality_summary(self) -> dict[str, Any]:
        return await scan_quality_summary()

    async def tunings(self) -> dict[str, dict[str, Any]]:
        return await list_applied_tunings()

    async def _recommend(
        self,
        scan_id: int,
        module: str,
        stats: dict[str, Any],
    ) -> tuple[str, str]:
        heuristic = heuristic_recommendation(stats)
        cache_key = f"learning:{scan_id}:{module}"
        cached = await get_ai_cache(cache_key)
        if cached is not None:
            try:
                response = cached["response"]
                payload = response if isinstance(response, dict) else json.loads(str(response))
                action = str(payload.get("action") or "")
                rationale = str(payload.get("rationale") or "")
                if action in {"disable", "tune", "review", "keep"}:
                    return action, rationale or heuristic[1]
            except (TypeError, json.JSONDecodeError):
                pass
        try:
            action, rationale = await self._ask_llm(scan_id, module, stats)
        except Exception as exc:
            logger.warning("Learning LLM call failed for %s/%s: %s", scan_id, module, exc)
            return heuristic
        if action not in {"disable", "tune", "review", "keep"}:
            return heuristic
        await set_ai_cache(
            cache_key,
            finding_id=None,
            evidence_hash=f"{module}:{stats['total_count']}",
            language="en",
            model="openrouter/free",
            response={"action": action, "rationale": rationale},
        )
        return action, rationale

    async def _ask_llm(
        self,
        scan_id: int,
        module: str,
        stats: dict[str, Any],
    ) -> tuple[str, str]:
        user_prompt = json.dumps(
            {
                "module": module,
                "total_count": stats["total_count"],
                "true_positives": stats["true_positives"],
                "false_positives": stats["false_positives"],
                "unrated_count": stats["unrated_count"],
                "true_positive_rate": stats["true_positive_rate"],
                "false_positive_rate": stats["false_positive_rate"],
            },
            ensure_ascii=False,
            default=str,
        )
        if self._llm is not None:
            content = await self._llm(user_prompt, SYSTEM_PROMPT, scan_id=scan_id)
        else:
            content = await call_openrouter(
                user_prompt,
                SYSTEM_PROMPT,
                max_tokens=200,
                timeout=15.0,
                retry_limit=1,
                scan_id=scan_id,
                json_response=True,
            )
        action, rationale = self._parse(content)
        if action is None:
            ai_usage_logger.log(
                model="openrouter/free",
                scan_id=scan_id,
                response_status="skipped",
                error="unparseable recommendation",
            )
            return None, ""
        return action, rationale

    @staticmethod
    def _parse(content: str) -> tuple[str | None, str]:
        if not content or not content.strip():
            return None, ""
        payload: Any = None
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            stripped = content.strip()
            start = stripped.find("{")
            end = stripped.rfind("}")
            if start < 0 or end < start:
                return None, ""
            try:
                payload = json.loads(stripped[start : end + 1])
            except json.JSONDecodeError:
                return None, ""
        if not isinstance(payload, dict):
            return None, ""
        action = payload.get("action")
        rationale = str(payload.get("rationale") or "")
        if not isinstance(action, str):
            return None, rationale
        return action, rationale
