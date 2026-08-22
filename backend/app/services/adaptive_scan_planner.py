"""AdaptiveScanPlanner.

Maps a Target Complexity Index band onto an executable scan profile: request
rate, intensity, module selection and safety limits. Consumes learned tunings
from the ContinuousLearningEngine (applied insights) so past true/false
positive experience influences future scan execution (closed loop).
"""

from dataclasses import replace
from typing import Any

from app.models import ScanRequest
from app.services.execution import SafetyLimits
from app.services.tci import BAND_CRITICAL, BAND_COMPLEX, BAND_MEDIUM, BAND_SIMPLE

ESSENTIAL_MODULES = [
    "input_security",
    "authentication",
    "authorization",
    "injection",
    "xss",
    "auth_session",
    "csrf",
]

FULL_MODULE_LIST = [
    "input_security",
    "authentication",
    "authorization",
    "injection",
    "xss",
    "auth_session",
    "access_control",
    "csrf",
    "ssrf",
    "file_upload",
    "api_security",
    "graphql",
    "jwt",
    "websocket",
    "websockets",
    "rate_limits",
    "business_logic",
    "path_handling",
    "redirect",
    "redirect_security",
    "cors",
    "security_headers",
    "tls_https",
    "sensitive_exposure",
]

BAND_PROFILES: dict[str, dict[str, Any]] = {
    BAND_SIMPLE: {
        "requests_per_second": 2.0,
        "intensity": "low",
        "modules": list(ESSENTIAL_MODULES),
        "depth": "standard",
        "deeper": False,
    },
    BAND_MEDIUM: {
        "requests_per_second": 5.0,
        "intensity": "medium",
        "modules": list(FULL_MODULE_LIST),
        "depth": "standard",
        "deeper": False,
    },
    BAND_COMPLEX: {
        "requests_per_second": 10.0,
        "intensity": "high",
        "modules": list(FULL_MODULE_LIST),
        "depth": "deep",
        "deeper": True,
    },
    BAND_CRITICAL: {
        "requests_per_second": 15.0,
        "intensity": "high",
        "modules": list(FULL_MODULE_LIST),
        "depth": "aggressive",
        "deeper": True,
    },
}


class AdaptiveScanPlanner:
    """Pure-planning service: given a TCI result, produce an execution profile."""

    def plan(
        self,
        complexity_result: dict[str, Any],
        scan_request: ScanRequest,
        limits: SafetyLimits,
        tunings: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        tunings = tunings or {}
        band = str(complexity_result.get("band") or BAND_MEDIUM)
        profile = BAND_PROFILES.get(band, BAND_PROFILES[BAND_MEDIUM])
        rationale: list[str] = []
        excluded_reasons: dict[str, str] = {}

        explicit = list(scan_request.selected_tests)
        if explicit:
            modules = [str(module) for module in explicit]
            rationale.append(f"User explicitly selected {len(modules)} module(s); band defaults overridden")
        else:
            modules = list(profile["modules"])
            rationale.append(
                f"TCI band '{band}' (score {complexity_result.get('score')}) -> {len(modules)} module(s)"
            )

        if not explicit:
            for module, settings in tunings.items():
                if module not in modules:
                    continue
                action = str(settings.get("action") or "")
                fp_rate = settings.get("fp_rate")
                fp_pct = float(fp_rate) * 100 if isinstance(fp_rate, (int, float)) else None
                sample = max(1, int(settings.get("sample_count") or 1))
                if action == "disable":
                    modules.remove(module)
                    excluded_reasons[module] = "learning: module disabled (high false positive rate)"
                    rationale.append(f"Excluded '{module}' via applied learning insight")
                elif action == "reduce_priority":
                    rationale.append(
                        f"'{module}' deprioritized via learning (FP rate "
                        f"{fp_pct:.0f}% over {sample} finding(s))"
                    )

        excluded_modules = [module for module in profile["modules"] if module not in modules]
        for module in excluded_modules:
            excluded_reasons.setdefault(module, "not selected for this profile")

        requested_rate = float(profile["requests_per_second"])
        capped_rate = min(requested_rate, float(limits.max_requests_per_second))
        if capped_rate < requested_rate:
            rationale.append(
                f"Request rate capped to {capped_rate:g}/s by configured safety limit "
                f"(env max {limits.max_requests_per_second:g}/s)"
            )

        adjusted_limits = replace(limits, max_requests_per_second=capped_rate)
        if profile.get("deeper"):
            adjusted_limits = replace(
                adjusted_limits,
                max_total_requests=min(limits.max_total_requests * 2, 100_000),
                max_scan_duration=max(limits.max_scan_duration, 600),
            )
            rationale.append("Deep/aggressive profile: larger request budget and longer window")

        return {
            "band": band,
            "score": int(complexity_result.get("score") or 0),
            "requests_per_second": capped_rate,
            "intensity": profile["intensity"],
            "modules": modules,
            "excluded_modules": excluded_modules,
            "excluded_reasons": excluded_reasons,
            "depth": profile["depth"],
            "deeper": bool(profile["deeper"]),
            "limits": {
                "max_requests_per_second": adjusted_limits.max_requests_per_second,
                "max_total_requests": adjusted_limits.max_total_requests,
                "max_scan_duration": adjusted_limits.max_scan_duration,
                "max_concurrent_scans": adjusted_limits.max_concurrent_scans,
            },
            "rationale": rationale,
        }
