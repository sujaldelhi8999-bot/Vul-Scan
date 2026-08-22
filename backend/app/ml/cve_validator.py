from __future__ import annotations

import logging
import re
from typing import Any

from packaging.version import InvalidVersion, Version

logger = logging.getLogger("phantomscan.ml.cve")


class CVEVersionValidator:
    """Validates whether a detected version falls inside a CVE's affected range.

    Combines exact/range/wildcard version parsing with a confidence model so
    that NVD matches are only reported with a measured certainty instead of a
    binary yes/no.
    """

    async def validate(
        self, cve: dict[str, Any], detected_version: str | None
    ) -> dict[str, Any]:
        affected_range = str(cve.get("version_affected") or "").strip()
        cve_id = str(cve.get("cve_id") or "")

        if not detected_version:
            return {
                "is_vulnerable": True,
                "confidence": 0.5,
                "match_type": "unknown_version",
                "reason": "Detected version unknown; keeping match for manual review",
            }

        if not affected_range:
            return {
                "is_vulnerable": True,
                "confidence": 0.55,
                "match_type": "unconstrained",
                "reason": "CVE declares no version constraint",
            }

        try:
            detected = Version(detected_version)
        except InvalidVersion:
            return {
                "is_vulnerable": False,
                "confidence": 0.4,
                "match_type": "unparsable_version",
                "reason": f"Could not parse detected version '{detected_version}'",
            }

        ranges = self._split_ranges(affected_range)
        if not ranges:
            return {
                "is_vulnerable": True,
                "confidence": 0.6,
                "match_type": "unparsable_range",
                "reason": f"Could not parse affected range '{affected_range}'",
            }

        in_any = any(self._version_in_range(detected, r) for r in ranges)
        if in_any:
            confidence = self._confidence_for(detected, affected_range, cve_id)
            return {
                "is_vulnerable": True,
                "confidence": round(confidence, 4),
                "match_type": "range"
                if len(ranges) > 1 or " and " in affected_range
                else "exact",
                "reason": f"Version {detected} is within affected range {affected_range}",
            }

        return {
            "is_vulnerable": False,
            "confidence": round(0.9, 4),
            "match_type": "range",
            "reason": f"Version {detected} is NOT within affected range {affected_range}",
        }

    async def validate_match(self, match: dict[str, Any]) -> dict[str, Any]:
        affected = str(match.get("affected_component") or "")
        version = self._extract_version(affected)
        result = await self.validate(match, version)
        result["detected_version"] = version
        return result

    def _extract_version(self, component: str) -> str | None:
        match = re.search(r"(\d+\.\d+(?:\.\d+)*)", component)
        return match.group(1) if match else None

    def _split_ranges(self, range_str: str) -> list[str]:
        # Comparator sets joined by ``and`` or commas are conjunctive.  Only
        # explicit OR operators create separate alternatives.
        parts = re.split(r"\s*(?:\|\||\bor\b)\s*", range_str, flags=re.IGNORECASE)
        cleaned = [p.strip() for p in parts if p.strip()]
        if not cleaned and range_str.strip():
            cleaned = [range_str.strip()]
        return cleaned

    def _version_in_range(self, detected: Version, range_str: str) -> bool:
        range_str = range_str.strip()
        if not range_str or range_str in ("*", "all", "any"):
            return True
        try:
            wildcard = re.fullmatch(
                r"(\d+(?:\.\d+)*)\.(?:x|\*)", range_str, flags=re.IGNORECASE
            )
            if wildcard:
                prefix = tuple(int(part) for part in wildcard.group(1).split("."))
                return detected.release[: len(prefix)] == prefix

            constraints = re.findall(
                r"(>=|<=|>|<|=)\s*(\d+(?:\.\d+)*)", range_str
            )
            if not constraints:
                exact = re.fullmatch(r"\d+(?:\.\d+)*", range_str)
                return exact is None or detected == Version(exact.group(0))

            for operator, raw_version in constraints:
                bound = self._bound_version(
                    raw_version, upper_inclusive=operator == "<="
                )
                if operator == ">=" and detected < bound:
                    return False
                if operator == ">" and detected <= bound:
                    return False
                if operator == "<=" and detected > bound:
                    return False
                if operator == "<" and detected >= bound:
                    return False
                if operator == "=" and detected != bound:
                    return False
            return True
        except InvalidVersion:
            return True

    @staticmethod
    def _bound_version(raw_version: str, *, upper_inclusive: bool = False) -> Version:
        """Normalize abbreviated bounds without excluding patch releases."""
        parts = raw_version.split(".")
        if len(parts) < 3:
            fill = "999" if upper_inclusive else "0"
            parts.extend([fill] * (3 - len(parts)))
        return Version(".".join(parts))

    def _confidence_for(self, detected: Version, range_str: str, cve_id: str) -> float:
        lower = 0.6
        if cve_id.startswith("CVE-"):
            lower += 0.1
        if "*" in range_str or "any" in range_str.lower():
            return 0.65
        if " and " in range_str:
            return 0.95
        bounds = re.findall(r"[<>=]+(\d+(?:\.\d+)*)", range_str)
        if bounds:
            matches_exact_bound = any(Version(b) == detected for b in bounds)
            return 0.85 if not matches_exact_bound else 0.75
        return lower
