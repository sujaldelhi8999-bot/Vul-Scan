from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from app.ml.base import ML_AVAILABLE, ModelRegistry, clamp

logger = logging.getLogger("phantomscan.ml.fp")

SEVERITY_WEIGHT = {
    "CRITICAL": 1.0,
    "HIGH": 0.85,
    "MEDIUM": 0.6,
    "LOW": 0.35,
    "INFO": 0.15,
}

CONFIDENCE_WEIGHT = {
    "CONFIRMED": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.55,
    "LOW": 0.3,
    "POTENTIAL": 0.2,
}

HIGH_FP_CATEGORIES = {
    "Security Headers",
    "Cookies",
    "Information Disclosure",
    "HTTP Methods",
    "TLS",
    "CORS",
}

LOW_FP_CATEGORIES = {
    "Injection",
    "XSS",
    "RCE",
    "Authentication",
    "Access Control",
    "SSRF",
    "LFI",
    "XXE",
    "CSRF",
    "CVE",
}


class FalsePositiveFilter:
    """Scores findings as true/false positives with an explanatory reason.

    Uses a logistic-regression classifier when trained artifacts exist;
    otherwise a calibrated evidence heuristic. Decisions never silently drop
    findings — callers decide whether to filter based on the returned score.
    """

    MODEL_NAME = "false_positive_filter"

    def __init__(self, *, use_ml: bool | None = None) -> None:
        from app.config import get_settings

        settings = get_settings()
        self.use_ml = settings.ml_enabled if use_ml is None else use_ml
        self.threshold = settings.ml_fp_threshold
        self.baseline_404_hash: str | None = None
        self.baseline_404_length: int | None = None
        self._classifier: Any | None = None
        if self.use_ml and ML_AVAILABLE:
            self._classifier = ModelRegistry.get(self.MODEL_NAME)

    async def filter_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        features = self._extract_features(finding)
        if self._classifier is not None:
            try:
                proba = float(
                    self._classifier.predict_proba([list(features.values())])[0][1]
                )
                return self._decision(finding, features, proba, "ml")
            except Exception as exc:
                logger.warning("FP filter ML inference failed: %s", exc)
        return self._decision(
            finding, features, self._heuristic_score(features), "heuristic"
        )

    def _extract_features(self, finding: dict[str, Any]) -> dict[str, float]:
        severity = str(finding.get("severity") or "INFO").upper()
        confidence = str(finding.get("confidence") or "MEDIUM").upper()
        category = str(finding.get("category") or "")
        evidence = str(finding.get("evidence") or "")
        verification = str(finding.get("verification") or "")

        category_risk = (
            1.0
            if category in LOW_FP_CATEGORIES
            else (0.2 if category in HIGH_FP_CATEGORIES else 0.55)
        )

        return {
            "severity_weight": SEVERITY_WEIGHT.get(severity, 0.3),
            "confidence_weight": CONFIDENCE_WEIGHT.get(confidence, 0.4),
            "evidence_len": min(1.0, len(evidence.strip()) / 200.0),
            "has_cve": 1.0 if finding.get("cve_id") else 0.0,
            "has_cvss": 1.0 if finding.get("cvss_score") is not None else 0.0,
            "has_verification": 1.0 if verification.strip() else 0.0,
            "category_risk": category_risk,
            "poc_likely": 1.0 if finding.get("poc_likely") else 0.0,
            "corroboration": min(
                1.0, len(finding.get("corroborating_agents") or []) / 3.0
            ),
            "error_code": 1.0
            if any(code in evidence for code in ("500", "502", "400", "403"))
            else 0.0,
            "reflection": 1.0 if "reflect" in evidence.lower() else 0.0,
        }

    def _heuristic_score(self, features: dict[str, float]) -> float:
        return clamp(
            0.15
            + 0.4 * features["severity_weight"]
            + 0.2 * features["confidence_weight"]
            + 0.08 * features["category_risk"]
            + 0.08 * features["has_cve"]
            + 0.06 * features["has_cvss"]
            + 0.05 * features["has_verification"]
            + 0.04 * features["poc_likely"]
            + 0.03 * features["corroboration"]
            + 0.02 * features["error_code"]
            + 0.02 * features["reflection"]
            + 0.02 * features["evidence_len"]
        )

    def _decision(
        self,
        finding: dict[str, Any],
        features: dict[str, float],
        score: float,
        backend: str,
    ) -> dict[str, Any]:
        is_tp = score >= self.threshold
        if is_tp:
            reason = self._tp_reason(finding, features)
        else:
            reason = self._fp_reason(finding, features)
        return {
            "is_true_positive": is_tp,
            "confidence": round(clamp(score), 4),
            "reason": reason,
            "backend": backend,
            "features": {k: round(v, 4) for k, v in features.items()},
        }

    def _tp_reason(self, finding: dict[str, Any], features: dict[str, float]) -> str:
        signals: list[str] = []
        if features["has_cve"]:
            signals.append("known CVE")
        if features["has_cvss"]:
            signals.append("CVSS score present")
        if features["severity_weight"] >= 0.85:
            signals.append("critical/high severity")
        if features["confidence_weight"] >= 0.8:
            signals.append("confirmed/high confidence")
        if features["category_risk"] >= 0.9:
            signals.append("high-risk category")
        if features["reflection"]:
            signals.append("payload reflection evidence")
        if features["corroboration"] >= 0.66:
            signals.append("corroborated by multiple agents")
        return "Likely true positive: " + (
            ", ".join(signals) if signals else "evidence is consistent"
        )

    def _fp_reason(self, finding: dict[str, Any], features: dict[str, float]) -> str:
        signals: list[str] = []
        if features["severity_weight"] <= 0.35 and not features["has_cve"]:
            signals.append("low severity with no CVE")
        if features["confidence_weight"] <= 0.3:
            signals.append("low/potential confidence")
        if features["category_risk"] <= 0.2:
            signals.append("baseline hardening category")
        if not features["has_verification"]:
            signals.append("no verification steps")
        if features["evidence_len"] <= 0.1:
            signals.append("thin evidence")
        return "Likely false positive: " + (
            ", ".join(signals) if signals else "weak overall evidence"
        )

    # ------------------------------------------------------------------
    # Soft 404 detection
    #
    # Servers often return HTTP 200 with a branded "not found" page instead
    # of a real 404.  Blindly trusting the status code then produces
    # garbage findings (e.g. "missing security headers") for pages that do
    # not actually exist.  These helpers identify soft 404 responses so the
    # caller can discard their findings entirely.
    # ------------------------------------------------------------------

    ERROR_TITLE_KEYWORDS = (
        "404",
        "not found",
        "page doesn't exist",
        "page not found",
        "error",
        "missing",
        "gone",
        "no such",
    )

    SOFT_404_SHORT_PAGE_BYTES = 500

    def set_baseline(self, response: Any) -> None:
        """Establish the server's canonical 404 fingerprint.

        Call with the response to a request for a random non-existent path.
        Stores the content hash and length so later responses that match it
        (same page, dynamically generated URL) can be recognised as soft
        404s.
        """
        status = getattr(response, "status_code", None)
        if status not in (404, 410):
            return
        content = getattr(response, "content", b"")
        if content is None:
            content = b""
        self.baseline_404_hash = hashlib.md5(content).hexdigest()
        self.baseline_404_length = len(content)

    def is_soft_404(self, response: Any) -> bool:
        """Return True when ``response`` looks like a soft 404 page."""
        status = getattr(response, "status_code", None)

        # 1. Explicit status codes are conclusive.
        if status in (404, 410):
            return True
        if status != 200:
            return False

        content = getattr(response, "content", b"") or b""
        text = getattr(response, "text", "") or ""

        # 2. HTML <title> contains classic error keywords.
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL
        )
        if title_match:
            title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip().lower()
            if any(keyword in title for keyword in self.ERROR_TITLE_KEYWORDS):
                return True

        # 3. Body matches the established 404 baseline.
        if self.baseline_404_hash and hashlib.md5(content).hexdigest() == self.baseline_404_hash:
            return True
        if (
            self.baseline_404_length
            and abs(len(content) - self.baseline_404_length) < self.SOFT_404_SHORT_PAGE_BYTES
        ):
            return True

        # 4. Very short HTML pages are usually error placeholders.
        content_type = str(getattr(response, "headers", {}).get("content-type", "")).lower()
        if len(content) < self.SOFT_404_SHORT_PAGE_BYTES and "text/html" in content_type:
            return True

        return False
