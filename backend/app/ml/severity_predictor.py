from __future__ import annotations

import logging
from typing import Any

from app.ml.base import ML_AVAILABLE, ModelRegistry, clamp, safe_float

logger = logging.getLogger("phantomscan.ml.severity")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

CATEGORY_BASE = {
    "RCE": 0.95,
    "Injection": 0.9,
    "SSRF": 0.8,
    "XSS": 0.75,
    "LFI": 0.75,
    "Authentication": 0.7,
    "CVE": 0.7,
    "Access Control": 0.65,
    "CORS": 0.55,
    "TLS": 0.5,
    "Information Disclosure": 0.45,
    "Security Headers": 0.4,
    "Cookies": 0.35,
    "HTTP Methods": 0.3,
    "CSRF": 0.6,
}

CONFIDENCE_ADJUST = {
    "CONFIRMED": 0.1,
    "HIGH": 0.05,
    "MEDIUM": 0.0,
    "LOW": -0.1,
    "POTENTIAL": -0.15,
}

SEVERITY_BANDS = [
    (0.85, "CRITICAL"),
    (0.7, "HIGH"),
    (0.45, "MEDIUM"),
    (0.25, "LOW"),
    (0.0, "INFO"),
]


def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0.0:
        return "LOW"
    return "INFO"


def score_to_severity(score: float) -> str:
    for band, label in SEVERITY_BANDS:
        if score >= band:
            return label
    return "INFO"


class SeverityPredictor:
    """Predicts finding severity from contextual features.

    Multinomial logistic regression when trained artifacts exist; otherwise a
    calibrated heuristic that blends CVSS, category risk and confidence.
    """

    MODEL_NAME = "severity_predictor"

    def __init__(self, *, use_ml: bool | None = None) -> None:
        from app.config import get_settings

        settings = get_settings()
        self.use_ml = settings.ml_enabled if use_ml is None else use_ml
        self._classifier: Any | None = None
        if self.use_ml and ML_AVAILABLE:
            self._classifier = ModelRegistry.get(self.MODEL_NAME)

    async def predict_severity(self, finding: dict[str, Any]) -> dict[str, Any]:
        if self._classifier is not None:
            try:
                features = self._extract_features(finding)
                proba = self._classifier.predict_proba([list(features.values())])[0]
                idx = int(proba.argmax())
                label = str(self._classifier.classes_[idx])
                return {
                    "severity": label,
                    "confidence": round(float(proba[idx]), 4),
                    "factors": self._factors(finding, features),
                    "backend": "ml",
                    "score": round(float(proba[idx]), 4),
                }
            except Exception as exc:
                logger.warning("Severity ML inference failed: %s", exc)
        return self._predict_heuristic(finding)

    def _predict_heuristic(self, finding: dict[str, Any]) -> dict[str, Any]:
        features = self._extract_features(finding)
        score = features["score"]
        severity = score_to_severity(score)
        return {
            "severity": severity,
            "confidence": round(clamp(0.5 + abs(score - 0.5)), 4),
            "factors": self._factors(finding, features),
            "backend": "heuristic",
            "score": round(score, 4),
        }

    def _extract_features(self, finding: dict[str, Any]) -> dict[str, float]:
        category = str(finding.get("category") or "")
        confidence = str(finding.get("confidence") or "MEDIUM").upper()
        cvss = safe_float(finding.get("cvss_score"))
        evidence = str(finding.get("evidence") or "")
        has_cve = 1.0 if finding.get("cve_id") else 0.0
        poc_likely = 1.0 if finding.get("poc_likely") else 0.0

        base = CATEGORY_BASE.get(category, 0.5)
        if cvss > 0.0:
            base = max(base, cvss / 10.0)

        score = clamp(
            base
            + CONFIDENCE_ADJUST.get(confidence, 0.0)
            + 0.05 * has_cve
            + 0.05 * poc_likely
            + (0.03 if len(evidence.strip()) >= 100 else 0.0)
        )
        return {
            "cvss_norm": clamp(cvss / 10.0),
            "category_base": base,
            "confidence_adj": CONFIDENCE_ADJUST.get(confidence, 0.0),
            "has_cve": has_cve,
            "poc_likely": poc_likely,
            "evidence_len": min(1.0, len(evidence.strip()) / 200.0),
            "score": score,
        }

    def _factors(
        self, finding: dict[str, Any], features: dict[str, float]
    ) -> list[str]:
        factors: list[str] = []
        cvss = safe_float(finding.get("cvss_score"))
        if cvss > 0.0:
            factors.append(f"CVSS {cvss} ({cvss_to_severity(cvss)})")
        if features["has_cve"]:
            factors.append("known CVE")
        if features["poc_likely"]:
            factors.append("public PoC likely")
        if features["category_base"] >= 0.8:
            factors.append("high-risk category")
        if features["confidence_adj"] >= 0.05:
            factors.append("confirmed/high confidence")
        if features["confidence_adj"] <= -0.1:
            factors.append("low confidence")
        if features["evidence_len"] >= 0.5:
            factors.append("detailed evidence")
        if not factors:
            factors.append("baseline category risk")
        return factors
