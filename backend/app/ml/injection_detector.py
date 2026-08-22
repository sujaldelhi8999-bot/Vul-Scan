from __future__ import annotations

import logging
import re
from typing import Any

from app.ml.base import ML_AVAILABLE, ModelRegistry, clamp, safe_float

logger = logging.getLogger("phantomscan.ml.injection")

SQL_KEYWORDS = [
    "select",
    "union",
    "or 1=1",
    "and 1=1",
    "sleep(",
    "benchmark(",
    "waitfor",
    "information_schema",
    "order by",
    "group by",
    "--",
    "/*",
    "*/",
    "' or '",
    "' and '",
    "0x",
    "char(",
    "concat(",
    "substring(",
    "updatexml",
    "extractvalue",
    "load_file",
    "into outfile",
    "pg_sleep",
    "dbms_pipe",
    "sysobjects",
    "xp_cmdshell",
    "into dumpfile",
    "having",
]

XSS_TOKENS = [
    "<script",
    "</script",
    "onerror",
    "onload",
    "onclick",
    "onmouseover",
    "javascript:",
    "alert(",
    "prompt(",
    "confirm(",
    "document.cookie",
    "<svg",
    "<img",
    "src=x",
    "&#x",
    "&#",
    "%3c",
    "%3e",
    "iframe",
    "srcdoc",
    "expression(",
    "vbscript",
    "data:text/html",
]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"incorrect syntax near",
    r"ora-\d{5}",
    r"postgresql.*error",
    r"sqlstate\[",
    r"microsoft ole db provider",
    r"mysql_num_rows",
    r"supplied argument is not a valid",
]

WEAK_SQL_INDICATORS = [
    "sql",
    "mysql",
    "postgres",
    "sqlite",
    "odbc",
    "database error",
    "syntax error",
]

XSS_REFLECTION_RE = re.compile(r"<script|alert\(|onerror=|javascript:|<svg", re.I)


class MLInjectionDetector:
    """ML classifier for SQLi/XSS detection with heuristic fallback.

    Uses char-level TF-IDF + RandomForest when trained artifacts exist
    (see ``app.ml.train_injection_detector``); otherwise falls back to a
    deterministic evidence scorer so detection always works.
    """

    MODEL_NAME = "injection_detector"
    VECTORIZER_NAME = "injection_vectorizer"

    def __init__(self, *, use_ml: bool | None = None) -> None:
        from app.config import get_settings

        settings = get_settings()
        self.use_ml = settings.ml_enabled if use_ml is None else use_ml
        self.threshold = settings.ml_injection_threshold
        self._vectorizer: Any | None = None
        self._classifier: Any | None = None
        self._load()

    def _load(self) -> None:
        if not self.use_ml or not ML_AVAILABLE:
            return
        vectorizer = ModelRegistry.get(self.VECTORIZER_NAME)
        classifier = ModelRegistry.get(self.MODEL_NAME)
        if (
            vectorizer is not None
            and callable(getattr(vectorizer, "transform", None))
            and classifier is not None
            and callable(getattr(classifier, "predict_proba", None))
            and hasattr(classifier, "classes_")
        ):
            self._vectorizer = vectorizer
            self._classifier = classifier

    @property
    def ml_ready(self) -> bool:
        return self._classifier is not None and self._vectorizer is not None

    async def predict(self, request_data: dict[str, Any]) -> dict[str, Any]:
        payload = str(request_data.get("payload") or "")
        body = str(request_data.get("response_body") or "")[:4000]
        status_code = safe_float(request_data.get("status_code"), 0)

        if self.ml_ready:
            try:
                return self._predict_ml(payload, body, status_code)
            except Exception as exc:
                logger.warning("ML inference failed, using heuristic fallback: %s", exc)

        return self._predict_heuristic(payload, body, status_code)

    def _predict_ml(
        self, payload: str, body: str, status_code: float
    ) -> dict[str, Any]:
        import numpy as np

        features = self._vectorizer.transform([payload[:500].lower()])
        proba = self._classifier.predict_proba(features)[0]
        classes = [int(c) for c in self._classifier.classes_]
        positive_idx = classes.index(1) if 1 in classes else int(np.argmax(proba))
        injection_prob = float(proba[positive_idx])
        injection_type = self._classify_type(payload, body)
        return {
            "is_injection": injection_prob >= self.threshold,
            "confidence": round(injection_prob, 4),
            "type": injection_type,
            "backend": "ml",
            "reason": self._build_reason(injection_type, injection_prob),
            "signals": {
                "model_proba": round(injection_prob, 4),
                "status_code": int(status_code),
            },
        }

    def _predict_heuristic(
        self, payload: str, body: str, status_code: float
    ) -> dict[str, Any]:
        pl = payload.lower()
        bl = body.lower()

        sqli_payload = sum(1 for kw in SQL_KEYWORDS if kw in pl)
        xss_payload = sum(1 for tok in XSS_TOKENS if tok in pl)
        sql_error_hits = sum(1 for pat in SQL_ERROR_PATTERNS if re.search(pat, bl))
        weak_sql_hits = sum(1 for ind in WEAK_SQL_INDICATORS if ind in bl)
        xss_reflected = bool(XSS_REFLECTION_RE.search(bl))
        error_changed = status_code in (400, 500, 501, 502)

        sqli_score = clamp(
            sqli_payload * 0.25
            + sql_error_hits * 0.35
            + weak_sql_hits * 0.08
            + (0.15 if error_changed else 0.0)
        )
        xss_score = clamp(xss_payload * 0.3 + (0.4 if xss_reflected else 0.0))

        if xss_score > sqli_score and xss_score >= 0.35:
            injection_type = "xss"
            confidence = xss_score
        elif sqli_score >= 0.35:
            injection_type = "sqli"
            confidence = sqli_score
        else:
            injection_type = "benign"
            confidence = max(sqli_score, xss_score)

        return {
            "is_injection": injection_type != "benign",
            "confidence": round(clamp(confidence), 4),
            "type": injection_type,
            "backend": "heuristic",
            "reason": self._build_reason(injection_type, confidence),
            "signals": {
                "sqli_score": round(sqli_score, 4),
                "xss_score": round(xss_score, 4),
                "sqli_payload_tokens": sqli_payload,
                "xss_payload_tokens": xss_payload,
                "sql_error_hits": sql_error_hits,
                "status_code": int(status_code),
            },
        }

    def _classify_type(self, payload: str, body: str) -> str:
        return self._predict_heuristic(payload, body, 0)["type"]

    def _build_reason(self, injection_type: str, confidence: float) -> str:
        if injection_type == "sqli":
            return f"SQL injection signals with confidence {confidence:.2f}"
        if injection_type == "xss":
            return f"XSS reflection/sink signals with confidence {confidence:.2f}"
        return f"No strong injection signals (score {confidence:.2f})"
