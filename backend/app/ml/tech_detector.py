from __future__ import annotations

import re
from typing import Any

from app.ml.base import ML_AVAILABLE, ModelRegistry, clamp

SIGNATURE_TABLE: dict[str, list[tuple[str, str]]] = {
    "web_servers": [
        ("nginx", "server: nginx"),
        ("apache", "server: apache"),
        ("microsoft-iis", "server: microsoft-iis"),
        ("openresty", "server: openresty"),
        ("caddy", "server: caddy"),
        ("traefik", "server: traefik"),
        ("lighttpd", "server: lighttpd"),
        ("gunicorn", "server: gunicorn"),
        ("jetty", "server: jetty"),
        ("kestrel", "server: kestrel"),
        ("litespeed", "server: litespeed"),
        ("tomcat", "server: coyote"),
    ],
    "frameworks": [
        ("react", "react-dom"),
        ("react", "__REACT_DEVTOOLS_GLOBAL_HOOK__"),
        ("angular", "ng-version"),
        ("vue", "__VUE__"),
        ("nextjs", "__NEXT_DATA__"),
        ("nuxt", "__NUXT__"),
        ("gatsby", "__gatsby"),
        ("laravel", "laravel_session"),
        ("laravel", "powered by laravel"),
        ("django", "csrftoken"),
        ("flask", "werkzeug"),
        ("fastapi", "swagger-ui"),
        ("express", "x-powered-by: express"),
        ("symfony", "x-powered-by: symfony"),
        ("spring", "x-application-context"),
        ("aspnet", "__VIEWSTATE"),
    ],
    "cms": [
        ("wordpress", "wp-content"),
        ("wordpress", "wp-json"),
        ("joomla", "com_content"),
        ("drupal", "drupal.js"),
        ("magento", "skin/frontend"),
        ("ghost", "ghost_url"),
        ("typo3", "fe_typo_user"),
    ],
    "analytics": [
        ("google_analytics", "google-analytics"),
        ("facebook_pixel", "connect.facebook.net"),
        ("hotjar", "static.hotjar.com"),
        ("clarity", "clarity.ms"),
        ("posthog", "posthog"),
    ],
    "waf": [
        ("cloudflare", "cf-ray"),
        ("cloudflare", "__cf_bm"),
        ("akamai", "akamai"),
        ("sucuri", "x-sucuri-"),
        ("imperva", "incap_ses"),
        ("aws_waf", "awswaf"),
        ("f5", "bigip"),
        ("modsecurity", "mod_security"),
        ("barracuda", "barracuda"),
    ],
    "cdn": [
        ("cloudfront", "x-amz-cf-id"),
        ("fastly", "x-served-by"),
        ("akamai", "x-akamai-transformed"),
    ],
    "languages": [
        ("php", "x-powered-by: php"),
        ("python", "python/"),
        ("java", "server: coyote"),
        ("go", "golang"),
        ("ruby", "x-runtime"),
        ("nodejs", "x-powered-by: express"),
        ("csharp", "__VIEWSTATE"),
        ("rust", "server: actix"),
    ],
}

GENERIC_TECH = {"javascript", "python", "java", "linux", "windows"}

TECH_CATEGORIES = {tech for group in SIGNATURE_TABLE.values() for _, tech in group}


class TechnologyDetector:
    """Deep-learning-assisted technology fingerprinting.

    Uses a char n-gram TF-IDF classifier over headers+body when trained
    artifacts exist (``tech_vectorizer`` / ``tech_detector``); otherwise falls
    back to signature matching. Detections always carry a measured confidence.
    """

    MODEL_NAME = "tech_detector"
    VECTORIZER_NAME = "tech_vectorizer"

    def __init__(self, *, use_ml: bool | None = None) -> None:
        from app.config import get_settings

        settings = get_settings()
        self.use_ml = settings.ml_enabled if use_ml is None else use_ml
        self._vectorizer: Any | None = None
        self._classifier: Any | None = None
        if self.use_ml and ML_AVAILABLE:
            self._vectorizer = ModelRegistry.get(self.VECTORIZER_NAME)
            self._classifier = ModelRegistry.get(self.MODEL_NAME)

    @property
    def ml_ready(self) -> bool:
        return self._classifier is not None and self._vectorizer is not None

    async def detect(self, response: dict[str, Any]) -> list[dict[str, Any]]:
        headers = response.get("headers") or {}
        body = str(response.get("body") or "")[:20000]
        if self.ml_ready:
            try:
                return self._detect_ml(headers, body)
            except Exception:
                pass
        return self._signature_detect(headers, body)

    async def refine(
        self,
        detections: list[dict[str, Any]],
        headers: dict[str, Any],
        body: str,
    ) -> list[dict[str, Any]]:
        for detection in detections:
            ml_conf = self._ml_confidence(detection, headers, body)
            detection["ml_confidence"] = ml_conf
            base = float(detection.get("confidence") or 0.0) / 100.0
            merged = clamp((base + ml_conf) / 2.0) * 100.0
            detection["confidence"] = round(merged, 2)
        return detections

    def _detect_ml(self, headers: dict[str, Any], body: str) -> list[dict[str, Any]]:
        text = self._build_text(headers, body)
        features = self._vectorizer.transform([text[:8000]])
        proba = self._classifier.predict_proba(features)[0]
        labels = [str(label) for label in self._classifier.classes_]
        results: list[dict[str, Any]] = []
        for label, prob in zip(labels, proba):
            if float(prob) >= 0.6:
                results.append(
                    {
                        "technology": label,
                        "confidence": round(float(prob), 3),
                        "version": self._extract_version(text, label),
                        "backend": "ml",
                    }
                )
        return sorted(results, key=lambda r: r["confidence"], reverse=True)

    def _signature_detect(
        self, headers: dict[str, Any], body: str
    ) -> list[dict[str, Any]]:
        text = self._build_text(headers, body).lower()
        found: dict[str, tuple[int, list[str]]] = {}
        for category, signatures in SIGNATURE_TABLE.items():
            for tech, needle in signatures:
                if needle in text:
                    evidence = found.setdefault(tech, [0, []])
                    evidence[0] += 1
                    evidence[1].append(needle)
        results: list[dict[str, Any]] = []
        for tech, (count, evidence) in found.items():
            results.append(
                {
                    "technology": tech,
                    "confidence": round(clamp(0.4 + 0.2 * count), 3),
                    "version": self._extract_version(text, tech),
                    "evidence": evidence[:3],
                    "backend": "signature",
                }
            )
        return sorted(results, key=lambda r: r["confidence"], reverse=True)

    def _ml_confidence(
        self, detection: dict[str, Any], headers: dict[str, Any], body: str
    ) -> float:
        name = str(detection.get("name") or "").lower()
        evidence = detection.get("evidence") or []
        header_based = any("header" in str(e) for e in evidence)
        body_based = any("body" in str(e) for e in evidence)
        multi_source = bool(detection.get("multi_source"))

        score = 0.35
        score += 0.15 * min(3, len(evidence))
        if header_based:
            score += 0.2
        if body_based:
            score += 0.1
        if multi_source:
            score += 0.15
        if name in GENERIC_TECH:
            score -= 0.2
        return round(clamp(score), 3)

    def _build_text(self, headers: dict[str, Any], body: str) -> str:
        header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        return f"{header_text}\n{body}"

    def _extract_version(self, text: str, tech: str) -> str | None:
        patterns = {
            "nginx": r"nginx/([\d.]+)",
            "apache": r"Apache/([\d.]+)",
            "microsoft-iis": r"Microsoft-IIS/([\d.]+)",
            "openresty": r"openresty/([\d.]+)",
            "caddy": r"Caddy/([\d.]+)",
            "traefik": r"Traefik/([\d.]+)",
            "wordpress": r'content="WordPress ([\d.]+)"',
            "php": r"PHP/([\d.]+)",
            "python": r"Python/([\d.]+)",
            "gunicorn": r"gunicorn/([\d.]+)",
            "kestrel": r"Kestrel/([\d.]+)",
            "litespeed": r"LiteSpeed/([\d.]+)",
            "jetty": r"Jetty\(([\d.]+)",
        }
        pattern = patterns.get(tech)
        if not pattern:
            return None
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1) if match else None
