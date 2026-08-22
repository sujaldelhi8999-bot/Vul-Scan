from __future__ import annotations

from typing import Any

from app.ml.base import clamp, safe_float

PRIORITY_LABELS = ["P0-Emergency", "P1-Critical", "P2-High", "P3-Medium", "P4-Deferred"]

SEVERITY_BASE = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.55,
    "LOW": 0.3,
    "INFO": 0.1,
}

CONFIDENCE_BASE = {
    "CONFIRMED": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.55,
    "LOW": 0.3,
    "POTENTIAL": 0.2,
}

EXPLOITABLE_MODULES = {
    "sqli",
    "xss",
    "rce",
    "command_injection",
    "lfi",
    "rfi",
    "ssrf",
    "xxe",
    "deserialization",
    "ssti",
    "auth_bypass",
}

PRIORITY_BANDS = [
    (85, "P0-Emergency"),
    (70, "P1-Critical"),
    (50, "P2-High"),
    (30, "P3-Medium"),
    (0, "P4-Deferred"),
]

# Passive findings (missing security headers, missing cookie flags, ...) are
# hardening gaps, not exploitable vulnerabilities.  They default to LOW and
# only escalate when they affect an authenticated / PII-handling surface.
PASSIVE_FINDING_TYPES = frozenset(
    {
        "missing_header",
        "missing_csp",
        "missing_hsts",
        "missing_xfo",
        "missing_coep",
        "missing_coop",
        "missing_corp",
        "missing_xcto",
        "missing_referrer_policy",
        "missing_permissions_policy",
        "missing_oac",
        "cookie_missing_flag",
    }
)

# Active findings represent directly exploitable flaws; they keep HIGH/CRITICAL.
ACTIVE_FINDING_TYPES = frozenset(
    {"sql_injection", "xss", "rce", "lfi", "rfi", "ssrf", "xxe", "command_injection", "ssti"}
)


def calculate_severity(
    finding_type: str,
    evidence: dict[str, Any] | None = None,
    *,
    is_authenticated: bool = False,
    has_pii: bool = False,
) -> str:
    """Assign a severity label, downgrading passive hardening findings.

    Passive findings (missing headers, cookie flags) default to ``LOW`` —
    they are far too common to be reported as HIGH.  They only escalate to
    ``MEDIUM`` when they touch an authenticated or PII-handling surface, or
    when HSTS is missing from a login/auth URL.  Active exploitable findings
    keep ``HIGH`` (``CRITICAL`` for RCE).
    """
    finding_type = str(finding_type or "").lower()
    evidence = evidence or {}

    if finding_type in ACTIVE_FINDING_TYPES:
        return "CRITICAL" if finding_type == "rce" else "HIGH"

    if finding_type in PASSIVE_FINDING_TYPES:
        if is_authenticated or has_pii:
            return "MEDIUM"
        url = str(evidence.get("url") or "").lower()
        if finding_type == "missing_hsts" and ("login" in url or "auth" in url):
            return "MEDIUM"
        return "LOW"

    return "MEDIUM"


def score_to_priority(score: float) -> str:
    for band, label in PRIORITY_BANDS:
        if score >= band:
            return label
    return "P4-Deferred"


class RiskPrioritizer:
    """Ranks findings into P0-P4 priority tiers using a weighted risk model.

    Combines severity, confidence and real-world exploitability signals
    (CVE presence, CVSS score, public PoC likelihood, vulnerable module type)
    into a 0-100 priority score per finding.
    """

    def prioritize(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for finding in findings:
            score, priority, reason = self._score(finding)
            finding["priority_score"] = score
            finding["priority"] = priority
            finding["priority_reason"] = reason
        return sorted(findings, key=lambda f: f["priority_score"], reverse=True)

    def _score(self, finding: dict[str, Any]) -> tuple[float, str, str]:
        severity = str(finding.get("severity") or "INFO").upper()
        confidence = str(finding.get("confidence") or "MEDIUM").upper()
        cvss = safe_float(finding.get("cvss_score"))
        module = str(finding.get("module") or "").lower()
        has_cve = bool(finding.get("cve_id"))
        poc_likely = bool(finding.get("poc_likely"))

        severity_w = SEVERITY_BASE.get(severity, 0.3)
        confidence_w = CONFIDENCE_BASE.get(confidence, 0.4)
        exploitability = 0.0
        factors: list[str] = []

        if cvss > 0.0:
            exploitability += min(cvss, 10.0) / 10.0 * 0.5
            factors.append(f"CVSS {cvss}")
        if has_cve:
            exploitability += 0.15
            factors.append("known CVE")
        if poc_likely:
            exploitability += 0.15
            factors.append("public PoC likely")
        if module in EXPLOITABLE_MODULES:
            exploitability += 0.2
            factors.append(f"exploitable module ({module})")
        if severity in ("CRITICAL", "HIGH"):
            factors.append(f"{severity} severity")
        if confidence in ("CONFIRMED", "HIGH"):
            factors.append(f"{confidence} confidence")

        score = round(
            clamp(
                100.0 * (0.45 * severity_w + 0.2 * confidence_w + 0.35 * exploitability),
                0.0,
                100.0,
            ),
            2,
        )
        priority = score_to_priority(score)
        reason = ", ".join(factors[:5]) if factors else "baseline risk assessment"
        return score, priority, reason
