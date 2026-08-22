"""
Health Score Calculator - 6-category weighted health score (0-100).

Ported from VULSCAN. Categories: Security 35%, Code Quality 25%,
Architecture 15%, Performance 10%, Documentation 5%, DevOps 10%.
"""

from dataclasses import dataclass, field
from typing import Optional


CLASSIFICATIONS = [
    (90, "Excellent", "green"),
    (80, "Good", "blue"),
    (70, "Fair", "yellow"),
    (60, "Needs Attention", "orange"),
    (40, "Poor", "red"),
    (0, "Critical", "red"),
]

EXECUTIVE_SUMMARIES = {
    "Excellent": "Repository is production-ready with minimal risks.",
    "Good": "Repository is healthy with a few areas for improvement.",
    "Fair": "Repository is functional but contains technical debt.",
    "Needs Attention": "Repository has multiple issues affecting maintainability and security.",
    "Poor": "Repository requires significant improvements.",
    "Critical": "Repository is at high risk and needs immediate remediation.",
}


@dataclass
class CategoryBreakdown:
    name: str
    score: int
    weight: float
    weighted_score: float
    factors: list[str]


@dataclass
class HealthScoreResult:
    health_score: int
    classification: str
    color: str
    categories: list[CategoryBreakdown]
    top_factors: list[str]
    executive_summary: str
    previous_score: Optional[int] = None
    score_change: Optional[int] = None
    trend: Optional[str] = None


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


def _get_classification(score: int) -> tuple[str, str]:
    for threshold, label, color in CLASSIFICATIONS:
        if score >= threshold:
            return label, color
    return "Critical", "red"


def _calc_security_score(summary: dict) -> tuple[int, list[str]]:
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    info = summary.get("info", 0)
    total = summary.get("total_findings", 0)
    secrets = summary.get("secrets_found", 0)
    factors: list[str] = []

    if total == 0 and secrets == 0:
        return 100, ["No vulnerabilities found"]

    penalty = critical * 10 + high * 7 + medium * 4 + low * 1 + info * 0.5
    max_possible = max(total, 1) * 10
    risk_percent = (penalty / max_possible) * 100

    if secrets > 0:
        risk_percent += min(secrets * 5, 20)
        factors.append(f"{secrets} secret(s) exposed")

    score = _clamp(int(100 - risk_percent))

    if critical > 0:
        factors.insert(0, f"{critical} critical vulnerability(ies)")
    if high > 0:
        factors.insert(0, f"{high} high severity finding(s)")
    if 0 < medium <= 10:
        factors.append(f"{medium} medium severity finding(s)")
    if not factors:
        factors.append(f"{total} total findings")

    return score, factors


def _calc_code_quality_score(summary: dict, findings: list[dict]) -> tuple[int, list[str]]:
    factors: list[str] = []
    total = summary.get("total_findings", 0)
    lines_scanned = summary.get("lines_scanned", 0)

    cq_count = len([f for f in findings if f.get("category") in ("code_quality", "other")])

    if total == 0 and cq_count == 0:
        return 100, ["No code quality issues found"]

    if lines_scanned > 0:
        density = (cq_count / lines_scanned) * 1000
        score = _clamp(int(100 - density * 10))
    elif cq_count > 0:
        score = _clamp(100 - cq_count * 5)
    else:
        score = 80

    if total > 0 and lines_scanned > 0:
        general_density = (total / lines_scanned) * 1000
        score = _clamp(score - min(int(general_density * 2), 20))

    if cq_count > 0:
        factors.append(f"{cq_count} code quality issue(s)")
    if total > 50:
        factors.append(f"High total finding count ({total})")
    if lines_scanned > 0 and total / max(lines_scanned, 1) > 0.05:
        factors.append("High finding density per line")
    if not factors:
        factors.append("Good code quality indicators")

    return score, factors


def _calc_architecture_score(summary: dict, findings: list[dict]) -> tuple[int, list[str]]:
    factors: list[str] = []
    total = summary.get("total_findings", 0)

    arch_categories = {"authentication", "cryptography", "configuration", "dependencies"}
    arch_count = len([f for f in findings if f.get("category") in arch_categories])

    if total == 0 and arch_count == 0:
        return 100, ["No architectural issues found"]

    if total > 0:
        score = _clamp(int(100 - (arch_count / total) * 100))
    else:
        score = 100

    crypto_count = sum(1 for f in findings if f.get("category") == "cryptography")
    auth_count = sum(1 for f in findings if f.get("category") == "authentication")
    if crypto_count > 0:
        score = _clamp(score - crypto_count * 5)
        factors.append(f"{crypto_count} cryptographic weakness(es)")
    if auth_count > 0:
        score = _clamp(score - auth_count * 5)
        factors.append(f"{auth_count} authentication issue(s)")
    if arch_count > 0 and not factors:
        factors.append(f"{arch_count} architectural finding(s)")
    if summary.get("total_files", 0) > 0 and summary.get("scanned_files", 0) == 0:
        factors.append("No files were scannable")
    if not factors:
        factors.append("Good architectural foundation")

    return score, factors


def _calc_performance_score(summary: dict, findings: list[dict]) -> tuple[int, list[str]]:
    factors: list[str] = []
    duration = summary.get("scan_duration_seconds", 0)
    total = summary.get("total_findings", 0)
    lines_scanned = summary.get("lines_scanned", 0)

    if duration <= 10:
        score = 100
    elif duration <= 60:
        score = 90
    elif duration <= 180:
        score = 75
    elif duration <= 300:
        score = 60
    else:
        score = 40

    if lines_scanned > 10000 and total > 100:
        score = _clamp(score - 10)
        factors.append("Large codebase with many findings")

    perf_findings = [f for f in findings if any(
        kw in f.get("title", "").lower() for kw in ("performance", "dos", "complex", "bottleneck")
    )]
    if perf_findings:
        score = _clamp(score - len(perf_findings) * 5)
        factors.append(f"{len(perf_findings)} performance-related finding(s)")

    if duration > 180:
        factors.append(f"Scan took {duration:.0f}s (slow)")
    if not factors:
        factors.append("No performance concerns detected")

    return score, factors


def _calc_documentation_score(summary: dict, findings: list[dict]) -> tuple[int, list[str]]:
    factors: list[str] = []
    total = summary.get("total_findings", 0)
    lines_scanned = summary.get("lines_scanned", 0)

    doc_findings = [f for f in findings if any(
        kw in f.get("file_path", "").lower()
        for kw in ("readme", "changelog", "license", "docs/", "doc/", "contributing")
    )]

    score = 70
    if doc_findings:
        score = _clamp(score + 15)
        factors.append(f"{len(doc_findings)} documentation file(s) detected")
    else:
        factors.append("No documentation files detected in scan")

    if total == 0:
        score = 90
        factors = ["No issues found — likely well-maintained"]
    if total > 200:
        score = _clamp(score - 15)
        factors.append("High finding count suggests insufficient documentation")
    if lines_scanned > 5000 and not doc_findings:
        score = _clamp(score - 10)
        factors.append("Large codebase without detected documentation")
    if not factors:
        factors.append("Adequate documentation indicators")

    return _clamp(score), factors


def _calc_devops_score(summary: dict, findings: list[dict]) -> tuple[int, list[str]]:
    factors: list[str] = []
    total = summary.get("total_findings", 0)

    devops_categories = {"docker", "configuration", "dependencies"}
    devops_count = len([f for f in findings if f.get("category") in devops_categories])

    if total == 0 and devops_count == 0:
        return 100, ["No DevOps issues found"]

    score = 100
    docker_count = sum(1 for f in findings if f.get("category") == "docker")
    if docker_count > 0:
        score -= docker_count * 5
        factors.append(f"{docker_count} Docker configuration issue(s)")
    config_count = sum(1 for f in findings if f.get("category") == "configuration")
    if config_count > 0:
        score -= config_count * 3
        factors.append(f"{config_count} configuration issue(s)")
    dep_count = sum(1 for f in findings if f.get("category") == "dependencies")
    if dep_count > 0:
        score -= dep_count * 4
        factors.append(f"{dep_count} vulnerable dependency(ies)")
    cicd_files = [f for f in findings if any(
        kw in f.get("file_path", "").lower()
        for kw in (".github/workflows", "jenkinsfile", ".gitlab-ci", "dockerfile", "docker-compose", "makefile", "terraform")
    )]
    if cicd_files:
        score = _clamp(score + 5)
        factors.append(f"{len(cicd_files)} CI/CD or infrastructure file(s) detected")

    return _clamp(score), factors or ["No significant DevOps concerns"]


def calculate_health_score(
    summary: dict,
    findings: Optional[list[dict]] = None,
    previous_score: Optional[int] = None,
) -> HealthScoreResult:
    """Calculate 6-category health score from scan results."""
    findings = findings or []

    security_score, security_factors = _calc_security_score(summary)
    cq_score, cq_factors = _calc_code_quality_score(summary, findings)
    arch_score, arch_factors = _calc_architecture_score(summary, findings)
    perf_score, perf_factors = _calc_performance_score(summary, findings)
    doc_score, doc_factors = _calc_documentation_score(summary, findings)
    devops_score, devops_factors = _calc_devops_score(summary, findings)

    categories = [
        CategoryBreakdown("Security", security_score, 0.35, round(security_score * 0.35, 2), security_factors),
        CategoryBreakdown("Code Quality", cq_score, 0.25, round(cq_score * 0.25, 2), cq_factors),
        CategoryBreakdown("Architecture", arch_score, 0.15, round(arch_score * 0.15, 2), arch_factors),
        CategoryBreakdown("Performance", perf_score, 0.10, round(perf_score * 0.10, 2), perf_factors),
        CategoryBreakdown("Documentation", doc_score, 0.05, round(doc_score * 0.05, 2), doc_factors),
        CategoryBreakdown("DevOps", devops_score, 0.10, round(devops_score * 0.10, 2), devops_factors),
    ]

    raw_score = sum(cat.weighted_score for cat in categories)
    health_score = _clamp(round(raw_score))
    classification, color = _get_classification(health_score)

    all_factors = []
    for cat in categories:
        for factor in cat.factors:
            all_factors.append((factor, int(cat.weight * 100)))
    all_factors.sort(key=lambda x: x[1], reverse=True)

    score_change = None
    trend = None
    if previous_score is not None:
        score_change = health_score - previous_score
        trend = "improved" if score_change > 0 else ("declined" if score_change < 0 else "stable")

    return HealthScoreResult(
        health_score=health_score,
        classification=classification,
        color=color,
        categories=categories,
        top_factors=[f[0] for f in all_factors[:5]],
        executive_summary=EXECUTIVE_SUMMARIES.get(classification, ""),
        previous_score=previous_score,
        score_change=score_change,
        trend=trend,
    )
