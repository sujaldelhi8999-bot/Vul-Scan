"""
Dependency Scanner - Scans package.json, requirements.txt, Pipfile for vulnerable packages.

Ported from VULSCAN. Integrates with OSV API (free, no rate limit) and NVD API
(rate-limited: 1 request per 6 seconds).
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("phantomscan.dependency_scanner")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_NVD_RATE_LIMIT_SECONDS = 6.0
_NVD_LAST_REQUEST_TIME = 0.0


@dataclass
class VulnerableDependency:
    package: str
    version: str
    ecosystem: str
    vulnerability_id: str
    severity: str = "unknown"
    cvss_score: float = 0.0
    summary: str = ""
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)
    source: str = "osv"


@dataclass
class DependencyScanResult:
    total_packages: int = 0
    vulnerable_count: int = 0
    findings: list[VulnerableDependency] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0


def _osv_query(package: str, version: str, ecosystem: str) -> list[dict]:
    payload = json.dumps({
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }).encode()
    req = Request(OSV_QUERY_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("vulns", [])
    except (URLError, HTTPError, OSError, json.JSONDecodeError):
        return []


def _nvd_query_single(cve_id: str) -> Optional[dict]:
    global _NVD_LAST_REQUEST_TIME
    elapsed = time.time() - _NVD_LAST_REQUEST_TIME
    if elapsed < _NVD_RATE_LIMIT_SECONDS:
        time.sleep(_NVD_RATE_LIMIT_SECONDS - elapsed)
    _NVD_LAST_REQUEST_TIME = time.time()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            return vulns[0].get("cve", {}) if vulns else None
    except (URLError, HTTPError, OSError, json.JSONDecodeError):
        return None


def _parse_cvss_from_nvd(cve_data: dict) -> tuple[float, str]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity_str = cvss_data.get("baseSeverity", "").lower()
            if severity_str:
                return score, severity_str
            if score >= 9.0:
                return score, "critical"
            elif score >= 7.0:
                return score, "high"
            elif score >= 4.0:
                return score, "medium"
            elif score > 0:
                return score, "low"
            return score, "unknown"
    return 0.0, "unknown"


def parse_package_json(content: str) -> list[tuple[str, str]]:
    deps = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version in data.get(section, {}).items():
                clean = re.sub(r"[\^~>=<*x]", "", version).strip()
                if not clean:
                    clean = "0.0.0"
                deps.append((name, clean))
    except (json.JSONDecodeError, TypeError):
        pass
    return deps


def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    deps = []
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([a-zA-Z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<|===)\s*([a-zA-Z0-9_.\-]+)", line)
        if match:
            deps.append((match.group(1), match.group(3)))
        else:
            match = re.match(r"^([a-zA-Z0-9_.\-]+)", line)
            if match:
                deps.append((match.group(1), "0.0.0"))
    return deps


def parse_pipfile(content: str) -> list[tuple[str, str]]:
    deps = []
    in_packages = False
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped in ("[packages]", "[dev-packages]"):
            in_packages = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_packages = False
            continue
        if in_packages and "=" in stripped:
            parts = stripped.split("=", 1)
            name = parts[0].strip().strip('"').strip("'")
            version = re.sub(r"[\^~>=<*]", "", parts[1].strip().strip('"').strip("'")).strip()
            if name and version:
                deps.append((name, version))
    return deps


class DependencyScanner:
    """Scans project dependencies for known vulnerabilities via OSV + NVD."""

    def __init__(self) -> None:
        self._nvd_cache: dict[str, dict] = {}

    def _get_nvd_data(self, cve_id: str) -> Optional[dict]:
        if cve_id in self._nvd_cache:
            return self._nvd_cache[cve_id]
        data = _nvd_query_single(cve_id)
        if data:
            self._nvd_cache[cve_id] = data
        return data

    def scan_file(self, file_path: str | Path) -> DependencyScanResult:
        path = Path(file_path)
        result = DependencyScanResult()
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError) as e:
            result.errors.append(f"Cannot read {path}: {e}")
            return result

        name = path.name.lower()
        if name == "package.json":
            deps = parse_package_json(content)
            ecosystem = "npm"
        elif name == "requirements.txt":
            deps = parse_requirements_txt(content)
            ecosystem = "PyPI"
        elif name == "pipfile":
            deps = parse_pipfile(content)
            ecosystem = "PyPI"
        else:
            result.errors.append(f"Unsupported dependency file: {name}")
            return result

        result.total_packages = len(deps)
        for pkg_name, pkg_version in deps:
            try:
                vulns = _osv_query(pkg_name, pkg_version, ecosystem)
                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary", "")
                    fixed_version = ""
                    for affected in vuln.get("affected", []):
                        for ranges in affected.get("ranges", []):
                            for event in ranges.get("events", []):
                                if "fixed" in event:
                                    fixed_version = event["fixed"]
                                    break
                    severity = vuln.get("database_specific", {}).get("severity", "unknown").lower()
                    cvss_score = 0.0
                    refs = [ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")]
                    aliases = vuln.get("aliases", [])
                    cve_ids = [a for a in aliases if a.startswith("CVE-")]

                    finding = VulnerableDependency(
                        package=pkg_name, version=pkg_version, ecosystem=ecosystem,
                        vulnerability_id=vuln_id, severity=severity, cvss_score=cvss_score,
                        summary=summary, fixed_version=fixed_version, references=refs[:5], source="osv",
                    )
                    result.findings.append(finding)

                    for cve_id in cve_ids[:1]:
                        nvd_data = self._get_nvd_data(cve_id)
                        if nvd_data:
                            score, sev = _parse_cvss_from_nvd(nvd_data)
                            if score > 0:
                                finding.cvss_score = score
                                finding.severity = sev
                                finding.source = "nvd"
            except Exception as e:
                result.errors.append(f"Error scanning {pkg_name}: {e}")

        result.vulnerable_count = len(result.findings)
        return result
