import asyncio
import logging
import re
from typing import Any
from urllib.parse import quote_plus

import httpx
from packaging.version import Version

from app.agents import Agent
from app.config import get_settings

logger = logging.getLogger("phantomscan.cve_matcher")


JS_VULN_CHECK = {
    "jquery": {
        "min_fixed": Version("3.5.0"),
        "cve": "CVE-2020-11023",
        "pattern": r'jquery[\/\-\s]*(\d+\.\d+(?:\.\d+)?)',
        "cpe_vendor": "jquery",
        "cpe_product": "jquery",
    },
    "lodash": {
        "min_fixed": Version("4.17.21"),
        "cve": "CVE-2021-23337",
        "pattern": r'lodash[\/\-\s@v]*(\d+\.\d+(?:\.\d+)?)',
        "cpe_vendor": "lodash",
        "cpe_product": "lodash",
    },
    "moment": {
        "min_fixed": Version("2.29.4"),
        "cve": "CVE-2022-24785",
        "pattern": r'moment[\/\-\s@v]*(\d+\.\d+(?:\.\d+)?)',
        "cpe_vendor": "moment",
        "cpe_product": "moment",
    },
    "axios": {
        "min_fixed": Version("1.6.0"),
        "cve": "CVE-2023-45857",
        "pattern": r'axios[\/\-\s@v]*(\d+\.\d+(?:\.\d+)?)',
        "cpe_vendor": "axios",
        "cpe_product": "axios",
    },
    "vue": {
        "min_fixed": Version("2.7.16"),
        "cve": "CVE-2024-28184",
        "pattern": r'(?:vue|vue\.js)[\/\-\s@v]*(\d+\.\d+(?:\.\d+)?)',
        "cpe_vendor": "vuejs",
        "cpe_product": "vue.js",
    },
    "react-dom": {
        "min_fixed": Version("18.2.0"),
        "cve": "CVE-2023-44270",
        "pattern": r'react-dom[\/\-\s@v]*(\d+\.\d+(?:\.\d+)?)',
        "cpe_vendor": "facebook",
        "cpe_product": "react",
    },
}

KNOWN_CPE_MAPPINGS: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "php": ("php", "php"),
    "python": ("python", "python"),
    "python/3": ("python", "python"),
    "ruby": ("ruby-lang", "ruby"),
    "ruby on rails": ("ruby-lang", "rails"),
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "java": ("oracle", "java"),
    "tomcat": ("apache", "tomcat"),
    "mysql": ("mysql", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "docker": ("docker", "docker"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "express": ("expressjs", "express"),
    "django": ("djangoproject", "django"),
    "flask": ("palletsprojects", "flask"),
    "laravel": ("laravel", "laravel"),
    "spring": ("pivotal_software", "spring_framework"),
    "iis": ("microsoft", "internet_information_server"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
}

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM")


class CVEMatcherAgent(Agent):
    def __init__(self) -> None:
        super().__init__("CVE Matcher Agent")
        self.settings = get_settings()
        self.provider_errors: list[dict[str, Any]] = []

    async def run(
        self, tech_stack: dict[str, Any], scan_id: int
    ) -> dict[str, list[dict[str, Any]]]:
        self.scan_id = scan_id
        self.status = "active"
        self.provider_errors = []
        await self.log_action("started", "Matching CVEs")

        technologies = self._extract_technologies(tech_stack)
        matches: list[dict[str, Any]] = []

        lookup_timeout = self._nvd_timeout()
        tasks = [asyncio.wait_for(self._search_nvd(tech), timeout=lookup_timeout) for tech in technologies]
        nvd_results = await asyncio.gather(*tasks, return_exceptions=True)
        for technology, results in zip(technologies, nvd_results, strict=False):
            if isinstance(results, asyncio.TimeoutError):
                self.provider_errors.append({"provider": "NVD", "error_type": "DEPENDENCY_UNAVAILABLE", "technology": technology, "message": f"NVD lookup timed out after {lookup_timeout:g}s"})
                continue
            if isinstance(results, Exception):
                self.provider_errors.append({"provider": "NVD", "error_type": "INTERNAL_SCANNER_ERROR", "technology": technology, "message": str(results)[:300]})
                continue
            matches.extend(results)

        body = str(tech_stack.get("headers", {}))
        body += str(tech_stack.get("technologies", []))
        matches.extend(self._check_js_libs(body))

        for m in matches:
            score = m.get("cvss_score")
            try:
                m["poc_likely"] = bool(score is not None and float(score) >= 3.0)
            except (TypeError, ValueError):
                m["poc_likely"] = False

        matches = self._filter_version_applicable(matches)
        matches = await self._ml_validate_versions(matches)

        self.status = "complete"
        await self.log_action("completed", f"Matched {len(matches)} CVEs (after version filtering)")
        return {"cve_matches": matches, "provider_errors": self.provider_errors}

    async def _ml_validate_versions(self, matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            from app.ml.cve_validator import CVEVersionValidator

            validator = CVEVersionValidator()
            for match in matches:
                match["version_validation"] = await validator.validate_match(match)
        except Exception as exc:
            logger.debug("ML version validation failed: %s", exc)
        return matches

    def _filter_version_applicable(self, matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        filtered: list[dict[str, Any]] = []
        for m in matches:
            version_affected = m.get("version_affected")
            detected_version_str = m.get("affected_component", "")

            if not version_affected or not detected_version_str:
                filtered.append(m)
                continue

            detected_version = self._extract_version_from_component(detected_version_str)
            if detected_version is None:
                filtered.append(m)
                continue

            if self._is_version_in_range(detected_version, version_affected):
                filtered.append(m)
        return filtered

    def _extract_version_from_component(self, component: str) -> Version | None:
        match = re.search(r'(\d+\.\d+(?:\.\d+)*)', component)
        if match:
            try:
                return Version(match.group(1))
            except Exception as e:
                logger.debug("Error: %s", e)
                return None
        return None

    def _is_version_in_range(self, detected: Version, range_str: str) -> bool:
        range_str = range_str.strip()
        if not range_str:
            return True

        try:
            gt_match = re.search(r'>(\d+(?:\.\d+)*)', range_str)
            gte_match = re.search(r'>=(\d+(?:\.\d+)*)', range_str)
            lt_match = re.search(r'<(\d+(?:\.\d+)*)', range_str)
            lte_match = re.search(r'<=(\d+(?:\.\d+)*)', range_str)

            if gte_match:
                if detected < Version(gte_match.group(1)):
                    return False
            elif gt_match:
                if detected <= Version(gt_match.group(1)):
                    return False

            if lte_match:
                if detected > Version(lte_match.group(1)):
                    return False
            elif lt_match:
                if detected >= Version(lt_match.group(1)):
                    return False

            return True
        except Exception as e:
            logger.debug("Error: %s", e)
            return True

    def _extract_technologies(self, tech_stack: dict[str, Any]) -> list[str]:
        techs: set[str] = set()
        for val in tech_stack.get("technologies", []):
            if isinstance(val, str) and val.strip():
                techs.add(val.strip())
        for key in ("server", "x_powered_by"):
            v = tech_stack.get(key)
            if isinstance(v, str) and v.strip():
                techs.add(v.strip())
        framework = tech_stack.get("framework", "")
        if isinstance(framework, str) and framework.strip() and framework != "unknown":
            techs.add(framework.strip())
        return sorted(techs)

    async def _search_nvd(self, technology: str) -> list[dict[str, Any]]:
        if not self.settings.nvd_api_key:
            await self.log_action("skipped", "NVD_API_KEY not configured")
            return []

        cpe = self._build_cpe(technology)
        matches: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=self._nvd_timeout(), verify=False) as client:
            if cpe:
                # CPE-based search for known technologies
                for severity in SEVERITY_ORDER:
                    url = (
                        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                        f"?cpeName={quote_plus(cpe)}&cvssV3Severity={severity}"
                    )
                    try:
                        r = await client.get(url, headers={"apiKey": self.settings.nvd_api_key})
                        r.raise_for_status()
                    except httpx.HTTPStatusError as e:
                        status_code = e.response.status_code
                        self.provider_errors.append({"provider": "NVD", "error_type": "RATE_LIMITED" if status_code == 429 else "DEPENDENCY_UNAVAILABLE", "status_code": status_code, "technology": technology})
                        logger.debug("NVD error for %s: %s", technology, e)
                        if status_code in {429, 500, 502, 503, 504}:
                            break
                        continue
                    except (httpx.TimeoutException, httpx.HTTPError) as e:
                        self.provider_errors.append({"provider": "NVD", "error_type": "DEPENDENCY_UNAVAILABLE", "technology": technology, "message": str(e)[:200]})
                        logger.debug("NVD request error for %s: %s", technology, e)
                        continue

                    try:
                        data = r.json()
                    except ValueError as exc:
                        self.provider_errors.append({"provider": "NVD", "error_type": "MALFORMED_RESPONSE", "technology": technology})
                        logger.debug("Malformed NVD response for %s: %s", technology, exc)
                        continue
                    for item in data.get("vulnerabilities", [])[:5]:
                        try:
                            cve = item.get("cve", {})
                            cve_id = cve.get("id", "")
                            descs = cve.get("descriptions", [])
                            desc = next(
                                (e.get("value", "") for e in descs if e.get("lang") == "en"), ""
                            )
                            score = self._extract_cvss(cve.get("metrics", {}))
                            cwes = self._extract_cwe(cve)
                            vuln_configs = self._extract_vulnerable_configs(item)

                            version_match = self._match_version(vuln_configs, technology)

                            matches.append({
                                "cve_id": cve_id,
                                "cvss_score": score,
                                "severity": severity,
                                "affected_component": technology,
                                "description": desc[:300],
                                "cwe": cwes,
                                "version_affected": version_match,
                                "poc_likely": bool(score is not None and float(score) >= 3.0),
                            })
                        except Exception as exc:
                            self.provider_errors.append({"provider": "NVD", "error_type": "MALFORMED_RESPONSE", "technology": technology, "message": str(exc)[:200]})
            else:
                # Keyword-based search for unmapped technologies
                # Only search the technology name (not version) to avoid bad queries
                name_only = re.sub(r'[\s/\\-]*\d+\.\d+(?:\.\d+)*.*', '', technology.lower()).strip()
                name_only = re.sub(r"[^a-z0-9 ]", "", name_only).strip()
                if not name_only or len(name_only) < 3:
                    return []
                keyword = name_only.split()[0]  # Use first word only
                url = (
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?keywordSearch={quote_plus(keyword)}"
                )
                try:
                    r = await client.get(url, headers={"apiKey": self.settings.nvd_api_key})
                    r.raise_for_status()
                    data = r.json()
                    for item in data.get("vulnerabilities", [])[:3]:
                        cve = item.get("cve", {})
                        cve_id = cve.get("id", "")
                        descs = cve.get("descriptions", [])
                        desc = next(
                            (e.get("value", "") for e in descs if e.get("lang") == "en"), ""
                        )
                        score = self._extract_cvss(cve.get("metrics", {}))
                        cwes = self._extract_cwe(cve)

                        matches.append({
                            "cve_id": cve_id,
                            "cvss_score": score,
                            "severity": "MEDIUM",
                            "affected_component": technology,
                            "description": desc[:300],
                            "cwe": cwes,
                            "version_affected": None,
                            "poc_likely": bool(score is not None and float(score) >= 3.0),
                        })
                except httpx.HTTPStatusError as e:
                    status_code = e.response.status_code
                    self.provider_errors.append({"provider": "NVD", "error_type": "RATE_LIMITED" if status_code == 429 else "DEPENDENCY_UNAVAILABLE", "status_code": status_code, "technology": technology})
                    logger.debug("Keyword search error: %s", e)
                except (httpx.TimeoutException, httpx.HTTPError, ValueError) as e:
                    self.provider_errors.append({"provider": "NVD", "error_type": "DEPENDENCY_UNAVAILABLE", "technology": technology, "message": str(e)[:200]})
                    logger.debug("Keyword search error: %s", e)

        return matches

    def _nvd_timeout(self) -> float:
        try:
            timeout = float(getattr(self.settings, "nvd_lookup_timeout", 10.0))
        except (TypeError, ValueError):
            return 10.0
        return timeout if timeout > 0 else 10.0

    def _extract_cwe(self, cve: dict[str, Any]) -> list[str]:
        cwes: list[str] = []
        problem_types = cve.get("problemTypes", [])
        for pt in problem_types:
            descriptions = pt.get("description", [])
            for desc in descriptions:
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwes.append(value)
        return cwes

    def _extract_vulnerable_configs(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        configs = item.get("configurations", [])
        results: list[dict[str, Any]] = []
        for config in configs:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cm in cpe_matches:
                    if cm.get("vulnerable"):
                        results.append({
                            "cpe23Uri": cm.get("criteria", ""),
                            "versionStartIncluding": cm.get("versionStartIncluding"),
                            "versionStartExcluding": cm.get("versionStartExcluding"),
                            "versionEndIncluding": cm.get("versionEndIncluding"),
                            "versionEndExcluding": cm.get("versionEndExcluding"),
                        })
        return results

    def _match_version(
        self, vuln_configs: list[dict[str, Any]], technology: str
    ) -> str | None:
        if not vuln_configs:
            return None
        for vc in vuln_configs:
            start = vc.get("versionStartIncluding") or vc.get("versionStartExcluding")
            end = vc.get("versionEndIncluding") or vc.get("versionEndExcluding")
            if start or end:
                range_str = ""
                if start:
                    range_str += f">={start}" if vc.get("versionStartIncluding") else f">{start}"
                if end:
                    if range_str:
                        range_str += " and "
                    range_str += f"<={end}" if vc.get("versionEndIncluding") else f"<{end}"
                return range_str
        return None

    def _build_cpe(self, tech: str) -> str:
        t = tech.lower().strip()

        version_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', t)
        version = version_match.group(1) if version_match else "*"
        name_only = re.sub(r'[\s/\\-]*\d+\.\d+(?:\.\d+)*.*', '', t).strip()
        name_only = re.sub(r"[^a-z0-9._-]", "", name_only)

        if name_only in KNOWN_CPE_MAPPINGS:
            vendor, product = KNOWN_CPE_MAPPINGS[name_only]
            return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

        for key, (vendor, product) in KNOWN_CPE_MAPPINGS.items():
            if key in name_only or name_only in key:
                return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

        t_clean = re.sub(r"[^a-z0-9._-]", "", t)
        if not t_clean:
            return ""
        # Unknown technology - return empty to avoid 404s with invalid CPEs
        return ""

    def _extract_cvss(self, metrics: dict[str, Any]) -> float | None:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                s = data.get("baseScore")
                if s is not None:
                    try:
                        return float(s)
                    except (TypeError, ValueError):
                        return None
        return None

    def _check_js_libs(self, body: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        b = body.lower()
        for lib, info in JS_VULN_CHECK.items():
            if lib in b:
                pattern = info.get(
                    "pattern",
                    rf'{re.escape(lib)}[\/\-\s@v]*(\d+\.\d+(?:\.\d+)?)',
                )
                version_match = re.search(pattern, body, re.IGNORECASE)
                if version_match:
                    try:
                        found_v = Version(version_match.group(1))
                        if found_v < info["min_fixed"]:
                            vendor = info.get("cpe_vendor", lib)
                            product = info.get("cpe_product", lib)
                            matches.append({
                                "cve_id": info["cve"],
                                "cvss_score": 7.5,
                                "severity": "HIGH",
                                "affected_component": f"{lib} {found_v}",
                                "description": f"Known vulnerable {lib} version {found_v}. Upgrade to {info['min_fixed']}+",
                                "poc_likely": True,
                                "cwe": [],
                                "version_affected": f"<{info['min_fixed']}",
                                "cpe": f"cpe:2.3:a:{vendor}:{product}:{found_v}:*:*:*:*:*:*:*",
                            })
                    except Exception as e:
                        logger.debug("Error: %s", e)
                        pass
        return matches
