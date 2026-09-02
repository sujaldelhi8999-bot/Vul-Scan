import asyncio
import json
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.database import get_connection
from app.services.openrouter_client import call_openrouter


class IntelligenceService:
    SENSITIVE_FILE_PATTERNS = [
        ".env", ".git", ".htaccess", "config.php", "wp-config.php",
        "backup.sql", "phpinfo.php", ".aws", "id_rsa", "credentials",
        "docker-compose.yml", "server-status", "web.config",
    ]

    def __init__(self, target_url: str, scan_id: Optional[int] = None, port_scan_depth: str = "standard") -> None:
        self.target_url = target_url
        self.scan_id = scan_id
        self.port_scan_depth = port_scan_depth
        self._resolved_scan_id: Optional[int] = None
        self._hostname: Optional[str] = None

    def _extract_hostname(self) -> str:
        parsed = urlparse(self.target_url)
        hostname = parsed.hostname
        if not hostname:
            hostname = self.target_url.replace("https://", "").replace("http://", "").split("/")[0]
        return hostname

    async def get_complete_intelligence(self) -> Dict[str, Any]:
        try:
            return await asyncio.wait_for(self._build_intelligence(), timeout=25.0)
        except asyncio.TimeoutError:
            return self._timeout_response()
        except Exception:
            return self._timeout_response()

    def _timeout_response(self) -> Dict[str, Any]:
        return {
            "target": {
                "url": self.target_url,
                "hostname": self._hostname or self._extract_hostname(),
                "ip": self._resolve_ip(),
                "timestamp": None,
            },
            "recon": {
                "dns": {"a_records": [], "aaaa_records": [], "mx_records": [], "txt_records": [],
                        "cname_records": [], "ns_records": [], "soa_records": [], "ptr_records": [],
                        "srv_records": [], "caa_records": [], "zone_transfer": None,
                        "wildcard": None, "dnssec": None},
                "ports": {"open": [], "closed": [], "filtered": [], "details": []},
                "technologies": {"frameworks": [], "servers": [], "waf": None, "cdn": None,
                                 "detailed": [], "waf_evidence": []},
                "headers": {},
                "tls": {"version": None, "cipher": None, "expiry": None, "valid": None,
                        "protocols": {}, "ciphers": [], "vulnerabilities": [], "port": None},
            },
            "exposed": {"robots_txt": None, "sitemap": [], "emails": [], "internal_ips": [],
                        "comments": [], "sensitive_files": {}, "js_source_maps": [],
                        "phones": [], "social_profiles": [], "discovered_files": []},
            "entry_points": {"url_parameters": [], "post_fields": [], "headers": [], "cookies": [],
                             "json_body": [], "websockets": [], "graphql_endpoints": [],
                             "api_endpoints": [], "file_uploads": []},
            "findings": {"critical": [], "high": [], "medium": [], "low": [], "info": []},
            "risk_score": {"score": 0, "level": "Timeout", "color": "gray"},
            "exploitation_roadmap": {"summary": "Request timed out - try again", "steps": [],
                                     "recommended_chain": []},
            "ai_analysis": {"attack_vector_summary": "Timed out while gathering intelligence. "
                            "Try a more specific target or check server load.",
                            "most_dangerous_entry": None, "recommended_next_steps": []},
        }

    async def _build_intelligence(self) -> Dict[str, Any]:
        self._hostname = self._extract_hostname()

        data: Dict[str, Any] = {
            "target": {
                "url": self.target_url,
                "hostname": self._hostname,
                "ip": self._resolve_ip(),
                "timestamp": None,
            },
            "recon": {
                "dns": {
                    "a_records": [],
                    "aaaa_records": [],
                    "mx_records": [],
                    "txt_records": [],
                    "cname_records": [],
                    "ns_records": [],
                    "soa_records": [],
                    "ptr_records": [],
                    "srv_records": [],
                    "caa_records": [],
                    "zone_transfer": None,
                    "wildcard": None,
                    "dnssec": None,
                },
                "ports": {"open": [], "closed": [], "filtered": [], "details": []},
                "technologies": {
                    "frameworks": [],
                    "servers": [],
                    "waf": None,
                    "cdn": None,
                    "detailed": [],
                    "waf_evidence": [],
                },
                "headers": {},
                "tls": {
                    "version": None,
                    "cipher": None,
                    "expiry": None,
                    "valid": None,
                    "protocols": {},
                    "ciphers": [],
                    "vulnerabilities": [],
                    "port": None,
                },
            },
            "exposed": {
                "robots_txt": None,
                "sitemap": [],
                "emails": [],
                "internal_ips": [],
                "comments": [],
                "sensitive_files": {},
                "js_source_maps": [],
                "phones": [],
                "social_profiles": [],
                "discovered_files": [],
            },
            "entry_points": {
                "url_parameters": [],
                "post_fields": [],
                "headers": [],
                "cookies": [],
                "json_body": [],
                "websockets": [],
                "graphql_endpoints": [],
                "api_endpoints": [],
                "file_uploads": [],
            },
            "findings": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": [],
            },
            "risk_score": {
                "score": 0,
                "level": "Unknown",
                "color": "gray",
            },
            "exploitation_roadmap": {
                "summary": None,
                "steps": [],
                "recommended_chain": [],
            },
            "ai_analysis": {
                "attack_vector_summary": None,
                "most_dangerous_entry": None,
                "recommended_next_steps": [],
            },
        }

        has_scan = await self._resolve_scan()
        if not has_scan:
            await self._run_lightweight_scan()
        await self._populate_recon_data(data)
        await self._populate_exposed_data(data)
        await self._populate_findings(data)
        await self._populate_entry_points(data)
        self._calculate_risk_score(data)
        await self._build_exploitation_roadmap(data)
        await self._generate_ai_summary(data)

        return data

    def _resolve_ip(self) -> Optional[str]:
        try:
            return socket.gethostbyname(self._hostname)
        except Exception:
            return None

    async def _resolve_scan(self) -> bool:
        from app.database import list_scans

        if self.scan_id:
            self._resolved_scan_id = self.scan_id
            return True

        scans = await list_scans()
        hostname = self._hostname or self._extract_hostname()

        for scan in scans:
            target = scan.get("target_url", "")
            if not target:
                continue
            if hostname in target or target.rstrip("/") == self.target_url.rstrip("/"):
                self._resolved_scan_id = scan["id"]
                return True

        return False

    async def _run_lightweight_scan(self) -> None:
        from app.database import create_scan, get_or_create_system_user, update_scan_status, add_audit_log
        from app.agents.scanner import ScannerAgent

        system_user_id = await get_or_create_system_user()
        scan_id = await create_scan(
            target_url=self.target_url,
            mode="recon",
            intensity="light",
            selected_tests="[]",
            user_id=system_user_id,
        )
        self._resolved_scan_id = scan_id
        await add_audit_log(scan_id, "System", "intelligence_scan", f"Triggered by intelligence for {self.target_url}")

        try:
            await update_scan_status(scan_id, "running")
            scanner = ScannerAgent()
            result = await scanner.run(self.target_url, scan_id)
            await update_scan_status(scan_id, "complete")
        except Exception as exc:
            await update_scan_status(scan_id, "error", str(exc)[:500])

    @staticmethod
    def _dict_get_ci(d: Dict[str, Any], key: str, default: Any = None) -> Any:
        for k, v in d.items():
            if k.lower() == key.lower():
                return v
        return default

    async def _enrich_recon_from_audit_logs(self, data: Dict[str, Any]) -> None:
        """Broader fallback: parse recon data from ALL audit logs, not just ReconAgent/ShadowReconAgent"""
        if not self._resolved_scan_id:
            return
        try:
            async with get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT agent_name, action, details, result FROM audit_logs WHERE scan_id = ? ORDER BY id DESC LIMIT 100",
                    (self._resolved_scan_id,),
                )
                rows = await cursor.fetchall()
                if not rows:
                    return

                all_text = ""
                for row in rows:
                    all_text += " " + (row["details"] or "") + " " + (row["result"] or "")

                if not data["recon"]["ports"]["open"]:
                    port_matches = re.findall(r'[Pp]ort[^\d]*(\d+)', all_text)
                    if port_matches:
                        data["recon"]["ports"]["open"] = sorted(set(int(p) for p in port_matches[:10]))

                if not data["recon"]["technologies"]["frameworks"]:
                    tech_patterns = [r'nginx', r'apache', r'iis', r'php', r'python', r'node', r'react', r'angular', r'vue', r'wordpress', r'django', r'laravel', r'rails', r'flask', r'tomcat', r'jetty', r'next\.js', r'nuxt', r'gatsby', r'express']
                    tech_matches = []
                    for pattern in tech_patterns:
                        if re.search(pattern, all_text, re.IGNORECASE):
                            tech_matches.append(pattern.lower().replace(r'\.', '.'))
                    if tech_matches:
                        data["recon"]["technologies"]["frameworks"] = sorted(set(tech_matches))

                if not data["recon"]["technologies"]["servers"]:
                    server_match = re.search(r'[Ss]erver[:\s=]+([a-zA-Z0-9/.\-_]+)', all_text)
                    if server_match:
                        data["recon"]["technologies"]["servers"] = [server_match.group(1)]

                if not data["recon"]["technologies"]["waf"]:
                    waf_patterns = ['cloudflare', 'modsecurity', 'aws.waf', 'akamai', 'imperva', 'f5', 'barracuda', 'sucuri']
                    for pattern in waf_patterns:
                        if re.search(pattern.replace('.', '\\.'), all_text, re.IGNORECASE):
                            data["recon"]["technologies"]["waf"] = pattern.replace('.', ' ').title()
                            break

                if not data["recon"]["technologies"]["cdn"]:
                    cdn_match = re.search(r'[Cc][Dd][Nn][:\s=]+([a-zA-Z0-9]+)', all_text)
                    if cdn_match:
                        data["recon"]["technologies"]["cdn"] = cdn_match.group(1).lower()

                if not data["exposed"]["emails"]:
                    email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', all_text)
                    if email_matches:
                        data["exposed"]["emails"] = sorted(set(email_matches[:10]))

                if not data["exposed"]["internal_ips"]:
                    ip_matches = re.findall(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', all_text)
                    if ip_matches:
                        data["exposed"]["internal_ips"] = sorted(set(ip_matches[:10]))

                sensitive_patterns = [r'\.git', r'\.env', r'config\.php', r'wp-config\.php', r'backup\.sql', r'\.htaccess', r'phpinfo\.php']
                for pattern in sensitive_patterns:
                    if re.search(pattern, all_text, re.IGNORECASE):
                        key = pattern.lstrip("\\.").replace("\\", "")
                        data["exposed"]["sensitive_files"][key] = True

                if not data["exposed"]["robots_txt"]:
                    for row in rows:
                        text = (row["details"] or "") + " " + (row["result"] or "")
                        if re.search(r'robots\.txt.*200|200.*robots\.txt|robots.*found', text, re.IGNORECASE):
                            data["exposed"]["robots_txt"] = "Found"
                            break

        except Exception:
            pass

    async def _populate_recon_data(self, data: Dict[str, Any]) -> None:
        artifacts = await self._load_artifacts()

        if not artifacts:
            artifacts = await self._load_recon_from_audit_logs()

        if not artifacts:
            await self._enrich_recon_from_audit_logs(data)
            return

        scanner = artifacts.get("scanner_output") or {}
        shadow = artifacts.get("shadow_recon_output") or {}

        dns_records = scanner.get("dns_records", {})
        if not isinstance(dns_records, dict):
            dns_records = {}
        data["recon"]["dns"]["a_records"] = self._dict_get_ci(dns_records, "A") or self._dict_get_ci(dns_records, "a") or []
        data["recon"]["dns"]["aaaa_records"] = self._dict_get_ci(dns_records, "AAAA") or self._dict_get_ci(dns_records, "aaaa") or []
        data["recon"]["dns"]["mx_records"] = self._dict_get_ci(dns_records, "MX") or self._dict_get_ci(dns_records, "mx") or []
        data["recon"]["dns"]["txt_records"] = self._dict_get_ci(dns_records, "TXT") or self._dict_get_ci(dns_records, "txt") or []
        data["recon"]["dns"]["cname_records"] = self._dict_get_ci(dns_records, "CNAME") or self._dict_get_ci(dns_records, "cname") or []
        data["recon"]["dns"]["ns_records"] = self._dict_get_ci(dns_records, "NS") or self._dict_get_ci(dns_records, "ns") or []
        for dns_key, out_key in (("SOA", "soa_records"), ("PTR", "ptr_records"),
                                 ("SRV", "srv_records"), ("CAA", "caa_records")):
            vals = self._dict_get_ci(dns_records, dns_key)
            if vals:
                data["recon"]["dns"][out_key] = vals if isinstance(vals, list) else [vals]
        data["recon"]["dns"]["zone_transfer"] = scanner.get("zone_transfer") or data["recon"]["dns"]["zone_transfer"]
        data["recon"]["dns"]["wildcard"] = scanner.get("wildcard")
        data["recon"]["dns"]["dnssec"] = scanner.get("dnssec")

        ports_details = (scanner.get("ports") or {}).get("details", [])
        data["recon"]["ports"]["open"] = scanner.get("open_ports", []) or [p["number"] for p in ports_details if isinstance(p, dict)]
        if ports_details:
            data["recon"]["ports"]["details"] = ports_details

        tech_stack = scanner.get("tech_stack", {})
        if isinstance(tech_stack, dict):
            raw_frameworks = self._dict_get_ci(tech_stack, "technologies") or self._dict_get_ci(tech_stack, "frameworks") or []
            data["recon"]["technologies"]["frameworks"] = raw_frameworks if isinstance(raw_frameworks, list) else [raw_frameworks]

            raw_servers = self._dict_get_ci(tech_stack, "server") or self._dict_get_ci(tech_stack, "servers") or []
            data["recon"]["technologies"]["servers"] = [raw_servers] if isinstance(raw_servers, str) else (raw_servers if isinstance(raw_servers, list) else [])

            data["recon"]["technologies"]["cdn"] = scanner.get("cdn_detected") or tech_stack.get("cdn")

        detailed = scanner.get("technologies_detailed", [])
        if detailed:
            data["recon"]["technologies"]["detailed"] = detailed
            for item in detailed:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "")
                version = str(item.get("version") or "")
                label = f"{name} {version}".strip()
                if label:
                    data["recon"]["technologies"]["frameworks"].append(label)

        data["recon"]["technologies"]["waf"] = scanner.get("waf_detected") or (tech_stack.get("waf") if isinstance(tech_stack, dict) else None)
        waf_details = scanner.get("waf_details") or {}
        if isinstance(waf_details, dict) and waf_details.get("evidence"):
            data["recon"]["technologies"]["waf_evidence"] = list(waf_details.get("evidence", {}).keys())

        whois = shadow.get("whois", {})
        if isinstance(whois, dict):
            data["target"]["ip"] = whois.get("ip") or data["target"]["ip"]

        headers = scanner.get("http_headers") or (tech_stack.get("headers") if isinstance(tech_stack, dict) else None)
        if isinstance(headers, dict):
            data["recon"]["headers"] = headers

        tls_info = scanner.get("tls_details") or scanner.get("tls_info", {})
        if isinstance(tls_info, dict):
            data["recon"]["tls"]["version"] = tls_info.get("negotiated_version") or tls_info.get("version")
            cipher_raw = tls_info.get("negotiated_cipher") or tls_info.get("cipher")
            data["recon"]["tls"]["cipher"] = cipher_raw
            data["recon"]["tls"]["port"] = tls_info.get("port")
            cert = tls_info.get("certificate") or {}
            if isinstance(cert, dict):
                data["recon"]["tls"]["expiry"] = cert.get("not_after") or cert.get("expiry")
                data["recon"]["tls"]["valid"] = cert.get("valid")
            data["recon"]["tls"]["protocols"] = tls_info.get("protocols", {})
            data["recon"]["tls"]["ciphers"] = tls_info.get("ciphers", [])
            data["recon"]["tls"]["vulnerabilities"] = tls_info.get("vulnerabilities", [])

        data["target"]["timestamp"] = artifacts.get("updated_at")

    async def _load_recon_from_audit_logs(self) -> Optional[Dict[str, Any]]:
        if not self._resolved_scan_id:
            return None
        try:
            async with get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT agent_name, details, result FROM audit_logs WHERE scan_id = ? "
                    "AND agent_name IN ('ReconAgent', 'ShadowReconAgent') ORDER BY id DESC LIMIT 50",
                    (self._resolved_scan_id,),
                )
                rows = await cursor.fetchall()
                if not rows:
                    return None
                scanner_out = {}
                shadow_out = {}
                for row in rows:
                    agent = row["agent_name"]
                    details = row["details"] or ""
                    result = row["result"] or ""
                    combined = details + " " + result

                    for blob in (details, result):
                        if not blob:
                            continue
                        try:
                            parsed = json.loads(blob)
                            if not isinstance(parsed, dict):
                                continue
                            if agent == "ReconAgent":
                                for key in ("open_ports", "dns_records", "tech_stack", "waf_detected",
                                            "http_headers", "tls_info", "tls_details", "ip", "cdn_detected",
                                            "ports", "technologies_detailed", "wildcard", "dnssec",
                                            "zone_transfer", "waf_details"):
                                    if key in parsed and not scanner_out.get(key):
                                        scanner_out[key] = parsed[key]
                            elif agent == "ShadowReconAgent":
                                for key in ("whois", "leaked_emails", "internal_ips", "sitemap_urls",
                                            "robots_txt", "html_comments", "comments", "js_sourcemaps",
                                            "exposed_files", "disallowed_paths", "phones",
                                            "social_profiles", "api_endpoints", "graphql_schema",
                                            "discovered_files"):
                                    if key in parsed and not shadow_out.get(key):
                                        shadow_out[key] = parsed[key]
                        except (json.JSONDecodeError, TypeError):
                            continue

                    port_matches = re.findall(r'open_port[s]?[:\s]+(\d+)', combined, re.IGNORECASE)
                    if not port_matches:
                        port_matches = re.findall(r'[Pp]ort[^\d]*(\d+)', combined)
                    if port_matches and "open_ports" not in scanner_out:
                        scanner_out["open_ports"] = sorted(set(int(p) for p in port_matches))

                    tech_matches = re.findall(
                        r'(nginx|apache\s*httpd|iis|php|python|node\.?js|react|angular|vue|'
                        r'wordpress|django|laravel|rails|express|flask|tomcat|jetty|next\.?js|nuxt|gatsby)',
                        combined, re.IGNORECASE
                    )
                    if tech_matches and "tech_stack" not in scanner_out:
                        scanner_out["tech_stack"] = {"technologies": sorted(set(t.lower() for t in tech_matches))}

                    server_match = re.search(r'[Ss]erver[:\s=]+([a-zA-Z0-9/.\-_]+)', combined)
                    if server_match and "tech_stack" not in scanner_out:
                        scanner_out.setdefault("tech_stack", {})["server"] = server_match.group(1)

                    waf_match = re.search(r'[Ww][Aa][Ff][:\s=]+([a-zA-Z0-9]+)', combined)
                    if waf_match and "waf_detected" not in scanner_out:
                        scanner_out["waf_detected"] = waf_match.group(1).lower()

                    cdn_match = re.search(r'[Cc][Dd][Nn][:\s=]+([a-zA-Z0-9]+)', combined)
                    if cdn_match and "cdn_detected" not in scanner_out:
                        scanner_out["cdn_detected"] = cdn_match.group(1).lower()

                    dns_A = re.findall(r'[Aa][-_\s]?[Rr]ecord[s]?[:\s]+([0-9.]+)', combined)
                    dns_AAAA = re.findall(r'[Aa][Aa][Aa][Aa][-_\s]?[Rr]ecord[s]?[:\s]+([0-9a-f:]+)', combined)
                    if (dns_A or dns_AAAA) and "dns_records" not in scanner_out:
                        dns_out = {}
                        if dns_A:
                            dns_out["A"] = dns_A[:10]
                        if dns_AAAA:
                            dns_out["AAAA"] = dns_AAAA[:5]
                        scanner_out["dns_records"] = dns_out

                    if agent == "ShadowReconAgent":
                        email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', combined)
                        if email_matches and "leaked_emails" not in shadow_out:
                            shadow_out["leaked_emails"] = list(set(email_matches))

                        ip_matches = re.findall(
                            r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|'
                            r'192\.168\.\d{1,3}\.\d{1,3})', combined
                        )
                        if ip_matches and "internal_ips" not in shadow_out:
                            shadow_out["internal_ips"] = list(set(ip_matches))

                        sensitive_patterns = [r'\.git', r'\.env', r'config\.php', r'wp-config\.php',
                                              r'backup\.sql', r'\.htaccess', r'phpinfo\.php']
                        found_sensitive = [p.lstrip("\\.").replace("\\", "") for p in sensitive_patterns
                                           if re.search(p, combined, re.IGNORECASE)]
                        if found_sensitive and "exposed_files" not in shadow_out:
                            shadow_out["exposed_files"] = [{"path": f, "status_code": 200} for f in found_sensitive]

                if scanner_out or shadow_out:
                    return {
                        "scanner_output": scanner_out,
                        "shadow_recon_output": shadow_out,
                        "updated_at": None,
                    }
                return None
        except Exception:
            return None

    async def _populate_exposed_data(self, data: Dict[str, Any]) -> None:
        artifacts = await self._load_artifacts()
        if not artifacts:
            artifacts = await self._load_recon_from_audit_logs()
        if not artifacts:
            await self._enrich_recon_from_audit_logs(data)
            return

        shadow = artifacts.get("shadow_recon_output") or {}

        robots = shadow.get("robots_txt", {})
        if isinstance(robots, dict):
            data["exposed"]["robots_txt"] = robots.get("body", "") if robots.get("body") else None
        elif isinstance(robots, str):
            data["exposed"]["robots_txt"] = robots or None

        data["exposed"]["sitemap"] = shadow.get("sitemap_urls", [])
        data["exposed"]["emails"] = shadow.get("leaked_emails", [])
        data["exposed"]["internal_ips"] = shadow.get("internal_ips", [])
        data["exposed"]["comments"] = shadow.get("html_comments") or shadow.get("comments") or []
        data["exposed"]["js_source_maps"] = shadow.get("js_sourcemaps", [])
        data["exposed"]["phones"] = shadow.get("phones", [])
        social_profiles = shadow.get("social_profiles", [])
        data["exposed"]["social_profiles"] = social_profiles
        data["exposed"]["discovered_files"] = shadow.get("discovered_files", [])

        exposed_files = shadow.get("exposed_files", [])
        known_keys = list(data["exposed"]["sensitive_files"].keys())
        for entry in exposed_files:
            if not isinstance(entry, dict):
                continue
            path = (entry.get("path") or "") + " " + (entry.get("url") or "")
            for key in known_keys:
                if key in path or key.rstrip("/") in path:
                    data["exposed"]["sensitive_files"][key] = entry.get("status_code")
            for pattern in self.SENSITIVE_FILE_PATTERNS:
                if pattern in path:
                    data["exposed"]["sensitive_files"][pattern] = entry.get("status_code")

        apis = shadow.get("api_endpoints", [])
        for api in apis:
            if isinstance(api, dict):
                ep = api.get("url") or api.get("endpoint") or api.get("path") or ""
                if ep and ep not in data["entry_points"]["api_endpoints"]:
                    data["entry_points"]["api_endpoints"].append(ep)
            elif isinstance(api, str) and api not in data["entry_points"]["api_endpoints"]:
                data["entry_points"]["api_endpoints"].append(api)

        graphql = shadow.get("graphql_schema") or {}
        if isinstance(graphql, dict) and graphql.get("enabled"):
            endpoint = graphql.get("endpoint") or "/graphql"
            if endpoint not in data["entry_points"]["graphql_endpoints"]:
                data["entry_points"]["graphql_endpoints"].append(endpoint)

    async def _populate_findings(self, data: Dict[str, Any]) -> None:
        from app.database import get_findings

        findings: List[Dict[str, Any]] = []

        if self._resolved_scan_id:
            findings = await get_findings(self._resolved_scan_id)

        if not findings and self._hostname:
            async with get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT * FROM findings WHERE target LIKE ? ORDER BY id ASC LIMIT 500",
                    (f"%{self._hostname}%",),
                )
                findings = [dict(row) for row in await cursor.fetchall()]

        deduped = self._dedupe_real_findings(findings)
        for finding in deduped:
            severity = (finding.get("severity") or "INFO").upper()
            normalized = {
                "id": finding.get("id"),
                "title": finding.get("title"),
                "description": finding.get("description") or "",
                "category": finding.get("category"),
                "severity": severity,
                "confidence": finding.get("confidence"),
                "target": finding.get("target"),
                "endpoint": finding.get("endpoint"),
                "evidence": finding.get("evidence", "")[:500],
                "impact": finding.get("impact", "")[:300],
                "parameter": finding.get("parameter"),
                "module": finding.get("module"),
                "cve_id": finding.get("cve_id"),
                "cvss_score": finding.get("cvss_score"),
                "recommended_fix": finding.get("recommended_fix"),
                "confidence_score": finding.get("confidence_score"),
                "confidence_label": finding.get("confidence_label"),
                "risk_status": finding.get("risk_status"),
                "reproduction_command": finding.get("reproduction_command"),
                "request_response_diff": finding.get("request_response_diff"),
                "verification_result": self._json_value(finding.get("verification_result")),
            }
            verification = normalized.get("verification_result") if isinstance(normalized.get("verification_result"), dict) else {}
            if verification.get("affected_urls"):
                normalized["affected_urls"] = verification.get("affected_urls")
            elif finding.get("_affected_urls"):
                normalized["affected_urls"] = finding.get("_affected_urls")
            severity_lower = severity.lower()
            if severity_lower in data["findings"]:
                data["findings"][severity_lower].append(normalized)
        for severity in data["findings"]:
            data["findings"][severity].sort(key=self._finding_priority, reverse=True)

    @staticmethod
    def _json_value(value: Any) -> Any:
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return value

    def _dedupe_real_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        by_signature: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            if self._is_false_positive_or_non_issue(finding):
                continue
            signature = self._evidence_signature(finding)
            current = by_signature.get(signature)
            if current is None or self._finding_priority(finding) > self._finding_priority(current):
                merged = dict(finding)
                merged["_affected_urls"] = self._affected_urls(current, finding) if current else self._affected_urls(None, finding)
                by_signature[signature] = merged
            elif current is not None:
                current["_affected_urls"] = self._affected_urls(current, finding)
        return list(by_signature.values())

    def _is_false_positive_or_non_issue(self, finding: Dict[str, Any]) -> bool:
        if str(finding.get("risk_status") or "ACTIVE").upper() == "FALSE_POSITIVE":
            return True
        if str(finding.get("remediation_status") or "").upper() == "RESOLVED":
            return True
        if str(finding.get("verification_status") or "").upper() == "FIX_VERIFIED":
            return True
        text = " ".join(str(finding.get(name) or "") for name in ("title", "category", "evidence", "request_response_diff", "verification_result")).lower()
        verification = self._json_value(finding.get("verification_result"))
        if "hsts" in text or "strict-transport-security" in text:
            if re.search(r"hsts (enabled|present|valid)|strict-transport-security: max-age=[1-9]", text):
                return True
        if "tls" in text or "https" in text:
            tls = verification.get("tls") if isinstance(verification, dict) and isinstance(verification.get("tls"), dict) else {}
            if (tls.get("supports_tls12") or tls.get("supports_tls13")) and tls.get("certificate_ok", True):
                return True
            if re.search(r"tls (1\.2|1\.3).*(works|ok|succeeded|supported)", text):
                return True
        return False

    def _evidence_signature(self, finding: Dict[str, Any]) -> str:
        endpoint = str(finding.get("endpoint") or finding.get("target") or self.target_url)
        host = urlparse(endpoint if endpoint.startswith(("http://", "https://")) else self.target_url).netloc.lower()
        verification = self._json_value(finding.get("verification_result"))
        if isinstance(verification, dict) and verification.get("evidence_signature"):
            evidence = str(verification["evidence_signature"])
        else:
            evidence = str(finding.get("parameter") or finding.get("cwe") or finding.get("title") or "").lower()
        module = str(finding.get("module") or finding.get("category") or "").lower()
        title = str(finding.get("title") or "").lower()
        header = ""
        header_match = re.search(r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|frame-protection)", title + " " + evidence)
        if header_match:
            header = header_match.group(1)
        return f"{module}|{host}|{header or title}|{evidence}"

    def _affected_urls(self, current: Dict[str, Any] | None, finding: Dict[str, Any]) -> List[str]:
        urls: List[str] = []
        for source in (current, finding):
            if not source:
                continue
            verification = self._json_value(source.get("verification_result"))
            if isinstance(verification, dict) and isinstance(verification.get("affected_urls"), list):
                urls.extend(str(item) for item in verification["affected_urls"] if item)
            if source.get("_affected_urls"):
                urls.extend(str(item) for item in source["_affected_urls"] if item)
            if source.get("endpoint"):
                urls.append(str(source["endpoint"]))
        return sorted(set(urls))

    @staticmethod
    def _finding_priority(finding: Dict[str, Any]) -> tuple[int, float, int]:
        severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        confidence_rank = {"CONFIRMED": 1.0, "HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3, "POTENTIAL": 0.2}
        severity = severity_rank.get(str(finding.get("severity") or "INFO").upper(), 0)
        try:
            confidence = float(finding.get("confidence_score"))
        except (TypeError, ValueError):
            confidence = confidence_rank.get(str(finding.get("confidence_label") or finding.get("confidence") or "LOW").upper(), 0.1)
        return (severity, confidence, int(finding.get("id") or 0))

    async def _populate_entry_points(self, data: Dict[str, Any]) -> None:
        seen_params: set = set()
        seen_endpoints: set = set()
        seen_cookies: set = set()
        seen_post_fields: set = set()

        for severity in data["findings"]:
            for finding in data["findings"][severity]:
                param = finding.get("parameter")
                if param and param not in seen_params:
                    seen_params.add(param)
                    data["entry_points"]["url_parameters"].append(param)

                endpoint = finding.get("endpoint") or ""
                if endpoint and endpoint not in seen_endpoints:
                    seen_endpoints.add(endpoint)
                    if "api" in endpoint.lower() or "graphql" in endpoint.lower() or "rest" in endpoint.lower():
                        data["entry_points"]["api_endpoints"].append(endpoint)
                        if "graphql" in endpoint.lower():
                            data["entry_points"]["graphql_endpoints"].append(endpoint)

                evidence = finding.get("evidence") or ""
                if evidence:
                    self._extract_from_text(evidence, seen_params, seen_endpoints, seen_post_fields, seen_cookies, data)

        await self._populate_entry_points_from_evidence(data, seen_params, seen_endpoints, seen_post_fields, seen_cookies)

        if not data["entry_points"]["url_parameters"]:
            parsed = urlparse(self.target_url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        name = param.split("=")[0]
                        data["entry_points"]["url_parameters"].append(name)

        data["entry_points"]["url_parameters"] = sorted(set(data["entry_points"]["url_parameters"]))
        data["entry_points"]["api_endpoints"] = sorted(set(data["entry_points"]["api_endpoints"]))
        data["entry_points"]["post_fields"] = sorted(set(data["entry_points"]["post_fields"]))
        data["entry_points"]["cookies"] = sorted(set(data["entry_points"]["cookies"]))

        artifacts = await self._load_artifacts()
        if artifacts:
            shadow = artifacts.get("shadow_recon_output") or {}
            disallowed = shadow.get("disallowed_paths", [])
            for path in disallowed:
                if path not in seen_endpoints:
                    data["entry_points"]["api_endpoints"].append(path)
            browser = artifacts.get("browser_security_output") or {}
            for api in browser.get("api_inventory", []):
                if isinstance(api, dict):
                    ep = api.get("endpoint") or ""
                    if ep and ep not in seen_endpoints:
                        seen_endpoints.add(ep)
                        data["entry_points"]["api_endpoints"].append(ep)

        if not data["entry_points"]["url_parameters"] and self._resolved_scan_id:
            async with get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT details, result FROM audit_logs WHERE scan_id = ? ORDER BY id DESC LIMIT 50",
                    (self._resolved_scan_id,),
                )
                rows = await cursor.fetchall()
                all_logs = " ".join((r["details"] or "") + " " + (r["result"] or "") for r in rows)
                if all_logs:
                    self._extract_from_text(all_logs, seen_params, seen_endpoints, seen_post_fields, seen_cookies, data)

    async def _populate_entry_points_from_evidence(
        self, data: Dict[str, Any],
        seen_params: set, seen_endpoints: set,
        seen_post_fields: set, seen_cookies: set,
    ) -> None:
        if not self._resolved_scan_id:
            return
        async with get_connection() as conn:
            cursor = await conn.execute(
                "SELECT request_url, method, evidence_summary FROM evidence_records WHERE scan_id = ? ORDER BY id DESC LIMIT 100",
                (self._resolved_scan_id,),
            )
            rows = await cursor.fetchall()
            for row in rows:
                url = row["request_url"] or ""
                evidence_text = row["evidence_summary"] or ""

                if "?" in url:
                    qs = url.split("?", 1)[1].split("#", 1)[0]
                    for pair in qs.split("&"):
                        if "=" in pair:
                            p = pair.split("=", 1)[0]
                            if p not in seen_params:
                                seen_params.add(p)
                                data["entry_points"]["url_parameters"].append(p)

                api_match = re.search(r"(https?://[^/]+(/[a-zA-Z0-9_/.\-]+))", url)
                if api_match:
                    path = api_match.group(2)
                    if path and path not in seen_endpoints:
                        seen_endpoints.add(path)
                        if any(t in path.lower() for t in ["api", "graphql", "rest"]):
                            data["entry_points"]["api_endpoints"].append(path)
                            if "graphql" in path.lower():
                                data["entry_points"]["graphql_endpoints"].append(path)

                self._extract_from_text(evidence_text, seen_params, seen_endpoints, seen_post_fields, seen_cookies, data)

    @staticmethod
    def _extract_from_text(
        text: str,
        seen_params: set, seen_endpoints: set,
        seen_post_fields: set, seen_cookies: set,
        data: Dict[str, Any],
    ) -> None:
        param_matches = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', text)
        for p in param_matches:
            if p not in seen_params:
                seen_params.add(p)
                data["entry_points"]["url_parameters"].append(p)

        api_matches = re.findall(r'(/api/[a-zA-Z0-9_/.\-]+)', text)
        for api in api_matches:
            if api not in seen_endpoints:
                seen_endpoints.add(api)
                data["entry_points"]["api_endpoints"].append(api)

        post_matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']', text)
        for f in post_matches:
            if f not in seen_post_fields:
                seen_post_fields.add(f)
                data["entry_points"]["post_fields"].append(f)

        cookie_matches = re.findall(r'(?:^|[\s;])([a-zA-Z_][a-zA-Z0-9_]*)=[^;]+', text)
        for c in cookie_matches:
            c = c.strip()
            if c and c not in seen_cookies:
                seen_cookies.add(c)
                data["entry_points"]["cookies"].append(c)

    def _calculate_risk_score(self, data: Dict[str, Any]) -> None:
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

        total_weighted = 0
        max_possible = 0

        for severity, items in data["findings"].items():
            w = weights.get(severity, 0)
            total_weighted += len(items) * w
            max_possible += len(items) * 10

        if max_possible > 0:
            score = int((total_weighted / max_possible) * 100)
        else:
            score = 0

        score = max(0, min(100, score))

        if score >= 70:
            level, color = "Critical", "red"
        elif score >= 50:
            level, color = "High", "orange"
        elif score >= 30:
            level, color = "Medium", "yellow"
        elif score >= 10:
            level, color = "Low", "blue"
        else:
            level, color = "Secure", "green"

        data["risk_score"] = {"score": score, "level": level, "color": color}

    async def _build_exploitation_roadmap(self, data: Dict[str, Any]) -> None:
        steps: List[str] = []
        categories_found: set = set()

        all_findings = []
        for severity in ("critical", "high", "medium", "low", "info"):
            all_findings.extend(data["findings"][severity])

        for f in all_findings:
            title = (f.get("title") or "").lower()
            category = (f.get("category") or "").lower()
            combined = f"{title} {category}"
            if re.search(r"cors|cross.?origin", combined):
                categories_found.add("CORS")
            if re.search(r"sql.?injection|sqli", combined):
                categories_found.add("SQLi")
            if re.search(r"cross.?site.?script|xss", combined):
                categories_found.add("XSS")
            if re.search(r"path.?traversal|lfi|directory.?traversal", combined):
                categories_found.add("LFI")
            if re.search(r"remote.?file.?include|rfi", combined):
                categories_found.add("RFI")
            if re.search(r"csrf|cross.?site.?request.?forgery", combined):
                categories_found.add("CSRF")
            if re.search(r"ssti|template.?injection", combined):
                categories_found.add("SSTI")
            if re.search(r"command.?injection|rce|remote.?code.?execution|code.?injection|os.?command", combined):
                categories_found.add("RCE")
            if re.search(r"ssrf|server.?side.?request.?forgery", combined):
                categories_found.add("SSRF")
            if re.search(r"idors|insecure.?direct.?object.?reference|idor", combined):
                categories_found.add("IDOR")
            if re.search(r"open.?redirect", combined):
                categories_found.add("OpenRedirect")
            if re.search(r"jwt|token", combined):
                categories_found.add("JWT")
            if re.search(r"race.?condition|race", combined):
                categories_found.add("RaceCondition")
            if re.search(r"no.?sql|nosql", combined):
                categories_found.add("NoSQLi")
            if re.search(r"xxe|xml.?external.?entity", combined):
                categories_found.add("XXE")
            if re.search(r"graphql|graphql.?introspection", combined):
                categories_found.add("GraphQL")
            if re.search(r"broken.?auth|broken.?authentication|auth.?bypass|password.?spray|credential.?stuffing|weak.?password", combined):
                categories_found.add("BrokenAuth")
            if re.search(r"rate.?limit|rate.?limiting|brute.?force|bruteforce", combined):
                categories_found.add("RateLimiting")
            if re.search(r"mass.?assignment|mass.?assignment", combined):
                categories_found.add("MassAssignment")
            if re.search(r"prototype.?pollution", combined):
                categories_found.add("PrototypePollution")
            if re.search(r"hpp|http.?parameter.?pollution", combined):
                categories_found.add("HPP")

        category_steps = {
            "RCE": ["Attempt command injection via input fields and URL parameters",
                    "Test file upload functionality with executable payloads",
                    "Check for unsafe deserialization endpoints"],
            "SQLi": ["Confirm SQL injection by extracting database version via payloads like ' AND 1=2 UNION SELECT @@version--",
                     "Map database schema using UNION-based extraction",
                     "Dump credential tables and look for password hashes"],
            "XSS": ["Validate stored XSS by injecting <script>alert(1)</script> into form fields",
                    "Confirm reflected XSS via URL parameters with onerror/onload handlers",
                    "Check DOM-based XSS sinks like innerHTML, document.write, eval"],
            "SSRF": ["Test SSRF by pointing internal services to http://169.254.169.254/latest/meta-data/",
                     "Use SSRF to probe internal ports and services",
                     "Chain SSRF with cloud metadata endpoints for credential extraction"],
            "LFI": ["Read /etc/passwd via path traversal: ../../../etc/passwd",
                    "Use PHP wrappers (php://filter) for source code disclosure",
                    "Escalate LFI to RCE via log poisoning or /proc/self/environ"],
            "RFI": ["Host a malicious script and inject via RFI parameter",
                    "Confirm outbound request from server to verify RFI"],
            "CSRF": ["Craft a stealth form that auto-submits to the target endpoint",
                     "Test if anti-CSRF tokens are absent or predictable",
                     "Demonstrate impact by performing a state-changing action via CSRF"],
            "SSTI": ["Inject {{7*7}} / #{7*7} / ${7*7} to detect template engine",
                     "Escalate SSTI to RCE using framework-specific payloads"],
            "CORS": ["Capture sensitive data via cross-origin read with arbitrary Origin header",
                     "Verify Access-Control-Allow-Credentials is not broadly enabled"],
            "IDOR": ["Enumerate sequential IDs in endpoints to access unauthorized resources",
                     "Attempt vertical privilege escalation via IDOR in admin endpoints"],
            "JWT": ["Attempt JWT alg:none attack and algorithm confusion",
                    "Check if JWT secret is weak or leaked in source code",
                    "Forge a valid JWT with elevated privileges"],
            "OpenRedirect": ["Craft phishing link using open redirect parameter",
                             "Chain open redirect with XSS or credential harvesting page"],
            "NoSQLi": ["Test MongoDB injection via JSON body payloads: {\"$ne\": null}",
                       "Extract data using NoSQL boolean-based blind injection"],
            "XXE": ["Read local files via external entity: <!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
                    "Use XXE for SSRF to internal systems"],
            "GraphQL": ["Run introspection query to dump full GraphQL schema",
                        "Test for batching attacks and deep query nesting (DoS)",
                        "Check for missing authorization on GraphQL mutations"],
            "BrokenAuth": ["Test for password reset token poisoning",
                           "Attempt credential stuffing with common credentials",
                           "Check session fixation and lack of MFA on sensitive actions"],
            "RateLimiting": ["Attempt credential brute force on login endpoint",
                             "Test OTP/2FA bypass via rapid-fire requests without rate limiting"],
            "MassAssignment": ["Try updating protected fields via extra JSON body parameters",
                               "Check for privilege escalation via mass assignment on user roles"],
            "PrototypePollution": ["Test __proto__ pollution via JSON body: {\"__proto__\": {\"isAdmin\": true}}"],
            "HPP": ["Test parameter pollution to bypass security controls or WAF rules"],
            "RaceCondition": ["Fire concurrent requests to exploit time-of-check/time-of-use in transactions",
                              "Test race conditions in coupon/points/like endpoints"],
        }

        crit_high = data["findings"]["critical"] + data["findings"]["high"]
        if crit_high:
            steps.append(f"Start with {len(crit_high)} critical/high severity vulnerabilities")
            for f in crit_high[:3]:
                cve = f" ({f.get('cve_id')})" if f.get("cve_id") else ""
                steps.append(f"Exploit {f.get('category', 'vulnerability')}: {f.get('title')}{cve} on {f.get('endpoint', 'target')}")

        for cat in sorted(categories_found):
            cat_steps = category_steps.get(cat, [])
            for s in cat_steps:
                steps.append(f"[{cat}] {s}")

        if data["entry_points"]["url_parameters"]:
            params = data["entry_points"]["url_parameters"][:5]
            steps.append(f"Test URL parameters with injection payloads: {', '.join(params)}")

        if data["entry_points"]["api_endpoints"]:
            apis = data["entry_points"]["api_endpoints"][:5]
            steps.append(f"Probe API endpoints for excessive data exposure: {', '.join(apis)}")

        exposed = [k for k, v in data["exposed"]["sensitive_files"].items() if v]
        if exposed:
            steps.append(f"Access exposed sensitive files: {', '.join(exposed)}")

        if data["exposed"]["emails"]:
            steps.append(f"Use leaked emails ({len(data['exposed']['emails'])}) for credential stuffing or phishing simulations")

        if not steps:
            steps.append("No obvious exploitation path. Run a full pentest scan with active modules.")

        steps.append("Review and document all findings for the security report.")

        data["exploitation_roadmap"]["steps"] = steps
        total_findings = sum(len(v) for v in data["findings"].values())
        data["exploitation_roadmap"]["summary"] = f"Found {total_findings} findings across {len([k for k, v in data['findings'].items() if v])} severity levels. {len(steps)} exploitation steps identified."
        data["exploitation_roadmap"]["recommended_chain"] = steps[:3]

    async def _generate_ai_summary(self, data: Dict[str, Any]) -> None:
        try:
            findings_summary = self._summarize_findings(data["findings"])
            entry_summary = self._summarize_entry_points(data["entry_points"])
            exposed_summary = self._summarize_exposed(data["exposed"])
            risk = data["risk_score"]

            prompt = (
                "You are an offensive security analyst. Based on the following recon data, "
                "generate a concise attack intelligence summary.\n\n"
                f"Target: {data['target']['url']}\n"
                f"Hostname: {data['target']['hostname']}\n"
                f"Risk Score: {risk['score']} ({risk['level']})\n"
                f"Findings: {findings_summary}\n"
                f"Entry Points: {entry_summary}\n"
                f"Exposed Assets: {exposed_summary}\n\n"
                "Respond in JSON format with exactly three keys:\n"
                '{"attack_vector_summary": "<2-3 sentence summary of the most likely attack vector>", '
                '"most_dangerous_entry": "<the single most dangerous entry point or vulnerability>", '
                '"recommended_next_steps": ["<step 1>", "<step 2>", "<step 3>"]}'
            )

            response = await call_openrouter(prompt, max_tokens=500, json_response=True)
            if response:
                parsed = json.loads(response)
                data["ai_analysis"]["attack_vector_summary"] = parsed.get("attack_vector_summary")
                data["ai_analysis"]["most_dangerous_entry"] = parsed.get("most_dangerous_entry")
                steps = parsed.get("recommended_next_steps")
                if isinstance(steps, list):
                    data["ai_analysis"]["recommended_next_steps"] = steps
                elif isinstance(steps, str):
                    data["ai_analysis"]["recommended_next_steps"] = [s.strip() for s in steps.replace("\n", ",").split(",") if s.strip()]
        except Exception:
            pass

        if not data["ai_analysis"]["attack_vector_summary"]:
            total = self._total_findings(data["findings"])
            entry_count = len(data["entry_points"]["url_parameters"]) + len(data["entry_points"]["api_endpoints"])
            risk = data["risk_score"]
            data["ai_analysis"]["attack_vector_summary"] = (
                f"Target {data['target']['hostname'] or data['target']['url']} has {total} findings "
                f"(Risk: {risk['level']} - {risk['score']}%) and {entry_count} entry points. "
                f"{'Review critical and high severity items first.' if total > 0 else 'No vulnerabilities detected.'}"
            )
            if data["findings"]["critical"]:
                data["ai_analysis"]["most_dangerous_entry"] = data["findings"]["critical"][0]["title"]
            elif data["findings"]["high"]:
                data["ai_analysis"]["most_dangerous_entry"] = data["findings"]["high"][0]["title"]
            elif data["entry_points"]["url_parameters"]:
                data["ai_analysis"]["most_dangerous_entry"] = f"URL parameters: {', '.join(data['entry_points']['url_parameters'][:3])}"
            elif data["entry_points"]["api_endpoints"]:
                data["ai_analysis"]["most_dangerous_entry"] = f"API endpoints: {', '.join(data['entry_points']['api_endpoints'][:3])}"
            else:
                data["ai_analysis"]["most_dangerous_entry"] = "No clear entry points identified."

            if not data["ai_analysis"]["recommended_next_steps"]:
                steps = []
                if data["findings"]["critical"]:
                    steps.append("Exploit critical vulnerabilities immediately")
                if data["findings"]["high"]:
                    steps.append("Exploit high-severity vulnerabilities")
                if data["findings"]["medium"]:
                    steps.append("Review medium-severity findings")
                if data["entry_points"]["url_parameters"]:
                    steps.append("Test all URL parameters for injection")
                if data["entry_points"]["api_endpoints"]:
                    steps.append("Probe API endpoints for data exposure")
                if not steps:
                    steps.append("Run a full authorized pentest scan")
                    steps.append("Check for exposed files and directories")
                data["ai_analysis"]["recommended_next_steps"] = steps

    async def _load_artifacts(self) -> Optional[Dict[str, Any]]:
        if not self._resolved_scan_id:
            return None
        from app.database import get_scan_artifacts
        return await get_scan_artifacts(self._resolved_scan_id)

    @staticmethod
    def _summarize_findings(findings: Dict[str, Any]) -> str:
        parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            items = findings.get(sev, [])
            if items:
                parts.append(f"{len(items)} {sev}")
        return ", ".join(parts) if parts else "0 findings"

    @staticmethod
    def _summarize_entry_points(entry_points: Dict[str, Any]) -> str:
        parts = []
        if entry_points.get("url_parameters"):
            parts.append(f"{len(entry_points['url_parameters'])} URL parameters")
        if entry_points.get("api_endpoints"):
            parts.append(f"{len(entry_points['api_endpoints'])} API endpoints")
        if entry_points.get("post_fields"):
            parts.append(f"{len(entry_points['post_fields'])} POST fields")
        return "; ".join(parts) if parts else "No entry points found"

    @staticmethod
    def _summarize_exposed(exposed: Dict[str, Any]) -> str:
        parts = []
        sensitive = [k for k, v in exposed.get("sensitive_files", {}).items() if v]
        if sensitive:
            parts.append(f"{len(sensitive)} sensitive files exposed")
        if exposed.get("emails"):
            parts.append(f"{len(exposed['emails'])} leaked emails")
        return "; ".join(parts) if parts else "No exposed assets found"

    @staticmethod
    def _total_findings(findings: Dict[str, Any]) -> int:
        return sum(len(v) for v in findings.values())
