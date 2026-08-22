import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import whois

from app.agents import Agent

logger = logging.getLogger("phantomscan.shadow_recon")

DORK_QUERIES = [
    "site:{domain} ext:env OR ext:sql OR ext:log OR ext:bak",
    "site:{domain} inurl:admin OR inurl:login OR inurl:dashboard",
    'site:{domain} "index of /" OR "parent directory"',
    '"{domain}" filetype:pdf OR filetype:xlsx OR filetype:docx',
    'site:{domain} intitle:"phpinfo" OR intitle:"phpmyadmin"',
    'site:{domain} inurl:api OR inurl:rest OR inurl:graphql',
]

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
CRTSH_URL = "https://crt.sh/?q={domain}&output=json"

DIRECTORY_WORDLIST = [
    "/admin", "/login", "/signin", "/dashboard", "/home", "/index",
    "/api", "/v1", "/v2", "/v3", "/v4", "/api/v1", "/api/v2", "/api/v3",
    "/uploads", "/upload", "/files", "/file", "/assets", "/static",
    "/public", "/private", "/secret", "/internal", "/confidential",
    "/config", "/configuration", "/configs", "/setup", "/install",
    "/update", "/updates", "/backup", "/backups", "/temp", "/tmp",
    "/cache", "/logs", "/log", "/debug", "/test", "/tests", "/testing",
    "/dev", "/development", "/stage", "/staging", "/beta", "/alpha",
    "/prod", "/production", "/internal", "/intranet", "/portal",
    "/gateway", "/proxy", "/auth", "/authenticate", "/oauth", "/oauth2",
    "/sso", "/saml", "/graphql", "/graphiql", "/playground", "/explorer",
    "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api-docs", "/docs", "/documentation", "/doc", "/reference",
    "/openapi.json", "/openapi.yaml", "/redoc",
    "/health", "/healthz", "/ready", "/status", "/ping", "/heartbeat",
    "/metrics", "/prometheus", "/grafana", "/kibana", "/elasticsearch",
    "/redis", "/rabbitmq", "/kafka", "/zookeeper", "/memcached",
    "/jenkins", "/sonarqube", "/jira", "/confluence", "/bamboo",
    "/git", "/svn", "/hg", "/cvs", "/repo", "/repositories",
    "/.git", "/.git/", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.git/config", "/.svn", "/.hg", "/.cvs", "/.env", "/.env.local",
    "/.env.production", "/.env.staging", "/.env.development", "/.env.test",
    "/.env.backup", "/.env.example", "/.config", "/.aws", "/.azure",
    "/.gcp", "/.kube", "/.docker", "/.github", "/.gitlab", "/.bitbucket",
    "/.circleci", "/.travis", "/.jenkins", "/.dockerignore",
    "/composer.json", "/composer.lock", "/package.json", "/yarn.lock",
    "/package-lock.json", "/npm-shrinkwrap.json", "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock", "/poetry.lock",
    "/Cargo.toml", "/Cargo.lock", "/go.mod", "/go.sum", "/pubspec.yaml",
    "/.htaccess", "/.htpasswd", "/web.config", "/.well-known",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml",
    "/favicon.ico", "/apple-touch-icon.png", "/manifest.json",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/phpinfo.php", "/info.php", "/php.ini", "/.user.ini", "/info",
    "/wp-config.php", "/wp-config-sample.php", "/wp-login.php",
    "/xmlrpc.php", "/wp-json", "/wp-content", "/wp-includes", "/wp-admin",
    "/wp-cron.php", "/wp-settings.php", "/wp-blog-header.php",
    "/config.php", "/configuration.php", "/settings.php", "/config.php.bak",
    "/database.php", "/db.php", "/connection.php", "/db.sql", "/dump.sql",
    "/backup.sql", "/backup.zip", "/backup.tar.gz", "/backup.tar",
    "/data.sql", "/database.sql", "/schema.sql", "/users.sql",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/docker-compose.override.yml", "/k8s", "/kubernetes", "/helm",
    "/charts", "/terraform", "/ansible", "/chef", "/puppet",
    "/.vscode", "/.idea", "/.eclipse", "/.netbeans",
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/server-status", "/server-info", "/status.html", "/whm-server-status",
    "/cgi-bin", "/cgi-bin/", "/cgi-bin/test.cgi", "/phpmyadmin",
    "/pma", "/myadmin", "/mysql-admin", "/adminer", "/adminer.php",
    "/webmin", "/cpanel", "/plesk", "/user", "/user/login", "/register",
    "/signup", "/forgot-password", "/reset-password", "/password-reset",
    "/verify", "/verification", "/confirm", "/invite", "/referral",
    "/search", "/search.php", "/index.php", "/index.html", "/default.aspx",
    "/default.php", "/home.php", "/main.php", "/page.php", "/view.php",
    "/download", "/downloads", "/media", "/images", "/img", "/css",
    "/js", "/scripts", "/lib", "/libs", "/vendor", "/node_modules",
    "/src", "/source", "/build", "/dist", "/out", "/target", "/bin",
    "/war", "/classes", "/servlet", "/ws", "/wsdl", "/soap", "/rest",
    "/rest/v1", "/rest/v2", "/services", "/service", "/webapi",
    "/odata", "/entities", "/data", "/datasource", "/db2", "/mssql",
    "/oracle", "/sqlite", "/data.sqlite", "/test.php", "/test.html",
    "/debug.log", "/error.log", "/access.log", "/nginx.log", "/apache.log",
    "/syslog", "/messages", "/auth.log", "/tmp/", "/var", "/proc",
    "/server-status.php", "/shell", "/shell.php", "/cmd.php", "/exec.php",
    "/eval.php", "/upload.php", "/c99.php", "/r57.php",
    "/1.php", "/1.txt", "/a.php", "/x.php", "/hack.php",
    "/.well-known/security.txt", "/.well-known/acme-challenge",
    "/security.txt", "/humans.txt", "/ads.txt", "/app-ads.txt",
    "/license.txt", "/changelog.txt", "/CHANGELOG", "/README",
    "/README.md", "/LICENSE", "/COPYRIGHT", "/VERSION", "/release-notes",
    "/api/swagger.json", "/api/docs", "/api/openapi.json", "/api/graphql",
    "/api/health", "/api/status", "/api/users", "/api/admin",
    "/api/config", "/api/v1/docs", "/api/v1/health", "/graphql/console",
]

API_PATTERNS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/api/rest", "/api/rest/v1",
    "/service", "/services",
    "/webapi", "/webapi/v1",
    "/odata", "/odata/v1",
    "/graphql", "/graphiql", "/api/graphql",
    "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/docs", "/documentation", "/redoc", "/openapi.json",
    "/api/openapi.json", "/api/swagger.json", "/api/docs",
]

GRAPHQL_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { kind name }
  }
}
"""

PHONE_PATTERNS = [
    r"\b\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b",
    r"tel:\+?[\d\-()\s]+",
    r"\+?1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
    r"\+?91[-.\s]?\d{5}[-.\s]?\d{5}",
]

SOCIAL_PATTERNS = {
    "twitter": r"(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/[A-Za-z0-9_]{1,30}/?",
    "facebook": r"(?:https?://)?(?:www\.)?facebook\.com/[A-Za-z0-9._\-]{3,}/?",
    "linkedin": r"(?:https?://)?(?:www\.)?linkedin\.com/(?:company|in|school)/[A-Za-z0-9\-_%]{2,}/?",
    "instagram": r"(?:https?://)?(?:www\.)?instagram\.com/[A-Za-z0-9_.]{2,}/?",
    "youtube": r"(?:https?://)?(?:www\.)?youtube\.com/(?:@|c/|channel/|user/)[A-Za-z0-9_\-]{2,}/?",
    "github": r"(?:https?://)?(?:www\.)?github\.com/[A-Za-z0-9_-]{2,}/?",
    "telegram": r"(?:https?://)?t\.me/[A-Za-z0-9_]{3,}/?",
    "discord": r"(?:https?://)?discord\.(?:gg|com)/(?:invite/)?[A-Za-z0-9_\-]{2,}/?",
    "whatsapp": r"(?:https?://)?wa\.me/\d{6,15}",
    "medium": r"(?:https?://)?medium\.com/[@A-Za-z0-9._\-]{2,}/?",
    "reddit": r"(?:https?://)?(?:www\.)?reddit\.com/r/[A-Za-z0-9_]{2,}/?",
    "pinterest": r"(?:https?://)?(?:www\.)?pinterest\.com/[A-Za-z0-9_\-]{2,}/?",
    "tiktok": r"(?:https?://)?(?:www\.)?tiktok\.com/[@A-Za-z0-9._\-]{2,}/?",
    "snapchat": r"(?:https?://)?(?:www\.)?snapchat\.com/add/[A-Za-z0-9_\-]{2,}/?",
}


class ShadowReconAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Shadow Recon Agent")

    async def run(self, target_url: str, scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Shadow recon for {target_url}")

        domain = self._extract_domain(target_url)
        base = target_url if "://" in target_url else f"https://{target_url}"

        whois_data = await self._lookup_whois(domain)
        dork_urls = self._build_dorks(domain)
        robots = await self._fetch_path(base, "/robots.txt")
        sitemap = await self._fetch_path(base, "/sitemap.xml")
        wayback_urls = await self._fetch_wayback_urls(domain)
        crtsh_subdomains = await self._fetch_crtsh_subdomains(domain)

        disallowed = self._parse_robots(robots.get("body", ""))
        sitemap_urls = self._parse_sitemap(sitemap.get("body", ""))

        homepage = await self._fetch_path(base, "")
        body = homepage.get("body", "")
        leaked_emails = self._extract_emails(body)
        js_sourcemaps = self._extract_sourcemaps(body, base)
        internal_ips = self._extract_internal_ips(body)
        comments = self._extract_html_comments(body)
        phones = self._extract_phones(body)
        social_profiles = self._extract_social(body)

        extra_scan_paths = [p for p in disallowed if p not in DIRECTORY_WORDLIST and p.startswith("/")]
        try:
            async with asyncio.timeout(90.0):
                discovered_files = await self._brute_force_paths(base, DIRECTORY_WORDLIST + extra_scan_paths)
        except asyncio.TimeoutError:
            logger.warning("Path brute-force timed out after 90s, continuing with partial results")
            discovered_files = []

        fetched_bodies = 0
        for entry in discovered_files:
            if fetched_bodies >= 10:
                break
            if entry.get("status_code") != 200:
                continue
            content_type = entry.get("content_type", "")
            if not any(t in content_type for t in ("text/html", "text/plain", "application/json", "application/xml", "text/xml")):
                continue
            url = entry.get("url", "")
            if not url:
                continue
            body2 = await self._fetch_path(base, url.replace(base.rstrip("/"), ""))
            fetched_bodies += 1
            body_text = body2.get("body", "")
            leaked_emails.extend(self._extract_emails(body_text))
            internal_ips.extend(self._extract_internal_ips(body_text))
            phones.extend(self._extract_phones(body_text))
            social_profiles.extend(self._extract_social(body_text))
            comments.extend(self._extract_html_comments(body_text))

        exposed_files = [e for e in discovered_files if e.get("status_code") in (200, 301, 302)]

        try:
            async with asyncio.timeout(90.0):
                apis = await self._discover_apis(base, hint_bodies=[body, robots.get("body", ""), sitemap.get("body", "")])
        except asyncio.TimeoutError:
            logger.warning("API discovery timed out after 90s, continuing with partial results")
            apis = []
        graphql = await self._introspect_graphql(base)

        leaked_emails = list(dict.fromkeys(leaked_emails))
        internal_ips = list(dict.fromkeys(internal_ips))
        phones = list(dict.fromkeys(phones))
        social_seen: set[str] = set()
        social_unique: list[dict[str, Any]] = []
        for profile in social_profiles:
            key = profile.get("url", "")
            if key and key not in social_seen:
                social_seen.add(key)
                social_unique.append(profile)
        social_profiles = social_unique
        comments = list(dict.fromkeys(comments))

        all_subdomains = list(dict.fromkeys(
            [s["subdomain"] for s in crtsh_subdomains]
        ))

        self.discovered_emails = leaked_emails
        self.internal_ips = internal_ips
        self.js_source_maps = js_sourcemaps
        self.html_comments = comments
        self.sensitive_files_found = {f["path"]: True for f in exposed_files} if exposed_files else {}
        self.robots_txt_content = robots.get("body", "")
        self.sitemap_urls = [u["url"] for u in sitemap_urls] if sitemap_urls else []

        self.status = "complete"
        await self.log_action(
            "completed",
            f"WHOIS: {'yes' if whois_data else 'no'}, "
            f"Dorks: {len(dork_urls)}, "
            f"Disallowed: {len(disallowed)}, "
            f"Sitemap: {len(sitemap_urls)}, "
            f"Emails: {len(leaked_emails)}, "
            f"Phones: {len(phones)}, "
            f"Social: {len(social_profiles)}, "
            f"Sourcemaps: {len(js_sourcemaps)}, "
            f"Files: {len(discovered_files)}, "
            f"APIs: {len(apis)}, "
            f"GraphQL: {'enabled' if graphql else 'disabled'}, "
            f"Wayback URLs: {len(wayback_urls)}, "
            f"crt.sh Subdomains: {len(crtsh_subdomains)}"
        )

        result = {
            "whois": whois_data,
            "dork_urls": dork_urls,
            "disallowed_paths": disallowed,
            "sitemap_urls": sitemap_urls,
            "exposed_files": exposed_files,
            "discovered_files": discovered_files,
            "leaked_emails": leaked_emails,
            "js_sourcemaps": js_sourcemaps,
            "robots_txt": robots.get("body", "")[:2000],
            "sitemap_xml": sitemap.get("body", "")[:2000],
            "internal_ips": internal_ips,
            "html_comments": comments,
            "phones": phones,
            "social_profiles": social_profiles,
            "api_endpoints": apis,
            "graphql_schema": graphql,
            "wayback_urls": wayback_urls[:200],
            "crtsh_subdomains": crtsh_subdomains,
            "all_subdomains": all_subdomains,
        }

        await self._save_artifacts(result)
        await self.save_shadow_recon_results()

        return result

    async def _save_artifacts(self, result: dict[str, Any]) -> None:
        try:
            from app.database import set_scan_artifacts
            await set_scan_artifacts(self.scan_id, shadow_recon_output=result)
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save shadow recon artifacts: {exc}")

    async def save_shadow_recon_results(self) -> None:
        try:
            from app.database import get_connection
            async with get_connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO shadow_recon_results (
                        scan_id, emails, internal_ips, js_source_maps,
                        html_comments, sensitive_files, robots_txt_content, sitemap_urls,
                        wayback_urls, crtsh_subdomains, all_subdomains
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        emails = excluded.emails,
                        internal_ips = excluded.internal_ips,
                        js_source_maps = excluded.js_source_maps,
                        html_comments = excluded.html_comments,
                        sensitive_files = excluded.sensitive_files,
                        robots_txt_content = excluded.robots_txt_content,
                        sitemap_urls = excluded.sitemap_urls,
                        wayback_urls = excluded.wayback_urls,
                        crtsh_subdomains = excluded.crtsh_subdomains,
                        all_subdomains = excluded.all_subdomains
                    """,
                    (
                        self.scan_id,
                        json.dumps(self.discovered_emails or []) if hasattr(self, 'discovered_emails') else None,
                        json.dumps(self.internal_ips or []) if hasattr(self, 'internal_ips') else None,
                        json.dumps(self.js_source_maps or []) if hasattr(self, 'js_source_maps') else None,
                        json.dumps(self.html_comments or []) if hasattr(self, 'html_comments') else None,
                        json.dumps(self.sensitive_files_found or {}) if hasattr(self, 'sensitive_files_found') else None,
                        self.robots_txt_content if hasattr(self, 'robots_txt_content') else None,
                        json.dumps(self.sitemap_urls or []) if hasattr(self, 'sitemap_urls') else None,
                        json.dumps(self.wayback_urls or []) if hasattr(self, 'wayback_urls') else None,
                        json.dumps(self.crtsh_subdomains or []) if hasattr(self, 'crtsh_subdomains') else None,
                        json.dumps(self.all_subdomains or []) if hasattr(self, 'all_subdomains') else None,
                    ),
                )
                await conn.commit()
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save shadow recon results: {exc}")

    def _extract_domain(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        return parsed.hostname or target_url

    async def _lookup_whois(self, domain: str) -> dict[str, Any]:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, domain, quiet=True),
                timeout=12,
            )
            data = {}
            for k, v in dict(result).items():
                if v is not None:
                    data[k] = str(v)
            return {
                "registrar": data.get("registrar", ""),
                "creation_date": str(data.get("creation_date", "")),
                "expiration_date": str(data.get("expiration_date", "")),
                "name_servers": data.get("name_servers", ""),
                "registrant_org": data.get("org", "") or data.get("name", ""),
                "raw": {k: v for k, v in data.items() if k in ("dnssec", "status", "emails", "country")},
            }
        except Exception as exc:
            logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
            return {}

    def _build_dorks(self, domain: str) -> list[str]:
        return [q.format(domain=domain) for q in DORK_QUERIES]

    async def _fetch_path(self, base: str, path: str) -> dict[str, Any]:
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as c:
            try:
                r = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                return {"url": url, "status_code": r.status_code, "body": r.text[:50000]}
            except Exception as e:
                logger.debug("Failed to fetch %s: %s", url, e)
                return {"url": url, "status_code": None, "body": ""}

    async def _fetch_wayback_urls(self, domain: str) -> list[dict[str, Any]]:
        urls: list[dict[str, Any]] = []
        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "limit": "500",
                "filter": "statuscode:200",
                "collapse": "urlkey",
            }
            async with httpx.AsyncClient(timeout=15.0) as c:
                r = await c.get(WAYBACK_CDX_URL, params=params)
                r.raise_for_status()
                data = r.json()
                for row in data[1:] if len(data) > 1 else []:
                    if len(row) >= 4:
                        urls.append({
                            "url": row[1],
                            "timestamp": row[0],
                            "status_code": int(row[2]) if row[2].isdigit() else None,
                            "mime_type": row[3] if len(row) > 3 else None,
                            "source": "wayback",
                        })
        except Exception as e:
            logger.debug("Wayback Machine lookup failed for %s: %s", domain, e)
        return urls

    async def _fetch_crtsh_subdomains(self, domain: str) -> list[dict[str, Any]]:
        subdomains: list[dict[str, Any]] = []
        url = CRTSH_URL.format(domain=domain)
        last_exc: Exception | None = None
        # crt.sh is prone to transient 503s — retry with exponential backoff
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
                    r = await c.get(url)
                    if r.status_code in (429, 503):
                        raise httpx.HTTPStatusError(
                            f"crt.sh returned {r.status_code}",
                            request=r.request,
                            response=r,
                        )
                    r.raise_for_status()
                    data = r.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        if name_value:
                            for sub in name_value.split("\n"):
                                sub = sub.strip().lower()
                                if sub and sub.endswith(f".{domain}") and sub not in subdomains:
                                    subdomains.append({
                                        "subdomain": sub,
                                        "not_before": entry.get("not_before"),
                                        "not_after": entry.get("not_after"),
                                        "source": "crt.sh",
                                    })
                    return subdomains
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    await asyncio.sleep(1.5 * (attempt + 1))
        logger.debug("crt.sh lookup failed for %s: %s", domain, last_exc)
        return subdomains

    def _parse_robots(self, body: str) -> list[str]:
        paths: list[str] = []
        for line in body.split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    paths.append(path)
        return paths

    def _parse_sitemap(self, body: str) -> list[dict[str, Any]]:
        urls: list[dict[str, Any]] = []
        for match in re.finditer(r"<loc>(.*?)</loc>", body, re.IGNORECASE):
            loc = match.group(1).strip()
            is_https = loc.startswith("https://")
            urls.append({"url": loc, "https": is_https})
        return urls

    def _extract_emails(self, body: str) -> list[str]:
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
        return list(set(emails))

    def _extract_phones(self, body: str) -> list[str]:
        phones: list[str] = []
        for pattern in PHONE_PATTERNS:
            for match in re.finditer(pattern, body):
                candidate = match.group(0)
                digits = re.sub(r"\D", "", candidate)
                if 7 <= len(digits) <= 15:
                    cleaned = re.sub(r"^(?:\+?\d{1,3}[-.\s]?)?0*", "", candidate)
                    if cleaned and cleaned not in phones and re.search(r"\d{3}", cleaned):
                        phones.append(cleaned[:30])
        return phones

    def _extract_social(self, body: str) -> list[str]:
        profiles: list[str] = []
        for network, pattern in SOCIAL_PATTERNS.items():
            for match in re.finditer(pattern, body, re.IGNORECASE):
                url = match.group(0).rstrip("/")
                if not url.startswith("http"):
                    url = "https://" + url
                profiles.append({"network": network, "url": url[:200]})
        return profiles

    def _extract_sourcemaps(self, body: str, base: str) -> list[str]:
        maps: list[str] = []
        for m in re.finditer(r'sourceMappingURL=([^\s"\'<>]+)', body, re.IGNORECASE):
            url = m.group(1).strip()
            if not url.startswith("http"):
                url = urljoin(base + "/", url)
            maps.append(url)
        for m in re.finditer(r'//# sourceMappingURL=([^\s"\']+)', body):
            url = m.group(1).strip()
            if not url.startswith("http"):
                url = urljoin(base + "/", url)
            maps.append(url)
        return list(set(maps))

    def _extract_internal_ips(self, body: str) -> list[str]:
        ips = re.findall(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", body)
        return list(set(ips))

    def _extract_html_comments(self, body: str) -> list[str]:
        return re.findall(r"<!--(.*?)-->", body, re.DOTALL)

    async def _brute_force_paths(self, base: str, paths: list[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(12)
        base_url = base.rstrip("/")

        async def check(path: str) -> None:
            async with sem:
                url = urljoin(base_url + "/", path.lstrip("/"))
                try:
                    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, verify=False) as c:
                        r = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                        if r.status_code == 404 or r.status_code == 405:
                            return
                        headers = {k.lower(): v for k, v in r.headers.items()}
                        results.append({
                            "path": path,
                            "url": url,
                            "status_code": r.status_code,
                            "content_type": headers.get("content-type", ""),
                            "size": len(r.content),
                            "redirect": headers.get("location"),
                            "server": headers.get("server"),
                            "last_modified": headers.get("last-modified"),
                            "snippet": r.text[:200] if r.status_code in (200, 403) else "",
                        })
                except Exception as e:
                    logger.debug("Brute force check failed for %s: %s", url, e)

        chunk_size = 60
        for i in range(0, len(paths), chunk_size):
            chunk = paths[i:i + chunk_size]
            await asyncio.gather(*[check(p) for p in chunk], return_exceptions=True)

        results.sort(key=lambda e: e["status_code"])
        return results

    async def _discover_apis(self, base: str, hint_bodies: list[str] | None = None) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        base_url = base.rstrip("/")
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else base_url

        patterns: list[str] = list(API_PATTERNS)
        hint_urls: list[str] = []
        for body_text in hint_bodies or []:
            for match in re.finditer(
                r"[\"']((?:/?[A-Za-z0-9_\-./]*)?(?:api|rest|service|graphql|openapi|swagger|docs)[A-Za-z0-9_\-/.]*)[\"']",
                body_text,
                re.IGNORECASE,
            ):
                candidate = match.group(1).strip()
                if candidate.startswith("/") and len(candidate) > 1 and candidate not in hint_urls and len(hint_urls) < 30:
                    hint_urls.append(candidate)
        seen: set[str] = set()

        async def check(url: str, endpoint_label: str) -> None:
            if url in seen:
                return
            seen.add(url)
            try:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, verify=False) as c:
                    r = await c.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                    if r.status_code == 404:
                        return
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    schema = None
                    if any(t in endpoint_label for t in ("swagger", "openapi", "api-docs", "redoc")):
                        schema = self._extract_schema(r, headers.get("content-type", ""))
                    found.append({
                        "endpoint": endpoint_label,
                        "url": url,
                        "method": "GET",
                        "status": r.status_code,
                        "content_type": headers.get("content-type", ""),
                        "allow": headers.get("allow", ""),
                        "schema": schema,
                    })
            except Exception as e:
                logger.debug("API discovery check failed for %s: %s", url, e)

        tasks = []
        for pattern in patterns:
            tasks.append(check(base_url + pattern, pattern))
        for candidate in hint_urls:
            tasks.append(check(origin + candidate, candidate))
        await asyncio.gather(*tasks, return_exceptions=True)

        if any(a["status"] < 400 for a in found):
            try:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, verify=False) as c:
                    r = await c.options(base_url + "/api", headers={"User-Agent": "PhantomScan/1.0"})
                    allow = r.headers.get("allow", "")
                    if allow and r.status_code != 404:
                        for entry in found:
                            if entry["endpoint"] == "/api":
                                entry["allow"] = allow
                                break
            except Exception as e:
                logger.debug("OPTIONS request failed for %s/api: %s", base_url, e)

        return sorted(found, key=lambda e: e["status"])

    def _extract_schema(self, response: httpx.Response, content_type: str) -> dict[str, Any] | None:
        if "json" not in content_type:
            return None
        try:
            data = response.json()
            if not isinstance(data, dict):
                return None
            summary: dict[str, Any] = {}
            if "openapi" in data or "swagger" in data:
                info = data.get("info", {})
                summary["type"] = "openapi" if "openapi" in data else "swagger"
                summary["title"] = info.get("title")
                summary["version"] = info.get("version")
                paths = data.get("paths", {})
                summary["paths_count"] = len(paths) if isinstance(paths, dict) else 0
                summary["paths"] = list(paths.keys())[:50] if isinstance(paths, dict) else []
            return summary or None
        except Exception as e:
            logger.debug("Failed to extract schema from response: %s", e)
            return None

    async def _introspect_graphql(self, base: str) -> dict[str, Any] | None:
        base_url = base.rstrip("/")
        candidates = ["/graphql", "/api/graphql", "/graphql/", "/graphiql"]
        for candidate in candidates:
            try:
                async with httpx.AsyncClient(timeout=6.0, follow_redirects=False, verify=False) as c:
                    r = await c.post(
                        base_url + candidate,
                        json={"query": GRAPHQL_INTROSPECTION},
                        headers={"User-Agent": "PhantomScan/1.0"},
                    )
                    if r.status_code != 200:
                        continue
                    data = r.json()
                    schema = (data or {}).get("data", {}).get("__schema")
                    if not schema:
                        continue
                    query_type = (schema.get("queryType") or {}).get("name")
                    mutation_type = (schema.get("mutationType") or {}).get("name")
                    types = sorted({t.get("name") for t in schema.get("types", []) if t.get("name") and not t.get("name", "").startswith("__")})
                    return {
                        "endpoint": base_url + candidate,
                        "enabled": True,
                        "queries": query_type,
                        "mutations": mutation_type,
                        "types": types[:100],
                        "types_count": len(types),
                    }
            except Exception as e:
                logger.debug("GraphQL introspection failed for %s%s: %s", base_url, candidate, e)
                continue
        return None
