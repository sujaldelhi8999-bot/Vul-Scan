import asyncio
import json
import logging
import random
import re
import ssl
import string
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.asyncresolver
import dns.query
import dns.rdatatype
import dns.zone
import httpx

from app.agents import Agent
from app.config import get_settings

logger = logging.getLogger("phantomscan.scanner")

SUBDOOM_WORDLIST = [
    "admin", "dev", "staging", "api", "mail", "vpn", "portal", "dashboard",
    "internal", "beta", "test", "old", "backup", "cdn", "auth", "login",
    "app", "shop", "cms", "blog", "git", "jenkins", "jira", "grafana",
    "kibana", "redis", "db", "mysql", "mongo", "ftp", "smtp", "pop",
    "imap", "ns1", "ns2", "mx", "support", "status", "docs", "www",
    "v2", "v3", "new", "live", "preview", "demo", "stage", "qa", "uat",
    "secure", "pay", "payment", "gateway", "billing", "account", "accounts",
    "user", "users", "customer", "customers", "adminpanel", "cpanel", "webmail",
    "owa", "exchange", "remote", "rdp", "ssh", "gitlab", "bitbucket", "github",
    "confluence", "wiki", "redmine", "moodle", "lms", "vpn", "vpn2", "openvpn",
    "proxy", "squid", "ftp2", "sftp", "uploads", "download", "files", "static",
    "assets", "media", "img", "images", "css", "js", "fonts", "m", "mobile",
    "api2", "api-internal", "internal-api", "private", "intranet", "office",
    "hr", "erp", "crm", "analytics", "metrics", "monitor", "monitoring",
    "prometheus", "graphite", "stats", "logs", "log", "sentry", "jenkins2",
    "ci", "cd", "build", "deploy", "docker", "k8s", "kube", "registry",
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443,
]

WEB_ALT_PORTS = [
    8000, 8001, 8008, 8010, 8081, 8082, 8083, 8085, 8088, 8090, 8180,
    8200, 8280, 8444, 8445, 8648, 8800, 8880, 8881, 8888, 9000, 9001,
    9043, 9080, 9090, 9091, 9100, 9200, 9300, 9443, 9999, 10000, 10443,
    11080, 11443, 18080, 19000, 28080,
]

SERVICE_ALT_PORTS = {
    22: [2222, 22022],
    25: [2525, 465, 587],
    3306: [3307, 13306, 33060],
    5432: [5433, 5434, 15432],
    6379: [6380, 16379, 26379],
    27017: [27018, 27019, 28017],
    9200: [9201, 9202, 9400],
    80: WEB_ALT_PORTS,
    443: [8443, 9443, 4443],
}

PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 179: "bgp", 194: "irc", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 515: "printer", 587: "smtp-submission",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1099: "rmi", 1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1812: "radius", 2049: "nfs", 2222: "ssh-alt", 2375: "docker", 2376: "docker-tls",
    3000: "http-alt", 3128: "squid", 3306: "mysql", 3389: "rdp", 4369: "erlang",
    5000: "http-alt", 5432: "postgresql", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    5985: "winrm", 6379: "redis", 6443: "kubernetes", 7001: "weblogic", 8000: "http-alt",
    8009: "ajp", 8080: "http-proxy", 8081: "http-alt", 8082: "http-alt",
    8083: "http-alt", 8088: "http-alt", 8180: "http-alt", 8443: "https-alt",
    8500: "consul", 8600: "dns-alt", 8888: "http-alt", 9000: "http-alt",
    9001: "supervisord", 9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 9443: "https-alt", 9999: "http-alt",
    10000: "webmin", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
    28017: "mongodb-http", 50000: "sap",
}

BANNER_SERVICE_HINTS = [
    ("ssh", re.compile(r"^SSH-", re.I)),
    ("ftp", re.compile(r"^220[- ]", re.I)),
    ("smtp", re.compile(r"^220 .*?(ESMTP|SMTP)", re.I)),
    ("pop3", re.compile(r"^\+OK ", re.I)),
    ("imap", re.compile(r"^\* OK", re.I)),
    ("http", re.compile(r"^HTTP/", re.I)),
    ("https", re.compile(r"^HTTP/", re.I)),
    ("telnet", re.compile(r"login:", re.I)),
    ("mysql", re.compile(r"mysql", re.I)),
    ("redis", re.compile(r"^-ERR|^\+OK", re.I)),
    ("mongodb", re.compile(r"^HELLO|^machine", re.I)),
]

TECHNOLOGY_SIGNATURES: dict[str, dict[str, dict[str, Any]]] = {
    "web_servers": {
        "nginx": {"headers": [("server", "nginx")], "version": {"pattern": r"nginx/([\d.]+)", "source": "headers"}},
        "openresty": {"headers": [("server", "openresty")], "version": {"pattern": r"openresty/([\d.]+)", "source": "headers"}},
        "apache": {"headers": [("server", "apache")], "version": {"pattern": r"Apache/([\d.]+)", "source": "headers"}},
        "iis": {"headers": [("server", "microsoft-iis")], "version": {"pattern": r"Microsoft-IIS/([\d.]+)", "source": "headers"}},
        "caddy": {"headers": [("server", "caddy")], "version": {"pattern": r"Caddy/([\d.]+)", "source": "headers"}},
        "traefik": {"headers": [("server", "traefik")], "version": {"pattern": r"Traefik/([\d.]+)", "source": "headers"}},
        "lighttpd": {"headers": [("server", "lighttpd")], "version": {"pattern": r"lighttpd/([\d.]+)", "source": "headers"}},
        "tomcat": {"headers": [("server", "coyote")], "body": ["tomcat"], "version": {"pattern": r"Apache[-\s]?Tomcat/([\d.]+)", "source": "headers"}},
        "gunicorn": {"headers": [("server", "gunicorn")], "version": {"pattern": r"gunicorn/([\d.]+)", "source": "headers"}},
        "uvicorn": {"headers": [("server", "uvicorn")], "version": {"pattern": r"uvicorn", "source": "headers"}},
        "jetty": {"headers": [("server", "jetty")], "version": {"pattern": r"Jetty\(([\d.]+)", "source": "headers"}},
        "kestrel": {"headers": [("server", "kestrel")], "version": {"pattern": r"Kestrel/([\d.]+)", "source": "headers"}},
        "apache-coyote": {"headers": [("server", "coyote")]},
        "litespeed": {"headers": [("server", "litespeed")], "version": {"pattern": r"LiteSpeed/([\d.]+)", "source": "headers"}},
    },
    "frameworks": {
        "react": {"body": ["react", "react-dom", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "reactjs", "_reactRootContainer", "react-root", "reactroot"]},
        "angular": {"body": ["ng-version", "ng-app", "angular.js", "angularjs", "ngrx"]},
        "vue": {"body": ["__VUE__", "vue.js", "v-bind", "vue.runtime", "data-v-"]},
        "nextjs": {"body": ["__NEXT_DATA__", "_next/static", "next/dist", "next/script"]},
        "nuxt": {"body": ["__NUXT__", "nuxt", "_nuxt/"]},
        "gatsby": {"body": ["gatsby", "__gatsby", "gatsby-link"]},
        "remix": {"body": ["remix-run", "__remixContext"]},
        "svelte": {"body": ["__sveltekit", "svelte", "data-svelte-"]},
        "astro": {"body": ["astro", "is:astro", "astro-static"]},
        "laravel": {"headers": [("x-powered-by", "laravel")], "body": ["laravel_session", "csrf-token"]},
        "django": {"headers": [("x-powered-by", "django")], "body": ["csrftoken", "django"], "path": ["/__debug__"]},
        "flask": {"body": ["flask", "werkzeug"], "version": {"pattern": r"Werkzeug/([\d.]+)", "source": "headers"}},
        "fastapi": {"body": ["fastapi", "swagger-ui"], "path": ["/docs", "/redoc", "/openapi.json"]},
        "rails": {"headers": [("x-runtime", ""), ("x-rails", "")], "body": ["csrf-param", "data-remote"]},
        "spring": {"headers": [("x-application-context", "")], "body": ["whitelabel error page"]},
        "aspnet": {"headers": [("x-aspnet-version", ""), ("x-aspnetmvc-version", "")], "body": ["__VIEWSTATE", "__EVENTVALIDATION"]},
        "express": {"body": ["x-powered-by"], "headers": [("x-powered-by", "express")]},
        "symfony": {"body": ["symfony", "sf_"], "headers": [("x-powered-by", "symfony")]},
        "codeigniter": {"body": ["codeigniter", "ci_session"]},
        "cakephp": {"body": ["cakephp", "cake"], "headers": [("x-powered-by", "cake")]},
        "drupal": {"body": ["drupal", "drupal.js"], "path": ["/user/login", "/sites/all"]},
        "joomla": {"body": ["joomla", "com_content"], "path": ["/administrator"]},
        "wordpress": {"body": ["wp-content", "wp-includes", "wp-json", "wp-cron"], "path": ["/wp-login.php", "/wp-admin"]},
    },
    "cms": {
        "wordpress": {"body": ["wp-content", "wp-includes", "wp-json", "wp-cron"], "version": {"pattern": r'content="WordPress ([\d.]+)"', "source": "body"}},
        "joomla": {"body": ["joomla", "com_content"], "version": {"pattern": r'content="Joomla! ([\d.]+)"', "source": "body"}},
        "drupal": {"body": ["drupal", "drupal.js"], "version": {"pattern": r'content="Drupal ([\d.]+)', "source": "body"}},
        "shopify": {"headers": [("x-shopify-stage", ""), ("x-shopid", "")], "body": ["shopify"]},
        "magento": {"body": ["magento", "skin/frontend", "mage/cookies"], "headers": [("x-magento-cache-debug", "")]},
        "wix": {"headers": [("x-wix-request-id", ""), ("x-wix-*", "")], "body": ["wix.com", "wix-static"]},
        "squarespace": {"headers": [("x-squarespace-*", "")], "body": ["squarespace"]},
        "ghost": {"body": ["ghost", "ghost_url"], "headers": [("x-powered-by", "ghost")]},
        "typo3": {"body": ["typo3", "fe_typo_user"]},
        "prestashop": {"body": ["prestashop", "ps_"]},
        "webflow": {"body": ["webflow", "wfx"]},
        "contentful": {"body": ["contentful", "ctfassets"]},
    },
    "analytics": {
        "google_analytics": {"body": ["google-analytics", "gtag", "ga(", "ga.js", "g4a-"]},
        "facebook_pixel": {"body": ["fbq(", "facebook-pixel", "connect.facebook.net"]},
        "hotjar": {"body": ["hotjar", "static.hotjar.com"]},
        "clarity": {"body": ["clarity.ms", "clarity(", "microsoft clarity"]},
        "matomo": {"body": ["matomo", "piwik"]},
        "mixpanel": {"body": ["mixpanel"]},
        "segment": {"body": ["segment.com", "analytics.js", "cdn.segment"]},
        "amplitude": {"body": ["amplitude", "cdn.amplitude"]},
        "posthog": {"body": ["posthog", "us-assets.i.posthog"]},
        "fullstory": {"body": ["fullstory", "fullstory.com"]},
        "yandex_metrika": {"body": ["mc.yandex.ru", "metrika", "yandex_metrika"]},
        "linkedin_insight": {"body": ["snap.licdn.com", "li-tracker"]},
    },
    "advertising": {
        "google_ads": {"body": ["google_ads", "googletag", "googleadservices", "adsbygoogle"]},
        "facebook_ads": {"body": ["facebook_ads", "fbq('track', 'lead'", "adform"]},
        "adroll": {"body": ["adroll", "a.adsymptotic"]},
        "taboola": {"body": ["taboola", "cdn.taboola"]},
        "outbrain": {"body": ["outbrain", "odb.outbrain"]},
        "criteo": {"body": ["criteo", "static.criteo"]},
        "doubleclick": {"body": ["doubleclick.net", "googlesyndication"]},
    },
    "cloud_providers": {
        "aws": {"headers": [("x-amz", "")], "body": ["amazonaws.com", "aws"], "path": ["/.well-known"]},
        "gcp": {"headers": [("x-goog-*", "")], "body": ["googlecloudplatform", "googleapis.com", "appspot.com"]},
        "azure": {"headers": [("x-azure-*", ""), ("x-ms-*", "")], "body": ["azurewebsites.net", "windows.net"]},
        "cloudflare": {"headers": [("cf-ray", ""), ("cf-cache-status", ""), ("cf-*", "")], "body": ["cloudflare"]},
        "vercel": {"headers": [("x-vercel-*", ""), ("x-vercel-id", "")], "body": ["vercel"]},
        "netlify": {"headers": [("server", "netlify")], "body": ["netlify"]},
        "heroku": {"headers": [("x-heroku-*", ""), ("via", "heroku")]},
        "github_pages": {"headers": [("server", "github.com"), ("x-github-*", "")]},
        "digitalocean": {"body": ["digitalocean", "droplet"]},
        "firebase": {"headers": [("x-firebase-*", "")], "body": ["firebaseapp.com", "firebaseio"]},
    },
    "payment": {
        "stripe": {"body": ["stripe.com", "js.stripe", "pk_live_", "pk_test_"]},
        "paypal": {"body": ["paypal.com", "paypalobjects", "paypal"]},
        "braintree": {"body": ["braintree", "js.braintreegateway"]},
        "square": {"body": ["squareup.com", "square.js"]},
        "razorpay": {"body": ["razorpay", "razorpay.com"]},
        "cashfree": {"body": ["cashfree"]},
        "paytm": {"body": ["paytm", "paytm.com"]},
        "klarna": {"body": ["klarna", "klarnasdk"]},
        "payu": {"body": ["payu", "secure.payu"]},
        "adyen": {"body": ["adyen", "adyen.com"]},
    },
    "cdn": {
        "cloudflare": {"headers": [("cf-ray", ""), ("cf-cache-status", "")]},
        "cloudfront": {"headers": [("x-amz-cf-id", ""), ("x-cache", ""), ("x-amz-cf-pop", "")]},
        "fastly": {"headers": [("x-served-by", ""), ("x-cache-hits", ""), ("x-fastly-*", "")]},
        "akamai": {"headers": [("x-akamai-*", ""), ("x-akamai-transformed", ""), ("server", "akamaighost")]},
        "stackpath": {"headers": [("x-stackpath-*", "")]},
        "keycdn": {"headers": [("x-keycdn-*", "")]},
        "azure_cdn": {"headers": [("x-azure-ref", "")]},
        "bunny": {"headers": [("x-bunny-*", "")]},
        "jsdelivr": {"body": ["cdn.jsdelivr.net"]},
        "unpkg": {"body": ["unpkg.com"]},
        "bootstrapcdn": {"body": ["bootstrapcdn.com", "cdnjs.cloudflare.com"]},
    },
    "waf": {
        "cloudflare": {"headers": [("cf-ray", ""), ("cf-mitigated", ""), ("__cf_bm", "")], "body": ["cloudflare", "cf-request-id"]},
        "modsecurity": {"headers": [("x-modsecurity", "")], "body": ["mod_security"]},
        "aws_waf": {"headers": [("x-amzn-requestid", "")], "body": ["awswaf"]},
        "akamai": {"headers": [("x-akamai-*", ""), ("akamai", "")], "body": ["akamai"]},
        "imperva": {"headers": [("x-iinfo", ""), ("x-cdn", "incapsula")], "body": ["incapsula", "imperva"]},
        "f5": {"headers": [("x-f5-*", ""), ("x-cnection", ""), ("bigip", "")]},
        "barracuda": {"headers": [("x-waf-*", ""), ("barracuda", "")]},
        "sucuri": {"headers": [("x-sucuri-*", ""), ("x-cache", "sucuri")], "body": ["sucuri"]},
        "fortinet": {"headers": [("x-forti-*", "")]},
        "radware": {"headers": [("x-radware-*", "")]},
        "citrix": {"headers": [("x-citrix-*", "")]},
        "comodo": {"headers": [("x-comodo-*", "")]},
        "incapsula": {"headers": [("x-iinfo", ""), ("incap_ses", "")]},
    },
    "languages": {
        "php": {"headers": [("x-powered-by", "php")], "body": ["php", ".php", "php_session"], "version": {"pattern": r"PHP/([\d.]+)", "source": "headers"}},
        "python": {"body": ["python", "flask", "django", "fastapi"], "version": {"pattern": r"Python/([\d.]+)", "source": "headers"}},
        "javascript": {"body": ["<script", ".js", "modulepreload", "type=\"module\""]},
        "typescript": {"body": ["tsconfig", "typescript", ".tsx"]},
        "java": {"headers": [("x-powered-by", "java"), ("server", "coyote")], "body": ["java", ".jsp"]},
        "go": {"headers": [("server", "go")], "body": ["golang", "go1."], "version": {"pattern": r"Go-http-server/([\d.]+)", "source": "headers"}},
        "ruby": {"headers": [("x-powered-by", "phusion"), ("x-runtime", "")], "body": ["ruby on rails"]},
        "csharp": {"headers": [("x-aspnet-version", "")], "body": [".aspx", "__VIEWSTATE"]},
        "rust": {"headers": [("server", "actix"), ("server", "warp"), ("server", "axum")]},
        "nodejs": {"headers": [("x-powered-by", "express")], "body": ["nodejs", "node.js"], "version": {"pattern": r"node[/v]([\d.]+)", "source": "headers"}},
        "perl": {"headers": [("x-powered-by", "perl")], "body": [".pl", "cgi-bin"]},
    },
    "databases": {
        "mysql": {"body": ["mysql", "mysqli"], "path": ["/phpmyadmin"]},
        "postgresql": {"body": ["postgres", "pgsql"], "path": ["/pgadmin"]},
        "mongodb": {"body": ["mongodb", "mongo"]},
        "redis": {"body": ["redis"], "path": ["/redis"]},
        "sqlite": {"body": ["sqlite", "sqlite3"]},
        "mssql": {"body": ["sql server", "mssql", ".aspx"]},
        "oracle": {"body": ["oracle", "v$version"]},
        "elasticsearch": {"body": ["elasticsearch", "kibana"]},
        "couchdb": {"body": ["couchdb"]},
        "firebase": {"body": ["firebaseio", "firebaseapp"]},
    },
    "operating_systems": {
        "linux": {"headers": [("server", "ubuntu"), ("server", "debian"), ("server", "centos")], "body": ["linux"]},
        "ubuntu": {"headers": [("server", "ubuntu")], "body": ["ubuntu"]},
        "debian": {"headers": [("server", "debian")], "body": ["debian"]},
        "centos": {"headers": [("server", "centos")], "body": ["centos"]},
        "windows": {"headers": [("server", "microsoft-iis")], "body": ["windows", ".aspx", "iis"]},
        "freebsd": {"headers": [("server", "freebsd")], "body": ["freebsd"]},
        "macos": {"headers": [("server", "darwin")], "body": ["macos"]},
    },
}

CIPHER_PROBES = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-CHACHA20-POLY1305",
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-SHA",
    "AES256-SHA",
    "DHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "DES-CBC3-SHA",
]

TLS_VULNERABLE_CIPHERS: dict[str, str] = {
    "RC4-SHA": "RC4: weak stream cipher",
    "RC4-MD5": "RC4: weak stream cipher",
    "DES-CBC3-SHA": "Sweet32: 3DES cipher supported",
    "DES-CBC-SHA": "Sweet32: 3DES cipher supported",
    "DES-CBC-MD5": "Sweet32: 3DES cipher supported",
    "RC2-CBC-MD5": "RC2: weak block cipher",
    "PSK-AES256-CBC-SHA": "PSK: pre-shared key cipher",
    "PSK-3DES-EDE-CBC-SHA": "PSK: 3DES weak cipher",
    "KRB5-DES-CBC3-SHA": "Kerberos: DES weak cipher",
    "KRB5-RC4-SHA": "Kerberos: RC4 weak cipher",
    "EDH-RSA-DES-CBC3-SHA": "EDH: 3DES weak cipher",
    "EDH-RSA-DES-CBC-SHA": "EDH: DES weak cipher",
    "DHE-RSA-DES-CBC-SHA": "DHE: DES weak cipher",
    "DHE-RSA-CAMELLIA128-SHA": "DHE: Camellia weak cipher",
    "DHE-RSA-CAMELLIA256-SHA": "DHE: Camellia weak cipher",
    "ECDHE-RSA-DES-CBC3-SHA": "ECDHE: 3DES weak cipher",
    "ECDHE-RSA-DES-CBC-SHA": "ECDHE: DES weak cipher",
    "SRP-DSS-AES-256-CBC-SHA": "SRP: weak cipher",
    "SRP-RSA-AES-256-CBC-SHA": "SRP: weak cipher",
    "SRP-DSS-3DES-EDE-CBC-SHA": "SRP: 3DES weak cipher",
    "SRP-RSA-3DES-EDE-CBC-SHA": "SRP: 3DES weak cipher",
    "PSK-AES128-CBC-SHA256": "PSK: weak cipher",
    "PSK-AES256-CBC-SHA384": "PSK: weak cipher",
    "DHE-PSK-AES256-CBC-SHA": "DHE-PSK: weak cipher",
    "DHE-PSK-AES128-CBC-SHA": "DHE-PSK: weak cipher",
    "RSA-PSK-AES256-CBC-SHA": "RSA-PSK: weak cipher",
    "RSA-PSK-AES128-CBC-SHA": "RSA-PSK: weak cipher",
}

TLS_PROTOCOL_VULNERABILITIES: dict[str, list[str]] = {
    "TLSv1": ["POODLE: TLS 1.0 enabled", "BEAST: TLS 1.0 CBC ciphers enabled"],
    "TLSv1.1": ["BEAST: TLS 1.1 CBC ciphers enabled"],
}

WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray", "__cf_bm"],
    "akamai": ["akamai", "akamaighost", "akamai-x-"],
    "sucuri": ["sucuri", "x-sucuri-"],
    "imperva": ["imperva", "incapsula", "_incap_", "x-iinfo"],
    "aws_waf": ["awswaf", "x-amzn-requestid", "x-amzn-waf-"],
    "f5": ["x-cnection", "bigip", "x-f5-"],
    "modsecurity": ["mod_security", "x-modsecurity"],
    "barracuda": ["barracuda", "x-waf-"],
    "fortinet": ["x-forti-"],
    "radware": ["x-radware-", "radware"],
    "citrix": ["x-citrix-"],
    "comodo": ["x-comodo-"],
    "fastly": ["x-fastly-", "x-served-by"],
    "incapsula": ["incap_ses", "x-iinfo"],
}


class ScannerAgent(Agent):
    def __init__(self) -> None:
        super().__init__("Scanner Agent")
        self.settings = get_settings()

    async def run(self, target_url: str, scan_id: int) -> dict[str, Any]:
        self.scan_id = scan_id
        self.status = "active"
        await self.log_action("started", f"Scanning {target_url}")

        hostname = self._extract_hostname(target_url)

        subdomains, dns_records, dangling_cnames, wildcard, dnssec, zone_transfer = await self._dns_enum(hostname)
        port_scan = await self.scan_all_ports(hostname)
        fingerprint = await self._fingerprint(target_url)
        tls_analysis = await self._tls_analysis(hostname, port_scan["open_ports"])

        open_ports = [p["number"] for p in port_scan["details"]]
        self.open_ports = open_ports
        self.dns_records = dns_records
        self.tech_stack = fingerprint["tech_stack"]
        self.waf_detected = fingerprint["waf_detected"]
        self.cdn_detected = fingerprint["cdn_detected"]
        self.tls_version = tls_analysis.get("negotiated_version")
        self.tls_cipher = tls_analysis.get("negotiated_cipher")
        self.tls_expiry = tls_analysis.get("certificate", {}).get("not_after")
        self.tls_valid = tls_analysis.get("certificate", {}).get("valid")

        self.status = "complete"
        await self.log_action(
            "completed",
            f"Found {len(subdomains)} subdomains, {len(open_ports)} open ports, "
            f"{len(dangling_cnames)} dangling CNAMEs, "
            f"{len(fingerprint['technologies_detailed'])} technologies, "
            f"WAF: {fingerprint['waf_detected'] or 'none'}"
        )

        result = {
            "subdomains": subdomains,
            "open_ports": open_ports,
            "ports": port_scan,
            "tech_stack": fingerprint["tech_stack"],
            "technologies_detailed": fingerprint["technologies_detailed"],
            "dns_records": dns_records,
            "dangling_cnames": dangling_cnames,
            "wildcard": wildcard,
            "dnssec": dnssec,
            "zone_transfer": zone_transfer,
            "waf_detected": fingerprint["waf_detected"],
            "waf_details": fingerprint["waf_details"],
            "cdn_detected": fingerprint["cdn_detected"],
            "tls_details": tls_analysis,
            "http_headers": fingerprint["headers"],
            "http_body_technologies": fingerprint.get("body_technologies", []),
        }

        await self._save_artifacts(result)
        await self.save_scan_artifacts()

        return result

    async def _save_artifacts(self, result: dict[str, Any]) -> None:
        try:
            from app.database import set_scan_artifacts
            await set_scan_artifacts(self.scan_id, scanner_output=result)
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save scan artifacts: {exc}")

    async def save_scan_artifacts(self) -> None:
        try:
            from app.database import get_connection
            technologies = (self.tech_stack or {}).get("technologies", [])
            server_header = (self.tech_stack or {}).get("headers", {}).get("server", "")
            body_techs = (self.tech_stack or {}).get("body_technologies", [])
            async with get_connection() as conn:
                await conn.execute("INSERT OR IGNORE INTO scan_artifacts (scan_id) VALUES (?)", (self.scan_id,))
                await conn.execute(
                    """
                    UPDATE scan_artifacts SET
                        ports_open = ?,
                        technologies = ?,
                        server_header = ?,
                        waf_detected = ?,
                        cdn_detected = ?,
                        dns_records = ?,
                        tls_version = ?,
                        tls_cipher = ?,
                        tls_expiry = ?,
                        tls_valid = ?,
                        body_technologies = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE scan_id = ?
                    """,
                    (
                        json.dumps(self.open_ports or []) if hasattr(self, 'open_ports') else None,
                        json.dumps(technologies) if technologies else None,
                        server_header or None,
                        self.waf_detected if hasattr(self, 'waf_detected') else None,
                        self.cdn_detected if hasattr(self, 'cdn_detected') else None,
                        json.dumps(self.dns_records or {}) if hasattr(self, 'dns_records') else None,
                        self.tls_version if hasattr(self, 'tls_version') else None,
                        self.tls_cipher if hasattr(self, 'tls_cipher') else None,
                        self.tls_expiry if hasattr(self, 'tls_expiry') else None,
                        1 if getattr(self, 'tls_valid', None) else 0,
                        json.dumps(body_techs) if body_techs else None,
                        self.scan_id,
                    ),
                )
                await conn.commit()
        except Exception as exc:
            await self.log_action("save_error", f"Failed to save recon artifacts: {exc}")

    def _extract_hostname(self, target_url: str) -> str:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        return parsed.hostname or target_url

    async def _dns_enum(
        self, hostname: str
    ) -> tuple[list[str], dict[str, Any], list[str], bool, bool, str]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 2.0

        records: dict[str, Any] = {}
        for rtype in ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "PTR", "SRV", "CAA"):
            try:
                answers = await resolver.resolve(hostname, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception as e:
                logger.debug("Failed to resolve %s for %s: %s", rtype, hostname, e)
                records[rtype] = []

        wildcard = await self._check_wildcard(hostname, resolver)

        dnssec = False
        try:
            dnskeys = await resolver.resolve(hostname, "DNSKEY")
            dnssec = len(dnskeys) > 0
        except Exception as e:
            logger.debug("DNSKEY resolution failed for %s: %s", hostname, e)
            dnssec = False

        zone_transfer = "not_attempted"
        try:
            zone = await asyncio.to_thread(
                dns.zone.from_xfr, dns.query.xfr(hostname, hostname, lifetime=5)
            )
            zone_names = [str(name) for name in zone.nodes]
            if zone_names:
                zone_transfer = "success"
                for name in zone_names[:50]:
                    subdomains_add = f"{name}.{hostname}"
                    records.setdefault("AXFR", [])
                    records["AXFR"].append(subdomains_add)
            else:
                zone_transfer = "empty_zone"
        except Exception as exc:
            if "XFR" in str(exc) or "refused" in str(exc).lower() or "denied" in str(exc).lower():
                zone_transfer = "refused"
            else:
                zone_transfer = "failed"

        candidates = [f"{prefix}.{hostname}" for prefix in SUBDOOM_WORDLIST]
        if hostname not in candidates:
            candidates.insert(0, hostname)

        async def try_resolve(sub: str) -> tuple[str, bool, str]:
            try:
                answers = await resolver.resolve(sub, "CNAME")
                cname_target = str(answers[0])
                try:
                    await resolver.resolve(sub, "A")
                    return sub, True, ""
                except Exception as e:
                    logger.debug("A record resolution failed for %s after CNAME: %s", sub, e)
                    return sub, False, cname_target
            except Exception as e:
                logger.debug("CNAME resolution failed for %s: %s", sub, e)
                try:
                    await resolver.resolve(sub, "A")
                    return sub, True, ""
                except Exception as e2:
                    logger.debug("A record resolution also failed for %s: %s", sub, e2)
                    return sub, False, ""

        tasks = [try_resolve(sub) for sub in candidates]
        results = await asyncio.gather(*tasks)

        subdomains: list[str] = []
        dangling_cnames: list[str] = []
        for sub, found, cname_target in results:
            if found:
                subdomains.append(sub)
            elif cname_target:
                dangling_cnames.append(f"{sub} -> {cname_target}")

        return sorted(set(subdomains)), records, dangling_cnames, wildcard, dnssec, zone_transfer

    async def _check_wildcard(self, hostname: str, resolver: dns.asyncresolver.Resolver) -> bool:
        random_sub = f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{hostname}"
        try:
            await resolver.resolve(random_sub, "A")
            return True
        except Exception as e:
            logger.debug("Wildcard check failed for %s: %s", hostname, e)
            return False

    async def scan_all_ports(self, target_host: str, max_ports: int = 0, depth: str = "standard") -> dict[str, Any]:
        if max_ports <= 0:
            max_ports = self.settings.port_scan_max_ports
        concurrency = self.settings.port_scan_concurrency
        sweep_timeout = self.settings.port_scan_sweep_timeout

        if depth == "fast":
            tier1 = await self._quick_scan(target_host, COMMON_PORTS, timeout=1.5)
            open_set = set(tier1)
            tier2: list[int] = []
            tier3: list[int] = []
        else:
            tier1 = await self._quick_scan(target_host, COMMON_PORTS, timeout=1.5)
            open_set = set(tier1)

            tier2: list[int] = []
            if any(p in open_set for p in (80, 443, 8080, 8443, 3000)):
                tier2 = await self._quick_scan(target_host, WEB_ALT_PORTS, timeout=1.2)
                open_set.update(tier2)

            tier3: list[int] = []
            for base in list(open_set):
                for alt in SERVICE_ALT_PORTS.get(base, []):
                    if alt not in open_set and alt not in SERVICE_ALT_PORTS.get(80, []):
                        tier3.append(alt)
            tier3 = list(dict.fromkeys(tier3))
            if tier3:
                found_t3 = await self._quick_scan(target_host, tier3, timeout=1.2)
                open_set.update(found_t3)

        truncated = False
        if depth == "full" and max_ports > 1024:
            remaining = [p for p in range(1, max_ports + 1) if p not in open_set]
            extra, truncated = await self._sweep_ports(target_host, remaining, concurrency, sweep_timeout)
            open_set.update(extra)

        open_ports = sorted(open_set)
        banners = await self._grab_banners(target_host, open_ports)

        version_tasks = []
        for port in open_ports:
            banner = banners.get(port)
            service = self._identify_service(port, banner)
            version_tasks.append(self._probe_service_version(target_host, port, service))
        version_results = await asyncio.gather(*version_tasks)

        detailed = []
        for port, banner, version_info in zip(open_ports, [banners.get(p) for p in open_ports], version_results):
            service = self._identify_service(port, banner)
            tls = port in (443, 8443, 9443, 4443) or "https" in service
            port_detail: dict[str, Any] = {
                "number": port,
                "service": service,
                "banner": banner,
                "tls": tls,
                "version": version_info.get("version"),
                "protocol": version_info.get("protocol"),
                "http_version": version_info.get("http_version"),
                "server": version_info.get("server"),
                "x_powered_by": version_info.get("x_powered_by"),
            }
            detailed.append(port_detail)

        return {
            "open_ports": open_ports,
            "details": detailed,
            "truncated": truncated,
            "tier1_count": len(tier1),
            "tier2_count": len(tier2),
            "tier3_count": len(tier3),
            "total_scanned": min(max_ports, 65535),
        }

    async def _quick_scan(self, host: str, ports: list[int], timeout: float) -> list[int]:
        sem = asyncio.Semaphore(32)

        async def check(port: int) -> int | None:
            async with sem:
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=timeout
                    )
                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception as e:
                        logger.debug("Error closing connection for port %d: %s", port, e)
                    return port
                except Exception as e:
                    logger.debug("Connection check failed for port %d: %s", port, e)
                    return None

        results = await asyncio.gather(*[check(p) for p in ports])
        return sorted([p for p in results if p is not None])

    async def _sweep_ports(
        self, host: str, ports: list[int], concurrency: int, time_cap: float
    ) -> tuple[list[int], bool]:
        if not ports:
            return [], False

        found: list[int] = []
        sem = asyncio.Semaphore(min(concurrency, 64))
        started = asyncio.get_running_loop().time()
        truncated = False

        async def check(port: int) -> None:
            async with sem:
                if asyncio.get_running_loop().time() - started >= time_cap:
                    return
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=0.8
                    )
                    found.append(port)
                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception as e:
                        logger.debug("Error closing connection for port %d: %s", port, e)
                except Exception as e:
                    logger.debug("Port check failed for %s:%d: %s", host, port, e)

        batch_size = max(concurrency * 4, 256)
        if batch_size > 512:
            batch_size = 512
        empty_batches = 0
        for i in range(0, len(ports), batch_size):
            if asyncio.get_running_loop().time() - started >= time_cap:
                truncated = True
                break
            batch = ports[i:i + batch_size]
            before = len(found)
            await asyncio.gather(*[check(p) for p in batch])
            if len(found) == before:
                empty_batches += 1
                if empty_batches >= 6:
                    truncated = True
                    break
            else:
                empty_batches = 0
            if asyncio.get_running_loop().time() - started >= time_cap:
                truncated = True

        return sorted(found), truncated

    async def _grab_banners(self, host: str, ports: list[int]) -> dict[int, str]:
        banners: dict[int, str] = {}
        if not ports:
            return banners

        sem = asyncio.Semaphore(10)

        async def grab(port: int) -> None:
            async with sem:
                try:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=2.0
                    )
                    banner = b""
                    try:
                        banner = await asyncio.wait_for(r.read(2048), timeout=1.5)
                    except asyncio.TimeoutError:
                        pass

                    if not banner and port in (25, 110, 143, 21, 23, 79, 220):
                        try:
                            w.write(b"\r\n")
                            await w.drain()
                            banner = await asyncio.wait_for(r.read(2048), timeout=1.5)
                        except Exception as e:
                            logger.debug("Banner retry failed for port %d: %s", port, e)

                    if port in (80, 8080, 8000, 8888, 3000, 9000, 9090, 9200, 28017, 10000):
                        if not banner or b"HTTP/" not in banner[:64]:
                            try:
                                w.write(
                                    b"HEAD / HTTP/1.1\r\nHost: " + host.encode() +
                                    b"\r\nUser-Agent: PhantomScan/1.0\r\nConnection: close\r\n\r\n"
                                )
                                await w.drain()
                                banner = await asyncio.wait_for(r.read(4096), timeout=2.5)
                            except Exception as e:
                                logger.debug("HTTP HEAD banner grab failed for port %d: %s", port, e)

                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception as e:
                        logger.debug("Error closing banner connection for port %d: %s", port, e)

                    if banner:
                        text = banner.decode("utf-8", errors="replace").strip()
                        banners[port] = text[:500]
                except Exception as e:
                    logger.debug("Banner grab failed for %s:%d: %s", host, port, e)

        await asyncio.gather(*[grab(p) for p in ports])
        return banners

    def _identify_service(self, port: int, banner: str | None) -> str:
        known = PORT_SERVICES.get(port)
        if banner:
            lowered = banner.lower()
            for name, pattern in BANNER_SERVICE_HINTS:
                if pattern.search(lowered):
                    if name in ("http", "https"):
                        if port in (443, 8443, 9443, 4443):
                            return "https"
                        return "http"
                    return name
            if "server:" in lowered:
                match = re.search(r"server:\s*([a-z0-9/\-_.]+)", lowered)
                if match:
                    return match.group(1).lower()
        return known or "unknown"

    async def _probe_service_version(
        self, hostname: str, port: int, service: str
    ) -> dict[str, Any]:
        version_info: dict[str, Any] = {"service": service, "version": None, "protocol": None}
        try:
            if service in ("http", "https"):
                version_info = await self._probe_http_version(hostname, port, service)
            elif service == "ssh":
                version_info = await self._probe_ssh_version(hostname, port)
            elif service in ("ftp", "smtp", "pop3", "imap"):
                version_info = await self._probe_mail_version(hostname, port, service)
        except Exception as e:
            logger.debug("Service version probe failed for %s:%d: %s", hostname, port, e)
        return version_info

    async def _probe_http_version(
        self, hostname: str, port: int, service: str
    ) -> dict[str, Any]:
        scheme = "https" if service == "https" else "http"
        url = f"{scheme}://{hostname}:{port}/"
        headers = {"User-Agent": "PhantomScan/1.0", "Accept": "*/*"}
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=False) as client:
                resp = await client.get(url, headers=headers)
                http_version = resp.http_version
                server = resp.headers.get("server")
                x_powered = resp.headers.get("x-powered-by")
                result: dict[str, Any] = {
                    "service": service,
                    "http_version": http_version,
                    "server": server,
                    "x_powered_by": x_powered,
                    "version": None,
                    "protocol": f"{scheme}/{http_version}",
                }
                if server:
                    version_match = re.search(r"([\d.]+)", server)
                    if version_match:
                        result["version"] = version_match.group(1)
                elif x_powered:
                    version_match = re.search(r"([\d.]+)", x_powered)
                    if version_match:
                        result["version"] = version_match.group(1)
                return result
        except Exception as e:
            logger.debug("HTTP version probe failed for %s:%d: %s", hostname, port, e)
            return {"service": service, "version": None, "protocol": scheme}

    async def _probe_ssh_version(self, hostname: str, port: int) -> dict[str, Any]:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=5.0
            )
            banner = await asyncio.wait_for(r.read(1024), timeout=3.0)
            w.close()
            try:
                await w.wait_closed()
            except Exception as e:
                logger.debug("Error closing SSH probe connection: %s", e)
            text = banner.decode("utf-8", errors="replace").strip()
            version_match = re.search(r"SSH-([\d.]+)-([^\s]+)", text)
            if version_match:
                return {
                    "service": "ssh",
                    "version": version_match.group(2),
                    "protocol": f"SSH-{version_match.group(1)}",
                }
            return {"service": "ssh", "banner": text[:200], "protocol": "SSH"}
        except Exception as e:
            logger.debug("SSH version probe failed for %s:%d: %s", hostname, port, e)
            return {"service": "ssh", "version": None, "protocol": None}

    async def _probe_mail_version(
        self, hostname: str, port: int, service: str
    ) -> dict[str, Any]:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=5.0
            )
            banner = await asyncio.wait_for(r.read(1024), timeout=3.0)
            w.close()
            try:
                await w.wait_closed()
            except Exception as e:
                logger.debug("Error closing mail probe connection: %s", e)
            text = banner.decode("utf-8", errors="replace").strip()
            version_match = re.search(r"([\w.-]+)/([\d.]+)", text, re.I)
            if version_match:
                return {
                    "service": service,
                    "version": version_match.group(2),
                    "protocol": version_match.group(1),
                }
            return {"service": service, "banner": text[:200], "protocol": None}
        except Exception as e:
            logger.debug("Mail version probe failed for %s:%d (%s): %s", hostname, port, service, e)
            return {"service": service, "version": None, "protocol": None}

    async def _fingerprint(self, target_url: str) -> dict[str, Any]:
        url = target_url if "://" in target_url else f"https://{target_url}"
        headers: dict[str, str] = {}
        body = ""
        waf_detected: str | None = None
        waf_evidence: dict[str, list[str]] = {}

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(url, headers={"User-Agent": "PhantomScan/1.0"})
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:50000]

                raw = str(resp.headers).lower()
                body_lower = body.lower()
                for waf_name, sigs in WAF_SIGNATURES.items():
                    if any(s in raw or s in body_lower for s in sigs):
                        waf_detected = waf_name
                        waf_evidence[waf_name] = [s for s in sigs if s in raw or s in body_lower]
                        break

                await self._save_evidence(url, "GET", f"Status: {resp.status_code}, Server: {headers.get('server', 'unknown')}, Body length: {len(resp.text)}")
            except Exception as exc:
                await self._save_evidence(url, "GET", f"Error: {exc}")

        detailed = self._detect_technologies(headers, body)
        detailed = await self._ml_refine_technologies(detailed, headers, body)

        body_detailed = self._detect_body_technologies(body, headers)
        detailed.extend(body_detailed)

        tech_names: list[str] = []
        for tech in detailed:
            label = tech["name"]
            if tech.get("version"):
                label = f"{label} {tech['version']}"
            tech_names.append(label)

        legacy_headers_tech = []
        for h in ("server", "x-powered-by", "x-generator", "via", "x-aspnet-version"):
            v = headers.get(h)
            if v:
                for part in str(v).split(","):
                    part = part.strip()
                    if part and part not in legacy_headers_tech:
                        legacy_headers_tech.append(part)

        tech_stack: dict[str, Any] = {
            "technologies": tech_names,
            "headers": headers,
            "server": headers.get("server", ""),
            "x_powered_by": headers.get("x-powered-by", ""),
            "framework": self._detect_framework(headers, body),
            "detailed": detailed,
        }

        body_tech_names: list[str] = []
        for tech in body_detailed:
            label = tech["name"]
            if tech.get("version"):
                label = f"{label} {tech['version']}"
            body_tech_names.append(label)

        return {
            "tech_stack": tech_stack,
            "technologies_detailed": detailed,
            "body_technologies": body_detailed,
            "waf_detected": waf_detected,
            "waf_details": {"provider": waf_detected, "evidence": waf_evidence} if waf_detected else {"provider": None, "evidence": {}},
            "cdn_detected": self._detect_cdn(headers, detailed),
            "headers": headers,
        }

    def _detect_body_technologies(self, body: str, headers: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        b = body.lower()

        meta_generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)', b, re.I)
        if meta_generator:
            gen = meta_generator.group(1).strip()
            findings.append({
                "category": "web_frameworks",
                "name": "Meta Generator",
                "version": gen[:50],
                "confidence": 60,
                "evidence": [f'meta generator tag: {gen[:120]}'],
            })

        x_powered = headers.get("x-powered-by", "")
        if x_powered and not any(t.get("name") == x_powered for t in findings):
            findings.append({
                "category": "web_frameworks",
                "name": x_powered,
                "version": None,
                "confidence": 50,
                "evidence": [f"X-Powered-By: {x_powered}"],
            })

        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', b, re.I)
        for src in script_srcs:
            src_lower = src.lower()
            if "jquery" in src_lower and "jquery" not in [t.get("name") for t in findings]:
                ver_match = re.search(r'jquery[.-]([\d.]+)', src_lower)
                findings.append({
                    "category": "frameworks",
                    "name": "jQuery",
                    "version": ver_match.group(1) if ver_match else None,
                    "confidence": 70,
                    "evidence": [f"script src: {src[:120]}"],
                })
            if "angular" in src_lower and "angular" not in [t.get("name") for t in findings]:
                findings.append({
                    "category": "frameworks",
                    "name": "Angular",
                    "version": None,
                    "confidence": 60,
                    "evidence": [f"script src: {src[:120]}"],
                })
            if "react" in src_lower and "react" not in [t.get("name") for t in findings]:
                findings.append({
                    "category": "frameworks",
                    "name": "React",
                    "version": None,
                    "confidence": 60,
                    "evidence": [f"script src: {src[:120]}"],
                })
            if "vue" in src_lower and "vue" not in [t.get("name") for t in findings]:
                findings.append({
                    "category": "frameworks",
                    "name": "Vue.js",
                    "version": None,
                    "confidence": 60,
                    "evidence": [f"script src: {src[:120]}"],
                })

        link_hrefs = re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', b, re.I)
        for href in link_hrefs:
            href_lower = href.lower()
            if "bootstrap" in href_lower and "bootstrap" not in [t.get("name") for t in findings]:
                ver_match = re.search(r'bootstrap[.-]([\d.]+)', href_lower)
                findings.append({
                    "category": "css_frameworks",
                    "name": "Bootstrap",
                    "version": ver_match.group(1) if ver_match else None,
                    "confidence": 60,
                    "evidence": [f"link href: {href[:120]}"],
                })

        return findings

    def _detect_technologies(self, headers: dict[str, str], body: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        all_header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        body_lower = body.lower()

        for category, techs in TECHNOLOGY_SIGNATURES.items():
            for tech_name, sig in techs.items():
                score = 0
                evidence: list[str] = []
                source_count = 0
                has_header_match = False
                has_body_match = False

                for header_name, header_sub in sig.get("headers", []):
                    hkey = header_name.rstrip("*").lower()
                    for h, v in headers.items():
                        hl = h.lower()
                        if (header_name.endswith("*") and hl.startswith(hkey)) or hl == hkey:
                            if header_sub:
                                if header_sub in v.lower():
                                    score += 2
                                    source_count += 1
                                    has_header_match = True
                                    evidence.append(f"header {h}: {v[:120]}")
                            else:
                                score += 2
                                source_count += 1
                                has_header_match = True
                                evidence.append(f"header {h}: {v[:120]}")
                            break

                for body_pattern in sig.get("body", []):
                    if body_pattern.lower() in body_lower:
                        score += 1
                        source_count += 1
                        has_body_match = True
                        evidence.append(f'body contains "{body_pattern}"')

                for path in sig.get("path", []):
                    if path in body:
                        score += 1
                        source_count += 1
                        has_body_match = True
                        evidence.append(f'body contains path "{path}"')

                version: str | None = None
                version_rule = sig.get("version")
                if version_rule:
                    pattern = version_rule["pattern"]
                    if version_rule.get("source") == "headers":
                        match = re.search(pattern, all_header_text, re.IGNORECASE)
                    else:
                        match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else match.group(0).strip()
                        score += 3
                        source_count += 1
                        evidence.append(f"version match: {match.group(0)}")

                min_score = 2
                if source_count >= 2 and has_header_match and has_body_match:
                    min_score = 2
                elif has_header_match:
                    min_score = 2
                elif has_body_match:
                    min_score = 3

                if score >= min_score:
                    if source_count >= 3 or (has_header_match and has_body_match and version):
                        confidence = min(100, score * 25)
                    elif source_count >= 2:
                        confidence = min(90, score * 20)
                    else:
                        confidence = min(70, score * 15)

                    results.append({
                        "category": category,
                        "name": tech_name,
                        "version": version,
                        "confidence": confidence,
                        "evidence": list(dict.fromkeys(evidence))[:5],
                        "multi_source": source_count >= 2,
                    })

        return sorted(results, key=lambda t: t["confidence"], reverse=True)

    async def _ml_refine_technologies(
        self, detailed: list[dict[str, Any]], headers: dict[str, str], body: str
    ) -> list[dict[str, Any]]:
        try:
            from app.ml.tech_detector import TechnologyDetector

            return await TechnologyDetector().refine(detailed, headers, body)
        except Exception as exc:
            logger.debug("ML technology refinement failed: %s", exc)
            return detailed

    def _detect_cdn(self, headers: dict[str, str], detailed: list[dict[str, Any]]) -> str | None:
        for tech in detailed:
            if tech["category"] == "cdn" and tech["confidence"] >= 40:
                return tech["name"]
        via = headers.get("via", "")
        server = headers.get("server", "").lower()
        if "cloudfront" in via or "amazon" in via:
            return "cloudfront"
        if "cloudflare" in server:
            return "cloudflare"
        if "akamai" in via:
            return "akamai"
        return None

    async def _tls_analysis(self, hostname: str, open_ports: list[int]) -> dict[str, Any]:
        candidates = [p for p in (443, 8443, 9443, 4443) if p in open_ports]
        if not candidates and open_ports:
            for p in open_ports:
                if p in (8080, 8000, 8888, 3000, 9000, 9443):
                    candidates.append(p)
        if not candidates:
            return {
                "negotiated_version": None,
                "negotiated_cipher": None,
                "certificate": {"valid": None},
                "protocols": {},
                "ciphers": [],
                "vulnerabilities": [],
                "port": None,
            }

        port = candidates[0]
        result: dict[str, Any] = {
            "port": port,
            "negotiated_version": None,
            "negotiated_cipher": None,
            "certificate": {},
            "protocols": {},
            "ciphers": [],
            "vulnerabilities": [],
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=context, server_hostname=hostname),
                timeout=6.0,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object:
                negotiated_version = ssl_object.version()
                negotiated_cipher = ssl_object.cipher()
                cert_dict = ssl_object.getpeercert()
                result["negotiated_version"] = negotiated_version
                result["negotiated_cipher"] = (negotiated_cipher[0] + " " + str(negotiated_cipher[1]) + " bits") if negotiated_cipher else None
                result["certificate"] = self._parse_certificate(cert_dict)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as e:
                logger.debug("Error: %s", e)
                pass
        except Exception as exc:
            result["certificate"] = {"valid": None}
            result["errors"] = str(exc)[:200]

        protocol_versions = [
            ("tlsv1.0", ssl.TLSVersion.TLSv1),
            ("tlsv1.1", ssl.TLSVersion.TLSv1_1),
            ("tlsv1.2", ssl.TLSVersion.TLSv1_2),
            ("tlsv1.3", ssl.TLSVersion.TLSv1_3),
        ]
        for label, version in protocol_versions:
            result["protocols"][label] = await self._probe_protocol(hostname, port, version)

        if result["protocols"].get("tlsv1.2"):
            result["ciphers"] = await self._probe_ciphers(hostname, port)

        if result["protocols"].get("tlsv1.0"):
            for vuln in TLS_PROTOCOL_VULNERABILITIES.get("TLSv1", []):
                if vuln not in result["vulnerabilities"]:
                    result["vulnerabilities"].append(vuln)
        if result["protocols"].get("tlsv1.1"):
            for vuln in TLS_PROTOCOL_VULNERABILITIES.get("TLSv1.1", []):
                if vuln not in result["vulnerabilities"]:
                    result["vulnerabilities"].append(vuln)
        for cipher in result["ciphers"]:
            vuln = TLS_VULNERABLE_CIPHERS.get(cipher)
            if vuln and vuln not in result["vulnerabilities"]:
                result["vulnerabilities"].append(vuln)
        if not result["protocols"].get("tlsv1.3"):
            if "INFO: TLS 1.3 not supported" not in result["vulnerabilities"]:
                result["vulnerabilities"].append("INFO: TLS 1.3 not supported")

        cert = result["certificate"]
        if cert.get("not_after"):
            try:
                expiry = datetime.strptime(cert["not_after"], "%b %d %H:%M:%S %Y GMT")
                days_left = (expiry - datetime.utcnow()).days
                cert["days_remaining"] = days_left
                cert["valid"] = days_left > 0
                if days_left < 30 and days_left >= 0:
                    result["vulnerabilities"].append(f"Certificate expires soon ({days_left} days)")
                if days_left < 0:
                    result["vulnerabilities"].append(f"Certificate EXPIRED {-days_left} days ago")
            except Exception as e:
                logger.debug("Failed to parse certificate expiry: %s", e)
                pass

        return result

    def _parse_certificate(self, cert_dict: dict[str, Any] | None) -> dict[str, Any]:
        if not cert_dict:
            return {"valid": None}
        return {
            "subject": self._rfc2253(cert_dict.get("subject")),
            "issuer": self._rfc2253(cert_dict.get("issuer")),
            "not_before": cert_dict.get("notBefore"),
            "not_after": cert_dict.get("notAfter"),
            "serial": cert_dict.get("serialNumber"),
            "version": cert_dict.get("version"),
            "san": [item[1] for item in cert_dict.get("subjectAltName", [])],
            "algorithm": cert_dict.get("signatureAlgorithm"),
            "valid": None,
        }

    @staticmethod
    def _rfc2253(name: Any) -> str:
        if not name:
            return ""
        parts = []
        for rdn in name:
            for attr, value in rdn:
                parts.append(f"{attr}={value}")
        return ", ".join(parts)

    async def _probe_protocol(self, hostname: str, port: int, version: ssl.TLSVersion) -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except Exception as e:
            logger.debug("Failed to set TLS version to %s: %s", version, e)
            return False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=context, server_hostname=hostname),
                timeout=3.0,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as e:
                logger.debug("Error closing TLS probe connection: %s", e)
            return True
        except Exception as e:
            logger.debug("TLS protocol probe failed for %s:%d (%s): %s", hostname, port, version, e)
            return False

    async def _probe_ciphers(self, hostname: str, port: int) -> list[str]:
        supported: list[str] = []
        sem = asyncio.Semaphore(8)

        async def probe(cipher: str) -> None:
            async with sem:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                    context.set_ciphers(cipher)
                except Exception as e:
                    logger.debug("Failed to set cipher %s: %s", cipher, e)
                    return
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port, ssl=context, server_hostname=hostname),
                        timeout=1.5,
                    )
                    supported.append(cipher)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception as e:
                        logger.debug("Error closing cipher probe connection for %s: %s", cipher, e)
                except Exception as e:
                    logger.debug("Cipher probe failed for %s:%d (%s): %s", hostname, port, cipher, e)

        await asyncio.gather(*[probe(c) for c in CIPHER_PROBES])
        return sorted(supported)

    async def _save_evidence(self, request_url: str, method: str, summary: str) -> None:
        try:
            from app.database import get_connection
            async with get_connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO evidence_records (
                        request_id, scan_id, request_url, method, evidence_summary,
                        request_timestamp, module
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        self.scan_id,
                        request_url[:1000],
                        method,
                        summary[:500],
                        datetime.now(timezone.utc).isoformat(),
                        "scanner",
                    ),
                )
                await conn.commit()
        except Exception as e:
            logger.debug("Failed to save evidence record: %s", e)

    def _detect_framework(self, headers: dict[str, str], body: str) -> str:
        b = body.lower()
        if "wp-content" in b or "wp-includes" in b:
            return "WordPress"
        if "drupal" in b:
            return "Drupal"
        if "csrf-token" in b and "laravel" in b:
            return "Laravel"
        if "rails" in b or "ruby on rails" in b:
            return "Ruby on Rails"
        if "next.js" in b or "__next" in b or "nextjs" in b:
            return "Next.js"
        if "react" in b or "reactroot" in b:
            return "React"
        if "vue" in b or "vuejs" in b:
            return "Vue.js"
        if "angular" in b:
            return "Angular"
        if "express" in b:
            return "Express"
        if "django" in b:
            return "Django"
        if "flask" in b:
            return "Flask"
        if "spring" in b:
            return "Spring"
        if "asp.net" in b or "aspx" in b:
            return "ASP.NET"
        if "nginx" in headers.get("server", "").lower():
            return "Nginx"
        if "apache" in headers.get("server", "").lower():
            return "Apache"
        return "unknown"
