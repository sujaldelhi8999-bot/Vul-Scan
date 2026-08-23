import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite

logger = logging.getLogger("phantomscan.database")

from app.config import BASE_DIR, get_settings
from app.models import FindingCreate
from app.security import redact_payload, redact_sensitive

SYSTEM_TARGET_URL = "system://phantomscan"
LATEST_SCHEMA_VERSION = 16
_UNSET = object()
_db_lock = asyncio.Lock()
_db_connection: aiosqlite.Connection | None = None


async def _ensure_connection() -> aiosqlite.Connection:
    global _db_connection
    if _db_connection is None or _db_connection._connection is None:
        _db_connection = await aiosqlite.connect(DATABASE_PATH)
        _db_connection.row_factory = aiosqlite.Row
        await _db_connection.execute("PRAGMA foreign_keys = ON")
        await _db_connection.execute("PRAGMA journal_mode = WAL")
        await _db_connection.execute("PRAGMA busy_timeout = 30000")
    return _db_connection


def resolve_database_path() -> Path:
    database_url = get_settings().database_url
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise ValueError("DATABASE_URL must use the sqlite:/// URL format")
    configured_path = Path(database_url[len(prefix) :])
    if not configured_path.is_absolute():
        configured_path = BASE_DIR / configured_path
    return configured_path.resolve()


DATABASE_PATH = resolve_database_path()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'manager', 'employee')),
    permission_level TEXT NOT NULL DEFAULT 'execute' CHECK (permission_level IN ('view', 'propose', 'execute')),
    is_active INTEGER NOT NULL DEFAULT 1,
    last_login TEXT,
    subscription_tier TEXT NOT NULL DEFAULT 'FREE' CHECK (subscription_tier IN ('FREE', 'PRO', 'ENTERPRISE')),
    subscription_status TEXT NOT NULL DEFAULT 'active' CHECK (subscription_status IN ('active', 'canceled', 'past_due')),
    stripe_customer_id TEXT,
    subscription_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users (stripe_customer_id);

CREATE TABLE IF NOT EXISTS authorized_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    target_origin TEXT NOT NULL,
    verification_method TEXT NOT NULL CHECK (verification_method IN ('dns', 'http')),
    verification_token_hash TEXT NOT NULL,
    challenge_expires_at TEXT NOT NULL,
    verified_at TEXT,
    expires_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'VERIFIED', 'EXPIRED', 'REVOKED')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('defend', 'pentest', 'multi_agent')),
    intensity TEXT NOT NULL DEFAULT 'medium' CHECK (intensity IN ('low', 'medium', 'high')),
    selected_tests TEXT NOT NULL DEFAULT '[]',
    user_id TEXT NOT NULL DEFAULT 'local-user',
    enterprise_id TEXT,
    authorization_id INTEGER,
    authorization_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (authorization_confirmed IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'cancelling', 'cancelled', 'complete', 'error')),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    request_count INTEGER NOT NULL DEFAULT 0,
    sandbox_id TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (authorization_id) REFERENCES authorized_targets (id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    confidence TEXT NOT NULL CHECK (confidence IN ('CONFIRMED', 'HIGH', 'MEDIUM', 'LOW', 'POTENTIAL')),
    target TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    verification TEXT NOT NULL DEFAULT '',
    agent TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL DEFAULT '',
    how_exploited TEXT NOT NULL DEFAULT '',
    fix TEXT NOT NULL DEFAULT '',
    cve_id TEXT,
    cvss_score REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    cwe TEXT,
    version_affected TEXT,
    file_path TEXT,
    line_number INTEGER,
    code_snippet TEXT,
    fix_recommendation TEXT,
    parameter TEXT,
    module TEXT,
    recommended_fix TEXT,
    remediation_status TEXT NOT NULL DEFAULT 'OPEN' CHECK (remediation_status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')),
    verification_status TEXT NOT NULL DEFAULT 'NOT_VERIFIED' CHECK (verification_status IN ('NOT_VERIFIED', 'FIX_VERIFIED', 'ISSUE_STILL_PRESENT', 'VERIFY_FAILED')),
    risk_status TEXT NOT NULL DEFAULT 'ACTIVE',
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT NOT NULL,
    user_id TEXT,
    target TEXT,
    authorization_status TEXT,
    selected_module TEXT,
    start_time TEXT,
    end_time TEXT,
    result TEXT,
    request_count INTEGER,
    sandbox_id TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE TABLE IF NOT EXISTS scan_artifacts (
    scan_id INTEGER PRIMARY KEY,
    scanner_output TEXT,
    shadow_recon_output TEXT,
    hindi_findings TEXT,
    markdown_report TEXT,
    notification_result TEXT,
    active_security_output TEXT,
    browser_security_output TEXT,
    ai_analyst_output TEXT,
    exploitation_output TEXT,
    tci_output TEXT,
    ai_consultation TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    execution_time REAL,
    attempts INTEGER NOT NULL DEFAULT 1,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_scan_id ON agent_runs (scan_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_agent_name ON agent_runs (agent_name);

CREATE TABLE IF NOT EXISTS scan_event_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    event_data TEXT,
    agent_name TEXT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_event_logs_scan_id ON scan_event_logs (scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_event_logs_event_type ON scan_event_logs (event_type);

CREATE TABLE IF NOT EXISTS audit_log_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL UNIQUE,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    color TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name TEXT NOT NULL,
    run_id TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL CHECK (status IN ('idle', 'active', 'complete', 'error')),
    tasks_completed INTEGER NOT NULL DEFAULT 0,
    tasks_failed INTEGER NOT NULL DEFAULT 0,
    execution_time REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES agent_runs (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_scan_id ON audit_logs (scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_agent_name ON audit_logs (agent_name, id);
CREATE TABLE IF NOT EXISTS authorized_test_jobs (
    id TEXT PRIMARY KEY,
    authorization_id INTEGER,
    target_url TEXT NOT NULL,
    normalized_target_origin TEXT NOT NULL,
    selected_modules TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    current_module TEXT,
    current_phase TEXT,
    surfaces_total INTEGER NOT NULL DEFAULT 0,
    surfaces_completed INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    completed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,
    error_code TEXT,
    result_summary TEXT,
    scan_id INTEGER,
    FOREIGN KEY (authorization_id) REFERENCES authorized_targets (id)
);

CREATE INDEX IF NOT EXISTS idx_authorized_test_jobs_status ON authorized_test_jobs (status);
CREATE INDEX IF NOT EXISTS idx_authorized_test_jobs_target ON authorized_test_jobs (normalized_target_origin, status);
CREATE INDEX IF NOT EXISTS idx_authorized_targets_lookup ON authorized_targets (user_id, target_origin, status);

CREATE TABLE IF NOT EXISTS execution_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_type TEXT,
    lifecycle TEXT NOT NULL DEFAULT 'IDLE' CHECK (lifecycle IN ('IDLE', 'QUEUED', 'STARTING', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED')),
    job_id TEXT,
    scan_id INTEGER,
    target_url TEXT NOT NULL DEFAULT '',
    progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    current_module TEXT,
    current_phase TEXT,
    surfaces_total INTEGER NOT NULL DEFAULT 0,
    surfaces_completed INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    agent_states TEXT NOT NULL DEFAULT '[]',
    started_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    error_message TEXT,
    error_code TEXT,
    is_lab INTEGER NOT NULL DEFAULT 0,
    authorization_status TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS job_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    module TEXT,
    event_type TEXT NOT NULL,
    message TEXT,
    status TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES authorized_test_jobs (id)
);

CREATE INDEX IF NOT EXISTS idx_job_events_job_id_seq ON job_events (job_id, sequence_number);

CREATE TABLE IF NOT EXISTS evidence_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    job_id TEXT,
    scan_id INTEGER,
    module TEXT NOT NULL DEFAULT '',
    surface TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    request_url TEXT NOT NULL DEFAULT '',
    safe_test_marker TEXT NOT NULL DEFAULT '',
    request_timestamp TEXT NOT NULL,
    response_status INTEGER,
    response_time_ms INTEGER,
    response_observed INTEGER NOT NULL DEFAULT 0,
    detection_result TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
    evidence_summary TEXT NOT NULL DEFAULT '',
    finding_id INTEGER,
    error TEXT,
    FOREIGN KEY (job_id) REFERENCES authorized_test_jobs (id),
    FOREIGN KEY (finding_id) REFERENCES findings (id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_job_id ON evidence_records (job_id);
CREATE INDEX IF NOT EXISTS idx_evidence_request_id ON evidence_records (request_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_records (finding_id);

CREATE TABLE IF NOT EXISTS learning_insights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    module TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'module' CHECK (kind IN ('module', 'scan')),
    total_count INTEGER NOT NULL DEFAULT 0,
    true_positives INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    unrated_count INTEGER NOT NULL DEFAULT 0,
    true_positive_rate REAL NOT NULL DEFAULT 0,
    false_positive_rate REAL NOT NULL DEFAULT 0,
    recommendation TEXT,
    recommendation_data TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'dismissed')),
    applied_settings TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
    UNIQUE (scan_id, module, kind)
);

CREATE INDEX IF NOT EXISTS idx_learning_insights_scan ON learning_insights (scan_id);
CREATE INDEX IF NOT EXISTS idx_learning_insights_module ON learning_insights (module, status);

CREATE TABLE IF NOT EXISTS dos_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL UNIQUE,
    target_url TEXT NOT NULL,
    intensity TEXT NOT NULL,
    duration INTEGER NOT NULL,
    status TEXT NOT NULL,
    requests_sent INTEGER DEFAULT 0,
    responses_received INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    baseline_latency REAL NOT NULL DEFAULT 0,
    peak_latency REAL NOT NULL DEFAULT 0,
    avg_latency_during REAL NOT NULL DEFAULT 0,
    recovery_latency REAL NOT NULL DEFAULT 0,
    impact_score REAL NOT NULL DEFAULT 0,
    effective INTEGER NOT NULL DEFAULT 0,
    website_status TEXT NOT NULL DEFAULT 'unknown',
    health_score REAL NOT NULL DEFAULT 100,
    p95_latency REAL NOT NULL DEFAULT 0,
    p99_latency REAL NOT NULL DEFAULT 0,
    jitter_ms REAL NOT NULL DEFAULT 0,
    error_rate REAL NOT NULL DEFAULT 0,
    throughput_mbps REAL NOT NULL DEFAULT 0,
    total_requests INTEGER NOT NULL DEFAULT 0,
    status_2xx INTEGER NOT NULL DEFAULT 0,
    status_3xx INTEGER NOT NULL DEFAULT 0,
    status_4xx INTEGER NOT NULL DEFAULT 0,
    status_5xx INTEGER NOT NULL DEFAULT 0,
    total_data_mb REAL NOT NULL DEFAULT 0,
    avg_dns_ms REAL NOT NULL DEFAULT 0,
    avg_tcp_ms REAL NOT NULL DEFAULT 0,
    avg_tls_ms REAL NOT NULL DEFAULT 0,
    avg_ttfb_ms REAL NOT NULL DEFAULT 0,
    packet_loss REAL NOT NULL DEFAULT 0,
    recovery_ratio REAL NOT NULL DEFAULT 0,
    recovered INTEGER NOT NULL DEFAULT 1,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stopped_at TIMESTAMP,
    user_id TEXT,
    scan_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_dos_jobs_status ON dos_jobs(status);
CREATE INDEX IF NOT EXISTS idx_dos_jobs_target ON dos_jobs(target_url);

CREATE TABLE IF NOT EXISTS private_scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT UNIQUE NOT NULL,
    added_by TEXT DEFAULT 'admin',
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used TEXT
);

CREATE INDEX IF NOT EXISTS idx_private_scope_target_url ON private_scope (target_url);

CREATE TABLE IF NOT EXISTS shadow_recon_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL UNIQUE,
    emails TEXT,
    internal_ips TEXT,
    js_source_maps TEXT,
    html_comments TEXT,
    sensitive_files TEXT,
    robots_txt_content TEXT,
    sitemap_urls TEXT,
    wayback_urls TEXT,
    crtsh_subdomains TEXT,
    all_subdomains TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_shadow_recon_scan_id ON shadow_recon_results (scan_id);

CREATE TABLE IF NOT EXISTS exploitation_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    scan_id INTEGER NOT NULL,
    vulnerability_type TEXT NOT NULL,
    target_url TEXT,
    database_type TEXT,
    tables_extracted TEXT,
    extracted_data TEXT,
    raw_result TEXT,
    status TEXT NOT NULL DEFAULT 'completed',
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE SET NULL,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs are append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs are append-only');
END;

-- Multi-source scanning tables
CREATE TABLE IF NOT EXISTS scan_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('local', 'github', 'gitlab', 'bitbucket', 'live', 'api_spec', 'docker', 'kubernetes', 'terraform')),
    source_config TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    priority INTEGER NOT NULL DEFAULT 1,
    findings_count INTEGER NOT NULL DEFAULT 0,
    scan_duration_seconds REAL NOT NULL DEFAULT 0,
    error_message TEXT,
    artifacts TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_sources_scan_id ON scan_sources (scan_id);

CREATE TABLE IF NOT EXISTS github_oauth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    github_user_id INTEGER NOT NULL,
    github_login TEXT NOT NULL,
    access_token_encrypted TEXT NOT NULL,
    refresh_token_encrypted TEXT,
    token_type TEXT DEFAULT 'bearer',
    scope TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, github_user_id)
);

CREATE INDEX IF NOT EXISTS idx_github_oauth_user_id ON github_oauth_tokens (user_id);

CREATE TABLE IF NOT EXISTS github_oauth_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    state TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_github_oauth_states_user_id ON github_oauth_states (user_id);

CREATE TABLE IF NOT EXISTS github_app_installations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    installation_id INTEGER NOT NULL,
    account_login TEXT NOT NULL,
    account_type TEXT NOT NULL,
    repository_selection TEXT NOT NULL,
    permissions TEXT NOT NULL,
    events TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, installation_id)
);

CREATE INDEX IF NOT EXISTS idx_github_app_user_id ON github_app_installations (user_id);

CREATE TABLE IF NOT EXISTS source_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    unified_id TEXT NOT NULL,
    correlation_type TEXT NOT NULL CHECK (correlation_type IN ('exact_match', 'same_file', 'same_endpoint', 'data_flow', 'vulnerability_chain')),
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    source_types TEXT NOT NULL,
    finding_ids TEXT NOT NULL,
    evidence TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_source_correlations_scan_id ON source_correlations (scan_id);
CREATE INDEX IF NOT EXISTS idx_source_correlations_unified_id ON source_correlations (unified_id);

CREATE TABLE IF NOT EXISTS finding_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('local', 'github', 'gitlab', 'bitbucket', 'live', 'api_spec', 'docker', 'kubernetes', 'terraform')),
    source_identifier TEXT NOT NULL,
    location TEXT,
    tool TEXT,
    rule_id TEXT,
    commit_sha TEXT,
    branch TEXT,
    pr_number INTEGER,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_sources_finding_id ON finding_sources (finding_id);

CREATE TABLE IF NOT EXISTS sast_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE,
    language TEXT NOT NULL,
    framework TEXT,
    file_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    start_column INTEGER,
    end_column INTEGER,
    function_name TEXT,
    class_name TEXT,
    code_snippet TEXT,
    rule_id TEXT NOT NULL,
rule_name TEXT,
    rule_severity TEXT,
    tool TEXT NOT NULL,
    "references" TEXT,
    cwe_ids TEXT,
    owasp_category TEXT,
    fix_suggestion TEXT,
    fix_example TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sast_findings_file_path ON sast_findings (file_path);
CREATE INDEX IF NOT EXISTS idx_sast_findings_rule_id ON sast_findings (rule_id);

CREATE TABLE IF NOT EXISTS secret_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE,
    secret_type TEXT NOT NULL,
    detector_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    matched_content TEXT,
    entropy REAL,
    is_validated INTEGER NOT NULL DEFAULT 0,
    validation_error TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iac_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE,
    resource_type TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    configuration TEXT,
    misconfiguration_type TEXT NOT NULL,
    platform TEXT NOT NULL CHECK (platform IN ('terraform', 'kubernetes', 'cloudformation', 'helm', 'dockerfile')),
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sca_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    vulnerable_versions TEXT NOT NULL,
    fixed_version TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    license TEXT,
    is_direct INTEGER NOT NULL DEFAULT 1,
    dependency_path TEXT,
    advisory_url TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_code_fixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    patch TEXT NOT NULL,
    explanation TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    fix_type TEXT NOT NULL,
    verification_steps TEXT,
    related_cwe TEXT,
    estimated_effort TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'verified', 'rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    applied_at TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ai_code_fixes_finding_id ON ai_code_fixes (finding_id);

CREATE TABLE IF NOT EXISTS ai_tutor_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    finding_id INTEGER,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    explanation TEXT,
    code_examples TEXT,
    "references" TEXT,
    follow_up_questions TEXT,
    confidence REAL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_tutor_user_id ON ai_tutor_sessions (user_id);

CREATE TABLE IF NOT EXISTS pr_descriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_ids TEXT NOT NULL,
    base_branch TEXT NOT NULL,
    head_branch TEXT NOT NULL,
    repo_url TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    labels TEXT,
    reviewers TEXT,
    related_issues TEXT,
    status TEXT NOT NULL DEFAULT 'generated' CHECK (status IN ('generated', 'submitted', 'merged', 'rejected')),
    pr_url TEXT,
    pr_number INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);
"""


SCANS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('defend', 'pentest', 'multi_agent')),
    intensity TEXT NOT NULL DEFAULT 'medium' CHECK (intensity IN ('low', 'medium', 'high')),
    selected_tests TEXT NOT NULL DEFAULT '[]',
    user_id TEXT NOT NULL DEFAULT 'local-user',
    enterprise_id TEXT,
    authorization_id INTEGER,
    authorization_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (authorization_confirmed IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'cancelling', 'cancelled', 'complete', 'error')),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    request_count INTEGER NOT NULL DEFAULT 0,
    sandbox_id TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (authorization_id) REFERENCES authorized_targets (id)
);
"""


SCANS_MODE_LEGACY_MARKER = "CHECK (mode IN ('defend', 'pentest'))"


@asynccontextmanager
async def get_connection() -> AsyncIterator[aiosqlite.Connection]:
    async with _db_lock:
        connection = await _ensure_connection()
    for attempt in range(3):
        try:
            yield connection
            return
        except aiosqlite.OperationalError as exc:
            if "database is locked" not in str(exc).lower() or attempt == 2:
                raise
            delay = 0.1 * (2 ** attempt)
            logger.debug("DB locked, retry %d in %.1fs", attempt + 1, delay)
            await asyncio.sleep(delay)


def serialize_row(row: Any | None) -> dict[str, Any] | None:
    return None if row is None else dict(row)


async def _table_exists(connection: aiosqlite.Connection, table: str) -> bool:
    cursor = await connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,))
    return await cursor.fetchone() is not None


async def _column_exists(connection: aiosqlite.Connection, table: str, column: str) -> bool:
    cursor = await connection.execute(f"PRAGMA table_info({table})")
    return any(row["name"] == column for row in await cursor.fetchall())


async def _migrate_evidence_job_id_nullable(connection: aiosqlite.Connection) -> None:
    """Rebuild evidence_records when job_id was created NOT NULL (stale schema).

    The declared schema allows NULL job_id so scan-flow active tests (which
    have no authorized-test job) can persist evidence records.
    """
    if not await _table_exists(connection, "evidence_records"):
        return
    cursor = await connection.execute("PRAGMA table_info(evidence_records)")
    columns = {row["name"]: row for row in await cursor.fetchall()}
    if "job_id" not in columns or columns["job_id"]["notnull"] == 0:
        return
    await connection.execute("PRAGMA foreign_keys = OFF")
    await connection.executescript(
        """
        CREATE TABLE evidence_records_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            job_id TEXT,
            scan_id INTEGER,
            module TEXT NOT NULL DEFAULT '',
            surface TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT '',
            request_url TEXT NOT NULL DEFAULT '',
            safe_test_marker TEXT NOT NULL DEFAULT '',
            request_timestamp TEXT NOT NULL,
            response_status INTEGER,
            response_time_ms INTEGER,
            response_observed INTEGER NOT NULL DEFAULT 0,
            detection_result TEXT NOT NULL DEFAULT 'INCONCLUSIVE',
            evidence_summary TEXT NOT NULL DEFAULT '',
            finding_id INTEGER,
            error TEXT,
            FOREIGN KEY (job_id) REFERENCES authorized_test_jobs (id),
            FOREIGN KEY (finding_id) REFERENCES findings (id)
        );
        INSERT INTO evidence_records_new (
            id, request_id, job_id, scan_id, module, surface, method, request_url,
            safe_test_marker, request_timestamp, response_status, response_time_ms,
            response_observed, detection_result, evidence_summary, finding_id, error
        )
        SELECT
            id, request_id, job_id, scan_id, module, surface, method, request_url,
            safe_test_marker, request_timestamp, response_status, response_time_ms,
            response_observed, detection_result, evidence_summary, finding_id, error
        FROM evidence_records;
        DROP TABLE evidence_records;
        ALTER TABLE evidence_records_new RENAME TO evidence_records;
        CREATE INDEX IF NOT EXISTS idx_evidence_job_id ON evidence_records (job_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_request_id ON evidence_records (request_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_records (finding_id);
        """
    )
    await connection.commit()
    await connection.execute("PRAGMA foreign_keys = ON")


async def _migrate_scans_mode_check(connection: aiosqlite.Connection) -> None:
    """Rebuild the scans table when its mode CHECK predates the multi_agent mode."""
    cursor = await connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
    )
    row = await cursor.fetchone()
    if row is None or SCANS_MODE_LEGACY_MARKER not in str(row["sql"]):
        return
    create_new = SCANS_TABLE_SQL.replace(
        "CREATE TABLE IF NOT EXISTS scans ", "CREATE TABLE scans_new "
    )
    enterprise_select = "enterprise_id" if await _column_exists(connection, "scans", "enterprise_id") else "NULL"
    await connection.execute("PRAGMA foreign_keys = OFF")
    await connection.executescript(
        create_new
        + f"""
        INSERT INTO scans_new (
            id, target_url, mode, intensity, selected_tests, user_id, {enterprise_select}, authorization_id,
            authorization_confirmed, status, progress, request_count, sandbox_id,
            error_message, created_at, started_at, completed_at
        )
        SELECT
            id, target_url, mode, intensity, selected_tests, user_id, enterprise_id, authorization_id,
            authorization_confirmed, status, progress, request_count, sandbox_id,
            error_message, created_at, started_at, completed_at
        FROM scans;
        DROP TABLE scans;
        ALTER TABLE scans_new RENAME TO scans;
        """
    )
    await connection.commit()
    await connection.execute("PRAGMA foreign_keys = ON")


async def initialize_database() -> None:
    async with get_connection() as connection:
        if not await _table_exists(connection, "scans"):
            await connection.executescript(SCHEMA_SQL)
            await connection.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION}")
            await connection.commit()
            # Fall through to the migration block below (guarded by
            # _table_exists/_column_exists, so idempotent) so fresh databases
            # also get the migration-only tables (brutal_ops, sast_findings, ...).

        if not await _column_exists(connection, "findings", "confidence"):
            await _migrate_legacy_schema(connection)
            return

        await connection.executescript(SCHEMA_SQL)
        await _migrate_scans_mode_check(connection)
        await _migrate_active_finding_columns(connection)
        await _migrate_active_artifact_columns(connection)
        await _migrate_browser_artifact_columns(connection)
        await _migrate_exploitation_artifact_column(connection)
        await _migrate_tci_artifact_column(connection)
        await _migrate_ai_columns(connection)
        await _migrate_authorized_test_jobs_table(connection)
        await _migrate_job_events_table(connection)
        await _migrate_evidence_job_id_nullable(connection)
        await _migrate_execution_status_table(connection)
        await _migrate_shadow_recon_table(connection)
        await _migrate_shadow_recon_columns(connection)
        await _migrate_scan_artifact_recon_columns(connection)
        await _migrate_dos_metrics_columns(connection)
        # Multi-source scanning migrations
        await _migrate_scan_sources_table(connection)
        await _migrate_github_oauth_table(connection)
        await _migrate_github_oauth_states_table(connection)
        await _migrate_github_app_table(connection)
        await _migrate_source_correlations_table(connection)
        await _migrate_finding_sources_table(connection)
        await _migrate_sast_findings_table(connection)
        await _migrate_secret_findings_table(connection)
        await _migrate_iac_findings_table(connection)
        await _migrate_sca_findings_table(connection)
        await _migrate_ai_code_fixes_table(connection)
        await _migrate_ai_tutor_sessions_table(connection)
        await _migrate_pr_descriptions_table(connection)
        await _migrate_findings_correlation_columns(connection)
        await _migrate_finding_attribution_columns(connection)
        await _migrate_scan_duration_limit_column(connection)
        await _migrate_brutal_ops_table(connection)
        await _migrate_brutal_sessions_table(connection)
        await _migrate_users_enterprise(connection)
        await _migrate_enterprise_tables(connection)
        await connection.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION}")
        await connection.commit()


async def _migrate_legacy_schema(connection: aiosqlite.Connection) -> None:
    await connection.execute("PRAGMA foreign_keys = OFF")
    await connection.executescript(
        """
        DROP TRIGGER IF EXISTS audit_logs_no_delete;
        DROP TRIGGER IF EXISTS audit_logs_no_update;
        ALTER TABLE scans RENAME TO scans_legacy;
        ALTER TABLE findings RENAME TO findings_legacy;
        ALTER TABLE audit_logs RENAME TO audit_logs_legacy;
        """
    )
    await connection.executescript(SCHEMA_SQL)
    await connection.executescript(
        """
        INSERT INTO scans (
            id, target_url, mode, intensity, selected_tests, user_id, authorization_confirmed,
            status, progress, request_count, created_at, started_at, completed_at
        )
        SELECT
            id, target_url, mode, 'medium', '[]', 'local-user', 0,
            status, CASE WHEN status = 'complete' THEN 100 ELSE 0 END, 0,
            created_at, created_at, completed_at
        FROM scans_legacy;

        INSERT INTO findings (
            id, scan_id, title, category, severity, confidence, target, endpoint, evidence,
            impact, recommendation, verification, agent, timestamp, description,
            how_exploited, fix, cve_id, cvss_score
        )
        SELECT
            f.id,
            f.scan_id,
            f.title,
            f.category,
            CASE UPPER(f.severity)
                WHEN 'CRITICAL' THEN 'CRITICAL'
                WHEN 'HIGH' THEN 'HIGH'
                WHEN 'MEDIUM' THEN 'MEDIUM'
                WHEN 'LOW' THEN 'LOW'
                ELSE 'INFO'
            END,
            'MEDIUM',
            COALESCE((SELECT target_url FROM scans_legacy WHERE id = f.scan_id), 'unknown'),
            COALESCE((SELECT target_url FROM scans_legacy WHERE id = f.scan_id), ''),
            f.description,
            f.how_exploited,
            f.fix,
            'Deploy the recommended fix and rerun the relevant PhantomScan check.',
            'Legacy Agent',
            COALESCE((SELECT created_at FROM scans_legacy WHERE id = f.scan_id), CURRENT_TIMESTAMP),
            f.description,
            f.how_exploited,
            f.fix,
            f.cve_id,
            f.cvss_score
        FROM findings_legacy AS f;

        INSERT INTO audit_logs (id, scan_id, agent_name, action, timestamp, details)
        SELECT id, scan_id, agent_name, action, timestamp, details FROM audit_logs_legacy;

        DROP TABLE findings_legacy;
        DROP TABLE audit_logs_legacy;
        DROP TABLE scans_legacy;
        """
    )
    # Renamed legacy indexes retain their old names until the legacy tables are dropped.
    await connection.executescript(SCHEMA_SQL)
    await connection.execute(f"PRAGMA user_version = {LATEST_SCHEMA_VERSION}")
    await connection.commit()
    await connection.execute("PRAGMA foreign_keys = ON")


async def _migrate_active_finding_columns(connection: aiosqlite.Connection) -> None:
    columns = [
        ("parameter", "TEXT"),
        ("module", "TEXT"),
        ("recommended_fix", "TEXT"),
        ("remediation_status", "TEXT NOT NULL DEFAULT 'OPEN'"),
        ("verification_status", "TEXT NOT NULL DEFAULT 'NOT_VERIFIED'"),
    ]
    for column, definition in columns:
        if not await _column_exists(connection, "findings", column):
            await connection.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")


async def _migrate_finding_attribution_columns(connection: aiosqlite.Connection) -> None:
    columns = [
        ("file_path", "TEXT"),
        ("line_number", "INTEGER"),
        ("code_snippet", "TEXT"),
        ("fix_recommendation", "TEXT"),
    ]
    for column, definition in columns:
        if not await _column_exists(connection, "findings", column):
            await connection.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")


async def _migrate_scan_duration_limit_column(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "scans", "max_duration_minutes"):
        await connection.execute("ALTER TABLE scans ADD COLUMN max_duration_minutes INTEGER DEFAULT 120")


async def _migrate_active_artifact_columns(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "scan_artifacts", "active_security_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN active_security_output TEXT")


async def _migrate_browser_artifact_columns(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "scan_artifacts", "browser_security_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN browser_security_output TEXT")


async def _migrate_exploitation_artifact_column(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "scan_artifacts", "exploitation_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN exploitation_output TEXT")


async def _migrate_tci_artifact_column(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "scan_artifacts", "tci_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN tci_output TEXT")


async def _migrate_users_enterprise(connection: aiosqlite.Connection) -> None:
    """Upgrade the users table for enterprise accounts.

    SQLite cannot alter CHECK constraints in place, so installations created
    before enterprise support are rebuilt while preserving existing users.
    """
    for column, definition in [
        ("permission_level", "TEXT NOT NULL DEFAULT 'execute'"),
        ("is_active", "INTEGER NOT NULL DEFAULT 1"),
        ("last_login", "TEXT"),
    ]:
        if not await _column_exists(connection, "users", column):
            await connection.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")

    cursor = await connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
    )
    row = await cursor.fetchone()
    ddl = str(row["sql"] if row else "").lower()
    if ddl and ("manager" not in ddl or "enterprise" not in ddl):
        await connection.execute("PRAGMA foreign_keys = OFF")
        await connection.executescript(
            """
            CREATE TABLE users_enterprise (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'manager', 'employee')),
                permission_level TEXT NOT NULL DEFAULT 'execute' CHECK (permission_level IN ('view', 'propose', 'execute')),
                is_active INTEGER NOT NULL DEFAULT 1,
                last_login TEXT,
                subscription_tier TEXT NOT NULL DEFAULT 'FREE' CHECK (subscription_tier IN ('FREE', 'PRO', 'ENTERPRISE')),
                subscription_status TEXT NOT NULL DEFAULT 'active' CHECK (subscription_status IN ('active', 'canceled', 'past_due')),
                stripe_customer_id TEXT,
                subscription_expires_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO users_enterprise (
                id, email, password_hash, name, role, permission_level, is_active, last_login, subscription_tier,
                subscription_status, stripe_customer_id, subscription_expires_at,
                created_at, updated_at
            )
            SELECT id, email, password_hash, name, role, permission_level, is_active, last_login, subscription_tier,
                   subscription_status, stripe_customer_id, subscription_expires_at,
                   created_at, updated_at
            FROM users;
            DROP TABLE users;
            ALTER TABLE users_enterprise RENAME TO users;
            CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
            CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users (stripe_customer_id);
            """
        )
        await connection.execute("PRAGMA foreign_keys = ON")


ENTERPRISE_ORGANIZATION_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS enterprises (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    allowed_email_domains TEXT NOT NULL DEFAULT '[]',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enterprise_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enterprise_id TEXT NOT NULL,
    user_id TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'manager', 'employee')),
    max_severity TEXT NOT NULL DEFAULT 'LOW' CHECK (max_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ALL')),
    can_request_audit INTEGER NOT NULL DEFAULT 0 CHECK (can_request_audit IN (0, 1)),
    can_request_fix INTEGER NOT NULL DEFAULT 0 CHECK (can_request_fix IN (0, 1)),
    can_approve INTEGER NOT NULL DEFAULT 0 CHECK (can_approve IN (0, 1)),
    can_manage_members INTEGER NOT NULL DEFAULT 0 CHECK (can_manage_members IN (0, 1)),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (enterprise_id, user_id),
    FOREIGN KEY (enterprise_id) REFERENCES enterprises (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_enterprise_memberships_enterprise ON enterprise_memberships (enterprise_id, is_active);
CREATE INDEX IF NOT EXISTS idx_enterprise_memberships_user ON enterprise_memberships (user_id, is_active);
"""


ENTERPRISE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS enterprise_approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enterprise_id TEXT NOT NULL,
    employee_id TEXT NOT NULL,
    manager_id TEXT,
    request_type TEXT NOT NULL CHECK (request_type IN (
        'scan', 'add_target', 'remove_target', 'enable_brutal_mode',
        'intensity_change', 'share_report', 'delete_finding', 'change_settings',
        'github_push', 'code_audit', 'code_fix', 'remediation'
    )),
    target_url TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    urgency TEXT NOT NULL DEFAULT 'normal' CHECK (urgency IN ('low', 'normal', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'started', 'completed')),
    decided_by TEXT,
    decided_at TEXT,
    comment TEXT,
    started_at TEXT,
    completed_at TEXT,
    execution_result TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enterprise_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enterprise_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enterprise_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info' CHECK (type IN ('info', 'success', 'warning', 'error')),
    title TEXT NOT NULL,
    body TEXT,
    link TEXT,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ent_notifications_user ON enterprise_notifications (user_id);
"""


async def _migrate_enterprise_tables(connection: aiosqlite.Connection) -> None:
    await connection.executescript(ENTERPRISE_ORGANIZATION_TABLES_SQL)
    cursor = await connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'enterprise_approval_requests'"
    )
    row = await cursor.fetchone()
    ddl = str(row["sql"] if row else "").lower()
    if row and ("code_audit" not in ddl or "enterprise_id" not in ddl or "started" not in ddl):
        # SQLite cannot alter a CHECK constraint in place. Rebuild this small
        # table so existing installations can use tenant-scoped requests.
        cursor = await connection.execute("PRAGMA table_info(enterprise_approval_requests)")
        old_columns = {str(item["name"]) for item in await cursor.fetchall()}

        def old_value(column: str, fallback: str) -> str:
            return column if column in old_columns else fallback

        await connection.execute("PRAGMA foreign_keys = OFF")
        await connection.executescript(
            f"""
            CREATE TABLE enterprise_approval_requests_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enterprise_id TEXT NOT NULL,
                employee_id TEXT NOT NULL,
                manager_id TEXT,
                request_type TEXT NOT NULL CHECK (request_type IN (
                    'scan', 'add_target', 'remove_target', 'enable_brutal_mode',
                    'intensity_change', 'share_report', 'delete_finding', 'change_settings',
                    'github_push', 'code_audit', 'code_fix', 'remediation'
                )),
                target_url TEXT,
                details TEXT NOT NULL DEFAULT '{{}}',
                urgency TEXT NOT NULL DEFAULT 'normal' CHECK (urgency IN ('low', 'normal', 'high', 'critical')),
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'started', 'completed')),
                decided_by TEXT,
                decided_at TEXT,
                comment TEXT,
                started_at TEXT,
                completed_at TEXT,
                execution_result TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            INSERT INTO enterprise_approval_requests_new (
                id, enterprise_id, employee_id, manager_id, request_type, target_url, details,
                urgency, status, decided_by, decided_at, comment, started_at, completed_at,
                execution_result, created_at
            )
            SELECT
                id, {old_value('enterprise_id', "''")}, employee_id, manager_id, request_type, target_url, details,
                urgency, status, decided_by, decided_at, comment, {old_value('started_at', 'NULL')},
                {old_value('completed_at', 'NULL')}, {old_value('execution_result', 'NULL')}, created_at
            FROM enterprise_approval_requests;

            DROP TABLE enterprise_approval_requests;
            ALTER TABLE enterprise_approval_requests_new RENAME TO enterprise_approval_requests;
            CREATE INDEX IF NOT EXISTS idx_ent_approvals_employee ON enterprise_approval_requests (employee_id);
            CREATE INDEX IF NOT EXISTS idx_ent_approvals_status ON enterprise_approval_requests (status);
            CREATE INDEX IF NOT EXISTS idx_ent_approvals_enterprise ON enterprise_approval_requests (enterprise_id, status);
            """
        )
        await connection.execute("PRAGMA foreign_keys = ON")
    await connection.executescript(ENTERPRISE_TABLES_SQL)

    for table, column, definition in [
        ("scans", "enterprise_id", "TEXT"),
        ("authorized_targets", "enterprise_id", "TEXT"),
        ("private_scope", "enterprise_id", "TEXT"),
        ("authorized_test_jobs", "enterprise_id", "TEXT"),
        ("authorized_test_jobs", "user_id", "TEXT"),
        ("enterprise_audit_logs", "enterprise_id", "TEXT"),
    ]:
        if await _table_exists(connection, table) and not await _column_exists(connection, table, column):
            await connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    await connection.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_scans_enterprise_id ON scans (enterprise_id);
        CREATE INDEX IF NOT EXISTS idx_authorized_targets_enterprise ON authorized_targets (enterprise_id, target_origin);
        CREATE INDEX IF NOT EXISTS idx_private_scope_enterprise ON private_scope (enterprise_id, target_url);
        CREATE INDEX IF NOT EXISTS idx_authorized_jobs_enterprise ON authorized_test_jobs (enterprise_id, status);
        CREATE INDEX IF NOT EXISTS idx_ent_approvals_employee ON enterprise_approval_requests (employee_id);
        CREATE INDEX IF NOT EXISTS idx_ent_approvals_status ON enterprise_approval_requests (status);
        CREATE INDEX IF NOT EXISTS idx_ent_approvals_enterprise ON enterprise_approval_requests (enterprise_id, status);
        CREATE INDEX IF NOT EXISTS idx_ent_audit_user ON enterprise_audit_logs (user_id);
        CREATE INDEX IF NOT EXISTS idx_ent_audit_enterprise ON enterprise_audit_logs (enterprise_id, timestamp);
        """
    )


AUTHORIZED_TEST_JOBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorized_test_jobs (
    id TEXT PRIMARY KEY,
    authorization_id INTEGER,
    target_url TEXT NOT NULL,
    normalized_target_origin TEXT NOT NULL,
    selected_modules TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    current_module TEXT,
    current_phase TEXT,
    surfaces_total INTEGER NOT NULL DEFAULT 0,
    surfaces_completed INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    completed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    error_message TEXT,
    error_code TEXT,
    result_summary TEXT,
    scan_id INTEGER,
    FOREIGN KEY (authorization_id) REFERENCES authorized_targets (id)
);
CREATE INDEX IF NOT EXISTS idx_authorized_test_jobs_status ON authorized_test_jobs (status);
CREATE INDEX IF NOT EXISTS idx_authorized_test_jobs_target ON authorized_test_jobs (normalized_target_origin, status);
"""


async def _migrate_authorized_test_jobs_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "authorized_test_jobs"):
        await connection.executescript(AUTHORIZED_TEST_JOBS_SCHEMA)


async def _migrate_job_events_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "job_events"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS job_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                module TEXT,
                event_type TEXT NOT NULL,
                message TEXT,
                status TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (job_id) REFERENCES authorized_test_jobs (id)
            );
"""
        )
    await _migrate_job_surface_columns(connection)


async def _migrate_job_surface_columns(connection: aiosqlite.Connection) -> None:
    for col, definition in [
        ("raw_surfaces_discovered", "INTEGER NOT NULL DEFAULT 0"),
        ("testable_surfaces", "INTEGER NOT NULL DEFAULT 0"),
        ("surface_groups", "INTEGER NOT NULL DEFAULT 0"),
    ]:
        if not await _column_exists(connection, "authorized_test_jobs", col):
            await connection.execute(f"ALTER TABLE authorized_test_jobs ADD COLUMN {col} {definition}")


async def _migrate_ai_columns(connection: aiosqlite.Connection) -> None:
    if not await _column_exists(connection, "findings", "risk_status"):
        await connection.execute("ALTER TABLE findings ADD COLUMN risk_status TEXT NOT NULL DEFAULT 'ACTIVE'")
    if not await _column_exists(connection, "scan_artifacts", "ai_analyst_output"):
        await connection.execute("ALTER TABLE scan_artifacts ADD COLUMN ai_analyst_output TEXT")
    await connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_cache (
            cache_key TEXT PRIMARY KEY,
            finding_id INTEGER,
            evidence_hash TEXT NOT NULL,
            language TEXT NOT NULL,
            model TEXT NOT NULL,
            response TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


async def _migrate_shadow_recon_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "shadow_recon_results"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS shadow_recon_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL UNIQUE,
                emails TEXT,
                internal_ips TEXT,
                js_source_maps TEXT,
                html_comments TEXT,
                sensitive_files TEXT,
                robots_txt_content TEXT,
                sitemap_urls TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_shadow_recon_scan_id ON shadow_recon_results (scan_id);
            """
        )


async def _migrate_shadow_recon_columns(connection: aiosqlite.Connection) -> None:
    for col, definition in [
        ("wayback_urls", "TEXT"),
        ("crtsh_subdomains", "TEXT"),
        ("all_subdomains", "TEXT"),
    ]:
        if not await _column_exists(connection, "shadow_recon_results", col):
            await connection.execute(f"ALTER TABLE shadow_recon_results ADD COLUMN {col} {definition}")


async def _migrate_scan_artifact_recon_columns(connection: aiosqlite.Connection) -> None:
    for col, definition in [
        ("ports_open", "TEXT"),
        ("technologies", "TEXT"),
        ("server_header", "TEXT"),
        ("waf_detected", "TEXT"),
        ("cdn_detected", "TEXT"),
        ("dns_records", "TEXT"),
        ("tls_version", "TEXT"),
        ("tls_cipher", "TEXT"),
        ("tls_expiry", "TEXT"),
         ("tls_valid", "INTEGER"),
         ("body_technologies", "TEXT"),
     ]:
        if not await _column_exists(connection, "scan_artifacts", col):
            await connection.execute(f"ALTER TABLE scan_artifacts ADD COLUMN {col} {definition}")


async def _migrate_dos_metrics_columns(connection: aiosqlite.Connection) -> None:
    columns = [
        ("baseline_latency", "REAL NOT NULL DEFAULT 0"),
        ("peak_latency", "REAL NOT NULL DEFAULT 0"),
        ("avg_latency_during", "REAL NOT NULL DEFAULT 0"),
        ("recovery_latency", "REAL NOT NULL DEFAULT 0"),
        ("impact_score", "REAL NOT NULL DEFAULT 0"),
        ("effective", "INTEGER NOT NULL DEFAULT 0"),
        ("website_status", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("health_score", "REAL NOT NULL DEFAULT 100"),
        ("p95_latency", "REAL NOT NULL DEFAULT 0"),
        ("p99_latency", "REAL NOT NULL DEFAULT 0"),
        ("jitter_ms", "REAL NOT NULL DEFAULT 0"),
        ("error_rate", "REAL NOT NULL DEFAULT 0"),
        ("throughput_mbps", "REAL NOT NULL DEFAULT 0"),
        ("total_requests", "INTEGER NOT NULL DEFAULT 0"),
        ("status_2xx", "INTEGER NOT NULL DEFAULT 0"),
        ("status_3xx", "INTEGER NOT NULL DEFAULT 0"),
        ("status_4xx", "INTEGER NOT NULL DEFAULT 0"),
        ("status_5xx", "INTEGER NOT NULL DEFAULT 0"),
        ("total_data_mb", "REAL NOT NULL DEFAULT 0"),
        ("avg_dns_ms", "REAL NOT NULL DEFAULT 0"),
        ("avg_tcp_ms", "REAL NOT NULL DEFAULT 0"),
        ("avg_tls_ms", "REAL NOT NULL DEFAULT 0"),
        ("avg_ttfb_ms", "REAL NOT NULL DEFAULT 0"),
        ("packet_loss", "REAL NOT NULL DEFAULT 0"),
        ("recovery_ratio", "REAL NOT NULL DEFAULT 0"),
        ("recovered", "INTEGER NOT NULL DEFAULT 1"),
        ("attack_mode", "TEXT NOT NULL DEFAULT 'get_flood'"),
        ("endpoint", "TEXT NOT NULL DEFAULT ''"),
        ("target_class", "TEXT NOT NULL DEFAULT 'external'"),
        ("workers", "INTEGER NOT NULL DEFAULT 8"),
    ]
    for column, definition in columns:
        if not await _column_exists(connection, "dos_jobs", column):
            await connection.execute(f"ALTER TABLE dos_jobs ADD COLUMN {column} {definition}")


async def _migrate_execution_status_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "execution_status"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS execution_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_type TEXT,
                lifecycle TEXT NOT NULL DEFAULT 'IDLE' CHECK (lifecycle IN ('IDLE', 'QUEUED', 'STARTING', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED')),
                job_id TEXT,
                scan_id INTEGER,
                target_url TEXT NOT NULL DEFAULT '',
                progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
                current_module TEXT,
                current_phase TEXT,
                surfaces_total INTEGER NOT NULL DEFAULT 0,
                surfaces_completed INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                agent_states TEXT NOT NULL DEFAULT '[]',
                started_at TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                error_message TEXT,
                error_code TEXT,
                is_lab INTEGER NOT NULL DEFAULT 0,
                authorization_status TEXT NOT NULL DEFAULT ''
            );
            """
        )


async def _migrate_scan_sources_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "scan_sources"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                source_type TEXT NOT NULL CHECK (source_type IN ('local', 'github', 'gitlab', 'bitbucket', 'live', 'api_spec', 'docker', 'kubernetes', 'terraform')),
                source_config TEXT NOT NULL,
                source_identifier TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
                priority INTEGER NOT NULL DEFAULT 1,
                findings_count INTEGER NOT NULL DEFAULT 0,
                scan_duration_seconds REAL NOT NULL DEFAULT 0,
                error_message TEXT,
                artifacts TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                started_at TEXT,
                completed_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_scan_sources_scan_id ON scan_sources (scan_id);
            """
        )


async def _migrate_github_oauth_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "github_oauth_tokens"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS github_oauth_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                github_user_id INTEGER NOT NULL,
                github_login TEXT NOT NULL,
                access_token_encrypted TEXT NOT NULL,
                refresh_token_encrypted TEXT,
                token_type TEXT DEFAULT 'bearer',
                scope TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (user_id, github_user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_github_oauth_user_id ON github_oauth_tokens (user_id);
            """
        )


async def _migrate_github_oauth_states_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "github_oauth_states"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS github_oauth_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                state TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_github_oauth_states_user_id ON github_oauth_states (user_id);
            """
        )


async def _migrate_github_app_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "github_app_installations"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS github_app_installations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                installation_id INTEGER NOT NULL,
                account_login TEXT NOT NULL,
                account_type TEXT NOT NULL,
                repository_selection TEXT NOT NULL,
                permissions TEXT NOT NULL,
                events TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (user_id, installation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_github_app_user_id ON github_app_installations (user_id);
            """
        )


async def _migrate_source_correlations_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "source_correlations"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS source_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                unified_id TEXT NOT NULL,
                correlation_type TEXT NOT NULL CHECK (correlation_type IN ('exact_match', 'same_file', 'same_endpoint', 'data_flow', 'vulnerability_chain')),
                confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
                source_types TEXT NOT NULL,
                finding_ids TEXT NOT NULL,
                evidence TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_source_correlations_scan_id ON source_correlations (scan_id);
            CREATE INDEX IF NOT EXISTS idx_source_correlations_unified_id ON source_correlations (unified_id);
            """
        )


async def _migrate_finding_sources_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "finding_sources"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS finding_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                source_type TEXT NOT NULL CHECK (source_type IN ('local', 'github', 'gitlab', 'bitbucket', 'live', 'api_spec', 'docker', 'kubernetes', 'terraform')),
                source_identifier TEXT NOT NULL,
                location TEXT,
                tool TEXT,
                rule_id TEXT,
                commit_sha TEXT,
                branch TEXT,
                pr_number INTEGER,
                FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_finding_sources_finding_id ON finding_sources (finding_id);
            """
        )


async def _migrate_sast_findings_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "sast_findings"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sast_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL UNIQUE,
                language TEXT NOT NULL,
                framework TEXT,
                file_path TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                start_column INTEGER,
                end_column INTEGER,
                function_name TEXT,
                class_name TEXT,
                code_snippet TEXT,
                rule_id TEXT NOT NULL,
rule_name TEXT,
    rule_severity TEXT,
    tool TEXT NOT NULL,
    "references" TEXT,
    cwe_ids TEXT,
                owasp_category TEXT,
                fix_suggestion TEXT,
                fix_example TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_sast_findings_file_path ON sast_findings (file_path);
            CREATE INDEX IF NOT EXISTS idx_sast_findings_rule_id ON sast_findings (rule_id);
            """
        )


async def _migrate_brutal_ops_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "brutal_ops"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS brutal_ops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                target_url TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                detail TEXT,
                payload TEXT,
                output TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_brutal_ops_session ON brutal_ops (session_id);
            CREATE INDEX IF NOT EXISTS idx_brutal_ops_created ON brutal_ops (created_at);
            """
        )


async def _migrate_brutal_sessions_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "brutal_sessions"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS brutal_sessions (
                session_id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'established',
                simulation INTEGER NOT NULL DEFAULT 0,
                findings TEXT,
                sim_intel TEXT,
                sim_findings TEXT,
                timeline TEXT,
                loot TEXT,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_brutal_sessions_created ON brutal_sessions (created_at);
            """
        )


async def _migrate_secret_findings_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "secret_findings"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS secret_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL UNIQUE,
                secret_type TEXT NOT NULL,
                detector_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                matched_content TEXT,
                entropy REAL,
                is_validated INTEGER NOT NULL DEFAULT 0,
                validation_error TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
            );
            """
        )


async def _migrate_iac_findings_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "iac_findings"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS iac_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL UNIQUE,
                resource_type TEXT NOT NULL,
                resource_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_start INTEGER NOT NULL,
                line_end INTEGER NOT NULL,
                configuration TEXT,
                misconfiguration_type TEXT NOT NULL,
                platform TEXT NOT NULL CHECK (platform IN ('terraform', 'kubernetes', 'cloudformation', 'helm', 'dockerfile')),
                FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
            );
            """
        )


async def _migrate_sca_findings_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "sca_findings"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sca_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL UNIQUE,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                vulnerability_id TEXT NOT NULL,
                vulnerable_versions TEXT NOT NULL,
                fixed_version TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                license TEXT,
                is_direct INTEGER NOT NULL DEFAULT 1,
                dependency_path TEXT,
                advisory_url TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
            );
            """
        )


async def _migrate_ai_code_fixes_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "ai_code_fixes"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ai_code_fixes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                patch TEXT NOT NULL,
                explanation TEXT NOT NULL,
                confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
                fix_type TEXT NOT NULL,
                verification_steps TEXT,
                related_cwe TEXT,
                estimated_effort TEXT,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'verified', 'rejected')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                applied_at TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_ai_code_fixes_finding_id ON ai_code_fixes (finding_id);
            """
        )


async def _migrate_ai_tutor_sessions_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "ai_tutor_sessions"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ai_tutor_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                finding_id INTEGER,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                explanation TEXT,
                code_examples TEXT,
                "references" TEXT,
                follow_up_questions TEXT,
                confidence REAL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ai_tutor_user_id ON ai_tutor_sessions (user_id);
            """
        )


async def _migrate_pr_descriptions_table(connection: aiosqlite.Connection) -> None:
    if not await _table_exists(connection, "pr_descriptions"):
        await connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS pr_descriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                finding_ids TEXT NOT NULL,
                base_branch TEXT NOT NULL,
                head_branch TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                labels TEXT,
                reviewers TEXT,
                related_issues TEXT,
                status TEXT NOT NULL DEFAULT 'generated' CHECK (status IN ('generated', 'submitted', 'merged', 'rejected')),
                pr_url TEXT,
                pr_number INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                submitted_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
            """
        )


async def _migrate_findings_correlation_columns(connection: aiosqlite.Connection) -> None:
    columns = [
        ("sources", "TEXT"),
        ("correlation", "TEXT"),
        ("primary_source", "TEXT NOT NULL DEFAULT 'live'"),
        ("patch", "TEXT"),
        ("patch_status", "TEXT"),
        ("patch_applied_at", "TEXT"),
        ("assigned_to", "TEXT"),
        ("due_date", "TEXT"),
        ("fix_commit_sha", "TEXT"),
        ("fix_pr_url", "TEXT"),
    ]
    for column, definition in columns:
        if not await _column_exists(connection, "findings", column):
            await connection.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")


async def create_scan(
    target_url: str,
    mode: str,
    intensity: str = "medium",
    selected_tests: str = "[]",
    user_id: str = "local-user",
    authorization_id: int | None = None,
    authorization_confirmed: bool = False,
    max_duration_minutes: int = 120,
    enterprise_id: str | None = None,
) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO scans (
                target_url, mode, intensity, selected_tests, user_id, enterprise_id,
                authorization_id, authorization_confirmed, status, max_duration_minutes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?)
            """,
            (
                target_url,
                mode,
                intensity,
                selected_tests,
                user_id,
                enterprise_id,
                authorization_id,
                int(authorization_confirmed),
                max_duration_minutes,
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_or_create_system_scan() -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT id FROM scans WHERE target_url = ? ORDER BY id ASC LIMIT 1",
            (SYSTEM_TARGET_URL,),
        )
        row = await cursor.fetchone()
        if row is not None:
            return int(row["id"])
        cursor = await connection.execute(
            """
            INSERT INTO scans (target_url, mode, intensity, status, progress, completed_at)
            VALUES (?, 'defend', 'low', 'complete', 100, CURRENT_TIMESTAMP)
            """,
            (SYSTEM_TARGET_URL,),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_scan(scan_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return serialize_row(await cursor.fetchone())


async def list_scans(user_id: str | None = None, enterprise_id: str | None = None) -> list[dict[str, Any]]:
    count_columns = """
        s.*,
        COALESCE(COUNT(f.id), 0) AS findings_count,
        COALESCE(SUM(CASE WHEN f.severity = 'CRITICAL'
            AND f.remediation_status != 'RESOLVED'
            AND f.verification_status != 'FIX_VERIFIED'
            AND COALESCE(f.risk_status, 'ACTIVE') = 'ACTIVE' THEN 1 ELSE 0 END), 0) AS critical_findings_count,
        COALESCE(SUM(CASE WHEN f.severity = 'HIGH'
            AND f.remediation_status != 'RESOLVED'
            AND f.verification_status != 'FIX_VERIFIED'
            AND COALESCE(f.risk_status, 'ACTIVE') = 'ACTIVE' THEN 1 ELSE 0 END), 0) AS high_findings_count
    """
    async with get_connection() as connection:
        if enterprise_id:
            cursor = await connection.execute(
                f"""
                SELECT {count_columns}
                FROM scans s
                LEFT JOIN findings f ON f.scan_id = s.id
                WHERE s.enterprise_id = ? AND s.target_url != ?
                GROUP BY s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT 100
                """,
                (enterprise_id, SYSTEM_TARGET_URL),
            )
        elif user_id:
            cursor = await connection.execute(
                f"""
                SELECT {count_columns}
                FROM scans s
                LEFT JOIN findings f ON f.scan_id = s.id
                WHERE s.user_id = ? AND s.target_url != ?
                GROUP BY s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT 100
                """,
                (user_id, SYSTEM_TARGET_URL),
            )
        else:
            cursor = await connection.execute(
                f"""
                SELECT {count_columns}
                FROM scans s
                LEFT JOIN findings f ON f.scan_id = s.id
                WHERE s.target_url != ?
                GROUP BY s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT 100
                """,
                (SYSTEM_TARGET_URL,),
            )
        return [dict(row) for row in await cursor.fetchall()]


async def get_latest_scan(user_id: str | None = None) -> dict[str, Any] | None:
    async with get_connection() as connection:
        if user_id:
            cursor = await connection.execute(
                "SELECT * FROM scans WHERE user_id = ? AND target_url != ? ORDER BY created_at DESC, id DESC LIMIT 1",
                (user_id, SYSTEM_TARGET_URL),
            )
        else:
            cursor = await connection.execute(
                "SELECT * FROM scans WHERE target_url != ? ORDER BY created_at DESC, id DESC LIMIT 1",
                (SYSTEM_TARGET_URL,),
            )
        return serialize_row(await cursor.fetchone())


async def get_previous_scan_for_target(target_url: str, scan_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT previous.* FROM scans previous
            JOIN scans current ON current.id = ?
            WHERE previous.target_url = ? AND previous.target_url != ?
              AND previous.id < ? AND previous.status = 'complete'
              AND (
                (current.enterprise_id IS NOT NULL AND previous.enterprise_id = current.enterprise_id)
                OR (
                  current.enterprise_id IS NULL AND previous.enterprise_id IS NULL
                  AND previous.user_id = current.user_id
                )
              )
            ORDER BY previous.id DESC
            LIMIT 1
            """,
            (scan_id, target_url, SYSTEM_TARGET_URL, scan_id),
        )
        return serialize_row(await cursor.fetchone())


async def get_latest_scan_for_agent(agent_name: str, user_id: str | None = None) -> dict[str, Any] | None:
    async with get_connection() as connection:
        if user_id:
            cursor = await connection.execute(
                """
                SELECT scans.*
                FROM scans
                JOIN audit_logs ON audit_logs.scan_id = scans.id
                WHERE audit_logs.agent_name = ? AND scans.user_id = ?
                ORDER BY audit_logs.id DESC
                LIMIT 1
                """,
                (agent_name, user_id),
            )
        else:
            cursor = await connection.execute(
                """
                SELECT scans.*
                FROM scans
                JOIN audit_logs ON audit_logs.scan_id = scans.id
                WHERE audit_logs.agent_name = ?
                ORDER BY audit_logs.id DESC
                LIMIT 1
                """,
                (agent_name,),
            )
        return serialize_row(await cursor.fetchone())


async def update_scan_status(scan_id: int, status: str, error_message: str | None = None) -> None:
    started_sql = ", started_at = COALESCE(started_at, CURRENT_TIMESTAMP)" if status == "running" else ""
    terminal_sql = ", completed_at = CURRENT_TIMESTAMP" if status in {"cancelled", "complete", "error"} else ""
    complete_sql = ", progress = 100" if status == "complete" else ""
    async with get_connection() as connection:
        await connection.execute(
            f"UPDATE scans SET status = ?, error_message = ?{started_sql}{terminal_sql}{complete_sql} WHERE id = ?",
            (status, error_message, scan_id),
        )
        await connection.commit()


async def update_scan_progress(
    scan_id: int,
    progress: int,
    request_count: int | None = None,
    sandbox_id: str | None = None,
) -> None:
    assignments = ["progress = ?"]
    values: list[Any] = [max(0, min(progress, 100))]
    if request_count is not None:
        assignments.append("request_count = ?")
        values.append(request_count)
    if sandbox_id is not None:
        assignments.append("sandbox_id = ?")
        values.append(sandbox_id)
    values.append(scan_id)
    async with get_connection() as connection:
        await connection.execute(f"UPDATE scans SET {', '.join(assignments)} WHERE id = ?", values)
        await connection.commit()


async def create_finding(scan_id: int, finding: FindingCreate | dict[str, Any]) -> int:
    data = finding.model_dump(mode="json") if isinstance(finding, FindingCreate) else FindingCreate(**finding).model_dump(mode="json")
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO findings (
                scan_id, title, category, severity, confidence, target, endpoint, evidence,
                impact, recommendation, verification, agent, timestamp, description,
                how_exploited, fix, cve_id, cvss_score, cwe, version_affected,
                file_path, line_number, code_snippet, fix_recommendation,
                parameter, module, recommended_fix,
                remediation_status, verification_status, risk_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                data["title"],
                data["category"],
                data["severity"],
                data["confidence"],
                data["target"],
                data["endpoint"],
                data["evidence"],
                data["impact"],
                data["recommendation"],
                data["verification"],
                data["agent"],
                data["timestamp"],
                data.get("description") or data.get("evidence") or "",
                data.get("how_exploited") or data.get("impact") or "",
                data.get("fix") or data.get("recommendation") or "",
                data.get("cve_id"),
                data.get("cvss_score"),
                data.get("cwe"),
                data.get("version_affected"),
                data.get("file_path"),
                data.get("line_number"),
                data.get("code_snippet"),
                data.get("fix_recommendation"),
                data.get("parameter"),
                data.get("module"),
                data.get("recommended_fix"),
                data.get("remediation_status", "OPEN"),
                data.get("verification_status", "NOT_VERIFIED"),
                data.get("risk_status", "ACTIVE"),
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_findings(scan_id: int, limit: int = 1000) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC LIMIT ?", (scan_id, limit),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    for row in rows:
        for col in ("sources",):
            raw = row.get(col)
            if raw is None or raw == "":
                row[col] = []
            elif isinstance(raw, str):
                try:
                    row[col] = json.loads(raw)
                except json.JSONDecodeError:
                    row[col] = []
        for col in ("correlation", "patch"):
            raw = row.get(col)
            if isinstance(raw, str):
                try:
                    row[col] = json.loads(raw)
                except json.JSONDecodeError:
                    row[col] = None
    return rows


async def get_finding(finding_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = await cursor.fetchone()
    result = serialize_row(row)
    if result is None:
        return None
    raw = result.get("sources")
    if raw is None or raw == "":
        result["sources"] = []
    elif isinstance(raw, str):
        try:
            result["sources"] = json.loads(raw)
        except json.JSONDecodeError:
            result["sources"] = []
    raw = result.get("correlation")
    if isinstance(raw, str):
        try:
            result["correlation"] = json.loads(raw)
        except json.JSONDecodeError:
            result["correlation"] = None
    return result


async def update_finding(finding_id: int, **fields: Any) -> None:
    allowed = {
        "title",
        "category",
        "severity",
        "confidence",
        "target",
        "endpoint",
        "evidence",
        "impact",
        "recommendation",
        "verification",
        "description",
        "how_exploited",
        "fix",
        "parameter",
        "module",
        "recommended_fix",
        "remediation_status",
        "verification_status",
        "risk_status",
    }
    updates = [(name, value) for name, value in fields.items() if name in allowed]
    if not updates:
        return
    assignments = ", ".join(f"{name} = ?" for name, _ in updates)
    values = [value for _, value in updates]
    values.append(finding_id)
    async with get_connection() as connection:
        await connection.execute(f"UPDATE findings SET {assignments} WHERE id = ?", values)
        await connection.commit()


async def list_findings(
    scan_id: int | None = None,
    user_id: str | None = None,
    enterprise_id: str | None = None,
    *,
    limit: int | None = None,
    offset: int = 0,
    include_details: bool = True,
    severity: str | None = None,
    category: str | None = None,
    query: str | None = None,
) -> list[dict[str, Any]]:
    summary_columns = """
        f.id, f.scan_id, f.title, f.category, f.severity, f.confidence,
        f.target, f.endpoint, f.agent, f.timestamp, f.cve_id, f.cvss_score,
        f.cwe, f.version_affected, f.file_path, f.line_number, f.parameter,
        f.module, f.remediation_status, f.verification_status, f.risk_status
    """
    columns = "f.*" if include_details else summary_columns
    joins: list[str] = []
    conditions: list[str] = []
    values: list[Any] = []

    if scan_id is not None:
        conditions.append("f.scan_id = ?")
        values.append(scan_id)
    if enterprise_id:
        joins.append("JOIN scans s ON f.scan_id = s.id")
        conditions.append("s.enterprise_id = ?")
        values.append(enterprise_id)
    elif user_id is not None:
        joins.append("JOIN scans s ON f.scan_id = s.id")
        conditions.append("s.user_id = ?")
        values.append(user_id)
    if severity and severity.upper() != "ALL":
        conditions.append("f.severity = ?")
        values.append(severity.upper())
    if category and category != "All":
        conditions.append("f.category = ?")
        values.append(category)
    if query:
        like = f"%{query.lower()}%"
        conditions.append(
            "(LOWER(f.title) LIKE ? OR LOWER(f.target) LIKE ? OR LOWER(f.endpoint) LIKE ? "
            "OR LOWER(f.category) LIKE ? OR LOWER(f.agent) LIKE ? OR LOWER(COALESCE(f.cve_id, '')) LIKE ?)"
        )
        values.extend([like, like, like, like, like, like])

    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    pagination = ""
    if limit is not None:
        pagination = " LIMIT ? OFFSET ?"
        values.extend([limit, max(0, offset)])

    async with get_connection() as connection:
        cursor = await connection.execute(
            f"SELECT {columns} FROM findings f {' '.join(dict.fromkeys(joins))}{where} ORDER BY f.id ASC{pagination}",
            values,
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    for row in rows:
        raw = row.get("sources")
        if raw is None or raw == "":
            row["sources"] = []
        elif isinstance(raw, str):
            try:
                row["sources"] = json.loads(raw)
            except json.JSONDecodeError:
                row["sources"] = []
        raw = row.get("correlation")
        if isinstance(raw, str):
            try:
                row["correlation"] = json.loads(raw)
            except json.JSONDecodeError:
                row["correlation"] = None
    return rows


async def count_findings(
    scan_id: int | None = None,
    user_id: str | None = None,
    enterprise_id: str | None = None,
    *,
    severity: str | None = None,
    category: str | None = None,
    query: str | None = None,
) -> int:
    joins: list[str] = []
    conditions: list[str] = []
    values: list[Any] = []

    if scan_id is not None:
        conditions.append("f.scan_id = ?")
        values.append(scan_id)
    if enterprise_id:
        joins.append("JOIN scans s ON f.scan_id = s.id")
        conditions.append("s.enterprise_id = ?")
        values.append(enterprise_id)
    elif user_id is not None:
        joins.append("JOIN scans s ON f.scan_id = s.id")
        conditions.append("s.user_id = ?")
        values.append(user_id)
    if severity and severity.upper() != "ALL":
        conditions.append("f.severity = ?")
        values.append(severity.upper())
    if category and category != "All":
        conditions.append("f.category = ?")
        values.append(category)
    if query:
        like = f"%{query.lower()}%"
        conditions.append(
            "(LOWER(f.title) LIKE ? OR LOWER(f.target) LIKE ? OR LOWER(f.endpoint) LIKE ? "
            "OR LOWER(f.category) LIKE ? OR LOWER(f.agent) LIKE ? OR LOWER(COALESCE(f.cve_id, '')) LIKE ?)"
        )
        values.extend([like, like, like, like, like, like])

    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    async with get_connection() as connection:
        cursor = await connection.execute(
            f"SELECT COUNT(*) AS count FROM findings f {' '.join(dict.fromkeys(joins))}{where}",
            values,
        )
        row = await cursor.fetchone()
    return int(row["count"] if row else 0)


async def list_finding_categories(
    scan_id: int | None = None,
    user_id: str | None = None,
    enterprise_id: str | None = None,
) -> list[str]:
    joins: list[str] = []
    conditions = ["f.category != ''"]
    values: list[Any] = []

    if scan_id is not None:
        conditions.append("f.scan_id = ?")
        values.append(scan_id)
    if enterprise_id:
        joins.append("JOIN scans s ON f.scan_id = s.id")
        conditions.append("s.enterprise_id = ?")
        values.append(enterprise_id)
    elif user_id is not None:
        joins.append("JOIN scans s ON f.scan_id = s.id")
        conditions.append("s.user_id = ?")
        values.append(user_id)

    where = f" WHERE {' AND '.join(conditions)}"
    async with get_connection() as connection:
        cursor = await connection.execute(
            f"SELECT DISTINCT f.category FROM findings f {' '.join(dict.fromkeys(joins))}{where} ORDER BY f.category ASC",
            values,
        )
        rows = await cursor.fetchall()
    return [str(row["category"]) for row in rows]


async def get_findings_by_target(host: str, limit: int = 50) -> list[dict[str, Any]]:
    """Latest findings whose target host matches the given host (case-insensitive)."""
    from urllib.parse import urlparse

    def host_of(raw: Any) -> str:
        value = str(raw or "").strip().lower()
        if not value:
            return ""
        if "://" in value:
            parsed = urlparse(value)
            return (parsed.hostname or "").lower()
        return value.split(":")[0]

    rows = await list_findings()
    target = host.strip().lower()
    matched = [row for row in rows if host_of(row.get("target")) == target]
    return matched[-limit:]


async def add_audit_log(
    scan_id: int,
    agent_name: str,
    action: str,
    details: str,
    *,
    user_id: str | None = None,
    target: str | None = None,
    authorization_status: str | None = None,
    selected_module: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    result: str | None = None,
    request_count: int | None = None,
    sandbox_id: str | None = None,
) -> int:
    safe_details = redact_sensitive(details[:2000])
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO audit_logs (
                scan_id, agent_name, action, details, user_id, target, authorization_status,
                selected_module, start_time, end_time, result, request_count, sandbox_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                agent_name,
                action,
                safe_details,
                user_id,
                target,
                authorization_status,
                selected_module,
                start_time,
                end_time,
                result,
                request_count,
                sandbox_id,
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_audit_logs(scan_id: int) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY timestamp ASC, id ASC",
            (scan_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]


async def start_agent_run(scan_id: int, agent_name: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO agent_runs (scan_id, agent_name, start_time, status)
            VALUES (?, ?, ?, 'running')
            """,
            (scan_id, agent_name, now),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def complete_agent_run(
    run_id: int,
    *,
    status: str = "completed",
    execution_time: float | None = None,
    error_message: str | None = None,
    attempts: int = 1,
) -> None:
    end_time = datetime.now(timezone.utc).isoformat()
    async with get_connection() as connection:
        await connection.execute(
            """
            UPDATE agent_runs
            SET end_time = ?, status = ?, execution_time = ?, error_message = ?, attempts = ?
            WHERE id = ?
            """,
            (end_time, status, execution_time, error_message, attempts, run_id),
        )
        await connection.commit()


async def upsert_learning_insights(scan_id: int, rows: list[dict[str, Any]]) -> None:
    async with get_connection() as connection:
        for row in rows:
            await connection.execute(
                """
                INSERT INTO learning_insights (
                    scan_id, module, kind, total_count, true_positives, false_positives,
                    unrated_count, true_positive_rate, false_positive_rate,
                    recommendation, recommendation_data, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                ON CONFLICT(scan_id, module, kind) DO UPDATE SET
                    total_count = excluded.total_count,
                    true_positives = excluded.true_positives,
                    false_positives = excluded.false_positives,
                    unrated_count = excluded.unrated_count,
                    true_positive_rate = excluded.true_positive_rate,
                    false_positive_rate = excluded.false_positive_rate,
                    recommendation = excluded.recommendation,
                    recommendation_data = excluded.recommendation_data,
                    updated_at = CURRENT_TIMESTAMP,
                    status = CASE
                        WHEN learning_insights.status = 'pending' THEN 'pending'
                        ELSE learning_insights.status
                    END
                """,
                (
                    scan_id,
                    row["module"],
                    row.get("kind", "module"),
                    int(row.get("total_count", 0)),
                    int(row.get("true_positives", 0)),
                    int(row.get("false_positives", 0)),
                    int(row.get("unrated_count", 0)),
                    float(row.get("true_positive_rate", 0.0)),
                    float(row.get("false_positive_rate", 0.0)),
                    str(row.get("recommendation") or "")[:2000] or None,
                    json.dumps(row.get("recommendation_data") or {}, ensure_ascii=True, default=str)
                    if row.get("recommendation_data")
                    else None,
                ),
            )
        await connection.commit()


async def list_learning_insights(
    scan_id: int | None = None,
    status_filter: str | None = None,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM learning_insights"
    conditions: list[str] = []
    parameters: list[Any] = []
    if scan_id is not None:
        conditions.append("scan_id = ?")
        parameters.append(scan_id)
    if status_filter is not None:
        conditions.append("status = ?")
        parameters.append(status_filter)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY scan_id DESC, module ASC"
    async with get_connection() as connection:
        cursor = await connection.execute(query, parameters)
        rows = [dict(row) for row in await cursor.fetchall()]
    for row in rows:
        for column in ("recommendation_data", "applied_settings"):
            value = row.get(column)
            if value is not None:
                try:
                    row[column] = json.loads(value)
                except (TypeError, json.JSONDecodeError):
                    row[column] = None
    return rows


async def get_learning_insight(insight_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM learning_insights WHERE id = ?", (insight_id,)
        )
        row = serialize_row(await cursor.fetchone())
    if row is not None:
        for column in ("recommendation_data", "applied_settings"):
            value = row.get(column)
            if value is not None:
                try:
                    row[column] = json.loads(value)
                except (TypeError, json.JSONDecodeError):
                    row[column] = None
    return row


async def update_learning_insight_status(
    insight_id: int,
    status: str,
    applied_settings: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    async with get_connection() as connection:
        await connection.execute(
            """
            UPDATE learning_insights
            SET status = ?, applied_settings = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, json.dumps(applied_settings, ensure_ascii=True, default=str) if applied_settings else None, insight_id),
        )
        await connection.commit()
    return await get_learning_insight(insight_id)


async def list_applied_tunings() -> dict[str, dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT module, applied_settings
            FROM learning_insights
            WHERE kind = 'module' AND status = 'applied' AND applied_settings IS NOT NULL
            ORDER BY updated_at DESC
            """
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    tunings: dict[str, dict[str, Any]] = {}
    for row in rows:
        module = str(row["module"] or "")
        if not module or module in tunings:
            continue
        try:
            settings = json.loads(str(row["applied_settings"]))
        except (TypeError, json.JSONDecodeError):
            settings = {}
        if isinstance(settings, dict):
            tunings[module] = settings
    return tunings


async def scan_quality_summary() -> dict[str, Any]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT
                module,
                SUM(total_count) AS total_count,
                SUM(true_positives) AS true_positives,
                SUM(false_positives) AS false_positives,
                SUM(unrated_count) AS unrated_count
            FROM learning_insights
            WHERE kind = 'module'
            GROUP BY module
            ORDER BY total_count DESC
            """
        )
        module_rows = [dict(row) for row in await cursor.fetchall()]
        cursor = await connection.execute(
            """
            SELECT l.*, s.target_url
            FROM learning_insights AS l
            LEFT JOIN scans AS s ON s.id = l.scan_id
            WHERE l.kind = 'scan'
            ORDER BY l.scan_id DESC
            """
        )
        scan_rows = [dict(row) for row in await cursor.fetchall()]
    for row in module_rows:
        total = max(1, int(row["total_count"]))
        row["true_positive_rate"] = round(int(row["true_positives"]) / total, 3)
        row["false_positive_rate"] = round(int(row["false_positives"]) / total, 3)
    for row in scan_rows:
        for column in ("recommendation_data", "applied_settings"):
            value = row.get(column)
            if value is not None:
                try:
                    row[column] = json.loads(value)
                except (TypeError, json.JSONDecodeError):
                    row[column] = None
    return {"modules": module_rows, "scans": scan_rows}


async def list_audit_logs(
    scan_id: int | None = None,
    user_id: str | None = None,
    enterprise_id: str | None = None,
) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        if scan_id is not None:
            if enterprise_id:
                cursor = await connection.execute(
                    """
                    SELECT al.* FROM audit_logs al
                    JOIN scans s ON al.scan_id = s.id
                    WHERE al.scan_id = ? AND s.enterprise_id = ?
                    ORDER BY al.timestamp ASC, al.id ASC
                    """,
                    (scan_id, enterprise_id),
                )
            else:
                if user_id is not None:
                    cursor = await connection.execute(
                        """
                        SELECT al.* FROM audit_logs al
                        JOIN scans s ON al.scan_id = s.id
                        WHERE al.scan_id = ? AND s.user_id = ?
                        ORDER BY al.timestamp ASC, al.id ASC
                        """,
                        (scan_id, user_id),
                    )
                else:
                    cursor = await connection.execute(
                        "SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY timestamp ASC, id ASC",
                        (scan_id,),
                    )
        elif enterprise_id:
            cursor = await connection.execute(
                """
                SELECT al.* FROM audit_logs al
                JOIN scans s ON al.scan_id = s.id
                WHERE s.enterprise_id = ?
                ORDER BY al.timestamp ASC, al.id ASC
                """,
                (enterprise_id,),
            )
        elif user_id is not None:
            cursor = await connection.execute(
                """
                SELECT al.* FROM audit_logs al
                JOIN scans s ON al.scan_id = s.id
                WHERE s.user_id = ?
                ORDER BY al.timestamp ASC, al.id ASC
                """,
                (user_id,),
            )
        else:
            cursor = await connection.execute("SELECT * FROM audit_logs ORDER BY timestamp ASC, id ASC")
        return [dict(row) for row in await cursor.fetchall()]


async def set_scan_artifacts(
    scan_id: int,
    *,
    scanner_output: Any = _UNSET,
    shadow_recon_output: Any = _UNSET,
    markdown_report: Any = _UNSET,
    notification_result: Any = _UNSET,
    active_security_output: Any = _UNSET,
    browser_security_output: Any = _UNSET,
    ai_analyst_output: Any = _UNSET,
    exploitation_output: Any = _UNSET,
    tci_output: Any = _UNSET,
    ai_consultation: Any = _UNSET,
) -> None:
    values = {
        "scanner_output": scanner_output,
        "shadow_recon_output": shadow_recon_output,
        "markdown_report": markdown_report,
        "notification_result": notification_result,
        "active_security_output": active_security_output,
        "browser_security_output": browser_security_output,
        "ai_analyst_output": ai_analyst_output,
        "exploitation_output": exploitation_output,
        "tci_output": tci_output,
        "ai_consultation": ai_consultation,
    }
    updates: list[str] = []
    parameters: list[Any] = []
    for column, value in values.items():
        if value is _UNSET:
            continue
        updates.append(f"{column} = ?")
        if column == "markdown_report" or value is None:
            parameters.append(redact_sensitive(value) if isinstance(value, str) else value)
        else:
            parameters.append(json.dumps(redact_payload(value), ensure_ascii=True, default=str))
    if not updates:
        return

    async with get_connection() as connection:
        await connection.execute("INSERT OR IGNORE INTO scan_artifacts (scan_id) VALUES (?)", (scan_id,))
        parameters.append(scan_id)
        await connection.execute(
            f"UPDATE scan_artifacts SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE scan_id = ?",
            parameters,
        )
        await connection.commit()


def deserialize_artifact_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    for column in ("scanner_output", "shadow_recon_output", "notification_result", "active_security_output", "browser_security_output", "ai_analyst_output", "exploitation_output", "tci_output", "ai_consultation"):
        value = row.get(column)
        if value is not None:
            try:
                row[column] = json.loads(value)
            except (TypeError, json.JSONDecodeError):
                row[column] = None
    return row


async def get_scan_artifacts(scan_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM scan_artifacts WHERE scan_id = ?", (scan_id,))
        row = serialize_row(await cursor.fetchone())
    return deserialize_artifact_row(row)


async def list_scan_artifacts(scan_id: int | None = None) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        if scan_id is None:
            cursor = await connection.execute("SELECT * FROM scan_artifacts ORDER BY updated_at DESC, scan_id DESC")
        else:
            cursor = await connection.execute(
                "SELECT * FROM scan_artifacts WHERE scan_id = ? ORDER BY updated_at DESC, scan_id DESC",
                (scan_id,),
            )
        rows = [dict(row) for row in await cursor.fetchall()]
    return [artifact for artifact in (deserialize_artifact_row(row) for row in rows) if artifact is not None]


async def get_ai_cache(cache_key: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM ai_cache WHERE cache_key = ?", (cache_key,))
        row = serialize_row(await cursor.fetchone())
    if row is None:
        return None
    try:
        row["response"] = json.loads(row["response"])
    except (TypeError, json.JSONDecodeError):
        row["response"] = None
    return row


async def set_ai_cache(
    cache_key: str,
    *,
    finding_id: int | None,
    evidence_hash: str,
    language: str,
    model: str,
    response: Any,
) -> None:
    safe_response = json.dumps(redact_payload(response), ensure_ascii=True, default=str)
    async with get_connection() as connection:
        await connection.execute(
            """
            INSERT INTO ai_cache (cache_key, finding_id, evidence_hash, language, model, response)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                finding_id = excluded.finding_id,
                evidence_hash = excluded.evidence_hash,
                language = excluded.language,
                model = excluded.model,
                response = excluded.response,
                updated_at = CURRENT_TIMESTAMP
            """,
            (cache_key, finding_id, evidence_hash, language, model, safe_response),
        )
        await connection.commit()


async def database_is_available() -> bool:
    try:
        async with get_connection() as connection:
            cursor = await connection.execute("SELECT 1")
            row = await cursor.fetchone()
            return row is not None and int(row[0]) == 1
    except (aiosqlite.Error, OSError, ValueError):
        return False


async def create_user(
    user_id: str,
    email: str,
    password_hash: str,
    name: str | None = None,
    role: str = "user",
    subscription_tier: str = "FREE",
) -> None:
    async with get_connection() as connection:
        await connection.execute(
            """
            INSERT INTO users (id, email, password_hash, name, role, subscription_tier, subscription_status)
            VALUES (?, ?, ?, ?, ?, ?, 'active')
            """,
            (user_id, email.lower(), password_hash, name, role, subscription_tier),
        )
        await connection.commit()


async def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return serialize_row(await cursor.fetchone())


async def get_enterprise_membership(user_id: str) -> dict[str, Any] | None:
    """Return the active enterprise membership and organization policy."""
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT
                m.id AS membership_id,
                m.enterprise_id,
                m.user_id,
                m.role AS enterprise_role,
                m.max_severity,
                m.can_request_audit,
                m.can_request_fix,
                m.can_approve,
                m.can_manage_members,
                m.is_active AS membership_active,
                e.name AS enterprise_name,
                e.allowed_email_domains,
                e.is_active AS enterprise_active
            FROM enterprise_memberships m
            JOIN enterprises e ON e.id = m.enterprise_id
            WHERE m.user_id = ? AND m.is_active = 1 AND e.is_active = 1
            LIMIT 1
            """,
            (user_id,),
        )
        row = await cursor.fetchone()
    if row is None:
        return None
    result = dict(row)
    try:
        result["allowed_email_domains"] = json.loads(result.get("allowed_email_domains") or "[]")
    except (TypeError, json.JSONDecodeError):
        result["allowed_email_domains"] = []
    return result


async def touch_last_login(user_id: str) -> None:
    """Record the current UTC time as the user's last login. Never raises."""
    try:
        from datetime import datetime, timezone
        async with get_connection() as connection:
            await connection.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), user_id),
            )
            await connection.commit()
    except Exception:
        pass


async def get_or_create_system_user() -> str:
    """Get or create a system user for background jobs like self-audit."""
    system_user_id = "system-self-audit"
    user = await get_user_by_id(system_user_id)
    if user:
        return system_user_id
    # Create system user with a random password (not used for login)
    import secrets
    password_hash = secrets.token_urlsafe(32)
    await create_user(
        user_id=system_user_id,
        email="system-self-audit@phantomscan.local",
        password_hash=password_hash,
        name="System Self-Audit",
        role="user",
    )
    return system_user_id


async def get_user_by_email(email: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
        return serialize_row(await cursor.fetchone())


async def update_user_password(user_id: str, password_hash: str) -> None:
    async with get_connection() as connection:
        await connection.execute(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (password_hash, user_id),
        )
        await connection.commit()


async def update_user_name(user_id: str, name: str) -> None:
    async with get_connection() as connection:
        await connection.execute(
            "UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (name, user_id),
        )
        await connection.commit()


async def update_user_subscription(
    user_id: str,
    tier: str | None = None,
    status: str | None = None,
    stripe_customer_id: str | None = None,
    expires_at: str | None = None,
) -> None:
    async with get_connection() as connection:
        fields = ["updated_at = CURRENT_TIMESTAMP"]
        values = []
        if tier is not None:
            fields.append("subscription_tier = ?")
            values.append(tier)
        if status is not None:
            fields.append("subscription_status = ?")
            values.append(status)
        if stripe_customer_id is not None:
            fields.append("stripe_customer_id = ?")
            values.append(stripe_customer_id)
        if expires_at is not None:
            fields.append("subscription_expires_at = ?")
            values.append(expires_at)
        values.append(user_id)
        await connection.execute(
            f"UPDATE users SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        await connection.commit()


async def create_authorized_target(
    user_id: str,
    domain: str,
    target_origin: str,
    verification_method: str,
    token_hash: str,
    challenge_expires_at: str,
) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO authorized_targets (
                user_id, domain, target_origin, verification_method, verification_token_hash,
                challenge_expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING')
            """,
            (user_id, domain, target_origin, verification_method, token_hash, challenge_expires_at),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_authorized_target(authorization_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM authorized_targets WHERE id = ?", (authorization_id,))
        return serialize_row(await cursor.fetchone())


async def find_authorized_target(user_id: str, target_origin: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT * FROM authorized_targets
            WHERE user_id = ? AND target_origin = ?
            ORDER BY CASE status WHEN 'VERIFIED' THEN 0 WHEN 'PENDING' THEN 1 ELSE 2 END, id DESC
            LIMIT 1
            """,
            (user_id, target_origin),
        )
        return serialize_row(await cursor.fetchone())


async def update_authorized_target(
    authorization_id: int,
    status: str,
    verified_at: str | None = None,
    expires_at: str | None = None,
) -> None:
    async with get_connection() as connection:
        await connection.execute(
            "UPDATE authorized_targets SET status = ?, verified_at = ?, expires_at = ? WHERE id = ?",
            (status, verified_at, expires_at, authorization_id),
        )
        await connection.commit()


async def create_authorized_test_job(
    authorization_id: int | None,
    target_url: str,
    normalized_target_origin: str,
    selected_modules: list[str],
    scan_id: int,
    enterprise_id: str | None = None,
    user_id: str | None = None,
) -> str:
    job_id = uuid.uuid4().hex
    async with get_connection() as connection:
        await connection.execute(
            """
            INSERT INTO authorized_test_jobs (
                id, authorization_id, target_url, normalized_target_origin,
                selected_modules, status, scan_id, enterprise_id, user_id
            ) VALUES (?, ?, ?, ?, ?, 'QUEUED', ?, ?, ?)
            """,
            (
                job_id,
                authorization_id,
                target_url,
                normalized_target_origin,
                json.dumps(selected_modules),
                scan_id,
                enterprise_id,
                user_id,
            ),
        )
        await connection.commit()
    return job_id


async def get_authorized_test_job(job_id: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM authorized_test_jobs WHERE id = ?", (job_id,))
        return serialize_row(await cursor.fetchone())


async def get_authorized_test_job_by_scan(scan_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM authorized_test_jobs WHERE scan_id = ? ORDER BY updated_at DESC LIMIT 1",
            (scan_id,),
        )
        return serialize_row(await cursor.fetchone())


async def find_active_authorized_test_job(
    target_origin: str, authorization_id: int | None, enterprise_id: str | None = None, user_id: str | None = None
) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT * FROM authorized_test_jobs
            WHERE normalized_target_origin = ?
              AND (authorization_id = ? OR (? IS NULL AND authorization_id IS NULL))
              AND (? IS NULL OR enterprise_id = ?)
              AND (? IS NULL OR user_id = ?)
              AND status IN ('QUEUED', 'RUNNING')
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (target_origin, authorization_id, authorization_id, enterprise_id, enterprise_id, user_id, user_id),
        )
        return serialize_row(await cursor.fetchone())


async def update_authorized_test_job(job_id: str, **fields: Any) -> None:
    allowed = {
        "status", "progress_percent", "current_module", "current_phase",
        "surfaces_total", "surfaces_completed", "findings_count",
        "started_at", "completed_at", "error_message", "error_code", "result_summary",
        "raw_surfaces_discovered", "testable_surfaces", "surface_groups",
    }
    updates = [(name, value) for name, value in fields.items() if name in allowed]
    if not updates:
        return
    updates.append(("updated_at", datetime.now(timezone.utc).isoformat()))
    assignments = ", ".join(f"{name} = ?" for name, _ in updates)
    values = [value for _, value in updates]
    values.append(job_id)
    async with get_connection() as connection:
        await connection.execute(
            f"UPDATE authorized_test_jobs SET {assignments} WHERE id = ?", values
        )
        await connection.commit()


async def add_job_event(
    job_id: str,
    event_type: str,
    message: str,
    *,
    module: str | None = None,
    status: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM job_events WHERE job_id = ?",
            (job_id,),
        )
        row = await cursor.fetchone()
        next_seq = int(row[0]) if row else 1
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata or {}, ensure_ascii=True, default=str)
        cursor = await connection.execute(
            """
            INSERT INTO job_events (job_id, sequence_number, timestamp, module, event_type, message, status, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (job_id, next_seq, now, module, event_type, message[:5000], status, meta_json),
        )
        await connection.commit()
        return next_seq


async def get_execution_status() -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM execution_status ORDER BY id DESC LIMIT 1"
        )
        row = serialize_row(await cursor.fetchone())
        if row is None:
            return None
        try:
            row["agent_states"] = json.loads(row.get("agent_states") or "[]")
        except (json.JSONDecodeError, TypeError):
            row["agent_states"] = []
        return row


async def upsert_execution_status(
    execution_type: str | None = None,
    lifecycle: str = "IDLE",
    job_id: str | None = None,
    scan_id: int | None = None,
    target_url: str = "",
    progress_percent: int = 0,
    current_module: str | None = None,
    current_phase: str | None = None,
    surfaces_total: int = 0,
    surfaces_completed: int = 0,
    findings_count: int = 0,
    agent_states: list[dict[str, Any]] | None = None,
    error_message: str | None = None,
    error_code: str | None = None,
    is_lab: bool = False,
    authorization_status: str = "",
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    started_sql = ", started_at = COALESCE(started_at, ?)" if lifecycle in ("QUEUED", "STARTING", "RUNNING") else ""
    terminal = lifecycle in ("COMPLETED", "FAILED", "CANCELLED")
    completed_sql = ", completed_at = ?" if terminal else ""
    progress_sql = ", progress_percent = 100" if lifecycle == "COMPLETED" else ""
    agent_json = json.dumps(agent_states or [], ensure_ascii=True, default=str)
    async with get_connection() as connection:
        existing = await connection.execute("SELECT id FROM execution_status ORDER BY id DESC LIMIT 1")
        row = await existing.fetchone()
        if row is not None:
            sets = [
                "execution_type = ?", "lifecycle = ?", "job_id = ?", "scan_id = ?",
                "target_url = ?", "progress_percent = ?", "current_module = ?",
                "current_phase = ?", "surfaces_total = ?", "surfaces_completed = ?",
                "findings_count = ?", "agent_states = ?", "updated_at = ?",
                "error_message = ?", "error_code = ?", "is_lab = ?", "authorization_status = ?",
            ]
            values = [
                execution_type, lifecycle, job_id, scan_id, target_url, progress_percent,
                current_module, current_phase, surfaces_total, surfaces_completed,
                findings_count, agent_json, now, error_message, error_code,
                int(is_lab), authorization_status,
            ]
            if terminal:
                sets.append("completed_at = ?")
                values.append(now)
            if lifecycle == "COMPLETED":
                sets.append("progress_percent = 100")
            values.append(int(row["id"]))
            await connection.execute(
                f"UPDATE execution_status SET {', '.join(sets)} WHERE id = ?", values
            )
        else:
            await connection.execute(
                """
                INSERT INTO execution_status (
                    execution_type, lifecycle, job_id, scan_id, target_url, progress_percent,
                    current_module, current_phase, surfaces_total, surfaces_completed,
                    findings_count, agent_states, started_at, updated_at,
                    completed_at, error_message, error_code, is_lab, authorization_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution_type, lifecycle, job_id, scan_id, target_url, progress_percent,
                    current_module, current_phase, surfaces_total, surfaces_completed,
                    findings_count, agent_json,
                    now if lifecycle in ("QUEUED", "STARTING", "RUNNING") else None,
                    now,
                    now if terminal else None,
                    error_message, error_code, int(is_lab), authorization_status,
                ),
            )
        await connection.commit()


async def clear_execution_status() -> None:
    async with get_connection() as connection:
        await connection.execute("DELETE FROM execution_status")
        await connection.commit()


async def create_evidence_record(evidence: dict[str, Any]) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO evidence_records (
                request_id, job_id, scan_id, module, surface, method, request_url,
                safe_test_marker, request_timestamp, response_status, response_time_ms,
                response_observed, detection_result, evidence_summary, finding_id, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence["request_id"],
                evidence["job_id"],
                evidence.get("scan_id"),
                evidence.get("module", ""),
                evidence.get("surface", ""),
                evidence.get("method", ""),
                evidence.get("request_url", ""),
                evidence.get("safe_test_marker", ""),
                evidence.get("request_timestamp", ""),
                evidence.get("response_status"),
                evidence.get("response_time_ms"),
                int(evidence.get("response_observed", False)),
                evidence.get("detection_result", "INCONCLUSIVE"),
                evidence.get("evidence_summary", ""),
                evidence.get("finding_id"),
                evidence.get("error"),
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def update_evidence_finding(evidence_id: int, finding_id: int) -> None:
    async with get_connection() as connection:
        await connection.execute(
            "UPDATE evidence_records SET finding_id = ? WHERE id = ?",
            (finding_id, evidence_id),
        )
        await connection.commit()


async def get_evidence_for_job(job_id: str) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM evidence_records WHERE job_id = ? ORDER BY id ASC",
            (job_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]


async def get_evidence_for_finding(finding_id: int) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM evidence_records WHERE finding_id = ? ORDER BY id ASC",
            (finding_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]


async def add_private_scope(target_url: str, added_by: str = "admin") -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO private_scope (target_url, added_by)
            VALUES (?, ?)
            ON CONFLICT(target_url) DO UPDATE SET
                added_by = excluded.added_by,
                added_at = datetime('now')
            """,
            (target_url, added_by),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def list_private_scope() -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM private_scope ORDER BY added_at DESC"
        )
        return [dict(row) for row in await cursor.fetchall()]


async def find_private_scope(target_url: str) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM private_scope WHERE target_url = ?",
            (target_url,),
        )
        row = await cursor.fetchone()
        return None if row is None else dict(row)


async def update_private_scope_last_used(target_url: str) -> None:
    async with get_connection() as connection:
        await connection.execute(
            "UPDATE private_scope SET last_used = datetime('now') WHERE target_url = ?",
            (target_url,),
        )
        await connection.commit()


async def remove_private_scope(target_url: str) -> bool:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "DELETE FROM private_scope WHERE target_url = ?",
            (target_url,),
        )
        await connection.commit()
        return cursor.rowcount > 0


async def create_brutal_op(
    session_id: str,
    target_url: str,
    actor: str,
    action: str,
    *,
    scan_id: int | None = None,
    status: str = "pending",
    detail: str | None = None,
    payload: str | None = None,
    output: str | None = None,
) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO brutal_ops (
                session_id, scan_id, target_url, actor, action, status, detail, payload, output
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                scan_id,
                target_url[:2048],
                actor,
                action[:200],
                status[:50],
                (detail or "")[:4000],
                (payload or "")[:8000],
                (output or "")[:12000],
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def update_brutal_op(
    op_id: int,
    *,
    status: str | None = None,
    detail: str | None = None,
    output: str | None = None,
) -> None:
    sets: list[str] = []
    values: list[Any] = []
    if status is not None:
        sets.append("status = ?")
        values.append(status[:50])
    if detail is not None:
        sets.append("detail = ?")
        values.append((detail or "")[:4000])
    if output is not None:
        sets.append("output = ?")
        values.append((output or "")[:12000])
    if not sets:
        return
    values.append(op_id)
    async with get_connection() as connection:
        await connection.execute(
            f"UPDATE brutal_ops SET {', '.join(sets)} WHERE id = ?", values
        )
        await connection.commit()


async def list_brutal_ops(session_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        if session_id:
            cursor = await connection.execute(
                "SELECT * FROM brutal_ops WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            )
        else:
            cursor = await connection.execute(
                "SELECT * FROM brutal_ops ORDER BY id DESC LIMIT ?", (limit,)
            )
        return [dict(row) for row in await cursor.fetchall()]


async def create_brutal_session_row(
    session_id: str,
    target_url: str,
    actor: str,
    created_at: float,
    *,
    status: str = "established",
    simulation: bool = False,
    findings: list[dict] | None = None,
    sim_intel: dict | None = None,
    timeline: list[dict] | None = None,
    loot: list[dict] | None = None,
) -> None:
    async with get_connection() as connection:
        await connection.execute(
            """
            INSERT INTO brutal_sessions (
                session_id, target_url, actor, created_at, status, simulation,
                findings, sim_intel, timeline, loot
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                target_url[:2048],
                actor[:200],
                created_at,
                status[:50],
                1 if simulation else 0,
                json.dumps(findings or []),
                json.dumps(sim_intel or {}),
                json.dumps(timeline or []),
                json.dumps(loot or []),
            ),
        )
        await connection.commit()


async def save_brutal_session_row(
    session_id: str,
    *,
    status: str | None = None,
    timeline: list[dict] | None = None,
    loot: list[dict] | None = None,
    findings: list[dict] | None = None,
    sim_intel: dict | None = None,
    target_url: str | None = None,
    actor: str | None = None,
    created_at: float | None = None,
    simulation: bool | None = None,
) -> None:
    """Upsert a session snapshot so any mutation persists the row (on insert or conflict)."""
    fields = {
        "status": status[:50] if status is not None else None,
        "timeline": json.dumps(timeline) if timeline is not None else None,
        "loot": json.dumps(loot) if loot is not None else None,
        "findings": json.dumps(findings) if findings is not None else None,
        "sim_intel": json.dumps(sim_intel) if sim_intel is not None else None,
        "target_url": target_url[:2048] if target_url is not None else None,
        "actor": actor[:200] if actor is not None else None,
        "created_at": created_at if created_at is not None else None,
        "simulation": (1 if simulation else 0) if simulation is not None else None,
    }
    cols = ["session_id"] + [c for c, v in fields.items() if v is not None]
    values = [session_id] + [v for v in fields.values() if v is not None]
    conflict = ", ".join(f"{c} = excluded.{c}" for c in cols if c != "session_id")
    async with get_connection() as connection:
        await connection.execute(
            f"""
            INSERT INTO brutal_sessions ({', '.join(cols)})
            VALUES ({', '.join('?' for _ in cols)})
            ON CONFLICT(session_id) DO UPDATE SET {conflict}
            """,
            values,
        )
        await connection.commit()


async def load_brutal_sessions() -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute("SELECT * FROM brutal_sessions ORDER BY created_at ASC")
        rows = [dict(row) for row in await cursor.fetchall()]
    for row in rows:
        for key in ("findings", "sim_intel", "timeline", "loot"):
            raw = row.get(key)
            row[key] = json.loads(raw) if raw else ({} if key == "sim_intel" else [])
    return rows


async def get_job_events(job_id: str, after_sequence: int = 0) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            SELECT id, job_id, sequence_number, timestamp, module, event_type,
                   message, status, metadata, created_at
            FROM job_events
            WHERE job_id = ? AND sequence_number > ?
            ORDER BY sequence_number ASC
            """,
            (job_id, after_sequence),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
        for row in rows:
            try:
                row["metadata"] = json.loads(row.get("metadata") or "{}")
            except (json.JSONDecodeError, TypeError):
                row["metadata"] = {}
        return rows


async def save_exploitation_result(
    *,
    finding_id: int | None = None,
    scan_id: int,
    vulnerability_type: str,
    target_url: str | None = None,
    database_type: str | None = None,
    tables_extracted: list[str] | None = None,
    extracted_data: list[dict[str, Any]] | None = None,
    raw_result: dict[str, Any] | None = None,
    status: str = "completed",
    error_message: str | None = None,
) -> int:
    async with get_connection() as connection:
        cursor = await connection.execute(
            """
            INSERT INTO exploitation_results (
                finding_id, scan_id, vulnerability_type, target_url, database_type,
                tables_extracted, extracted_data, raw_result, status, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                scan_id,
                vulnerability_type,
                target_url,
                database_type,
                json.dumps(tables_extracted or [], ensure_ascii=True, default=str),
                json.dumps(extracted_data or [], ensure_ascii=True, default=str),
                json.dumps(raw_result or {}, ensure_ascii=True, default=str),
                status,
                error_message,
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def get_exploitation_results(scan_id: int) -> list[dict[str, Any]]:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM exploitation_results WHERE scan_id = ? ORDER BY id ASC",
            (scan_id,),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
        for row in rows:
            for col in ("tables_extracted", "extracted_data", "raw_result"):
                try:
                    row[col] = json.loads(row.get(col) or "[]") if col != "raw_result" else json.loads(row.get(col) or "{}")
                except (json.JSONDecodeError, TypeError):
                    row[col] = [] if col != "raw_result" else {}
        return rows


async def get_exploitation_result(finding_id: int) -> dict[str, Any] | None:
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM exploitation_results WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
            (finding_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        result = dict(row)
        for col in ("tables_extracted", "extracted_data", "raw_result"):
            try:
                result[col] = json.loads(result.get(col) or "[]") if col != "raw_result" else json.loads(result.get(col) or "{}")
            except (json.JSONDecodeError, TypeError):
                result[col] = [] if col != "raw_result" else {}
        return result


async def get_exploitation_results_map(finding_ids: list[int]) -> dict[int, dict[str, Any]]:
    """Latest exploitation result per finding id, for attaching PoCs to findings."""
    ids = list(dict.fromkeys(int(fid) for fid in finding_ids if fid))
    if not ids:
        return {}
    batch_size = 500
    rows: list[dict[str, Any]] = []
    async with get_connection() as connection:
        for start in range(0, len(ids), batch_size):
            batch = ids[start:start + batch_size]
            placeholders = ",".join("?" * len(batch))
            cursor = await connection.execute(
                f"SELECT * FROM exploitation_results WHERE finding_id IN ({placeholders}) ORDER BY id ASC",
                batch,
            )
            rows.extend(dict(row) for row in await cursor.fetchall())
    latest: dict[int, dict[str, Any]] = {}
    for row in rows:
        for col in ("tables_extracted", "extracted_data", "raw_result"):
            try:
                row[col] = json.loads(row.get(col) or "[]") if col != "raw_result" else json.loads(row.get(col) or "{}")
            except (json.JSONDecodeError, TypeError):
                row[col] = [] if col != "raw_result" else {}
        latest[int(row["finding_id"])] = row
    return latest


async def list_scan_sources(scan_id: int) -> list[dict[str, Any]]:
    """List source entries for a scan."""
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM scan_sources WHERE scan_id = ? ORDER BY priority ASC, id ASC",
            (scan_id,),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    for row in rows:
        for col in ("source_config", "artifacts"):
            try:
                row[col] = json.loads(row.get(col) or "{}")
            except (json.JSONDecodeError, TypeError):
                row[col] = {}
    return rows


async def upsert_scan_source(
    scan_id: int,
    source_type: str,
    source_config: dict[str, Any],
    source_identifier: str,
    priority: int = 1,
    *,
    status: str = "pending",
    findings_count: int = 0,
    scan_duration_seconds: float = 0,
    error_message: str | None = None,
    artifacts: dict[str, Any] | None = None,
) -> int:
    """Insert or update a scan_sources row for a scan."""
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT id FROM scan_sources WHERE scan_id = ? AND source_type = ?",
            (scan_id, source_type),
        )
        row = await cursor.fetchone()
        if row is not None:
            await connection.execute(
                """
                UPDATE scan_sources SET
                    source_config = ?,
                    source_identifier = ?,
                    priority = ?,
                    status = ?,
                    findings_count = ?,
                    scan_duration_seconds = ?,
                    error_message = ?,
                    artifacts = ?,
                    completed_at = CASE WHEN ? IN ('completed', 'failed') THEN CURRENT_TIMESTAMP ELSE completed_at END
                WHERE id = ?
                """,
                (
                    json.dumps(source_config, separators=(",", ":")),
                    source_identifier,
                    priority,
                    status,
                    findings_count,
                    scan_duration_seconds,
                    error_message,
                    json.dumps(artifacts or {}, separators=(",", ":")),
                    status,
                    int(row["id"]),
                ),
            )
            await connection.commit()
            return int(row["id"])
        cursor = await connection.execute(
            """
            INSERT INTO scan_sources (
                scan_id, source_type, source_config, source_identifier, status, priority,
                findings_count, scan_duration_seconds, error_message, artifacts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                source_type,
                json.dumps(source_config, separators=(",", ":")),
                source_identifier,
                status,
                priority,
                findings_count,
                scan_duration_seconds,
                error_message,
                json.dumps(artifacts or {}, separators=(",", ":")),
            ),
        )
        await connection.commit()
        return int(cursor.lastrowid)


async def update_scan_source_status(
    scan_id: int,
    source_type: str,
    status: str,
    *,
    findings_count: int | None = None,
    scan_duration_seconds: float | None = None,
    error_message: str | None = None,
    artifacts: dict[str, Any] | None = None,
) -> None:
    """Update status of a scan_sources row."""
    sets = ["status = ?"]
    params: list[Any] = [status]
    if findings_count is not None:
        sets.append("findings_count = ?")
        params.append(findings_count)
    if scan_duration_seconds is not None:
        sets.append("scan_duration_seconds = ?")
        params.append(scan_duration_seconds)
    if error_message is not None:
        sets.append("error_message = ?")
        params.append(error_message)
    if artifacts is not None:
        sets.append("artifacts = ?")
        params.append(json.dumps(artifacts, separators=(",", ":")))
    if status in ("completed", "failed"):
        sets.append("completed_at = CURRENT_TIMESTAMP")
    sets.append("started_at = COALESCE(started_at, CURRENT_TIMESTAMP)")
    params.extend([scan_id, source_type])
    async with get_connection() as connection:
        await connection.execute(
            f"UPDATE scan_sources SET {', '.join(sets)} WHERE scan_id = ? AND source_type = ?",
            params,
        )
        await connection.commit()


async def list_source_correlations(scan_id: int) -> list[dict[str, Any]]:
    """List cross-source correlations for a scan."""
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM source_correlations WHERE scan_id = ? ORDER BY confidence DESC, id ASC",
            (scan_id,),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    for row in rows:
        for col in ("source_types", "finding_ids", "evidence"):
            try:
                if col == "evidence":
                    row[col] = json.loads(row.get(col) or "{}")
                else:
                    row[col] = json.loads(row.get(col) or "[]")
            except (json.JSONDecodeError, TypeError):
                row[col] = [] if col != "evidence" else {}
    return rows


async def list_finding_sources(finding_id: int) -> list[dict[str, Any]]:
    """List source metadata for a finding."""
    async with get_connection() as connection:
        cursor = await connection.execute(
            "SELECT * FROM finding_sources WHERE finding_id = ? ORDER BY id ASC",
            (finding_id,),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
    return rows


async def list_multi_source_scans(
    user_id: str | None = None, limit: int = 50, enterprise_id: str | None = None
) -> list[dict[str, Any]]:
    """List scans that ran with multiple sources (has scan_sources rows)."""
    async with get_connection() as connection:
        if enterprise_id:
            cursor = await connection.execute(
                """
                SELECT DISTINCT s.* FROM scans s
                INNER JOIN scan_sources ss ON ss.scan_id = s.id
                WHERE s.enterprise_id = ?
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (enterprise_id, limit),
            )
        elif user_id:
            cursor = await connection.execute(
                """
                SELECT DISTINCT s.* FROM scans s
                INNER JOIN scan_sources ss ON ss.scan_id = s.id
                WHERE s.user_id = ?
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (user_id, limit),
            )
        else:
            cursor = await connection.execute(
                """
                SELECT DISTINCT s.* FROM scans s
                INNER JOIN scan_sources ss ON ss.scan_id = s.id
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (limit,),
            )
        rows = [dict(row) for row in await cursor.fetchall()]
    for row in rows:
        for col in ("selected_tests",):
            try:
                row[col] = json.loads(row.get(col) or "[]")
            except (json.JSONDecodeError, TypeError):
                row[col] = []
    return rows
