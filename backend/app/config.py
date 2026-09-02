from functools import lru_cache
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BASE_DIR.parent

load_dotenv(BASE_DIR / ".env")
load_dotenv(ROOT_DIR / ".env")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name, str(default)).lower()
    return val in ("1", "true", "yes", "on")


class Settings:
    app_name = "PhantomScan API"
    database_url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'phantomscan.db'}")
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
    cors_origins = list(dict.fromkeys([frontend_url, "http://localhost:5173", "http://127.0.0.1:5173"]))
    openrouter_api_key = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_model = os.getenv("OPENROUTER_MODEL", "google/gemma-4-31b-it:free")
    use_production_ai = os.getenv("USE_PRODUCTION_AI", "false").lower() in ("1", "true", "yes", "on")
    ai_model = os.getenv("AI_MODEL", "google/gemma-4-31b-it:free" if not use_production_ai else "openai/gpt-5.5-mini")
    llm_provider = os.getenv("LLM_PROVIDER", "openrouter")
    llm_model = os.getenv("LLM_MODEL", "")
    llm_api_key = os.getenv("LLM_API_KEY", "")
    clone_dir = os.getenv("CLONE_DIR", str(BASE_DIR / "repos"))
    ai_max_modules = env_int("AI_MAX_MODULES", 10)
    ai_poc_max_per_scan = env_int("AI_POC_MAX_PER_SCAN", 5)
    exploit_sandbox = os.getenv("EXPLOIT_SANDBOX", "auto")
    exploit_docker_image = os.getenv("EXPLOIT_DOCKER_IMAGE", "python:3.12-slim")
    nvd_api_key = os.getenv("NVD_API_KEY", "")
    notification_webhook_url = os.getenv("PHANTOMSCAN_WEBHOOK_URL", "")
    self_audit_webhook = os.getenv("SELF_AUDIT_WEBHOOK", "http://localhost:8000/api/logs/alert")
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    secret_key = os.getenv("SECRET_KEY")
    local_user_id = os.getenv("LOCAL_USER_ID", "local-user")
    local_user_role = os.getenv("LOCAL_USER_ROLE", "user")
    verification_ttl_days = env_int("VERIFICATION_TTL_DAYS", 30)
    verification_challenge_minutes = env_int("VERIFICATION_CHALLENGE_MINUTES", 60)
    max_scan_duration = env_int("MAX_SCAN_DURATION", 900)
    max_requests_per_second = env_float("MAX_REQUESTS_PER_SECOND", 10.0)
    max_total_requests = env_int("MAX_TOTAL_REQUESTS", 5000)
    active_max_concurrency = env_int("ACTIVE_MAX_CONCURRENCY", 20)
    max_concurrent_scans = env_int("MAX_CONCURRENT_SCANS", 10)
    max_redirect_depth = env_int("MAX_REDIRECT_DEPTH", 5)
    max_response_size = env_int("MAX_RESPONSE_SIZE", 1_048_576)
    browser_page_limit = env_int("BROWSER_PAGE_LIMIT", 16)
    module_timeout = env_int("MODULE_TIMEOUT", 120)
    analysis_module_timeout = env_float("ANALYSIS_MODULE_TIMEOUT", 20.0)
    nvd_lookup_timeout = env_float("NVD_LOOKUP_TIMEOUT", 10.0)
    active_target_allowlist = os.getenv("ACTIVE_TARGET_ALLOWLIST", "")
    deep_port_scan_enabled = os.getenv("DEEP_PORT_SCAN", "1") not in ("0", "false", "False")
    port_scan_concurrency = env_int("PORT_SCAN_CONCURRENCY", 64)
    port_scan_max_ports = env_int("PORT_SCAN_MAX_PORTS", 1024)
    port_scan_sweep_timeout = env_float("PORT_SCAN_SWEEP_TIMEOUT", 75.0)

    # GitHub OAuth
    github_client_id = os.getenv("GITHUB_CLIENT_ID", "")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET", "")
    github_redirect_uri = os.getenv("GITHUB_REDIRECT_URI", "")

    # GitHub App
    github_app_id = os.getenv("GITHUB_APP_ID", "")
    github_app_private_key = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    github_webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")

    # Supabase Auth (Google / GitHub login)
    supabase_url = os.getenv("SUPABASE_URL", "")
    supabase_jwt_secret = os.getenv("SUPABASE_JWT_SECRET", "")
    supabase_anon_key = os.getenv("SUPABASE_ANON_KEY", "")
    supabase_admin_emails = os.getenv("SUPABASE_ADMIN_EMAILS", "")

    # Redis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis_max_connections = env_int("REDIS_MAX_CONNECTIONS", 50)
    redis_socket_timeout = env_float("REDIS_SOCKET_TIMEOUT", 5.0)
    redis_socket_connect_timeout = env_float("REDIS_SOCKET_CONNECT_TIMEOUT", 5.0)

    # PostgreSQL connection pool
    pg_pool_min_size = env_int("PG_POOL_MIN_SIZE", 5)
    pg_pool_max_size = env_int("PG_POOL_MAX_SIZE", 20)
    pg_pool_timeout = env_float("PG_POOL_TIMEOUT", 30.0)
    pg_command_timeout = env_float("PG_COMMAND_TIMEOUT", 60.0)

    # Rate limiting
    rate_limit_enabled = env_bool("RATE_LIMIT_ENABLED", True)
    rate_limit_requests = env_int("RATE_LIMIT_REQUESTS", 100)
    rate_limit_window = env_int("RATE_LIMIT_WINDOW", 60)

    # Observability
    otel_enabled = env_bool("OTEL_ENABLED", False)
    otel_endpoint = os.getenv("OTEL_ENDPOINT", "http://localhost:4317")
    otel_service_name = os.getenv("OTEL_SERVICE_NAME", "phantomscan")
    prometheus_metrics_enabled = env_bool("PROMETHEUS_METRICS_ENABLED", True)

    # Security
    require_auth_on_health = env_bool("REQUIRE_AUTH_ON_HEALTH", False)
    require_auth_on_websocket = env_bool("REQUIRE_AUTH_ON_WEBSOCKET", True)
    api_key_enabled = env_bool("API_KEY_ENABLED", False)
    api_key_header = os.getenv("API_KEY_HEADER", "X-API-Key")
    api_key_value = os.getenv("API_KEY_VALUE", "")

    # DoS testing
    dos_max_rps_external = env_int("DOS_MAX_RPS_EXTERNAL", 200)
    dos_max_rps_lab = env_int("DOS_MAX_RPS_LAB", 50_000)
    dos_max_duration = env_int("DOS_MAX_DURATION", 300)
    dos_max_workers = env_int("DOS_MAX_WORKERS", 512)

    # Exploitation engine — OFF by default. A scan only exploits when BOTH
    # this global kill-switch is enabled AND the user explicitly requests it
    # per-scan (enable_exploitation / enable_ai_exploitation).
    exploitation_enabled = env_bool("EXPLOITATION_ENABLED", False)
    ai_exploitation_enabled = env_bool("AI_EXPLOITATION_ENABLED", False)
    exploit_attempt_timeout = env_float("EXPLOIT_ATTEMPT_TIMEOUT", 30.0)
    exploit_max_findings = env_int("EXPLOIT_MAX_FINDINGS", 10)

    # Brutal Mode (Black Ops) — off by default. Enables active exploitation,
    # shells, post-exploitation, lateral movement and exfiltration, strictly
    # gated to admin + Private Scope targets + explicit ownership ack.
    brutal_mode_enabled = env_bool("BRUTAL_MODE_ENABLED", False)
    brutal_exfil_dir = os.getenv("BRUTAL_EXFIL_DIR", str(BASE_DIR / "brutal_exfil"))
    brutal_max_commands_per_shell = env_int("BRUTAL_MAX_COMMANDS_PER_SHELL", 100)
    brutal_command_timeout = env_float("BRUTAL_COMMAND_TIMEOUT", 12.0)
    # Loot archive password. When empty, the key is derived from SECRET_KEY +
    # session_id so the server can always decrypt its own archives.
    brutal_exfil_password = os.getenv("BRUTAL_EXFIL_PASSWORD", "")
    # Evasion toggles — OFF by default so canned lab keyword-matching still works.
    brutal_evasion_obfuscate = env_bool("BRUTAL_EVASION_OBFUSCATE", False)
    brutal_evasion_slow_scan = env_bool("BRUTAL_EVASION_SLOW_SCAN", False)

    # ML accuracy enhancement — heuristic fallbacks always run; trained models
    # (see app/ml/train_injection_detector.py) are loaded when ML_ENABLED=true.
    ml_enabled = env_bool("ML_ENABLED", False)
    ml_model_dir = os.getenv("ML_MODEL_DIR", "")
    ml_injection_threshold = env_float("ML_INJECTION_THRESHOLD", 0.5)
    ml_fp_threshold = env_float("ML_FP_THRESHOLD", 0.5)
    ml_priority_enabled = env_bool("ML_PRIORITY_ENABLED", True)
    ml_severity_override = env_bool("ML_SEVERITY_OVERRIDE", False)
    ml_fp_auto_filter = env_bool("ML_FP_AUTO_FILTER", False)

    # Stealth / evasion scanning
    stealth_enabled = env_bool("STEALTH_ENABLED", True)
    proxy_list_raw = os.getenv("PROXY_LIST", "")
    headless_browser = env_bool("HEADLESS_BROWSER", False)
    evasion_max_attempts = env_int("EVASION_MAX_ATTEMPTS", 3)
    evasion_delay_min = env_float("EVASION_DELAY_MIN", 0.5)
    evasion_delay_max = env_float("EVASION_DELAY_MAX", 2.0)
    evasion_header_injection = env_bool("EVASION_HEADER_INJECTION", True)
    evasion_path_transforms = env_bool("EVASION_PATH_TRANSFORMS", True)
    evasion_max_path_variants = env_int("EVASION_MAX_PATH_VARIANTS", 6)

    # Verified finding precision thresholds. These tune how numeric verifier
    # scores become analyst-facing confidence labels.
    confidence_high = env_float("CONFIDENCE_HIGH", 0.85)
    confidence_medium = env_float("CONFIDENCE_MEDIUM", 0.60)
    callback_domain = os.getenv("CALLBACK_DOMAIN", "")
    callback_base_url = os.getenv("CALLBACK_BASE_URL", "")
    callback_wait_timeout = env_float("CALLBACK_WAIT_TIMEOUT", 5.0)

    def validate_required(self, mode: str = "defend") -> list[str]:
        """Validate required settings for a given scan mode. Returns list of missing keys."""
        missing = []
        if not self.secret_key:
            missing.append("SECRET_KEY")
        if mode in ("pentest", "multi_agent") and not self.openrouter_api_key:
            missing.append("OPENROUTER_API_KEY")
        if mode in ("pentest", "multi_agent") and not self.nvd_api_key:
            missing.append("NVD_API_KEY")
        return missing


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_model() -> str:
    """Return the AI model to use based on configuration.
    
    If USE_PRODUCTION_AI is true, returns the PRODUCTION_MODEL.
    Otherwise returns the DEV_MODEL (Nemotron 3.5 Lightning).
    """
    from app.config import get_settings as _gs
    settings = _gs()
    if settings.use_production_ai:
        return settings.ai_model or "openai/gpt-5.5-mini"
    return settings.ai_model or "google/gemma-4-31b-it:free"
