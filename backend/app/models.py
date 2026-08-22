from datetime import datetime
from typing import Any, Literal, Optional
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator, HttpUrl


Mode = Literal["defend", "pentest", "multi_agent"]
JobStatus = Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]
Intensity = Literal["low", "medium", "high"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Confidence = Literal["CONFIRMED", "HIGH", "MEDIUM", "LOW", "POTENTIAL"]
ScanStatus = Literal["queued", "running", "cancelling", "cancelled", "complete", "error", "failed"]
AgentRunStatus = Literal["idle", "active", "complete", "error"]
ExecutionType = Literal["DEFEND_SCAN", "AUTHORIZED_TEST", "SELF_AUDIT", "LAB_OPERATION"]
ExecutionLifecycle = Literal["IDLE", "QUEUED", "STARTING", "RUNNING", "PAUSED", "COMPLETED", "FAILED", "CANCELLED"]
AgentApplicability = Literal["IDLE", "QUEUED", "RUNNING", "WAITING", "COMPLETED", "FAILED", "NOT_APPLICABLE"]
VerificationMethod = Literal["dns", "http"]
VerificationStatus = Literal["PENDING", "VERIFIED", "EXPIRED", "REVOKED"]
TestModule = Literal[
    "input_security",
    "authentication",
    "authorization",
    "injection",
    "xss",
    "auth_session",
    "access_control",
    "csrf",
    "ssrf",
    "file_upload",
    "api_security",
    "graphql",
    "jwt",
    "websocket",
    "websockets",
    "rate_limits",
    "business_logic",
    "path_handling",
    "redirect",
    "redirect_security",
    "cors",
    "security_headers",
    "tls_https",
    "sensitive_exposure",
]

# Multi-source scanning types
SourceType = Literal["local", "github", "gitlab", "bitbucket", "live", "api_spec", "docker", "kubernetes", "terraform"]
ScanSource = Literal["sast", "dast", "sca", "iac", "secrets", "combined"]
GitHubAuthType = Literal["oauth_user", "github_app", "pat"]
Language = Literal["python", "javascript", "typescript", "java", "go", "php", "csharp", "ruby", "rust", "kotlin", "swift", "scala"]
Framework = Literal["django", "flask", "fastapi", "express", "nextjs", "nestjs", "spring", "rails", "laravel", "dotnet", "gin", "echo", "actix", "symfony", "codeigniter"]
SastTool = Literal["semgrep", "codeql", "bandit", "eslint", "spotbugs", "gosec", "phpstan", "psalm", "brakeman", "rubocop", "clippy", "detekt", "custom"]


class SourceConfig(BaseModel):
    """Configuration for a single scan source."""
    model_config = ConfigDict(extra="forbid")

    type: SourceType
    enabled: bool = True
    priority: int = Field(default=1, ge=1, le=10)  # Execution priority


class LocalCodebaseConfig(SourceConfig):
    """Configuration for local codebase scanning (whitebox)."""
    type: Literal["local"] = "local"
    path: str = Field(min_length=1, max_length=500, description="Absolute path to codebase")
    languages: list[Language] = Field(default_factory=list, description="Override auto-detected languages")
    frameworks: list[Framework] = Field(default_factory=list, description="Override auto-detected frameworks")
    exclude_patterns: list[str] = Field(default_factory=list, description="Glob patterns to exclude")
    include_patterns: list[str] = Field(default_factory=list, description="Glob patterns to include")
    follow_symlinks: bool = False
    max_file_size_mb: int = Field(default=10, ge=1, le=100)


class GitHubConfig(SourceConfig):
    """Configuration for GitHub repository scanning."""
    type: Literal["github"] = "github"
    repo_url: HttpUrl = Field(description="GitHub repository URL (https://github.com/owner/repo)")
    branch: str = Field(default="main", description="Branch to scan")
    auth_type: GitHubAuthType = Field(default="oauth_user", description="Authentication method")
    github_app_id: str | None = Field(default=None, description="GitHub App ID (for github_app auth)")
    github_app_installation_id: str | None = Field(default=None, description="GitHub App installation ID")
    pat_token: str | None = Field(default=None, description="Personal Access Token (for pat auth)")
    pr_number: int | None = Field(default=None, description="Specific PR to scan (diff mode)")
    scan_mode: Literal["full", "diff", "changed_files"] = Field(default="full")
    base_branch: str = Field(default="main", description="Base branch for diff scans")
    include_workflows: bool = Field(default=True, description="Scan GitHub Actions workflows")
    include_dependabot: bool = Field(default=True, description="Include Dependabot alerts")
    exclude_patterns: list[str] = Field(default_factory=list, description="Glob patterns to exclude from scan")
    scan_timeout: int | None = Field(default=None, ge=60, le=3600, description="Custom scan timeout in seconds (60-3600)")


class GitLabConfig(SourceConfig):
    """Configuration for GitLab repository scanning."""
    type: Literal["gitlab"] = "gitlab"
    repo_url: HttpUrl = Field(description="GitLab repository URL")
    branch: str = Field(default="main")
    access_token: str | None = Field(default=None)
    project_id: str | None = Field(default=None)
    scan_mode: Literal["full", "diff"] = Field(default="full")


class BitbucketConfig(SourceConfig):
    """Configuration for Bitbucket repository scanning."""
    type: Literal["bitbucket"] = "bitbucket"
    repo_url: HttpUrl = Field(description="Bitbucket repository URL")
    branch: str = Field(default="main")
    access_token: str | None = Field(default=None)
    workspace: str | None = Field(default=None)


class LiveTargetConfig(SourceConfig):
    """Configuration for live application scanning (blackbox)."""
    type: Literal["live"] = "live"
    target_url: HttpUrl = Field(description="Live application URL")
    authorization_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False
    intensity: Intensity = "medium"
    selected_modules: list[str] = Field(default_factory=list)
    business_logic_tests: list[dict[str, Any]] = Field(default_factory=list)
    enable_exploitation: bool = False


class APISpecConfig(SourceConfig):
    """Configuration for API specification scanning."""
    type: Literal["api_spec"] = "api_spec"
    spec_url: HttpUrl | None = Field(default=None, description="URL to OpenAPI/Swagger spec")
    spec_content: str | None = Field(default=None, description="Inline spec content (JSON/YAML)")
    base_url: HttpUrl = Field(description="Base URL of the API")
    auth_header: str | None = Field(default=None)
    auth_token: str | None = Field(default=None)


class DockerConfig(SourceConfig):
    """Configuration for Docker image scanning."""
    type: Literal["docker"] = "docker"
    image: str = Field(description="Docker image name (e.g., nginx:latest)")
    registry_auth: dict[str, str] | None = Field(default=None)
    scan_layers: bool = True


class KubernetesConfig(SourceConfig):
    """Configuration for Kubernetes manifest scanning."""
    type: Literal["kubernetes"] = "kubernetes"
    manifests_path: str | None = Field(default=None, description="Path to K8s manifests (local or GitHub)")
    cluster_context: str | None = Field(default=None)
    namespaces: list[str] = Field(default_factory=list)


class TerraformConfig(SourceConfig):
    """Configuration for Terraform configuration scanning."""
    type: Literal["terraform"] = "terraform"
    config_path: str | None = Field(default=None, description="Path to Terraform configs")
    plan_file: str | None = Field(default=None, description="Path to Terraform plan output")
    variables: dict[str, Any] = Field(default_factory=dict)


# Union type for all source configs
SourceConfigUnion = LocalCodebaseConfig | GitHubConfig | GitLabConfig | BitbucketConfig | LiveTargetConfig | APISpecConfig | DockerConfig | KubernetesConfig | TerraformConfig


class MultiSourceScanRequest(BaseModel):
    """Extended scan request supporting multiple sources."""
    model_config = ConfigDict(extra="forbid")

    # Basic scan config
    name: str = Field(default="", max_length=200, description="Scan name/description")
    mode: Mode = "multi_agent"
    intensity: Intensity = "medium"
    
    # Sources to scan
    sources: list[SourceConfigUnion] = Field(default_factory=list, min_length=1, max_length=5)
    
    # Correlation settings
    correlate_findings: bool = Field(default=True, description="Cross-correlate findings across sources")
    data_flow_tracing: bool = Field(default=True, description="Enable taint analysis across sources")
    
    # Output settings
    generate_sarif: bool = Field(default=True)
    generate_pdf: bool = Field(default=False)
    compliance_frameworks: list[str] = Field(default_factory=list)
    
    # Budget
    max_cost_usd: float | None = Field(default=None, ge=0)
    max_duration_minutes: int = Field(default=120, ge=5, le=1440)
    
    # Notifications
    notify_on_critical: bool = True
    notify_on_complete: bool = True
    webhook_url: HttpUrl | None = None
    approval_request_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_sources(self) -> "MultiSourceScanRequest":
        source_types = [s.type for s in self.sources]
        if len(source_types) != len(set(source_types)):
            raise ValueError("Duplicate source types not allowed")
        
        # Must have at least one code source or live target
        code_sources = {"local", "github", "gitlab", "bitbucket", "api_spec", "docker", "kubernetes", "terraform"}
        live_sources = {"live"}
        has_code = any(s in code_sources for s in source_types)
        has_live = any(s in live_sources for s in source_types)
        
        if not has_code and not has_live:
            raise ValueError("At least one code source or live target required")
        
        return self


class BusinessLogicTest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    path: str = Field(min_length=1, max_length=500)
    expected_status: int = Field(ge=100, le=599)
    description: str = Field(default="", max_length=500)

    @field_validator("path")
    @classmethod
    def path_must_be_relative(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("Business logic paths must be relative to the verified target")
        return value


# Backward compatibility - original ScanRequest for existing agents
class ScanRequest(BaseModel):
    """Legacy scan request for backward compatibility."""
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    mode: Mode
    intensity: Intensity = "medium"
    selected_tests: list[TestModule] = Field(default_factory=list, max_length=25)
    attack_types: list[TestModule] = Field(default_factory=list, max_length=25)
    authorization_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False
    business_logic_tests: list[BusinessLogicTest] = Field(default_factory=list, max_length=10)
    enable_exploitation: bool = False
    enable_ai_exploitation: bool = False
    approval_request_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def normalize_test_selection(self) -> "ScanRequest":
        if self.selected_tests and self.attack_types and set(self.selected_tests) != set(self.attack_types):
            raise ValueError("selected_tests and attack_types cannot define different scopes")
        selected = self.selected_tests or self.attack_types
        self.selected_tests = list(dict.fromkeys(selected))
        self.attack_types = []
        return self


# GitHub OAuth Models
class GitHubOAuthRequest(BaseModel):
    """Request to initiate GitHub OAuth flow."""
    model_config = ConfigDict(extra="forbid")

    redirect_url: HttpUrl = Field(description="Frontend redirect URL after OAuth")
    scope: str = Field(default="repo read:org read:user user:email", description="OAuth scopes")
    state: str | None = Field(default=None, description="CSRF state parameter")


class GitHubOAuthCallback(BaseModel):
    """GitHub OAuth callback parameters."""
    code: str = Field(min_length=1, description="Authorization code from GitHub")
    state: str | None = Field(default=None, description="CSRF state parameter")
    redirect_uri: str | None = Field(default=None, description="Redirect URI used in the authorize request")


class GitHubTokenResponse(BaseModel):
    """GitHub OAuth token response."""
    access_token: str
    token_type: str = "bearer"
    scope: str
    expires_in: int | None = None
    refresh_token: str | None = None


class GitHubUserResponse(BaseModel):
    """GitHub user info response."""
    id: int
    login: str
    name: str | None = None
    email: str | None = None
    avatar_url: str
    html_url: str
    type: str
    organizations: list[dict[str, Any]] = Field(default_factory=list)


class GitHubRepoResponse(BaseModel):
    """GitHub repository info."""
    id: int
    full_name: str
    name: str
    owner: dict[str, Any]
    private: bool
    html_url: str
    clone_url: str
    ssh_url: str
    default_branch: str
    permissions: dict[str, bool]
    language: str | None = None
    topics: list[str] = Field(default_factory=list)
    updated_at: str
    pushed_at: str | None = None


class GitHubInstallationResponse(BaseModel):
    """GitHub App installation."""
    id: int
    account: dict[str, Any]
    repository_selection: str
    permissions: dict[str, str]
    events: list[str]
    html_url: str
    created_at: str
    updated_at: str


class GitHubWebhookPayload(BaseModel):
    """GitHub webhook payload for PR events."""
    action: str
    number: int
    pull_request: dict[str, Any]
    repository: dict[str, Any]
    sender: dict[str, Any]
    installation: dict[str, Any] | None = None


class GitHubAppConfig(BaseModel):
    """GitHub App configuration for installation."""
    app_id: str
    private_key: str
    webhook_secret: str
    client_id: str
    client_secret: str


# Enhanced Finding Models with Correlation Support
class FindingSource(BaseModel):
    """Source information for a finding."""
    type: SourceType
    identifier: str  # repo URL, file path, live URL, etc.
    location: dict[str, Any] = Field(default_factory=dict)  # file, line, function, etc.
    tool: str | None = None  # semgrep, active_security, etc.
    rule_id: str | None = None
    commit_sha: str | None = None
    branch: str | None = None
    pr_number: int | None = None


class CorrelationInfo(BaseModel):
    """Cross-source correlation information."""
    unified_id: str = Field(description="Unique ID across all sources for same vulnerability")
    correlated_sources: list[SourceType] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Correlation confidence")
    correlation_type: Literal["exact_match", "same_file", "same_endpoint", "data_flow", "vulnerability_chain"] = "exact_match"
    evidence: dict[str, Any] = Field(default_factory=dict)


class SASTFindingDetails(BaseModel):
    """SAST-specific finding details."""
    language: Language
    framework: Framework | None = None
    file_path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    function_name: str | None = None
    class_name: str | None = None
    code_snippet: str = Field(default="", max_length=5000)
    rule_id: str
    rule_name: str
    rule_severity: str
    tool: SastTool
    references: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_category: str | None = None
    fix_suggestion: str | None = None
    fix_example: str | None = None


class SecretFindingDetails(BaseModel):
    """Secret detection finding details."""
    secret_type: str  # api_key, password, token, private_key, etc.
    detector_name: str
    file_path: str
    line_number: int
    matched_content: str = Field(default="", max_length=200)
    entropy: float | None = None
    is_validated: bool = False
    validation_error: str | None = None


class IaCFindingDetails(BaseModel):
    """IaC finding details."""
    resource_type: str  # aws_s3_bucket, k8s_pod, etc.
    resource_name: str
    file_path: str
    line_range: tuple[int, int]
    configuration: dict[str, Any]
    misconfiguration_type: str
    platform: Literal["terraform", "kubernetes", "cloudformation", "helm", "dockerfile"]


class SCAFindingDetails(BaseModel):
    """Software Composition Analysis finding details."""
    package_name: str
    package_version: str
    ecosystem: str  # pypi, npm, maven, nuget, go, cargo, etc.
    vulnerability_id: str  # CVE or GHSA
    vulnerable_versions: str
    fixed_version: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    license: str | None = None
    is_direct: bool = True  # direct vs transitive dependency
    dependency_path: list[str] = Field(default_factory=list)  # dependency tree path
    advisory_url: str | None = None


# Enhanced FindingCreate with correlation support
class FindingCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str = Field(min_length=1, max_length=300)
    category: str = Field(min_length=1, max_length=120)
    severity: Severity
    confidence: Confidence
    target: str = Field(min_length=1, max_length=2048)
    endpoint: str = Field(default="", max_length=2048)
    evidence: str = Field(default="", max_length=12000)
    impact: str = Field(default="", max_length=4000)
    recommendation: str = Field(default="", max_length=6000)
    verification: str = Field(default="", max_length=4000)
    agent: str = Field(min_length=1, max_length=120)
    timestamp: datetime
    cve_id: str | None = Field(default=None, max_length=40)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cwe: str | None = Field(default=None, max_length=200)
    version_affected: str | None = Field(default=None, max_length=500)
    file_path: str | None = Field(default=None, max_length=2048)
    line_number: int | None = Field(default=None, ge=1)
    code_snippet: str | None = Field(default=None, max_length=12000)
    fix_recommendation: str | None = Field(default=None, max_length=6000)
    parameter: str | None = Field(default=None, max_length=200)
    module: str | None = Field(default=None, max_length=120)
    recommended_fix: str | None = Field(default=None, max_length=6000)
    remediation_status: Literal["OPEN", "IN_PROGRESS", "RESOLVED"] = "OPEN"
    verification_status: Literal["NOT_VERIFIED", "FIX_VERIFIED", "ISSUE_STILL_PRESENT", "VERIFY_FAILED"] = "NOT_VERIFIED"
    risk_status: Literal["ACTIVE", "FALSE_POSITIVE", "ACCEPTED_RISK"] = "ACTIVE"
    exploited: bool = False
    exploitation_result: dict[str, Any] | None = None
    poc: dict[str, Any] | None = None
    
    # Multi-source correlation fields
    sources: list[FindingSource] = Field(default_factory=list)
    correlation: CorrelationInfo | None = None
    primary_source: SourceType = "live"
    
    # Source-specific details (one will be populated based on primary_source)
    sast_details: SASTFindingDetails | None = None
    secret_details: SecretFindingDetails | None = None
    iac_details: IaCFindingDetails | None = None
    sca_details: SCAFindingDetails | None = None
    
    # Patch/fix info
    patch: str | None = Field(default=None, description="Unified diff patch")
    patch_status: Literal["pending", "applied", "failed", "verified"] | None = None
    patch_applied_at: datetime | None = None
    
    # Remediation tracking
    assigned_to: str | None = None
    due_date: datetime | None = None
    fix_commit_sha: str | None = None
    fix_pr_url: str | None = None


class Finding(FindingCreate):
    id: int
    scan_id: int
    description: str = ""
    how_exploited: str = ""
    fix: str = ""


class ScanResponse(BaseModel):
    scan_id: int
    target_url: str
    mode: Mode
    intensity: Intensity = "medium"
    selected_tests: list[TestModule] = Field(default_factory=list)
    user_id: str = "local-user"
    authorization_id: int | None = None
    authorization_confirmed: bool = False
    status: ScanStatus
    progress: int = Field(ge=0, le=100)
    request_count: int = Field(ge=0)
    sandbox_id: str | None = None
    error_message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings: list[Finding]


class ScanHistoryItem(BaseModel):
    id: int
    target_url: str
    mode: Mode
    status: ScanStatus
    progress: int = Field(ge=0, le=100)
    created_at: datetime
    completed_at: datetime | None = None


class AuditLog(BaseModel):
    id: int
    scan_id: int
    agent_name: str
    action: str
    timestamp: datetime
    details: str
    user_id: str | None = None
    target: str | None = None
    authorization_status: str | None = None
    selected_module: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    result: str | None = None
    request_count: int | None = None
    sandbox_id: str | None = None


class AgentStatus(BaseModel):
    name: str
    status: AgentRunStatus


class AuthorizationChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    verification_method: VerificationMethod


class AuthorizationChallengeResponse(BaseModel):
    id: int
    domain: str
    target_origin: str
    verification_method: VerificationMethod
    token: str
    dns_record: str
    http_url: str
    challenge_expires_at: datetime
    status: VerificationStatus


class AuthorizationStatusResponse(BaseModel):
    id: int | None = None
    domain: str
    target_origin: str
    verification_method: VerificationMethod | None = None
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    status: VerificationStatus
    message: str


class StopScanResponse(BaseModel):
    scan_id: int
    status: ScanStatus


class ScanArtifactsResponse(BaseModel):
    scan_id: int
    scanner_output: dict[str, Any] | None = None
    shadow_recon_output: dict[str, Any] | None = None
    markdown_report: str | None = None
    notification_result: dict[str, Any] | None = None
    active_security_output: dict[str, Any] | None = None
    browser_security_output: dict[str, Any] | None = None
    ai_analyst_output: dict[str, Any] | None = None
    tci_output: dict[str, Any] | None = None
    ai_consultation: dict[str, Any] | None = None
    updated_at: datetime | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: str
    database: Literal["available", "unavailable"]
    scheduler: Literal["running", "stopped", "unavailable"]
    agents: Literal["available", "unavailable"]
    ai_provider: str = "OpenRouter"
    ai_model: str = "openrouter/free"
    ai_status: Literal["connected", "offline"] = "offline"


class SelfAuditStatusResponse(BaseModel):
    status: ScanStatus | Literal["never_run"]
    scan_id: int | None = None
    target_url: str | None = None
    progress: int | None = Field(default=None, ge=0, le=100)
    finding_count: int | None = Field(default=None, ge=0)
    created_at: datetime | None = None
    completed_at: datetime | None = None


class ActiveRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)
    selected_modules: list[TestModule] = Field(default_factory=list, max_length=25)
    authorization_id: int | None = Field(default=None, ge=1)
    authorization_confirmed: bool = False
    enable_exploitation: bool = False
    enable_ai_exploitation: bool = False
    approval_request_id: int | None = Field(default=None, ge=1)


class AuthorizedTestRunResponse(BaseModel):
    job_id: str
    status: JobStatus
    message: str


class JobEvent(BaseModel):
    id: int
    job_id: str
    sequence_number: int
    timestamp: str
    module: str | None = None
    event_type: str
    message: str | None = None
    status: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str | None = None


class JobEventsResponse(BaseModel):
    job_id: str
    events: list[JobEvent] = Field(default_factory=list)
    latest_sequence: int = 0


class AuthorizedTestJobError(BaseModel):
    code: str
    message: str


class AuthorizedTestJobResponse(BaseModel):
    job_id: str
    status: JobStatus
    progress_percent: int = Field(ge=0, le=100)
    current_phase: str | None = None
    current_module: str | None = None
    surfaces_total: int = Field(ge=0)
    surfaces_completed: int = Field(ge=0)
    findings_count: int = Field(ge=0)
    raw_surfaces_discovered: int = Field(default=0, ge=0)
    testable_surfaces: int = Field(default=0, ge=0)
    surface_groups: int = Field(default=0, ge=0)
    started_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    error: AuthorizedTestJobError | None = None
    target_url: str = ""
    selected_modules: list[str] = Field(default_factory=list)
    authorization_id: int | None = None
    scan_id: int | None = None


class AuthorizedTestJobResultsResponse(BaseModel):
    job_id: str
    status: JobStatus
    target_url: str = ""
    surfaces_total: int = Field(ge=0)
    surfaces_completed: int = Field(ge=0)
    raw_surfaces_discovered: int = Field(default=0, ge=0)
    testable_surfaces: int = Field(default=0, ge=0)
    surface_groups: int = Field(default=0, ge=0)
    findings_count: int = Field(ge=0)
    started_at: str | None = None
    completed_at: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    result_summary: dict[str, Any] | None = None


class RequestEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int = 0
    request_id: str = Field(min_length=1, max_length=64)
    job_id: str | None = Field(default=None, max_length=64)
    scan_id: int | None = None
    module: str = Field(default="", max_length=120)
    surface: str = Field(default="", max_length=500)
    method: str = Field(default="", max_length=10)
    request_url: str = Field(default="", max_length=4096)
    safe_test_marker: str = Field(default="", max_length=200)
    request_timestamp: str = Field(default="")
    response_status: int | None = None
    response_time_ms: int | None = None
    response_observed: bool = False
    detection_result: str = Field(default="INCONCLUSIVE", max_length=30)
    evidence_summary: str = Field(default="", max_length=2000)
    finding_id: int | None = None
    error: str | None = Field(default=None, max_length=500)


AgentApplicabilityLiteral = Literal["IDLE", "QUEUED", "RUNNING", "WAITING", "COMPLETED", "FAILED", "NOT_APPLICABLE"]


class AgentStateDetail(BaseModel):
    name: str
    applicability: AgentApplicabilityLiteral
    responsibility: str = ""
    current_module: str | None = None
    progress: int = Field(default=0, ge=0, le=100)
    last_updated: str | None = None
    detail: str = ""


class ExecutionStatusResponse(BaseModel):
    execution_type: ExecutionType | None = None
    lifecycle: ExecutionLifecycle
    job_id: str | None = None
    scan_id: int | None = None
    target_url: str = ""
    progress_percent: int = Field(default=0, ge=0, le=100)
    current_module: str | None = None
    current_phase: str | None = None
    surfaces_total: int = Field(default=0, ge=0)
    surfaces_completed: int = Field(default=0, ge=0)
    findings_count: int = Field(default=0, ge=0)
    started_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    error_code: str | None = None
    agents: list[AgentStateDetail] = Field(default_factory=list)
    is_lab: bool = False
    authorization_status: str = ""


class ComplexityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=4, max_length=2048)


class ComplexityResponse(BaseModel):
    target_url: str
    score: int = Field(ge=0, le=100)
    band: str
    band_label: str
    breakdown: dict[str, Any] = Field(default_factory=dict)
    source: Literal["recon", "live", "fallback"] = "live"


class AdaptivePlanResponse(BaseModel):
    band: str
    score: int = Field(ge=0, le=100)
    requests_per_second: float = Field(ge=0.1)
    intensity: Intensity = "medium"
    modules: list[str] = Field(default_factory=list)
    excluded_modules: list[str] = Field(default_factory=list)
    excluded_reasons: dict[str, str] = Field(default_factory=dict)
    depth: str = "standard"
    deeper: bool = False
    limits: dict[str, Any] = Field(default_factory=dict)
    rationale: list[str] = Field(default_factory=list)


class LearningInsightResponse(BaseModel):
    id: int
    scan_id: int | None = None
    module: str | None = None
    kind: str = "module"
    total_count: int = 0
    true_positives: int = 0
    false_positives: int = 0
    unrated_count: int = 0
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    recommendation: str | None = None
    recommendation_data: dict[str, Any] | None = None
    status: str = "pending"
    applied_settings: dict[str, Any] | None = None
    created_at: str | None = None
    updated_at: str | None = None


class LearningInsightUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["applied", "dismissed"]
    applied_settings: dict[str, Any] | None = None


class ScanQualityResponse(BaseModel):
    modules: list[dict[str, Any]] = Field(default_factory=list)
    scans: list[dict[str, Any]] = Field(default_factory=list)


# Multi-Source Scan Response Models
class SourceScanResult(BaseModel):
    """Results from scanning a single source."""
    source_type: SourceType
    source_identifier: str  # repo URL, path, etc.
    status: ScanStatus
    findings_count: int = 0
    findings_by_severity: dict[Severity, int] = Field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    error_message: str | None = None
    artifacts: dict[str, Any] = Field(default_factory=dict)


class MultiSourceScanResponse(BaseModel):
    """Response for multi-source scan."""
    scan_id: int
    name: str
    mode: Mode
    overall_status: ScanStatus
    overall_progress: int = Field(ge=0, le=100)
    sources: list[SourceScanResult] = Field(default_factory=list)
    total_findings: int = 0
    findings_by_severity: dict[Severity, int] = Field(default_factory=dict)
    correlated_findings_count: int = 0
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_duration_seconds: float = 0.0
    max_duration_minutes: int = 120
    sarif_export_url: str | None = None
    pdf_report_url: str | None = None
    health_score: dict | None = None


class MultiSourceScanHistoryItem(BaseModel):
    """History item for multi-source scans."""
    scan_id: int
    name: str
    mode: Mode
    overall_status: ScanStatus
    sources: list[SourceType]
    total_findings: int
    correlated_findings: int
    created_at: datetime
    completed_at: datetime | None = None


class SourceCorrelationSummary(BaseModel):
    """Summary of cross-source correlations."""
    total_correlations: int
    by_type: dict[str, int]  # correlation_type -> count
    by_source_pair: dict[str, int]  # "sast+dast" -> count
    high_confidence: int  # confidence > 0.8
    data_flow_traces: int
    vulnerability_chains: int


class CorrelatedFindingGroup(BaseModel):
    """Group of correlated findings across sources."""
    unified_id: str
    title: str
    severity: Severity
    confidence: float
    sources: list[SourceType]
    primary_finding: Finding
    related_findings: list[Finding]
    correlation_type: str
    data_flow_trace: list[dict[str, Any]] | None = None
    vulnerability_chain: list[str] | None = None
    combined_evidence: dict[str, Any]


class AICodeFixRequest(BaseModel):
    """Request for AI-generated code fix."""
    model_config = ConfigDict(extra="forbid")

    finding_id: int
    finding_title: str
    category: str
    severity: Severity
    code_snippet: str
    file_path: str
    language: Language
    framework: Framework | None = None
    rule_id: str | None = None
    rule_description: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)  # Additional context from skills
    skill_context: str | None = None  # Pre-loaded skill knowledge


class AICodeFixResponse(BaseModel):
    """AI-generated code fix response."""
    patch: str = Field(description="Unified diff patch")
    explanation: str = Field(description="Human-readable explanation of the fix")
    confidence: float = Field(ge=0.0, le=1.0)
    fix_type: Literal["parameterized_query", "input_validation", "output_encoding", "auth_check", "config_change", "dependency_update", "custom"]
    verification_steps: list[str] = Field(default_factory=list)
    related_cwe: list[str] = Field(default_factory=list)
    estimated_effort: Literal["trivial", "easy", "moderate", "complex"]


class AITutorRequest(BaseModel):
    """Request for AI tutoring/explanation."""
    model_config = ConfigDict(extra="forbid")

    finding_id: int | None = None
    question: str = Field(min_length=1, max_length=5000)
    context: dict[str, Any] = Field(default_factory=dict)
    language: Language | None = None
    user_level: Literal["beginner", "intermediate", "expert"] = "intermediate"


class AITutorResponse(BaseModel):
    """AI tutor response."""
    answer: str
    explanation: str | None = None
    code_examples: list[dict[str, str]] = Field(default_factory=list)  # {"language": "python", "code": "..."}
    references: list[str] = Field(default_factory=list)
    follow_up_questions: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class PRDescriptionRequest(BaseModel):
    """Request for PR description generation."""
    model_config = ConfigDict(extra="forbid")

    finding_ids: list[int]
    base_branch: str
    head_branch: str
    repo_url: str
    include_fix_details: bool = True
    include_verification_steps: bool = True


class PRDescriptionResponse(BaseModel):
    """Generated PR description."""
    title: str
    body: str  # Markdown
    labels: list[str] = Field(default_factory=list)
    reviewers: list[str] = Field(default_factory=list)
    related_issues: list[str] = Field(default_factory=list)


class SupabaseLoginRequest(BaseModel):
    """Exchange a Supabase access token for a PhantomScan session."""
    model_config = ConfigDict(extra="forbid")

    access_token: str = Field(min_length=10, description="Supabase session access token")
