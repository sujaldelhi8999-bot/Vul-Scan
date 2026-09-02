export type ScanMode = 'defend' | 'pentest' | 'multi_agent';
export type ScanDepth = 'quick' | 'standard' | 'deep' | 'stealth';
export type ScanIntensity = 'low' | 'medium' | 'high';
export type ScanStatus = 'queued' | 'running' | 'cancelling' | 'cancelled' | 'complete' | 'error';
export type AgentState = 'idle' | 'active' | 'complete' | 'error';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Confidence = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'POTENTIAL';
export type VerificationMethod = 'dns' | 'http';
export type VerificationStatus = 'PENDING' | 'VERIFIED' | 'EXPIRED' | 'REVOKED';
export type ConnectionState = 'idle' | 'connecting' | 'open' | 'closed' | 'error';
export type AuthorizedJobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type TestModule =
  | 'input_security'
  | 'authentication'
  | 'authorization'
  | 'injection'
  | 'xss'
  | 'auth_session'
  | 'access_control'
  | 'csrf'
  | 'ssrf'
  | 'file_upload'
  | 'api_security'
  | 'graphql'
  | 'jwt'
  | 'websocket'
  | 'websockets'
  | 'rate_limits'
  | 'business_logic'
  | 'path_handling'
  | 'redirect'
  | 'redirect_security'
  | 'cors'
  | 'security_headers'
  | 'tls_https'
  | 'sensitive_exposure';

export type RemediationStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED';
export type FindingVerificationStatus = 'NOT_VERIFIED' | 'FIX_VERIFIED' | 'ISSUE_STILL_PRESENT' | 'VERIFY_FAILED';
export type RiskStatus = 'ACTIVE' | 'FALSE_POSITIVE' | 'ACCEPTED_RISK';

export interface BusinessLogicTest {
  name: string;
  method: 'GET' | 'HEAD' | 'OPTIONS';
  path: string;
  expected_status: number;
  description: string;
}

export interface ScanRequestPayload {
  target_url: string;
  mode: ScanMode;
  scan_depth?: ScanDepth;
  profile?: ScanDepth;
  intensity: ScanIntensity;
  severity_filters?: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO'>;
  selected_tests?: TestModule[];
  authorization_id?: number | null;
  authorization_confirmed?: boolean;
  business_logic_tests?: BusinessLogicTest[];
  confidence_profile?: 'strict' | 'balanced' | 'aggressive';
  confidence_sensitivity?: 'strict' | 'balanced' | 'aggressive';
  enable_exploitation?: boolean;
  enable_ai_exploitation?: boolean;
  approval_request_id?: number;
}

export interface Finding {
  id: number;
  scan_id: number;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  target: string;
  endpoint: string;
  evidence: string;
  impact: string;
  recommendation: string;
  verification: string;
  agent: string;
  timestamp: string;
  cve_id: string | null;
  cvss_score: number | null;
  cwe?: string | null;
  version_affected?: string | null;
  description: string;
  how_exploited: string;
  fix: string;
  file_path?: string | null;
  line_number?: number | null;
  code_snippet?: string | null;
  fix_recommendation?: string | null;
  parameter?: string | null;
  module?: string | null;
  recommended_fix?: string | null;
  remediation_status?: RemediationStatus;
  verification_status?: FindingVerificationStatus;
  risk_status?: RiskStatus;
  request_id?: string | null;
  verified?: boolean;
  confidence_percent?: number | null;
  confidence_score?: number | null;
  confidence_label?: string | null;
  reproduction_command?: string | null;
  request_response_diff?: string | null;
  verification_hash?: string | null;
  verification_method?: string | null;
  verification_stage?: string | null;
  verification_result?: Record<string, unknown> | null;
  source_correlation?: Record<string, unknown> | null;
  exploited?: boolean;
  exploitation_result?: ExploitationResult | null;
}

export interface FindingsPageResponse {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
}

export interface ExploitationResultRow {
  cells?: string[];
  text?: string;
}

export interface ExploitationResultData {
  table: string;
  rows: ExploitationResultRow[];
}

export interface ExploitationResult {
  status: string;
  database_type: string | null;
  tables: string[];
  data: ExploitationResultData[];
  error: string | null;
}

export interface ExploitationOutcome {
  success: boolean;
  status?: string;
  type: string;
  endpoint: string;
  summary: string;
  reason?: string;
  error?: string;
  severity?: string;
  poc_url?: string;
  poc_payload?: string;
  extracted?: string[];
  files?: Array<{ file?: string; payload_type?: string; content: string }>;
  commands?: Array<{ command: string; output: string }>;
  database_type?: string | null;
  tables?: string[];
  data?: ExploitationResultData[];
}

export interface AIExploitationOutcome {
  finding_id?: number | null;
  vulnerability_type?: string;
  status?: string;
  poc?: Record<string, unknown>;
  validation?: Record<string, unknown>;
  report?: string;
  error?: string;
}

export interface ExploitationSummary {
  static?: {
    status?: string;
    summary?: string;
    exploitation_results?: ExploitationOutcome[];
  } | null;
  ai?: {
    status?: string;
    summary?: string;
    ai_available?: boolean;
    exploitation_results?: AIExploitationOutcome[];
  } | null;
}

export interface AICitation {
  type?: string;
  id?: number | string | null;
  label?: string;
  title?: string;
  endpoint?: string;
  source?: string;
}

export interface AIPriority {
  priority: number;
  finding_id?: number | string | null;
  title?: string;
  score?: number;
  severity?: Severity | string;
  confidence?: Confidence | string;
  recommended_action?: string;
  factors?: string[];
  citation?: AICitation;
}

export interface AIDeveloperFinding {
  finding_id?: number | string | null;
  affected_endpoint?: string;
  evidence?: string;
  observed_behavior?: string;
  severity?: Severity | string;
  confidence?: Confidence | string;
  related_findings?: string[];
  technology?: string;
  remediation?: string;
  verification?: string;
  recommended_priority?: number | null;
}

export interface AISecurityAnalystOutput {
  scan_id?: number;
  generated_at?: string;
  ai_available?: boolean;
  ai_status?: string;
  safety?: Record<string, unknown> & { can_start_active_test?: boolean };
  security_summary?: Record<string, unknown>;
  ai_narrative?: string;
  priorities?: AIPriority[];
  related_security_chains?: Array<Record<string, unknown>>;
  root_causes?: Array<Record<string, unknown>>;
  remediation_plan?: Record<string, Array<Record<string, unknown>>>;
  score_explanation?: Record<string, unknown> & { score?: number };
  positive_controls?: Array<Record<string, unknown>>;
  scan_comparison?: Record<string, unknown>;
  security_timeline?: Array<Record<string, unknown>>;
  executive_report?: Record<string, unknown>;
  developer_report?: AIDeveloperFinding[];
  suggested_prompts?: string[];
  citations?: AICitation[];
  grounding?: Record<string, unknown>;
}

export interface AskVulScanResponse {
  scan_id: number;
  question: string;
  answer: string;
  citations: AICitation[];
  grounded: boolean;
  can_start_active_test: boolean;
  ai_note?: string | null;
}

export interface FindingAIExplanation {
  finding_id: number;
  language: 'en' | 'hi';
  title?: string;
  summary?: string;
  why_confirmed?: string[];
  why_potential?: string[];
  evidence_required_for_confirmation?: string;
  citations?: AICitation[];
  ai_text?: string;
  cached?: boolean;
  can_start_active_test: boolean;
}

export type TutorUserLevel = 'beginner' | 'intermediate' | 'expert';

export interface AITutorRequest {
  finding_id?: number | null;
  question: string;
  context?: Record<string, unknown>;
  language?: 'en' | 'hi' | null;
  user_level?: TutorUserLevel;
}

export interface AITutorCodeExample {
  language: string;
  title?: string;
  code: string;
}

export interface AITutorResponse {
  answer: string;
  explanation?: string | null;
  code_examples: AITutorCodeExample[];
  references: string[];
  follow_up_questions: string[];
  confidence: number;
}

export interface TutorChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  code_examples?: AITutorCodeExample[];
  references?: string[];
  follow_up_questions?: string[];
  timestamp: string;
}

export interface PRDescriptionRequest {
  finding_ids: number[];
  base_branch: string;
  head_branch: string;
  repo_url: string;
  include_fix_details?: boolean;
  include_verification_steps?: boolean;
}

export interface PRDescriptionResponse {
  title: string;
  body: string;
  labels: string[];
  reviewers: string[];
  related_issues: string[];
}

export interface GitHubRepo {
  id: number;
  full_name: string;
  name: string;
  owner: Record<string, unknown>;
  private: boolean;
  html_url: string;
  clone_url: string;
  ssh_url: string;
  default_branch: string;
  permissions: Record<string, boolean>;
  language: string | null;
  topics: string[];
  updated_at: string;
  pushed_at: string | null;
}

export interface GitHubInstallation {
  id: number;
  account: Record<string, unknown>;
  repository_selection: string;
  permissions: Record<string, string>;
  events: string[];
  html_url: string;
  created_at: string;
  updated_at: string;
}

export interface GitHubStatusResponse {
  connected: boolean;
  login?: string;
  connected_at?: string | null;
}

export interface GitHubConnectResponse {
  authorize_url: string;
  state: string;
}

export interface GitHubRepoListResponse {
  connected: boolean;
  repos: GitHubRepo[];
  total: number;
}

export interface GitHubInstallationListResponse {
  installations: GitHubInstallation[];
  total: number;
}

export type MultiSourceSourceType = 'local' | 'github' | 'gitlab' | 'bitbucket' | 'live' | 'api_spec' | 'docker' | 'kubernetes' | 'terraform';

export interface MultiSourceSourceResult {
  source_type: string;
  source_identifier: string;
  status: string;
  findings_count: number;
  findings_by_severity: Record<string, number>;
  scan_duration_seconds: number;
  error_message: string | null;
  artifacts: Record<string, unknown>;
}

export interface HealthScoreCategory {
  name: string;
  score: number;
  weighted_score: number;
  factors: string[];
}

export interface HealthScore {
  score: number;
  classification: string;
  color: string;
  categories: HealthScoreCategory[];
  top_factors: string[];
  executive_summary: string;
}

export interface MultiSourceScanResponse {
  scan_id: number;
  name: string;
  mode: string;
  overall_status: string;
  overall_progress: number;
  sources: MultiSourceSourceResult[];
  findings: Finding[];
  total_findings: number;
  findings_by_severity: Record<string, number>;
  correlated_findings_count: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  total_duration_seconds: number;
  max_duration_minutes?: number;
  sarif_export_url: string | null;
  pdf_report_url: string | null;
  health_score?: HealthScore | null;
}

export interface MultiSourceScanHistoryItem {
  scan_id: number;
  name: string;
  mode: string;
  overall_status: string;
  sources: string[];
  total_findings: number;
  correlated_findings: number;
  created_at: string;
  completed_at: string | null;
}

export interface MultiSourceScanPayload {
  name?: string;
  mode?: string;
  intensity?: 'low' | 'medium' | 'high';
  sources: Record<string, unknown>[];
  correlate_findings?: boolean;
  data_flow_tracing?: boolean;
  generate_sarif?: boolean;
  generate_pdf?: boolean;
  compliance_frameworks?: string[];
  max_cost_usd?: number | null;
  max_duration_minutes?: number;
  notify_on_critical?: boolean;
  notify_on_complete?: boolean;
  webhook_url?: string | null;
  approval_request_id?: number;
}

export interface SourceCorrelationGroup {
  unified_id: string;
  title: string;
  severity: string;
  confidence: number;
  sources: string[];
  correlation_type: string;
  related_findings: Finding[];
  evidence: Record<string, unknown>;
}

export interface SourceCorrelationSummary {
  total_correlations: number;
  by_type: Record<string, number>;
  by_source_pair: Record<string, number>;
  high_confidence: number;
  data_flow_traces: number;
  vulnerability_chains: number;
}

export interface SourceCorrelationsResponse {
  scan_id: number;
  summary: SourceCorrelationSummary;
  groups: SourceCorrelationGroup[];
}

export interface ActiveGateContext {
  allowed: boolean;
  target_url: string;
  target_origin: string;
  authorization_status: 'TRAINING' | 'ALLOWLIST' | 'VERIFIED' | 'BLOCKED' | 'NOT_REQUIRED' | 'ADMIN_OVERRIDE' | string;
  reason: string;
  authorization_id: number | null;
  is_lab: boolean;
}

export interface ActiveSurface {
  id?: string;
  type?: string;
  method?: string;
  path?: string;
  url?: string;
  parameters?: string[];
  module_hints?: string[];
  auth_required?: boolean | null;
  scenario?: string;
  state?: 'VULNERABLE' | 'PATCHED' | string;
  vulnerable?: boolean;
  description?: string;
}

export interface ActivePlanModule {
  module: string;
  surfaces: ActiveSurface[];
}

export interface ActivePlan {
  target_url?: string;
  source?: string;
  selected_modules: string[];
  modules: ActivePlanModule[];
  surface_count: number;
}

export interface ActiveScore {
  score: number;
  surface_count?: number;
  vulnerable_surface_count?: number;
  finding_count?: number;
  penalty?: number;
  resolved_count?: number;
}

export interface ActiveLimits {
  max_requests: number;
  requests_per_second: number;
  timeout_seconds: number;
  max_response_size: number;
  max_redirects: number;
  max_concurrency: number;
}

export interface ActiveMapRequest {
  target_url: string;
  selected_modules?: TestModule[];
  authorization_id?: number | null;
  authorization_confirmed?: boolean;
  approval_request_id?: number;
}

export interface ActiveMapResponse {
  gate: ActiveGateContext;
  surfaces: ActiveSurface[];
  plan: ActivePlan;
  score: ActiveScore;
  complexity?: ComplexityResult;
  limits: ActiveLimits;
}

export interface ActiveScoreResponse {
  gate: ActiveGateContext;
  score: ActiveScore;
  module_count: number;
  complexity?: ComplexityResult;
  limits: ActiveLimits;
}

export interface ComplexityResult {
  target_url?: string;
  score: number;
  band: 'simple' | 'medium' | 'complex' | 'critical' | string;
  band_label: string;
  breakdown: {
    ports: { web_ports: number[]; extra_web_ports: number[]; database_ports: number[]; admin_ports: number[]; points: number };
    tech_stack: { detected: string[]; points: number };
    authentication: { mechanisms: string[]; has_admin_surface: boolean; points: number };
    api_surface: { endpoints: number; graphql: boolean; openapi: boolean; points: number };
    waf: boolean;
    security_headers: { present: string[]; missing: string[]; points: number };
    scale: { endpoints: number; subdomains: number; points: number };
  };
  source?: 'recon' | 'live' | 'fallback';
}

export interface AdaptivePlan {
  band: ComplexityResult['band'];
  score: number;
  requests_per_second: number;
  intensity: ScanIntensity;
  modules: string[];
  excluded_modules: string[];
  excluded_reasons: Record<string, string>;
  depth: string;
  deeper: boolean;
  limits: Record<string, number>;
  rationale: string[];
}

export interface LearningInsight {
  id: number;
  scan_id: number | null;
  module: string | null;
  kind: 'module' | 'scan' | string;
  total_count: number;
  true_positives: number;
  false_positives: number;
  unrated_count: number;
  true_positive_rate: number;
  false_positive_rate: number;
  recommendation: string | null;
  recommendation_data: { action?: 'disable' | 'tune' | 'review' | 'keep'; rationale?: string; fp_rate?: number; tp_rate?: number; sample_count?: number } | null;
  status: 'pending' | 'applied' | 'dismissed' | string;
  applied_settings: Record<string, unknown> | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface ScanQualityReport {
  modules: Array<{
    module: string;
    total_count: number;
    true_positives: number;
    false_positives: number;
    unrated_count: number;
    true_positive_rate: number;
    false_positive_rate: number;
  }>;
  scans: Array<Record<string, unknown>>;
}

export interface ActiveSecurityOutput {
  status?: string;
  target_url?: string;
  attack_surface?: Record<string, unknown>;
  test_plan?: ActivePlan;
  events?: Array<Record<string, unknown>>;
  evidence?: Array<Record<string, unknown>>;
  findings?: Array<Record<string, unknown>>;
  final_report?: string;
  score?: ActiveScore;
  request_count?: number;
  sandbox_id?: string;
}

export interface BrowserSecurityOutput {
  status?: string;
  target_url?: string;
  browser_engine?: string;
  session?: Record<string, unknown>;
  pages?: Array<Record<string, unknown>>;
  routes?: Array<Record<string, unknown>>;
  dom?: Array<Record<string, unknown>>;
  network_events?: Array<Record<string, unknown>>;
  console_events?: Array<Record<string, unknown>>;
  api_inventory?: Array<Record<string, unknown>>;
  storage?: Record<string, unknown>;
  cookies?: Array<Record<string, unknown>>;
  csp?: Array<Record<string, unknown>>;
  csp_violations?: Array<Record<string, unknown>>;
  javascript?: Array<Record<string, unknown>>;
  source_maps?: Array<Record<string, unknown>>;
  auth_flow?: Record<string, unknown>;
  websockets?: Array<Record<string, unknown>>;
  service_workers?: Array<Record<string, unknown>>;
  cache?: Array<Record<string, unknown>>;
  third_party?: Array<Record<string, unknown>>;
  dataflow?: Record<string, unknown>;
  screenshots?: Array<Record<string, unknown>>;
  safety?: Record<string, unknown>;
  correlation?: Record<string, unknown>;
  findings?: Array<Record<string, unknown>>;
  request_count?: number;
}

export interface ScanResponse {
  scan_id: number;
  target_url: string;
  mode: ScanMode;
  intensity: ScanIntensity;
  selected_tests: TestModule[];
  user_id: string;
  authorization_id: number | null;
  authorization_confirmed: boolean;
  status: ScanStatus;
  progress: number;
  request_count: number;
  sandbox_id: string | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings: Finding[];
}

export interface ScanHistoryItem {
  id: number;
  target_url: string;
  mode: ScanMode;
  status: ScanStatus;
  progress: number;
  created_at: string;
  completed_at: string | null;
  findings_count?: number;
  critical_findings_count?: number;
  high_findings_count?: number;
}

export interface ScanArtifactsResponse {
  scan_id: number;
  scanner_output: Record<string, unknown> | null;
  shadow_recon_output: Record<string, unknown> | null;
  markdown_report: string | null;
  notification_result: Record<string, unknown> | null;
  active_security_output: ActiveSecurityOutput | null;
  browser_security_output: BrowserSecurityOutput | null;
  ai_analyst_output: AISecurityAnalystOutput | null;
  tci_output: ComplexityResult | null;
  ai_consultation: Record<string, unknown> | null;
  updated_at: string | null;
}

export interface LabStatusResponse {
  name: string;
  default_state: 'VULNERABLE' | 'PATCHED' | string;
  scenario_state: Record<string, 'VULNERABLE' | 'PATCHED' | string>;
  scenarios: Record<string, string[]>;
}

export interface LabManifestResponse {
  name: string;
  default_state?: 'VULNERABLE' | 'PATCHED' | string;
  base_path: string;
  users: Record<string, unknown>;
  scenario_state: Record<string, 'VULNERABLE' | 'PATCHED' | string>;
  scenarios: Record<string, string[]>;
  surfaces: ActiveSurface[];
}

export interface LabScenarioRequest {
  state?: 'VULNERABLE' | 'PATCHED';
  scenario?: string | null;
  states?: Record<string, 'VULNERABLE' | 'PATCHED'>;
}

export interface LabScenarioResponse {
  scenario_state: Record<string, 'VULNERABLE' | 'PATCHED' | string>;
}

export interface FindingVerificationResponse {
  finding_id: number;
  module: string;
  status: FindingVerificationStatus;
  remediation_status: RemediationStatus;
  request_count: number;
}

export interface AuditLog {
  id: number;
  scan_id: number;
  agent_name: string;
  action: string;
  timestamp: string;
  details: string;
  user_id: string | null;
  target: string | null;
  authorization_status: string | null;
  selected_module: string | null;
  start_time: string | null;
  end_time: string | null;
  result: string | null;
  request_count: number | null;
  sandbox_id: string | null;
}

export interface AgentStatus {
  name: string;
  status: AgentState;
}

export type AdminMeasurement<T = number> = {
  status: 'measured' | 'not_measured' | string;
  value: T | null;
};

export type AdminAgentStatus =
  | 'IDLE'
  | 'QUEUED'
  | 'RUNNING'
  | 'WAITING'
  | 'COMPLETED'
  | 'COMPLETED_WITH_LIMITATIONS'
  | 'FAILED'
  | 'TIMED_OUT'
  | 'CANCELLED'
  | 'SKIPPED'
  | 'UNKNOWN';

export interface AdminAgent {
  id: string;
  name: string;
  status: AdminAgentStatus;
  scan_id: number | null;
  runtime_seconds: number | null;
  requests: number;
  findings_generated: number;
  candidates_rejected: AdminMeasurement | number | null;
  errors: number;
  timeouts: number;
  last_execution: string | null;
  average_runtime_seconds: AdminMeasurement | number | null;
  yield_per_request: AdminMeasurement | number | null;
  yield_per_runtime: AdminMeasurement | number | null;
}

export interface AdminOperation {
  scan_id: number;
  target: string;
  owner: string | null;
  mode: string | null;
  profile: string | null;
  status: string;
  started_at: string | null;
  elapsed_seconds: number | null;
  progress: number;
  request_count: number | null;
  request_count_state: 'measured' | 'not_measured' | string;
  endpoints_discovered: number;
  parameters_discovered: number;
  findings: number;
  running_agent: string | null;
  running_agents: string[];
  completed_agents: string[];
  failed_agents: string[];
  timed_out_agents: string[];
  provider_limitations: unknown[];
  waf_state: string;
  authenticated_state: string;
  scan_quality: AdminMeasurement | Record<string, unknown>;
}

export interface AdminProvider {
  name: string;
  status: string;
  configured: boolean | null;
  last_failure: string | null;
  last_success: string | null;
  latency_ms: number | null;
  circuit_breaker: string | null;
}

export interface AdminListResponse<T> {
  items: T[];
}

export interface HealthResponse {
  status: 'ok' | 'degraded';
  service: string;
  database: 'available' | 'unavailable';
  scheduler: 'running' | 'stopped' | 'unavailable';
  agents: 'available' | 'unavailable';
  ai_provider: string;
  ai_model: string;
  ai_status: 'connected' | 'offline';
}

export interface SelfAuditStatusResponse {
  status: ScanStatus | 'never_run';
  scan_id: number | null;
  target_url: string | null;
  progress: number | null;
  finding_count: number | null;
  created_at: string | null;
  completed_at: string | null;
}

export interface AuthorizationChallengeRequest {
  target_url: string;
  verification_method: VerificationMethod;
}

export interface AuthorizationChallengeResponse {
  id: number;
  domain: string;
  target_origin: string;
  verification_method: VerificationMethod;
  token: string;
  dns_record: string;
  http_url: string;
  challenge_expires_at: string;
  status: VerificationStatus;
}

export interface AuthorizationStatusResponse {
  id: number | null;
  domain: string;
  target_origin: string;
  verification_method: VerificationMethod | null;
  verified_at: string | null;
  expires_at: string | null;
  status: VerificationStatus;
  message: string;
}

export interface StopScanResponse {
  scan_id: number;
  status: ScanStatus;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  detail?: string;
  agent?: string;
  tone: 'neutral' | 'purple' | 'green' | 'amber' | 'red' | 'blue';
}

export interface ToastEvent {
  title: string;
  detail?: string;
  tone?: TimelineEvent['tone'];
}

export const TEST_MODULES: Array<{ id: TestModule; label: string; group: string; description: string }> = [
  { id: 'input_security', label: 'Input Security', group: 'Application Security', description: 'Controlled input validation and reflection checks.' },
  { id: 'auth_session', label: 'Authentication', group: 'Application Security', description: 'Login, throttling, session, and token behavior checks.' },
  { id: 'access_control', label: 'Access Control', group: 'Access Control', description: 'Role and object access checks.' },
  { id: 'injection', label: 'Injection', group: 'Application Security', description: 'Controlled interpreter error probes.' },
  { id: 'xss', label: 'XSS Reflection', group: 'Application Security', description: 'Harmless reflection checks.' },
  { id: 'csrf', label: 'CSRF Controls', group: 'Application Security', description: 'Passive form protection checks.' },
  { id: 'file_upload', label: 'File Upload', group: 'Application Security', description: 'Upload surface discovery.' },
  { id: 'path_handling', label: 'Path Handling', group: 'Infrastructure', description: 'Controlled path traversal review.' },
  { id: 'api_security', label: 'REST APIs', group: 'API', description: 'HTTP method and API exposure checks.' },
  { id: 'graphql', label: 'GraphQL', group: 'API', description: 'Introspection exposure checks.' },
  { id: 'jwt', label: 'JWT', group: 'Session Security', description: 'Token exposure and claim checks.' },
  { id: 'websocket', label: 'WebSocket', group: 'API', description: 'Socket reference and auth-expectation discovery.' },
  { id: 'redirect', label: 'Redirect Security', group: 'Application Security', description: 'External redirect control checks.' },
  { id: 'cors', label: 'CORS', group: 'Infrastructure', description: 'Untrusted origin policy checks.' },
  { id: 'security_headers', label: 'Security Headers', group: 'Infrastructure', description: 'Browser security header verification.' },
  { id: 'tls_https', label: 'TLS / HTTPS', group: 'Infrastructure', description: 'HTTPS and transport enforcement checks.' },
  { id: 'sensitive_exposure', label: 'Sensitive Exposure', group: 'Infrastructure', description: 'Debug, metadata, and fake-secret exposure checks.' },
  { id: 'business_logic', label: 'Business Logic', group: 'Access Control', description: 'Approved workflow status checks.' },
];

export const DEFEND_CHECKS = [
  'Headers',
  'TLS posture',
  'CORS',
  'Authentication analysis',
  'Access control analysis',
  'API exposure',
  'Session analysis',
  'Infrastructure exposure',
  'Dependency analysis',
  'CVE intelligence',
  'Threat intelligence',
  'AI and Hindi explainers',
  'Remediation checklist',
  'Notifications'
];

export interface ActiveRunRequest {
  target_url: string;
  selected_modules: TestModule[];
  authorization_id: number | null;
  authorization_confirmed: boolean;
  enable_exploitation?: boolean;
  enable_ai_exploitation?: boolean;
  approval_request_id?: number;
}

export interface AuthorizedTestRunResponse {
  job_id: string;
  status: AuthorizedJobStatus;
  message: string;
}

export interface AuthorizedTestJobError {
  code: string;
  message: string;
}

export interface JobEvent {
  id: number;
  job_id: string;
  sequence_number: number;
  timestamp: string;
  module: string | null;
  event_type: string;
  message: string | null;
  status: string | null;
  metadata: Record<string, unknown>;
  created_at: string | null;
}

export interface JobEventsResponse {
  job_id: string;
  events: JobEvent[];
  latest_sequence: number;
}

export interface AuthorizedTestJobResponse {
  job_id: string;
  status: AuthorizedJobStatus;
  progress_percent: number;
  current_phase: string | null;
  current_module: string | null;
  surfaces_total: number;
  surfaces_completed: number;
  raw_surfaces_discovered: number;
  testable_surfaces: number;
  surface_groups: number;
  findings_count: number;
  started_at: string | null;
  updated_at: string | null;
  completed_at: string | null;
  error: AuthorizedTestJobError | null;
  target_url: string;
  selected_modules: string[];
  authorization_id: number | null;
  scan_id: number | null;
}

export interface AuthorizedTestJobResultsResponse {
  job_id: string;
  status: AuthorizedJobStatus;
  target_url: string;
  surfaces_total: number;
  surfaces_completed: number;
  raw_surfaces_discovered: number;
  testable_surfaces: number;
  surface_groups: number;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  findings: Finding[];
  result_summary: Record<string, unknown> | null;
}

export interface StoredActiveTest {
  job_id: string;
  target_url: string;
  authorization_id: number | null;
  started_at: string;
  map_result?: ActiveMapResponse;
}

export type ExecutionType = 'DEFEND_SCAN' | 'AUTHORIZED_TEST' | 'SELF_AUDIT' | 'LAB_OPERATION';
export type ExecutionLifecycle = 'IDLE' | 'QUEUED' | 'STARTING' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type AgentApplicability = 'IDLE' | 'QUEUED' | 'RUNNING' | 'WAITING' | 'COMPLETED' | 'FAILED' | 'NOT_APPLICABLE';

export interface AgentStateDetail {
  name: string;
  applicability: AgentApplicability;
  responsibility: string;
  current_module: string | null;
  progress: number;
  last_updated: string | null;
  detail: string;
}

export interface ExecutionStatusResponse {
  execution_type: ExecutionType | null;
  lifecycle: ExecutionLifecycle;
  job_id: string | null;
  scan_id: number | null;
  target_url: string;
  progress_percent: number;
  current_module: string | null;
  current_phase: string | null;
  surfaces_total: number;
  surfaces_completed: number;
  findings_count: number;
  started_at: string | null;
  updated_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  error_code: string | null;
  agents: AgentStateDetail[];
  is_lab: boolean;
  authorization_status: string;
}

export const EVENT_TYPES = [
  'JOB_STARTED',
  'SURFACE_DISCOVERED',
  'MODULE_STARTED',
  'TEST_PREPARED',
  'TEST_REQUEST_SENT',
  'RESPONSE_RECEIVED',
  'SECURITY_CONTROL_EVALUATED',
  'FINDING_DETECTED',
  'CONTROL_BLOCKED_TEST',
  'RETEST_STARTED',
  'FIX_VERIFIED',
  'MODULE_COMPLETED',
  'MODULE_FAILED',
  'JOB_COMPLETED',
] as const;

export type EventType = typeof EVENT_TYPES[number];

export interface PrivateScopeEntry {
  id: number;
  target_url: string;
  added_by: string;
  added_at: string | null;
  last_used: string | null;
}

export interface PrivateScopeAddResponse {
  success: boolean;
  message: string;
  target_url: string;
}

export interface PrivateScopeRemoveResponse {
  success: boolean;
  message: string;
}

export interface UserRoleResponse {
  role: string;
}

export const AGENT_NAMES = [
  'Orchestrator Agent',
  'Scanner Agent',
  'Shadow Recon Agent',
  'Analyzer Agent',
  'CVE Matcher Agent',
  'Authentication Security Agent',
  'Access Control Agent',
  'API Security Agent',
  'Session Security Agent',
  'Injection Analysis Agent',
  'Infrastructure Agent',
  'WebSocket Security Agent',
  'Dependency Agent',
  'Threat Intelligence Agent',
  'Sandbox Manager Agent',
  'Pentest Agent',
  'AI Explainer Agent',
  'AI Security Analyst Agent',
  'Hindi Explainer Agent',
  'Fixer Agent',
  'Notifier Agent',
  'Self Audit Agent'
] as const;
