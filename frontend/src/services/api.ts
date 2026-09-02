import axios from 'axios';
import toast from 'react-hot-toast';

import { clearSession, getStoredRefreshToken, refreshToken } from './auth';
import { isTokenExpired } from '../utils/jwt';

import type {
  AgentStatus,
  AISecurityAnalystOutput,
  ActiveMapRequest,
  ActiveMapResponse,
  ActiveRunRequest,
  AskVulScanResponse,
  ActiveScoreResponse,
  AITutorRequest,
  AITutorResponse,
  AuditLog,
  AuthorizedTestJobResponse,
  AuthorizedTestJobResultsResponse,
  AuthorizedTestRunResponse,
  AuthorizationChallengeRequest,
  AuthorizationChallengeResponse,
  AuthorizationStatusResponse,
  ComplexityResult,
  ExecutionStatusResponse,
  Finding,
  FindingAIExplanation,
  FindingVerificationResponse,
  FindingsPageResponse,
  GitHubConnectResponse,
  GitHubInstallation,
  GitHubInstallationListResponse,
  GitHubRepoListResponse,
  GitHubStatusResponse,
  HealthResponse,
  JobEvent,
  JobEventsResponse,
  LabManifestResponse,
  LabScenarioRequest,
  LabScenarioResponse,
  LabStatusResponse,
  LearningInsight,
  MultiSourceScanHistoryItem,
  MultiSourceScanPayload,
  MultiSourceScanResponse,
  PRDescriptionRequest,
  PRDescriptionResponse,
  RemediationStatus,
  RiskStatus,
  ScanArtifactsResponse,
  ScanHistoryItem,
  ScanQualityReport,
  ScanRequestPayload,
  ScanResponse,
  SelfAuditStatusResponse,
  SourceCorrelationsResponse,
  StopScanResponse
} from '../types';

const configuredBaseUrl =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const baseUrl = configuredBaseUrl
  .replace(/\/api\/?$/, "")
  .replace(/\/$/, "");

export const API_BASE_URL = baseUrl;

// Ensure a single axios instance with interceptor
const apiClient = axios.create({
  baseURL: baseUrl,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('phantom_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default apiClient;

const AUTH_ENDPOINTS = ['/api/auth/login', '/api/auth/register', '/api/auth/supabase', '/api/auth/refresh'];

let refreshInFlight: Promise<boolean> | null = null;

function responseDetail(error: unknown): string {
  if (!axios.isAxiosError(error)) return '';
  const data = error.response?.data as unknown;
  if (typeof data === 'string') return data;
  if (data && typeof data === 'object') {
    const detail = (data as Record<string, unknown>).detail;
    if (typeof detail === 'string') return detail;
  }
  return '';
}

function hasAuthorizationHeader(headers: unknown): boolean {
  if (!headers || typeof headers !== 'object') return false;
  const record = headers as Record<string, unknown>;
  return Boolean(record.Authorization || record.authorization);
}

function attachAuthorizationHeader(config: Record<string, any>, token: string) {
  config.headers = config.headers ?? {};
  config.headers.Authorization = `Bearer ${token}`;
}

function persistSession(response: Awaited<ReturnType<typeof refreshToken>>) {
  localStorage.setItem('phantom_token', response.token);
  if (response.refresh_token) {
    localStorage.setItem('phantom_refresh_token', response.refresh_token);
  }
  localStorage.setItem('phantom_user_role', response.role);
  localStorage.setItem('phantom_username', response.username);
  if (response.name) localStorage.setItem('phantom_user_name', response.name);
  if (response.email) localStorage.setItem('phantom_user_email', response.email);
  localStorage.setItem('phantom_subscription_tier', response.subscription_tier || 'FREE');
  localStorage.setItem('phantom_subscription_status', response.subscription_status || 'active');
}

async function attemptRefresh(): Promise<boolean> {
  const refreshValue = getStoredRefreshToken();
  if (!refreshValue) return false;
  try {
    const response = await refreshToken(refreshValue);
    persistSession(response);
    return true;
  } catch (error) {
    console.warn('Token refresh failed:', error);
    return false;
  }
}

/**
 * Refresh the access token if it is expired. Resolves true when a valid
 * token is present after the call. Safe to call from WebSocket hooks and
 * from the axios interceptor (refresh is single-flight).
 */
export async function refreshSessionToken(): Promise<boolean> {
  const token = localStorage.getItem('phantom_token');
  if (!token) return false;
  if (!isTokenExpired(token)) return true;
  refreshInFlight = refreshInFlight ?? attemptRefresh().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}

export function expireSession(message = 'Your session has expired. Please log in again.') {
  clearSession();
  toast.error(message);
  const path = window.location.pathname;
  if (!path.startsWith('/login') && !path.startsWith('/register')) {
    window.location.href = '/login';
  }
}

// Response interceptor - handle 401 errors
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const status = error.response?.status;
    const url: string = error.config?.url ?? '';
    const isAuthRequest = AUTH_ENDPOINTS.some((endpoint) => url.includes(endpoint));

    if (status === 401 && !isAuthRequest) {
      const token = localStorage.getItem('phantom_token');
      const detail = responseDetail(error);
      const config = (error.config ?? {}) as Record<string, any>;

      if (token && !hasAuthorizationHeader(config.headers) && !config.__authRetry) {
        config.__authRetry = true;
        attachAuthorizationHeader(config, token);
        return apiClient(config);
      }

      const expired = isTokenExpired(token) || /expired|invalid token|user not found/i.test(detail);

      if (token && expired && getStoredRefreshToken()) {
        const refreshed = await refreshSessionToken();
        if (refreshed) {
          attachAuthorizationHeader(config, localStorage.getItem('phantom_token') || '');
          return apiClient(config);
        }
      }

      if (!token || expired) {
        expireSession();
      }
    }

    return Promise.reject(error);
  }
);

export function apiErrorMessage(error: unknown, fallback = 'VulScan could not complete the request.'): string {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as unknown;
    if (typeof data === 'string') return data;
    if (data && typeof data === 'object') {
      const record = data as Record<string, unknown>;
      const nested = record.detail;
      if (typeof nested === 'string') return nested;
      if (Array.isArray(nested) && nested.length > 0) {
        const msgs = nested
          .map((item: Record<string, unknown>) => (typeof item?.msg === 'string' ? item.msg : null))
          .filter(Boolean);
        if (msgs.length > 0) return msgs.join('; ');
      }
      if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
        const nestedRecord = nested as Record<string, unknown>;
        if (typeof nestedRecord.message === 'string') return nestedRecord.message;
        if (typeof nestedRecord.code === 'string') return nestedRecord.code;
      }
    }
    return error.message || fallback;
  }
  return error instanceof Error ? error.message : fallback;
}

export function getWebSocketUrl(path: string): string {
  const configured = import.meta.env.VITE_WS_BASE_URL as string | undefined;
  const webSocketBase = (configured || baseUrl.replace(/^http/, 'ws')).replace(/\/$/, '');
  const wsPath = path.startsWith('/') ? path : '/' + path;
  return webSocketBase + wsPath;
}

export async function issueWebSocketTicket(scope: 'status' | 'scan' | 'brutal', scanId?: number | string): Promise<{ ticket: string; expires_at: string; scope: string; scan_id?: number | null }> {
  const response = await apiClient.post('/api/auth/ws-ticket', { scope, scan_id: scanId === undefined ? undefined : Number(scanId) });
  return response.data;
}

export async function createAuthenticatedWebSocket(path: string, scope: 'status' | 'scan' | 'brutal', scanId?: number | string): Promise<WebSocket> {
  const ticket = await issueWebSocketTicket(scope, scanId);
  return new WebSocket(getWebSocketUrl(path), ['phantomscan.ws-ticket', `ticket.${ticket.ticket}`]);
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>('/api/health');
  return response.data;
}

export async function getScanHistory(): Promise<ScanHistoryItem[]> {
  const response = await apiClient.get<ScanHistoryItem[] | { scans: ScanHistoryItem[] }>('/api/scan/history');
  return Array.isArray(response.data) ? response.data : response.data.scans;
}

export async function getScan(id: number | string): Promise<ScanResponse> {
  const response = await apiClient.get<ScanResponse>(`/api/scan/${id}`);
  return response.data;
}

export async function getScanArtifacts(id: number | string): Promise<ScanArtifactsResponse> {
  const response = await apiClient.get<ScanArtifactsResponse>(`/api/scan/${id}/artifacts`);
  return response.data;
}

export async function getScanArtifactsBatch(ids: Array<number | string>): Promise<Record<number, ScanArtifactsResponse>> {
  if (!ids.length) return {};
  const response = await apiClient.get<Record<string, ScanArtifactsResponse>>('/api/artifacts/batch', {
    params: { scan_ids: ids.join(',') },
  });
  return Object.fromEntries(Object.entries(response.data).map(([id, artifact]) => [Number(id), artifact]));
}

export async function getAIAnalysis(id: number | string, refresh = false): Promise<AISecurityAnalystOutput> {
  const response = await apiClient.get<AISecurityAnalystOutput>(`/api/ai/scan/${id}/analysis`, { params: refresh ? { refresh: true } : undefined });
  return response.data;
}

export async function askVulScan(id: number | string, question: string): Promise<AskVulScanResponse> {
  const response = await apiClient.post<AskVulScanResponse>(`/api/ai/scan/${id}/ask`, { question });
  return response.data;
}

export async function explainFinding(findingId: number, language: 'en' | 'hi' = 'en'): Promise<FindingAIExplanation> {
  const response = await apiClient.get<FindingAIExplanation>(`/api/ai/findings/${findingId}/explain`, { params: { language } });
  return response.data;
}

export async function tutorChat(payload: AITutorRequest): Promise<AITutorResponse> {
  const response = await apiClient.post<AITutorResponse>('/api/ai/tutor/chat', payload);
  return response.data;
}

export async function generatePRDescription(scanId: number, payload: PRDescriptionRequest): Promise<PRDescriptionResponse> {
  const response = await apiClient.post<PRDescriptionResponse>(`/api/scan/${scanId}/pr-description`, payload);
  return response.data;
}

export async function getGitHubStatus(): Promise<GitHubStatusResponse> {
  const response = await apiClient.get<GitHubStatusResponse>('/api/github/status');
  return response.data;
}

export async function connectGitHub(): Promise<GitHubConnectResponse> {
  const response = await apiClient.post<GitHubConnectResponse>('/api/github/connect');
  return response.data;
}

export async function listGitHubRepos(): Promise<GitHubRepoListResponse> {
  const response = await apiClient.get<GitHubRepoListResponse>('/api/github/repos');
  return response.data;
}

export async function listGitHubInstallations(): Promise<GitHubInstallation[]> {
  const response = await apiClient.get<GitHubInstallationListResponse>('/api/github/installations');
  return response.data.installations;
}

export async function disconnectGitHub(): Promise<{ status: string }> {
  const response = await apiClient.delete<{ status: string }>('/api/github/disconnect');
  return response.data;
}

export async function startMultiSourceScan(payload: MultiSourceScanPayload): Promise<MultiSourceScanResponse> {
  const response = await apiClient.post<MultiSourceScanResponse>('/api/multi-source/scan', payload);
  return response.data;
}

export interface UploadCodebaseResponse {
  scan_id: number;
  source_id: string;
  path: string;
  status: string;
  max_duration_minutes?: number;
  message?: string;
}

export async function uploadCodebase(file: File, maxDurationMinutes: number, approvalRequestId?: number): Promise<UploadCodebaseResponse> {
  const form = new FormData();
  form.append('file', file);
  form.append('max_duration_minutes', String(maxDurationMinutes));
  if (approvalRequestId) form.append('approval_request_id', String(approvalRequestId));
  const response = await apiClient.post<UploadCodebaseResponse>('/api/multi-source/upload-codebase', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}

export async function getMultiSourceHistory(): Promise<MultiSourceScanHistoryItem[]> {
  const response = await apiClient.get<MultiSourceScanHistoryItem[]>('/api/multi-source/history');
  return response.data;
}

export async function getMultiSourceStatus(scanId: number): Promise<MultiSourceScanResponse> {
  const response = await apiClient.get<MultiSourceScanResponse>(`/api/multi-source/${scanId}`);
  return response.data;
}

export async function getSourceCorrelations(scanId: number): Promise<SourceCorrelationsResponse> {
  const response = await apiClient.get<SourceCorrelationsResponse>(`/api/multi-source/${scanId}/correlations`);
  return response.data;
}

export async function stopMultiSourceScan(scanId: number): Promise<{ scan_id: string; status: string }> {
  const response = await apiClient.post<{ scan_id: string; status: string }>(`/api/multi-source/${scanId}/stop`);
  return response.data;
}

export async function startScan(payload: ScanRequestPayload): Promise<ScanResponse> {
  const response = await apiClient.post<ScanResponse>('/api/scan/start', payload);
  return response.data;
}

export async function stopScan(id: number | string): Promise<StopScanResponse> {
  const response = await apiClient.post<StopScanResponse>(`/api/scan/${id}/stop`);
  return response.data;
}

export async function getFindings(
  scanId?: number,
  options?: { limit?: number; offset?: number; includeDetails?: boolean }
): Promise<Finding[]> {
  const response = await apiClient.get<Finding[]>('/api/findings', {
    params: {
      ...(scanId ? { scan_id: scanId } : {}),
      ...(options?.limit ? { limit: options.limit } : {}),
      ...(options?.offset ? { offset: options.offset } : {}),
      ...(options?.includeDetails ? { include_details: true } : {}),
  },
});

  return response.data;
}

export async function getFindingsPage(params: {
  scanId?: number;
  limit?: number;
  offset?: number;
  severity?: string;
  category?: string;
  q?: string;
}): Promise<FindingsPageResponse> {
  const response = await apiClient.get<FindingsPageResponse>('/api/findings/page', {
    params: {
      scan_id: params.scanId,
      limit: params.limit,
      offset: params.offset,
      severity: params.severity && params.severity !== 'ALL' ? params.severity : undefined,
      category: params.category && params.category !== 'All' ? params.category : undefined,
      q: params.q?.trim() || undefined,
    },
  });
  return response.data;
}

export async function getFinding(findingId: number): Promise<Finding> {
  const response = await apiClient.get<Finding>(`/api/findings/${findingId}`);
  return response.data;
}

export async function activeMap(payload: ActiveMapRequest): Promise<ActiveMapResponse> {
  const response = await apiClient.post<ActiveMapResponse>('/api/active/map', payload);
  return response.data;
}

export async function activeScore(payload: ActiveMapRequest): Promise<ActiveScoreResponse> {
  const response = await apiClient.post<ActiveScoreResponse>('/api/active/score', payload);
  return response.data;
}

export async function getLabStatus(): Promise<LabStatusResponse> {
  const response = await apiClient.get<LabStatusResponse>('/api/lab/status');
  return response.data;
}

export async function getLabManifest(): Promise<LabManifestResponse> {
  const response = await apiClient.get<LabManifestResponse>('/api/lab/manifest');
  return response.data;
}

export async function setLabScenario(payload: LabScenarioRequest): Promise<LabScenarioResponse> {
  const response = await apiClient.post<LabScenarioResponse>('/api/lab/scenario', payload);
  return response.data;
}

export async function resetLab(): Promise<LabScenarioResponse> {
  const response = await apiClient.post<LabScenarioResponse>('/api/lab/reset');
  return response.data;
}

export async function verifyFindingFix(findingId: number, approvalRequestId?: number): Promise<FindingVerificationResponse> {
  const response = await apiClient.post<FindingVerificationResponse>(`/api/findings/${findingId}/verify`, null, {
    params: approvalRequestId ? { approval_request_id: approvalRequestId } : undefined,
  });
  return response.data;
}

export async function applyFindingPatch(
  findingId: number,
  payload: { approval_request_id: number; patch: string; file_path: string; target_root?: string; verify_after?: boolean },
): Promise<Record<string, unknown>> {
  const response = await apiClient.post<Record<string, unknown>>(`/api/findings/${findingId}/apply-patch`, payload);
  return response.data;
}

export async function updateFindingRemediation(findingId: number, remediationStatus: RemediationStatus): Promise<Finding> {
  const response = await apiClient.patch<Finding>(`/api/findings/${findingId}/remediation`, {
    remediation_status: remediationStatus
  });
  return response.data;
}

export async function updateFindingRiskStatus(findingId: number, riskStatus: RiskStatus): Promise<Finding> {
  const response = await apiClient.patch<Finding>(`/api/findings/${findingId}/risk`, {
    risk_status: riskStatus
  });
  return response.data;
}

export async function getLogs(scanId?: number): Promise<AuditLog[]> {
  const response = await apiClient.get<AuditLog[]>('/api/logs', { params: scanId ? { scan_id: scanId } : undefined });
  return response.data;
}

export async function getAgentStatuses(scanId?: number): Promise<AgentStatus[]> {
  const response = await apiClient.get<AgentStatus[]>('/api/agents/status', { params: scanId ? { scan_id: scanId } : undefined });
  return response.data;
}

export async function getSelfAuditStatus(): Promise<SelfAuditStatusResponse> {
  const response = await apiClient.get<SelfAuditStatusResponse>('/api/self-audit/status');
  return response.data;
}

export async function createAuthorizationChallenge(
  payload: AuthorizationChallengeRequest
): Promise<AuthorizationChallengeResponse> {
  const response = await apiClient.post<AuthorizationChallengeResponse>('/api/authorization/challenge', payload);
  return response.data;
}

export async function verifyAuthorization(id: number): Promise<AuthorizationStatusResponse> {
  const response = await apiClient.post<AuthorizationStatusResponse>(`/api/authorization/${id}/verify`);
  return response.data;
}

export async function getAuthorizationStatus(targetUrl: string): Promise<AuthorizationStatusResponse> {
  const response = await apiClient.get<AuthorizationStatusResponse>('/api/authorization/status', {
    params: { target_url: targetUrl }
  });
  return response.data;
}

export async function revokeAuthorization(id: number): Promise<AuthorizationStatusResponse> {
  const response = await apiClient.post<AuthorizationStatusResponse>(`/api/authorization/${id}/revoke`);
  return response.data;
}

export async function startAuthorizedTest(payload: ActiveRunRequest): Promise<AuthorizedTestRunResponse> {
  const response = await apiClient.post<AuthorizedTestRunResponse>('/api/active/run', payload);
  return response.data;
}

export async function getAuthorizedTestJobStatus(jobId: string): Promise<AuthorizedTestJobResponse> {
  const response = await apiClient.get<AuthorizedTestJobResponse>(`/api/active/jobs/${jobId}`);
  return response.data;
}

export async function getAuthorizedTestJobResults(jobId: string): Promise<AuthorizedTestJobResultsResponse> {
  const response = await apiClient.get<AuthorizedTestJobResultsResponse>(`/api/active/jobs/${jobId}/results`);
  return response.data;
}

export async function getExecutionStatus(): Promise<ExecutionStatusResponse> {
  const response = await apiClient.get<ExecutionStatusResponse>('/api/execution/status');
  return response.data;
}

export async function getJobEvents(jobId: string, afterSequence = 0): Promise<JobEventsResponse> {
  const response = await apiClient.get<JobEventsResponse>(`/api/active/jobs/${jobId}/events`, {
    params: { after_sequence: afterSequence }
  });
  return response.data;
}

export async function addToPrivateScope(targetUrl: string): Promise<{ success: boolean; message: string; target_url: string }> {
  const response = await apiClient.post('/api/admin/scope/add', { target_url: targetUrl });
  return response.data;
}

export async function listPrivateScope(): Promise<Array<{ id: number; target_url: string; added_by: string; added_at: string | null; last_used: string | null }>> {
  const response = await apiClient.get('/api/admin/scope/list');
  return response.data;
}

export async function removeFromPrivateScope(targetUrl: string): Promise<{ success: boolean; message: string }> {
  const response = await apiClient.delete('/api/admin/scope/remove', { params: { target_url: targetUrl } });
  return response.data;
}

export async function getUserRole(): Promise<{ role: string }> {
  const response = await apiClient.get('/api/admin/scope/role');
  return response.data;
}

export async function startDos(
  targetUrl: string,
  intensity: string,
  duration: number,
  mode: string = 'get_flood',
  endpoint: string | null = null,
  overrideCap: boolean = false,
): Promise<any> {
  const response = await apiClient.post('/api/admin/dos/start', {
    target_url: targetUrl,
    intensity,
    duration,
    mode,
    endpoint: endpoint || undefined,
    override_cap: overrideCap,
  });
  return response.data;
}

export async function stopDos(jobId: string): Promise<any> {
  const response = await apiClient.post(`/api/admin/dos/stop/${jobId}`);
  return response.data;
}

export async function getDosStatus(jobId: string): Promise<any> {
  const response = await apiClient.get(`/api/admin/dos/status/${jobId}`);
  return response.data;
}

export async function getDosHistory(): Promise<any[]> {
  const response = await apiClient.get('/api/admin/dos/history');
  return response.data;
}

export async function getJobEvidence(jobId: string, findingId?: number): Promise<any[]> {
  const response = await apiClient.get(`/api/active/jobs/${jobId}/evidence`, {
    params: findingId ? { finding_id: findingId } : {}
  });
  return response.data;
}

export async function activeComplexity(payload: ActiveMapRequest): Promise<ComplexityResult> {
  const response = await apiClient.post<ComplexityResult>('/api/active/complexity', payload);
  return response.data;
}

export async function getLearningInsights(scanId?: number, status?: string): Promise<LearningInsight[]> {
  const response = await apiClient.get<LearningInsight[]>('/api/learning/insights', {
    params: { scan_id: scanId ?? undefined, status: status ?? undefined }
  });
  return response.data;
}

export async function applyLearningInsight(
  insightId: number,
  appliedSettings?: Record<string, unknown>
): Promise<LearningInsight> {
  const response = await apiClient.post<LearningInsight>(`/api/learning/insights/${insightId}/apply`, {
    applied_settings: appliedSettings
  });
  return response.data;
}

export async function dismissLearningInsight(insightId: number): Promise<LearningInsight> {
  const response = await apiClient.post<LearningInsight>(`/api/learning/insights/${insightId}/dismiss`);
  return response.data;
}

export async function getScanQualityReport(): Promise<ScanQualityReport> {
  const response = await apiClient.get<ScanQualityReport>('/api/learning/quality');
  return response.data;
}

export async function startRuleScan(params: { repo_url?: string; local_path?: string; sensitivity?: string }) {
  const response = await apiClient.post('/api/rule-scan/scan', params);
  return response.data;
}

export async function getRuleScanFindings(scanId: number) {
  const response = await apiClient.get(`/api/rule-scan/${scanId}/findings`);
  return response.data;
}

export async function ruleScanChat(scanId: number, message: string) {
  const response = await apiClient.post(`/api/rule-scan/${scanId}/chat`, { message });
  return response.data;
}
