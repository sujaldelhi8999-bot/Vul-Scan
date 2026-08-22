import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { useAuth } from '../../context/AuthContext';
import {
  CheckCircle2,
  ClipboardCopy,
  Download,
  Loader2,
  LockKeyhole,
  ShieldCheck,
  Square,
} from 'lucide-react';

import {
  AlertTriangle,
  Trash2,
} from 'lucide-react';
import { Gauge } from 'lucide-react';
import {
  Button,
  cx,
  EmptyState,
  ErrorState,
  InfoCallout,
  Input,
  MetricCard,
  Page,
  PageHeader,
  Panel,
  PanelSkeleton,
  ProgressBar,
  SectionHeader,
  StatusBadge,
} from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import {
  API_BASE_URL,
  activeComplexity,
  activeMap,
  addToPrivateScope,
  apiErrorMessage,
  createAuthorizationChallenge,
  getAuthorizationStatus,
  getAuthorizedTestJobResults,
  getAuthorizedTestJobStatus,
  getLabStatus,
  getUserRole,
  listPrivateScope,
  removeFromPrivateScope,
  revokeAuthorization,
  setLabScenario,
  startAuthorizedTest,
  stopScan,
  verifyAuthorization,
} from '../../services/api';
import type {
  ActiveMapResponse,
  AuthorizationChallengeResponse,
  AuthorizationStatusResponse,
  AuthorizedJobStatus,
  AuthorizedTestJobResponse,
  ComplexityResult,
  ExploitationOutcome,
  ExploitationSummary,
  LabStatusResponse,
  PrivateScopeEntry,
  ScanIntensity,
  StoredActiveTest,
  TestModule,
  JobEvent,
} from '../../types';
import { TEST_MODULES } from '../../types';
import { targetName } from '../../utils/derived';
import LiveActivityConsole from './LiveActivityConsole';
import EventDetailDrawer from './EventDetailDrawer';
import AttackFlowAnimation from './AttackFlowAnimation';
import EvidencePanel from './EvidencePanel';
import ComplexityCard, { ComplexitySkeleton } from './ComplexityCard';
import { clearEnterpriseApproval, getEnterpriseApproval } from '../enterprise/approvalHandoff';

const labTarget = `${API_BASE_URL}/lab/phantombank`;
const defaultModules: TestModule[] = [
  'input_security',
  'xss',
  'auth_session',
  'access_control',
  'csrf',
  'file_upload',
  'api_security',
  'websocket',
  'redirect',
  'security_headers',
  'cors',
  'sensitive_exposure',
];
const terminalJobStatuses: AuthorizedJobStatus[] = ['COMPLETED', 'FAILED', 'CANCELLED'];
const TERMINAL_LIFECYCLES = ['COMPLETED', 'FAILED', 'CANCELLED'];
const STALE_JOB_AGE_MS = 60 * 60 * 1000;
const STORAGE_KEY = 'vulscan_active_test_job';
const MAP_STORAGE_KEY = 'vulscan_active_test_map';
const POLL_INTERVAL = 2000;

function formatLimit(seconds: number | undefined) {
  if (!seconds) return 'Backend default';
  if (seconds >= 60) return `${Math.round(seconds / 60)} minutes`;
  return `${seconds} seconds`;
}

function gateLabel(status: string | undefined) {
  if (status === 'TRAINING') return 'LAB VERIFIED';
  if (status === 'ALLOWLIST') return 'ALLOWLISTED';
  if (status === 'VERIFIED') return 'VERIFIED';
  if (status === 'ADMIN_OVERRIDE') return 'ADMIN OVERRIDE';
  if (status === 'BLOCKED') return 'BLOCKED';
  return 'NOT MAPPED';
}

function restoreTest(): StoredActiveTest | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as StoredActiveTest) : null;
  } catch {
    return null;
  }
}

function restoreMap(): ActiveMapResponse | null {
  try {
    const raw = localStorage.getItem(MAP_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as ActiveMapResponse) : null;
  } catch {
    return null;
  }
}

function saveTest(data: StoredActiveTest) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

function removeTest() {
  localStorage.removeItem(STORAGE_KEY);
}

function saveMap(map: ActiveMapResponse) {
  localStorage.setItem(MAP_STORAGE_KEY, JSON.stringify(map));
}

function removeMap() {
  localStorage.removeItem(MAP_STORAGE_KEY);
}

const modulesByGroup = TEST_MODULES.reduce<Record<string, typeof TEST_MODULES>>((acc, m) => {
  acc[m.group] = acc[m.group] ?? [];
  acc[m.group].push(m);
  return acc;
}, {});

export default function AuthorizedTestingPage() {
  const { refresh, executionStatus } = usePhantomData();
  const [target, setTarget] = useState('');
  const [method, setMethod] = useState<'dns' | 'http'>('dns');
  const [challenge, setChallenge] = useState<AuthorizationChallengeResponse | null>(null);
  const [authorization, setAuthorization] = useState<AuthorizationStatusResponse | null>(null);
  const [selectedTests, setSelectedTests] = useState<TestModule[]>(defaultModules);
  const [profile, setProfile] = useState<ScanIntensity>('medium');
  const [confirmation, setConfirmation] = useState(true);
  const [enableExploitation, setEnableExploitation] = useState(false);
  const [enableAIExploitation, setEnableAIExploitation] = useState(false);
  const [mapResult, setMapResult] = useState<ActiveMapResponse | null>(null);
  const [complexity, setComplexity] = useState<ComplexityResult | null>(null);
  const [complexityLoading, setComplexityLoading] = useState(false);
  const [labStatus, setLabStatus] = useState<LabStatusResponse | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();
  const userRole = user?.role || 'user';
  const [privateScopeList, setPrivateScopeList] = useState<PrivateScopeEntry[]>([]);
  const [loadingPrivateScope, setLoadingPrivateScope] = useState(false);
  const [approval, setApproval] = useState(() => getEnterpriseApproval(['scan', 'code_audit']));

  const isAdmin = userRole === 'admin';

  useEffect(() => {
    if (approval?.target_url && !target) setTarget(approval.target_url);
  }, [approval, target]);

  const fetchPrivateScope = useCallback(async () => {
    if (!isAdmin) return;
    setLoadingPrivateScope(true);
    try {
      const list = await listPrivateScope();
      setPrivateScopeList(list);
    } catch {
      /* ignore */
    } finally {
      setLoadingPrivateScope(false);
    }
  }, [isAdmin]);

  const [jobId, setJobId] = useState<string | null>(null);
  const [jobData, setJobData] = useState<AuthorizedTestJobResponse | null>(null);
  const [jobResults, setJobResults] = useState<{ findings: any[]; resultSummary: any } | null>(null);
  const [connectionWarning, setConnectionWarning] = useState<string | null>(null);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<JobEvent | null>(null);
  const [eventDrawerOpen, setEventDrawerOpen] = useState(false);

  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const planModules = mapResult?.plan.modules ?? [];
  const gateStatus = mapResult?.gate.authorization_status;
  const isLab = gateStatus === 'TRAINING' || target.includes('/lab/phantombank');
  const isRunning = Boolean(jobId && jobData && !terminalJobStatuses.includes(jobData.status));
  const canExecute = Boolean(
    mapResult?.gate.allowed &&
    selectedTests.length &&
    !isRunning,
  );

  /* ── Job polling ── */

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const fetchJobStatus = useCallback(
    async (id: string) => {
      try {
        const status = await getAuthorizedTestJobStatus(id);
        setJobData(status);
        setConnectionWarning(null);
        if (terminalJobStatuses.includes(status.status)) {
          stopPolling();
          if (status.status === 'COMPLETED') {
            try {
              const results = await getAuthorizedTestJobResults(id);
              setJobResults({ findings: results.findings, resultSummary: results.result_summary });
            } catch {
              /* ignore */
            }
          }
        } else {
          const updated = new Date(status.updated_at || status.started_at || 0).getTime();
          if (updated && Date.now() - updated > STALE_JOB_AGE_MS) {
            stopPolling();
            removeTest();
            setJobId(null);
            setJobData(null);
            setError('Previous test appears to have been interrupted. Start a new test.');
            return;
          }
        }
      } catch (err: any) {
        if (err?.response?.status === 404) {
          stopPolling();
          removeTest();
          setJobId(null);
          setJobData(null);
          setError('Previous test is no longer available.');
          return;
        }
        setConnectionWarning('Backend connection interrupted. Retrying…');
      }
    },
    [stopPolling],
  );

  const startPolling = useCallback(
    (id: string) => {
      stopPolling();
      void fetchJobStatus(id);
      pollingRef.current = setInterval(() => void fetchJobStatus(id), POLL_INTERVAL);
    },
    [fetchJobStatus, stopPolling],
  );

  useEffect(() => () => stopPolling(), [stopPolling]);

  const handleVis = useCallback(() => {
    if (document.visibilityState === 'visible' && jobId) void fetchJobStatus(jobId);
  }, [jobId, fetchJobStatus]);

  useEffect(() => {
    document.addEventListener('visibilitychange', handleVis);
    return () => document.removeEventListener('visibilitychange', handleVis);
  }, [handleVis]);

  useEffect(() => {
    if (userRole) void fetchPrivateScope();
  }, [userRole, fetchPrivateScope]);

  /* ── Restore state ── */

  useEffect(() => {
    void loadLabStatus();
    const stored = restoreTest();
    const storedMap = restoreMap();
    if (storedMap) setMapResult(storedMap);

    if (executionStatus && executionStatus.lifecycle !== 'IDLE' && executionStatus.job_id) {
      if (TERMINAL_LIFECYCLES.includes(executionStatus.lifecycle)) {
        if (jobId !== executionStatus.job_id) {
          removeTest();
          setJobId(null);
          setJobData(null);
        }
      } else {
        setTarget(executionStatus.target_url || stored?.target_url || target);
        setJobId(executionStatus.job_id);
        startPolling(executionStatus.job_id);
      }
    } else if (stored) {
      setTarget(stored.target_url);
      setJobId(stored.job_id);
      startPolling(stored.job_id);
    }
  }, [executionStatus?.lifecycle]);

  useEffect(() => {
    if (!jobId || !jobData) return;
    saveTest({
      job_id: jobId,
      target_url: jobData.target_url || target,
      authorization_id: jobData.authorization_id,
      started_at: jobData.started_at || new Date().toISOString(),
      map_result: mapResult ?? undefined,
    });
  }, [jobId, jobData, target, mapResult]);

  /* ── API actions ── */

  const loadLabStatus = async () => {
    try {
      setLabStatus(await getLabStatus());
    } catch {
      setLabStatus(null);
    }
  };

  const useLab = () => {
    stopPolling();
    setTarget(labTarget);
    setAuthorization(null);
    setChallenge(null);
    setConfirmation(true);
    setMapResult(null);
    setComplexity(null);
    setError(null);
    setJobId(null);
    setJobData(null);
    setJobResults(null);
    setConnectionWarning(null);
    removeTest();
    removeMap();
    toast.success('PhantomBank Lab selected');
  };

  const loadStatus = async () => {
    if (!target.trim()) return;
    setLoadingAction('status');
    setError(null);
    try {
      setAuthorization(await getAuthorizationStatus(target));
    } catch (err) {
      setError(apiErrorMessage(err, 'Unable to load authorization status.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const createChallenge = async () => {
    setLoadingAction('challenge');
    setError(null);
    try {
      const next = await createAuthorizationChallenge({ target_url: target, verification_method: method });
      setChallenge(next);
      setAuthorization({
        id: next.id,
        domain: next.domain,
        target_origin: next.target_origin,
        verification_method: next.verification_method,
        verified_at: null,
        expires_at: null,
        status: next.status,
        message: 'Verification pending.',
      });
      toast.success('Challenge created');
    } catch (err) {
      setError(apiErrorMessage(err, 'Unable to create challenge.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const verify = async () => {
    const id = challenge?.id ?? authorization?.id;
    if (!id) return;
    setLoadingAction('verify');
    setError(null);
    try {
      const next = await verifyAuthorization(id);
      setAuthorization(next);
      toast.success('Target verified');
    } catch (err) {
      const msg = apiErrorMessage(err, 'Verification token not found.');
      setError(msg);
      toast.error(msg);
    } finally {
      setLoadingAction(null);
    }
  };

  const copyToken = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success('Copied to clipboard');
    } catch {
      toast.error('Unable to copy');
    }
  }, []);

  const revoke = async () => {
    if (!authorization?.id) return;
    setLoadingAction('revoke');
    try {
      setAuthorization(await revokeAuthorization(authorization.id));
      setMapResult(null);
      setComplexity(null);
      toast.success('Authorization revoked');
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to revoke.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const mapSurface = async () => {
    setLoadingAction('map');
    setError(null);
    try {
      const mapped = await activeMap({
        target_url: target,
        selected_modules: selectedTests,
        authorization_id: authorization?.id ?? null,
        authorization_confirmed: confirmation,
      });
      setMapResult(mapped);
      saveMap(mapped);
      if (mapped.gate.authorization_status === 'TRAINING' || mapped.gate.authorization_status === 'ALLOWLIST') {
        setConfirmation(true);
      }
      toast.success(`Mapped ${mapped.surfaces.length} surfaces`);
    } catch (err) {
      setMapResult(null);
      removeMap();
      setError(apiErrorMessage(err, 'Mapping blocked by backend gate.'));
      toast.error('Mapping blocked');
    } finally {
      setLoadingAction(null);
    }
  };

  const analyzeComplexity = async () => {
    if (!target.trim()) return;
    setComplexityLoading(true);
    setError(null);
    try {
      const result = await activeComplexity({
        target_url: target,
        authorization_id: authorization?.id ?? null,
        authorization_confirmed: confirmation,
      });
      setComplexity(result);
      toast.success(`Complexity ${result.score}/100 (${result.band})`);
    } catch (err) {
      const msg = apiErrorMessage(err, 'Complexity analysis blocked by backend gate.');
      setError(msg);
      toast.error('Complexity analysis failed');
    } finally {
      setComplexityLoading(false);
    }
  };

  const stopTest = async () => {
    if (!jobId) return;
    setLoadingAction('stop');
    try {
      if (jobData?.scan_id) await stopScan(jobData.scan_id);
      stopPolling();
      setJobData((prev) => (prev ? { ...prev, status: 'CANCELLED' } : null));
      setJobId(null);
      removeTest();
      toast.success('Test stopped');
      refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to stop test.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const execute = async () => {
    if (!mapResult) return;
    setLoadingAction('execute');
    setError(null);
    setConnectionWarning(null);
    try {
      const verifiedExternal = mapResult.gate.authorization_status === 'VERIFIED';
      const response = await startAuthorizedTest({
        target_url: target,
        selected_modules: selectedTests,
        authorization_id: verifiedExternal ? mapResult.gate.authorization_id ?? authorization?.id ?? null : null,
        authorization_confirmed: verifiedExternal ? confirmation : false,
        enable_exploitation: enableExploitation,
        enable_ai_exploitation: enableAIExploitation,
        approval_request_id: approval?.id,
      });
      if (approval) {
        clearEnterpriseApproval();
        setApproval(null);
      }
      setJobId(response.job_id);
      setJobData({
        job_id: response.job_id,
        status: response.status,
        progress_percent: 0,
        current_phase: 'Starting…',
        current_module: null,
        surfaces_total: 0,
        surfaces_completed: 0,
        raw_surfaces_discovered: 0,
        testable_surfaces: 0,
        surface_groups: 0,
        findings_count: 0,
        started_at: null,
        updated_at: null,
        completed_at: null,
        error: null,
        target_url: target,
        selected_modules: selectedTests,
        authorization_id: mapResult.gate.authorization_id ?? null,
        scan_id: null,
      });
      saveTest({
        job_id: response.job_id,
        target_url: target,
        authorization_id: mapResult.gate.authorization_id ?? null,
        started_at: new Date().toISOString(),
        map_result: mapResult,
      });
      toast.success(response.message?.includes('already running') ? response.message : 'Test started');
      startPolling(response.job_id);
      refresh();
    } catch (err) {
      const msg = apiErrorMessage(err, 'Unable to start test.');
      setError(msg);
      toast.error(msg);
    } finally {
      setLoadingAction(null);
    }
  };

  const switchScenario = async (state: 'VULNERABLE' | 'PATCHED', scenario?: string) => {
    setLoadingAction(`${scenario ?? 'all'}-${state}`);
    try {
      const response = await setLabScenario({ state, scenario: scenario ?? 'all' });
      setLabStatus((curr) => (curr ? { ...curr, scenario_state: response.scenario_state } : curr));
      setMapResult(null);
      removeMap();
      toast.success(`${scenario ?? 'All'} → ${state}`);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to update scenario.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const toggleModule = (module: TestModule) => {
    setSelectedTests((curr) => (curr.includes(module) ? curr.filter((m) => m !== module) : [...curr, module]));
    setMapResult(null);
    removeMap();
  };

  /* ── Computed ── */

  const activeFindings = jobResults?.findings ?? [];
  const progressPercent = jobData?.progress_percent ?? 0;
  const currentPhase = jobData?.current_phase ?? '';
  const findingsCount = jobData?.findings_count ?? 0;
  const surfacesTotal = jobData?.surfaces_total ?? 0;
  const surfacesCompleted = jobData?.surfaces_completed ?? 0;

  const exploitationSummary = (jobResults?.resultSummary?.exploitation as ExploitationSummary | undefined) ?? null;
  const staticExploitation = exploitationSummary?.static?.exploitation_results ?? [];
  const aiExploitation = exploitationSummary?.ai?.exploitation_results ?? [];
  const exploitedCount = staticExploitation.filter((r) => r.success).length;
  const aiValidatedCount = aiExploitation.filter((r) => r.status === 'validated').length;
  const hasExploitationResults = staticExploitation.length > 0 || aiExploitation.length > 0;

  const downloadExploitationReport = () => {
    const lines: string[] = [
      '# VulScan Exploitation Report',
      '',
      `Target: ${target}`,
      `Scan ID: ${jobData?.scan_id ?? 'N/A'}`,
      `Generated: ${new Date().toISOString()}`,
      '',
      `## Static Exploitation (${exploitedCount}/${staticExploitation.length} confirmed)`,
    ];
    for (const r of staticExploitation) {
      lines.push('', `### ${r.type.replace(/_/g, ' ').toUpperCase()} — ${r.endpoint}`);
      lines.push(`- Status: ${r.success ? 'EXPLOITED' : (r.status ?? 'FAILED')}${r.reason ? ` (${r.reason})` : ''}`);
      lines.push(`- Summary: ${r.summary}`);
      if (r.database_type) lines.push(`- Database: ${r.database_type}`);
      if (r.tables?.length) lines.push(`- Tables: ${r.tables.join(', ')}`);
      if (r.extracted?.length) lines.push(`- Extracted: ${r.extracted.join(' | ')}`);
      if (r.files?.length) lines.push(`- Files: ${r.files.map((f) => f.file ?? f.payload_type ?? 'unknown').join(', ')}`);
      if (r.commands?.length) lines.push(`- Commands: ${r.commands.map((c) => c.command).join(', ')}`);
      if (r.poc_url) lines.push(`- PoC URL: ${r.poc_url}`);
      if (r.poc_payload) lines.push(`- PoC Payload: ${r.poc_payload}`);
      if (r.error) lines.push(`- Error: ${r.error}`);
    }
    if (exploitationSummary?.ai) {
      lines.push('', '## AI Exploitation');
      lines.push(`- AI available: ${exploitationSummary.ai.ai_available ? 'yes' : 'no (template fallback)'}`);
      lines.push(`- Summary: ${exploitationSummary.ai.summary ?? 'N/A'}`);
      for (const r of aiExploitation) {
        lines.push('', `### ${r.vulnerability_type ?? 'PoC'} (finding ${r.finding_id ?? 'N/A'})`);
        lines.push(`- Status: ${r.status ?? 'unknown'}`);
        if (r.error) lines.push(`- Error: ${r.error}`);
        if (r.report) lines.push('', r.report);
      }
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulscan-exploitation-${jobData?.scan_id ?? 'report'}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const currentStage = mapResult ? (isRunning ? 6 : jobData ? 7 : (authorization?.status === 'VERIFIED' || isAdmin) ? 3 : 2) : 1;
  const stages = [
    { id: 1, label: 'Target' },
    { id: 2, label: isAdmin ? 'Ownership (Skipped)' : 'Ownership' },
    { id: 3, label: 'Surface' },
    { id: 4, label: 'Plan' },
    { id: 5, label: 'Safety' },
    { id: 6, label: 'Execute' },
    isRunning || jobData ? { id: 7, label: 'Results' } : null,
  ].filter(Boolean) as Array<{ id: number; label: string }>;

  return (
    <Page>
      <PageHeader
        title="Authorized Testing"
        description="Controlled security testing for approved targets."
      />

      {/* Stage indicator */}
      <Panel>
        <div className="flex flex-wrap items-center gap-1 p-2.5">
          {stages.map((s, i) => {
            const isActive = s.id <= currentStage;
            const isCurrent = s.id === currentStage;
            const isLast = i === stages.length - 1;
            return (
              <div key={s.id} className="flex items-center gap-1">
                <span
                  className={`flex h-5 w-5 items-center justify-center rounded text-[9px] font-semibold ${
                    isCurrent
                      ? 'bg-[var(--accent)] text-white'
                      : isActive
                        ? 'bg-[var(--accent-subtle)] text-[var(--accent-hover)]'
                        : 'text-[var(--text-muted)]'
                  }`}
                >
                  {isActive && s.id < currentStage ? <CheckCircle2 className="h-3 w-3" /> : s.id}
                </span>
                <span className={cx('text-[10px]', isActive ? 'text-[var(--text-primary)]' : 'text-[var(--text-muted)]')}>
                  {s.label}
                </span>
                {!isLast ? <span className="mx-0.5 text-[var(--text-disabled)]">·</span> : null}
              </div>
            );
          })}
        </div>
      </Panel>

      {/* Admin / Public mode banner */}
      {userRole === 'admin' ? (
        <div className="rounded-xl border border-red-500/40 bg-red-600/20 p-4 flex items-center gap-4">
          <span className="text-2xl">🔓</span>
          <div>
            <h2 className="font-bold text-red-400">ADMIN OVERRIDE ACTIVE</h2>
            <p className="text-sm text-red-300/80">You can bypass ownership verification and test ANY external URL.</p>
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-blue-500/40 bg-blue-600/20 p-4 flex items-center gap-4">
          <span className="text-2xl">🛡️</span>
          <div>
            <h2 className="font-bold text-blue-400">PUBLIC MODE</h2>
            <p className="text-sm text-blue-300/80">You must verify ownership via DNS/HTTP before active testing.</p>
          </div>
        </div>
      )}

      {/* Error / Warning banners */}
      {error ? <ErrorState title="Error" description={error} /> : null}
      {connectionWarning ? <ErrorState title="Connection" description={connectionWarning} /> : null}

      {/* Stages 01-03: Target, Ownership, Attack Surface */}
      <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
        <div className="space-y-4">
          {/* 01 — Target */}
          <Panel>
            <div className="p-3">
              <SectionHeader title="01 — Target" description="Set the target domain or URL." />
              <div className="flex gap-3">
                <Input
                  value={target}
                  onChange={(e) => {
                    setTarget(e.target.value);
                    setMapResult(null);
                    setComplexity(null);
                    removeMap();
                  }}
                  placeholder="https://staging.example.com"
                  className="flex-1 font-mono"
                  disabled={isRunning}
                />
                {userRole === 'admin' && (
  <button
    onClick={async () => {
      if (!target.trim()) return;
      try {
        const result = await addToPrivateScope(target);
        toast.success(result.message || 'Added to private scope ✅');
        void fetchPrivateScope();
      } catch (err) {
        toast.error(apiErrorMessage(err, 'Failed to add to Private Scope.'));
      }
    }}
    className="ml-2 bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded whitespace-nowrap transition-all shadow-md"
  >
    ⚡ Add to Private Scope
  </button>
)}
                <Button variant="amber" onClick={useLab} disabled={isRunning}>
                  PhantomBank Lab
                </Button>
                {isAdmin ? (
                  <Button
                    variant="secondary"
                    onClick={async () => {
                      if (!target.trim()) return;
                      setLoadingAction('private_scope_add');
                      try {
                        const result = await addToPrivateScope(target);
                        toast.success(result.message);
                        void fetchPrivateScope();
                      } catch (err) {
                        toast.error(apiErrorMessage(err, 'Failed to add to Private Scope.'));
                      } finally {
                        setLoadingAction(null);
                      }
                    }}
                    disabled={!target.trim() || loadingAction === 'private_scope_add' || isRunning}
                    title="Add to Private Scope (Admin Only)"
                  >
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Add to Scope
                  </Button>
                ) : null}
              </div>
              {/* Admin Override Banner */}
              {isAdmin && mapResult?.gate.authorization_status === 'ADMIN_OVERRIDE' ? (
                <div className="mt-3 rounded-md border border-[var(--warning-subtle)] bg-[var(--warning-subtle)]/30 px-3 py-2.5 text-xs">
                  <div className="flex items-center gap-2 font-semibold text-[var(--warning)]">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    ADMIN OVERRIDE ACTIVE: Unrestricted targeting enabled for this asset.
                  </div>
                </div>
              ) : null}
            </div>
          </Panel>

          {/* 02 — Ownership */}
          {isAdmin ? (
            <Panel>
              <div className="p-3">
                <SectionHeader
                  title="02 — Ownership"
                  description="Admin override — verification skipped."
                  action={<span className="rounded-md bg-green-600/20 px-2.5 py-1 text-xs font-bold text-green-400">ADMIN</span>}
                />
                <div className="rounded-xl border border-green-500/40 bg-green-600/15 p-4 flex items-center gap-4">
                  <span className="text-2xl">✅</span>
                  <div>
                    <h3 className="font-bold text-green-400">Admin Override Active</h3>
                    <p className="text-sm text-green-300/80">
                      Ownership verification skipped. Target is authorized via admin privileges.
                      Proceed to map the attack surface and execute tests.
                    </p>
                  </div>
                </div>
              </div>
            </Panel>
          ) : (
            <Panel>
              <div className="p-3">
                <SectionHeader
                  title="02 — Ownership"
                  description="Verify target ownership for external targets."
                  action={
                    <StatusBadge status={gateLabel(authorization?.status ?? (isLab ? 'TRAINING' : 'PENDING'))} />
                  }
                />
                <div className="grid gap-3 lg:grid-cols-2">
                  <div>
                    <div className="mb-2 flex gap-2">
                      <button
                        onClick={() => setMethod('dns')}
                        className={`rounded-md px-2.5 py-1.5 text-xs ${
                          method === 'dns'
                            ? 'bg-[var(--warning-subtle)] text-[var(--warning)]'
                            : 'text-[var(--text-muted)] hover:bg-[var(--bg-hover)]'
                        }`}
                      >
                        DNS TXT
                      </button>
                      <button
                        onClick={() => setMethod('http')}
                        className={`rounded-md px-2.5 py-1.5 text-xs ${
                          method === 'http'
                            ? 'bg-[var(--warning-subtle)] text-[var(--warning)]'
                            : 'text-[var(--text-muted)] hover:bg-[var(--bg-hover)]'
                        }`}
                      >
                        HTTP File
                      </button>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        variant="secondary"
                        onClick={loadStatus}
                        disabled={!target.trim() || loadingAction === 'status' || isRunning}
                      >
                        {loadingAction === 'status' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                        Check
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={createChallenge}
                        disabled={isLab || !target.trim() || loadingAction === 'challenge' || isRunning}
                      >
                        <LockKeyhole className="h-3.5 w-3.5" />Challenge
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={verify}
                        disabled={(!challenge?.id && !authorization?.id) || loadingAction === 'verify' || isRunning}
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />Verify
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={revoke}
                        disabled={!authorization?.id || loadingAction === 'revoke' || isRunning}
                      >
                        Revoke
                      </Button>
                    </div>
                    {challenge ? (
                      <div className="mt-3 space-y-2">
                        <div className="rounded-md bg-[var(--bg-inset)] p-2.5">
                          <div className="text-[10px] text-[var(--text-muted)]">Token</div>
                          <div className="flex items-center gap-2">
                            <code className="flex-1 break-all font-mono text-xs text-[var(--warning)]">{challenge.token}</code>
                            <button
                              onClick={() => void copyToken(challenge.token)}
                              className="shrink-0 rounded bg-[var(--bg-hover)] p-1 text-[var(--text-muted)] hover:text-[var(--warning)]"
                              title="Copy"
                            >
                              <ClipboardCopy className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </div>
                        <div className="rounded-md bg-[var(--bg-inset)] p-2.5 font-mono text-[10px] text-[var(--text-muted)]">
                          <div className="mb-0.5 text-[10px] font-semibold text-[var(--text-disabled)]">Place at:</div>
                          <div className="break-all opacity-80">
                            {method === 'dns' ? challenge.dns_record : challenge.http_url}
                          </div>
                        </div>
                      </div>
                    ) : null}
                  </div>

                  <div className="space-y-2">
                    <InfoCallout title="Target Gate">
                      <p className="mt-1 text-[var(--text-muted)]">
                        {isLab
                          ? 'PhantomBank Lab targets are pre-approved.'
                          : 'External targets require DNS or HTTP ownership verification before active testing.'}
                      </p>
                    </InfoCallout>
                    {mapResult?.gate.allowed === false ? (
                      <div className="rounded-md border border-[var(--error-subtle)] p-2.5 text-xs text-[var(--error)]">
                        {mapResult.gate.reason || 'Blocked by backend gate.'}
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {/* 03 — Attack Surface */}
          <Panel>
            <div className="p-3">
              <SectionHeader
                title="03 — Attack Surface"
                description="Discover and review the target surface."
                action={
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-[var(--text-muted)]">
                      {mapResult?.surfaces.length ?? 0} surfaces
                    </span>
                    <span className="text-[11px] text-[var(--text-disabled)]">·</span>
                    <span className="text-[11px] text-[var(--text-muted)]">
                      {planModules.length} testable
                    </span>
                  </div>
                }
              />
              <div className="mb-3 flex items-center gap-2">
                <Button
                  variant="amber"
                  onClick={mapSurface}
                  disabled={!target.trim() || loadingAction === 'map' || isRunning}
                >
                  {loadingAction === 'map' ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5" />
                  )}
                  Map Surface
                </Button>
                {mapResult?.score ? (
                  <div className="rounded-md px-3 py-1.5 text-xs">
                    <span className="text-[var(--text-muted)]">Score: </span>
                    <span className="font-semibold text-[var(--text-primary)]">{mapResult.score.score}</span>
                  </div>
                ) : null}
              </div>
              {mapResult ? (
                <div className="grid gap-2 sm:grid-cols-2">
                  {mapResult.plan.modules.slice(0, 8).map((pm) => (
                    <div key={pm.module} className="rounded-md px-3 py-2">
                      <div className="text-xs font-medium text-[var(--text-primary)]">
                        {pm.module.replace(/_/g, ' ')}
                      </div>
                      <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                        {pm.surfaces.length} surface{pm.surfaces.length !== 1 ? 's' : ''}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="Not mapped yet"
                  description="Map the attack surface to discover endpoints."
                  compact
                />
              )}
            </div>
          </Panel>

          {/* 03b — Target Complexity */}
          <Panel>
            <div className="p-3">
              <SectionHeader
                title="Target Complexity"
                description="Live probe scoring the target before scanning."
                action={
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-[var(--text-muted)]">
                      {complexity ?? mapResult?.complexity
                        ? `${(complexity ?? mapResult?.complexity)?.score}/100`
                        : 'not analyzed'}
                    </span>
                  </div>
                }
              />
              <div className="mb-3 flex items-center gap-2">
                <Button
                  variant="secondary"
                  onClick={analyzeComplexity}
                  disabled={!target.trim() || complexityLoading || isRunning}
                >
                  {complexityLoading ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Gauge className="h-3.5 w-3.5" />
                  )}
                  {complexityLoading ? 'Analyzing…' : 'Analyze Complexity'}
                </Button>
              </div>
              {complexityLoading ? (
                <ComplexitySkeleton />
              ) : complexity ?? mapResult?.complexity ? (
                <ComplexityCard complexity={(complexity ?? mapResult?.complexity) as ComplexityResult} />
              ) : (
                <EmptyState
                  title="No complexity analysis yet"
                  description="Analyze the target to preview complexity-driven scan behavior."
                  compact
                />
              )}
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          {/* 04 — Test Plan */}
          <Panel>
            <div className="p-3">
              <SectionHeader
                title="04 — Test Plan"
                description={`${selectedTests.length} modules selected`}
              />
              <div className="max-h-[400px] space-y-3 overflow-y-auto scrollbar-compact">
                {Object.entries(modulesByGroup).map(([group, modules]) => (
                  <div key={group}>
                    <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-disabled)]">
                      {group}
                    </div>
                    <div className="space-y-0.5">
                      {modules.map((m) => (
                        <label
                          key={m.id}
                          className="flex items-center gap-2.5 rounded px-2.5 py-1.5 text-xs transition-colors hover:bg-[var(--bg-hover)]"
                        >
                          <input
                            type="checkbox"
                            checked={selectedTests.includes(m.id)}
                            onChange={() => toggleModule(m.id)}
                            disabled={isRunning}
                            className="h-3.5 w-3.5 rounded border-[var(--border-default)] bg-[var(--bg-inset)] text-[var(--accent)] focus:ring-[var(--accent)]/50"
                          />
                          <span className="min-w-0 flex-1 text-[var(--text-secondary)]">{m.label}</span>
                          {planModules.some((pm) => pm.module === m.id) ? (
                            <span className="shrink-0 rounded bg-[var(--accent-subtle)] px-1.5 py-0.5 text-[10px] text-[var(--accent-hover)]">
                              Planned
                            </span>
                          ) : null}
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </Panel>

          {/* 05 — Safety */}
          <Panel>
            <div className="p-3">
              <SectionHeader
                title="05 — Safety Limits"
                description="Backend-enforced constraints."
              />
              <div className="space-y-2 text-xs">
                <div className="flex justify-between rounded px-3 py-2">
                  <span className="text-[var(--text-muted)]">Request Limit</span>
                  <span className="text-[var(--text-primary)]">{mapResult?.limits.max_requests ?? 'Default'}</span>
                </div>
                <div className="flex justify-between rounded px-3 py-2">
                  <span className="text-[var(--text-muted)]">Timeout</span>
                  <span className="text-[var(--text-primary)]">{formatLimit(mapResult?.limits.timeout_seconds)}</span>
                </div>
                <div className="flex justify-between rounded px-3 py-2">
                  <span className="text-[var(--text-muted)]">Intensity</span>
                  <span className="text-[var(--text-primary)] capitalize">{profile}</span>
                </div>
                <label className="flex items-center gap-2 rounded px-3 py-2">
                  <input
                    type="checkbox"
                    checked={confirmation}
                    onChange={(e) => setConfirmation(e.target.checked)}
                    disabled={isRunning || gateStatus !== 'VERIFIED'}
                    className="h-3.5 w-3.5 rounded border-[var(--border-default)] bg-[var(--bg-inset)] text-[var(--accent)]"
                  />
                  <span className="text-[var(--text-secondary)]">
                    {gateStatus === 'VERIFIED'
                      ? 'I confirm authorization for this target.'
                      : gateStatus === 'ADMIN_OVERRIDE'
                        ? 'Admin override — authorization on file.'
                        : 'Lab target — auto-confirmed.'}
                  </span>
                </label>
                <div className="rounded-md border border-red-500/30 bg-red-500/10 p-3">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={enableExploitation}
                      onChange={(e) => {
                        setEnableExploitation(e.target.checked);
                        if (!e.target.checked) setEnableAIExploitation(false);
                      }}
                      disabled={isRunning}
                      className="h-3.5 w-3.5 rounded border-[var(--border-default)] bg-[var(--bg-inset)] text-[var(--danger)]"
                    />
                    <span className="font-semibold text-[var(--danger)]">Enable Exploitation</span>
                  </label>
                  <p className="mt-1 text-[10px] leading-relaxed text-[var(--text-muted)]">
                    Actively exploit CRITICAL/HIGH findings (SQL injection, XSS, path traversal, command injection)
                    against this authorized target.
                  </p>
                  {enableExploitation ? (
                    <div className="mt-2 border-t border-red-500/20 pt-2">
                      <label className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={enableAIExploitation}
                          onChange={(e) => setEnableAIExploitation(e.target.checked)}
                          disabled={isRunning}
                          className="h-3.5 w-3.5 rounded border-[var(--border-default)] bg-[var(--bg-inset)] text-[var(--danger)]"
                        />
                        <span className="text-[var(--text-secondary)]">Enable AI Exploitation</span>
                      </label>
                      <p className="mt-1 text-[10px] leading-relaxed text-[var(--text-muted)]">
                        Use OpenRouter to generate context-aware payloads. Falls back to deterministic templates
                        when no API key is configured.
                      </p>
                    </div>
                  ) : null}
                </div>
                <InfoCallout title="Safety is backend-enforced">
                  <p className="mt-0.5 text-[var(--text-muted)]">
                    Rate limits, timeout, and scope are enforced by the backend.
                  </p>
                </InfoCallout>
              </div>
            </div>
          </Panel>

          {/* 06 — Execute */}
          <Panel>
            <div className="p-3">
              <SectionHeader title="06 — Execute" description="Start the authorized test." />
              {isRunning ? (
                <div className="flex items-center gap-3">
                  <div className="min-w-0 flex-1">
                    <ProgressBar value={progressPercent} />
                    <div className="mt-1 text-xs text-[var(--text-muted)]">
                      {currentPhase || 'Running'} · {progressPercent}%
                    </div>
                  </div>
                  <Button variant="danger" onClick={stopTest} disabled={loadingAction === 'stop'}>
                    {loadingAction === 'stop' ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Square className="h-3.5 w-3.5" />
                    )}
                    Stop
                  </Button>
                </div>
              ) : canExecute ? (
                <Button
                  variant="primary"
                  className="w-full"
                  onClick={execute}
                  disabled={loadingAction === 'execute'}
                >
                  {loadingAction === 'execute' ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5" />
                  )}
                  Run Authorized Test
                </Button>
              ) : (
                <div className="rounded px-3 py-2 text-xs text-[var(--text-muted)]">
                  {!mapResult
                    ? 'Map the attack surface first.'
                    : !mapResult.gate.allowed
                      ? mapResult.gate.reason || 'Target blocked by backend gate.'
                      : !selectedTests.length
                        ? 'Select at least one module.'
                        : 'Configure target, ownership, and surface mapping.'}
                </div>
              )}
            </div>
          </Panel>
        </div>
      </div>

      {/* 07 — Results */}
      {jobData ? (
        <Panel>
          <div className="p-3">
            <SectionHeader
              title="07 — Results"
              description={
                terminalJobStatuses.includes(jobData.status)
                  ? `Test ${jobData.status.toLowerCase()}`
                  : 'Live execution progress'
              }
            />

            {/* Live progress summary */}
            {isRunning ? (
              <div className="mb-4 grid gap-3 sm:grid-cols-4">
                <MetricCard label="Progress" value={`${progressPercent}%`} />
                <MetricCard label="Phase" value={currentPhase || 'Starting'} />
                <MetricCard label="Surfaces" value={`${surfacesCompleted}/${surfacesTotal}`} />
                <MetricCard label="Findings" value={findingsCount} accent={findingsCount > 0} />
              </div>
            ) : jobData.status === 'COMPLETED' ? (
              <div className="mb-4 grid gap-3 sm:grid-cols-4">
                <MetricCard label="Final Status" value="Completed" />
                <MetricCard label="Surfaces" value={`${surfacesCompleted}/${surfacesTotal}`} />
                <MetricCard label="Findings" value={findingsCount} accent={findingsCount > 0} />
                <MetricCard label="Target" value={targetName(jobData.target_url)} />
              </div>
            ) : terminalJobStatuses.includes(jobData.status) ? (
              <div className="mb-4 grid gap-3 sm:grid-cols-3">
                <MetricCard label="Status" value={jobData.status} />
                <MetricCard label="Surfaces" value={`${surfacesCompleted}/${surfacesTotal}`} />
                <MetricCard label="Findings" value={findingsCount} />
              </div>
            ) : null}

            {/* Attack flow */}
            <AttackFlowAnimation events={events} />

            {/* Console */}
            <div className="mt-4">
              <SectionHeader
                title="Live Activity Console"
                action={
                  <StatusBadge
                    status={isRunning ? 'LIVE' : jobData?.status ?? 'IDLE'}
                  />
                }
              />
              <LiveActivityConsole
                jobId={jobId}
                isRunning={isRunning}
                onSelectEvent={(event) => {
                  setSelectedEvent(event);
                  setEventDrawerOpen(true);
                }}
                onEventsChange={setEvents}
              />
              <EvidencePanel jobId={jobId} isRunning={isRunning} />
            </div>

            {/* Exploitation Results */}
            {hasExploitationResults ? (
              <div className="mt-4">
                <SectionHeader
                  title="Exploitation Results"
                  description={
                    terminalJobStatuses.includes(jobData.status)
                      ? `${exploitedCount} exploited · ${aiValidatedCount} AI-validated PoCs`
                      : 'Exploitation phase in progress'
                  }
                  action={
                    <Button
                      variant="secondary"
                      onClick={downloadExploitationReport}
                      disabled={!terminalJobStatuses.includes(jobData.status)}
                    >
                      <Download className="h-3.5 w-3.5" />
                      Download Exploitation Report
                    </Button>
                  }
                />
                {staticExploitation.length > 0 ? (
                  <div className="space-y-2">
                    {staticExploitation.map((r, i) => (
                      <div key={`static-${i}`} className="rounded-md border border-[var(--border-default)] p-3">
                        <div className="flex items-center gap-2">
                          <StatusBadge status={r.success ? 'EXPLOITED' : (r.status ?? 'FAILED')} />
                          <span className="text-xs font-medium capitalize text-[var(--text-primary)]">
                            {r.type.replace(/_/g, ' ')}
                          </span>
                          <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-[var(--text-muted)]">
                            {r.endpoint}
                          </span>
                        </div>
                        <p className="mt-1.5 text-xs text-[var(--text-secondary)]">{r.summary}</p>
                        {r.reason ? (
                          <p className="mt-1 text-[10px] text-[var(--text-muted)]">Skipped: {r.reason}</p>
                        ) : null}
                        {r.database_type ? (
                          <p className="mt-1 text-[10px] text-[var(--text-muted)]">
                            Database: <span className="font-mono">{r.database_type}</span>
                            {r.tables?.length ? ` · Tables: ${r.tables.join(', ')}` : ''}
                          </p>
                        ) : null}
                        {r.poc_url || r.poc_payload ? (
                          <details className="mt-1.5">
                            <summary className="cursor-pointer text-[10px] text-[var(--text-muted)]">
                              PoC details
                            </summary>
                            <div className="mt-1 space-y-1">
                              {r.poc_url ? (
                                <code className="block break-all rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-secondary)]">
                                  {r.poc_url}
                                </code>
                              ) : null}
                              {r.poc_payload ? (
                                <code className="block break-all rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-secondary)]">
                                  {r.poc_payload}
                                </code>
                              ) : null}
                            </div>
                          </details>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState
                    title="No exploitable outcomes"
                    description="No CRITICAL/HIGH findings could be exploited on this target."
                    compact
                  />
                )}
                {aiExploitation.length > 0 ? (
                  <div className="mt-3">
                    <div className="mb-1.5 text-[11px] font-semibold text-[var(--text-secondary)]">
                      AI-generated PoCs{' '}
                      {exploitationSummary?.ai?.ai_available ? '' : '(template fallback — no OpenRouter key)'}
                    </div>
                    <div className="space-y-1.5">
                      {aiExploitation.map((r, i) => (
                        <div key={`ai-${i}`} className="rounded-md border border-[var(--border-default)] p-2.5">
                          <div className="flex items-center gap-2">
                            <StatusBadge status={r.status === 'validated' ? 'VALIDATED' : 'FAILED'} />
                            <span className="text-xs font-medium capitalize text-[var(--text-primary)]">
                              {(r.vulnerability_type ?? 'PoC').replace(/_/g, ' ')}
                            </span>
                            <span className="text-[10px] text-[var(--text-muted)]">finding #{r.finding_id ?? 'N/A'}</span>
                          </div>
                          {r.report ? (
                            <details className="mt-1.5">
                              <summary className="cursor-pointer text-[10px] text-[var(--text-muted)]">
                                PoC report
                              </summary>
                              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-secondary)]">
                                {r.report}
                              </pre>
                            </details>
                          ) : null}
                          {r.error ? (
                            <p className="mt-1 text-[10px] text-[var(--error)]">{r.error}</p>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </Panel>
      ) : null}

      {/* Private Scope Management — Admin Only */}
      {isAdmin ? (
        <Panel>
          <div className="p-3">
            <SectionHeader
              title="Private Scope Management"
              description="Admin-managed targets bypassing DNS/HTTP verification."
              action={
                <Button variant="ghost" onClick={fetchPrivateScope} disabled={loadingPrivateScope}>
                  Refresh
                </Button>
              }
            />
            {privateScopeList.length === 0 ? (
              <EmptyState
                title="No targets in Private Scope"
                description="Add a target using the 'Add to Scope' button above."
                compact
              />
            ) : (
              <div className="divide-y divide-[var(--border-light)]">
                {privateScopeList.map((entry) => (
                  <div key={entry.id} className="flex items-center gap-3 px-3 py-2.5">
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-xs text-[var(--text-primary)]">
                        {entry.target_url}
                      </div>
                      <div className="mt-0.5 text-[10px] text-[var(--text-muted)]">
                        Added {entry.added_at ? new Date(entry.added_at).toLocaleDateString() : 'N/A'}
                        {entry.last_used ? ` · Last used ${new Date(entry.last_used).toLocaleDateString()}` : ''}
                      </div>
                    </div>
                    <button
                      onClick={async () => {
                        try {
                          const result = await removeFromPrivateScope(entry.target_url);
                          toast.success(result.message);
                          void fetchPrivateScope();
                        } catch (err) {
                          toast.error(apiErrorMessage(err, 'Failed to remove from Private Scope.'));
                        }
                      }}
                      className="shrink-0 rounded p-1.5 text-[var(--text-muted)] hover:bg-[var(--danger-soft)] hover:text-[var(--danger)]"
                      title="Remove from Private Scope"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Panel>
      ) : null}

      {/* PhantomBank Lab */}
      {labStatus ? (
        <Panel>
          <div className="p-3">
            <SectionHeader
              title="PhantomBank Lab — Training Environment"
              description="Pre-configured test target for security training. Contains fake data and simulated vulnerabilities only."
            />
            <div className="mb-2 rounded-md border border-[var(--info-subtle)] px-3 py-2 text-xs text-[var(--info)]">
              This is a training-only environment with simulated users and fake data. No real systems are affected.
            </div>
            <div className="mb-3 flex gap-2">
              <Button
                variant="danger"
                onClick={() => void switchScenario('VULNERABLE')}
                disabled={loadingAction === 'all-VULNERABLE' || isRunning}
              >
                All Vulnerable
              </Button>
              <Button
                variant="secondary"
                onClick={() => void switchScenario('PATCHED')}
                disabled={loadingAction === 'all-PATCHED' || isRunning}
              >
                All Patched
              </Button>
            </div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {Object.entries(labStatus.scenarios).map(([scenario, modules]) => {
                const state = labStatus.scenario_state[scenario] ?? 'VULNERABLE';
                return (
                  <div key={scenario} className="rounded-md border border-[var(--border-default)] p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="truncate text-xs font-medium text-[var(--text-secondary)]">
                          {scenario.replace(/_/g, ' ')}
                        </div>
                        <div className="mt-0.5 text-[10px] text-[var(--text-muted)]">{modules.join(', ')}</div>
                      </div>
                      <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${
                        state === 'VULNERABLE'
                          ? 'bg-[var(--warning-subtle)] text-[var(--warning)]'
                          : 'bg-[var(--success-subtle)] text-[var(--success)]'
                      }`}>
                        {state === 'VULNERABLE' ? 'Vulnerable' : 'Patched'}
                      </span>
                    </div>
                    <div className="mt-2 flex gap-1.5">
                      <button
                        onClick={() => void switchScenario('VULNERABLE', scenario)}
                        className={`flex-1 rounded px-2 py-1 text-[10px] font-semibold ${
                          state === 'VULNERABLE'
                            ? 'bg-[var(--warning-subtle)] text-[var(--warning)] cursor-default'
                            : 'text-[var(--text-muted)] hover:bg-[var(--warning-subtle)] hover:text-[var(--warning)]'
                        }`}
                      >
                        Vulnerable
                      </button>
                      <button
                        onClick={() => void switchScenario('PATCHED', scenario)}
                        className={`flex-1 rounded px-2 py-1 text-[10px] font-semibold ${
                          state === 'PATCHED'
                            ? 'bg-[var(--success-subtle)] text-[var(--success)] cursor-default'
                            : 'text-[var(--text-muted)] hover:bg-[var(--success-subtle)] hover:text-[var(--success)]'
                        }`}
                      >
                        Patched
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </Panel>
      ) : null}

      <EventDetailDrawer
        event={selectedEvent}
        open={eventDrawerOpen}
        onClose={() => setEventDrawerOpen(false)}
      />
    </Page>
  );
}
