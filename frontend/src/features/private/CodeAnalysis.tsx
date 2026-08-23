import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Code2,
  ExternalLink,
  FileSearch,
  GitBranch,
  Lock,
  RefreshCw,
  ScanLine,
  ShieldCheck,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { useAuth } from '../../context/AuthContext';
import apiClient, { apiErrorMessage, listGitHubRepos } from '../../services/api';
import type { GitHubRepo } from '../../types';
import { hasElevatedAccess } from '../../utils/access';
import {
  Button,
  EmptyState,
  ErrorState,
  Input,
  Page,
  PageHeader,
  Panel,
  SeverityBadge,
} from '../../components/ui/Primitives';
import { clearEnterpriseApproval, getEnterpriseApproval } from '../enterprise/approvalHandoff';

interface SastSource {
  source_type: string;
  source_identifier: string;
  status: string;
  findings_count: number;
  findings_by_severity: Record<string, number>;
  scan_duration_seconds: number;
  error_message: string | null;
  artifacts: Record<string, unknown>;
}

interface SastFinding {
  id: number;
  title: string;
  severity: string;
  category: string;
  confidence: string;
  target: string;
  endpoint: string;
  evidence: string;
  impact: string;
  module: string | null;
  cwe: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  recommended_fix: string | null;
  recommendation: string | null;
}

interface SastScan {
  scan_id: number;
  repo_url: string;
  overall_status: string;
  overall_progress: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  sources: SastSource[];
  findings: SastFinding[];
  error_message?: string | null;
}

const TERMINAL = new Set(['complete', 'error', 'cancelled']);
const ACTIVE_REPO_ANALYSIS_KEY = 'vulscan:active-github-repo-analysis';

const toolLabels: Record<string, string> = {
  semgrep: 'Static Analysis',
  trufflehog: 'Secrets',
  gitleaks: 'Secrets',
  'pip-audit': 'Dependencies',
  'npm-audit': 'Dependencies',
};

function severityColor(severity: string) {
  const map: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    LOW: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    INFO: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
  };
  return map[severity?.toUpperCase()] ?? map.INFO;
}

const DEPTH_PRESETS: Record<string, { excludes: string[]; timeout: number; label: string }> = {
  quick: {
    excludes: ['tests/**', 'test/**', '__tests__/**', 'docs/**', 'examples/**', 'sample/**', '*.md', '*.min.js'],
    timeout: 600,
    label: 'Quick (10 min)',
  },
  standard: {
    excludes: [],
    timeout: 1200,
    label: 'Standard (20 min)',
  },
  full: {
    excludes: [],
    timeout: 2400,
    label: 'Full (40 min)',
  },
};

function isTerminalStatus(status?: string | null) {
  return status ? TERMINAL.has(status) : false;
}

function persistScanReference(scan: SastScan, branch?: string) {
  localStorage.setItem(ACTIVE_REPO_ANALYSIS_KEY, JSON.stringify({
    scan_id: scan.scan_id,
    repo_url: scan.repo_url,
    branch,
    overall_status: scan.overall_status,
    overall_progress: scan.overall_progress,
    total_findings: scan.total_findings,
  }));
}

function restoreScanReference(): (SastScan & { branch?: string }) | null {
  const stored = localStorage.getItem(ACTIVE_REPO_ANALYSIS_KEY);
  if (!stored) return null;
  try {
    const parsed = JSON.parse(stored) as Partial<SastScan> & { branch?: string };
    if (typeof parsed.scan_id !== 'number') return null;
    return {
      scan_id: parsed.scan_id,
      repo_url: String(parsed.repo_url ?? ''),
      branch: parsed.branch,
      overall_status: String(parsed.overall_status ?? 'queued'),
      overall_progress: typeof parsed.overall_progress === 'number' ? parsed.overall_progress : 0,
      total_findings: typeof parsed.total_findings === 'number' ? parsed.total_findings : 0,
      findings_by_severity: {},
      sources: [],
      findings: [],
    };
  } catch {
    localStorage.removeItem(ACTIVE_REPO_ANALYSIS_KEY);
    return null;
  }
}

export default function CodeAnalysis() {
  const { user } = useAuth();
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [depth, setDepth] = useState('standard');
  const [starting, setStarting] = useState(false);
  const [scan, setScan] = useState<SastScan | null>(null);
  const [error, setError] = useState('');
  const [polling, setPolling] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [githubConnected, setGithubConnected] = useState<boolean | null>(null);
  const [approval, setApproval] = useState(() => getEnterpriseApproval(['code_audit', 'scan']));
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, []);

  useEffect(() => {
    const restored = restoreScanReference();
    if (!restored) return;
    let cancelled = false;

    setScan(restored);
    if (restored.repo_url) setRepoUrl(restored.repo_url);
    if (restored.branch) setBranch(restored.branch);
    setPolling(!isTerminalStatus(restored.overall_status));

    apiClient.get<SastScan>(`/api/sast/${restored.scan_id}`)
      .then((response) => {
        if (cancelled) return;
        setScan(response.data);
        persistScanReference(response.data, restored.branch);
        setPolling(!isTerminalStatus(response.data.overall_status));
      })
      .catch(() => {
        if (!cancelled) setPolling(!isTerminalStatus(restored.overall_status));
      });

    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (approval?.target_url && !repoUrl) setRepoUrl(approval.target_url);
  }, [approval, repoUrl]);

  // Load the connected GitHub account's repos so they can be picked directly.
  useEffect(() => {
    let cancelled = false;
    listGitHubRepos()
      .then((result) => {
        if (cancelled) return;
        setGithubConnected(result.connected);
        setRepos(result.repos);
      })
      .catch(() => {
        if (!cancelled) setGithubConnected(false);
      });
    return () => { cancelled = true; };
  }, []);

  const selectRepo = (value: string) => {
    const repo = repos.find((r) => r.clone_url === value || r.html_url === value || r.full_name === value);
    if (!repo) return;
    setRepoUrl(repo.clone_url);
    if (repo.default_branch) setBranch(repo.default_branch);
  };

  const selectedRepoValue = repos.find(
    (r) => r.clone_url === repoUrl || r.html_url === repoUrl || r.full_name === repoUrl,
  )?.clone_url ?? '';

  const isValidRepoUrl = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+/.test(repoUrl.trim());

  const startScan = async () => {
    const url = repoUrl.trim();
    if (!isValidRepoUrl) {
      const msg = 'Enter a valid GitHub repository URL (https://github.com/owner/repo)';
      setError(msg);
      toast.error(msg);
      return;
    }
    setStarting(true);
    setError('');
    setScan(null);
    const preset = DEPTH_PRESETS[depth] || DEPTH_PRESETS.standard;
    try {
      const response = await apiClient.post<{ scan_id: number }>('/api/sast/scan-repo', null, {
        params: {
          repo_url: url,
          branch: branch.trim() || 'main',
          exclude_patterns: preset.excludes.join(','),
          scan_timeout: preset.timeout,
          approval_request_id: approval?.id,
        },
      });
      if (approval) {
        clearEnterpriseApproval();
        setApproval(null);
      }
      const nextScan: SastScan = {
        scan_id: response.data.scan_id,
        repo_url: url,
        overall_status: 'queued',
        overall_progress: 0,
        total_findings: 0,
        findings_by_severity: {},
        sources: [],
        findings: [],
      };
      setScan(nextScan);
      persistScanReference(nextScan, branch.trim() || 'main');
      toast.success('GitHub repo analysis started');
      setPolling(true);
    } catch (err) {
      const msg = apiErrorMessage(err, 'Failed to start GitHub repo analysis');
      setError(msg);
      toast.error(msg);
    } finally {
      setStarting(false);
    }
  };

  useEffect(() => {
    if (!polling || !scan) return;
    let cancelled = false;

    const poll = async () => {
      try {
        const response = await apiClient.get<SastScan>(`/api/sast/${scan.scan_id}`);
        if (cancelled) return;
        setScan((prev) => (prev ? { ...prev, ...response.data } : response.data));
        persistScanReference(response.data, branch.trim() || 'main');
        if (isTerminalStatus(response.data.overall_status)) {
          setPolling(false);
          if (response.data.overall_status === 'complete') {
            toast.success(`Scan complete — ${response.data.total_findings} findings`);
          } else {
            toast.error(`Scan ended: ${response.data.overall_status}`);
          }
        }
      } catch (err) {
        if (cancelled) return;
        const msg = apiErrorMessage(err, 'Failed to fetch scan status');
        setError(msg);
        setPolling(false);
      }
    };

    poll();
    pollTimer.current = setInterval(poll, 4000);
    return () => {
      cancelled = true;
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, [branch, polling, scan?.scan_id]);

  if (!hasElevatedAccess(user)) {
    return (
      <Page>
        <PageHeader title="GitHub Repo Analysis" description="Admin-only feature" />
        <Panel>
          <div className="flex items-center gap-3 p-6">
            <Lock className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-sm font-semibold text-red-600 dark:text-red-400">Admin access required</p>
              <p className="text-xs text-[var(--text-muted)]">Log in as admin or enterprise owner to scan GitHub repositories.</p>
            </div>
          </div>
        </Panel>
      </Page>
    );
  }

  const active = scan && !TERMINAL.has(scan.overall_status);

  return (
    <Page>
      <PageHeader
        title="GitHub Repo Analysis"
        description="Scan a GitHub repository for secrets, insecure patterns, and vulnerable dependencies. Connected-account repos (including private) are supported."
      />

      <div className="space-y-5">
        {active ? (
          <Panel>
            <div className="flex items-center gap-3 p-3.5 text-xs text-[var(--text-muted)]">
              <RefreshCw className="h-3.5 w-3.5 animate-spin text-[var(--brand)]" />
              <span>
                GitHub repo analysis #{scan.scan_id} is running in the background. You can switch pages and start other task types while this continues.
              </span>
            </div>
          </Panel>
        ) : null}

        <Panel>
          <div className="p-4">
            {githubConnected ? (
              <div className="mb-3">
                <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">
                  Your GitHub repositories ({repos.length} connected)
                </label>
                <select
                  value={selectedRepoValue}
                  onChange={(e) => selectRepo(e.target.value)}
                  disabled={starting || polling}
                  className="w-full rounded-md border border-[var(--border-light)] bg-[var(--surface-primary)] px-3 py-1.5 text-xs text-[var(--text-default)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]"
                >
                  <option value="">— Select a repository —</option>
                  {repos.map((repo) => (
                    <option key={repo.id} value={repo.clone_url}>
                      {repo.full_name}{repo.private ? ' (private)' : ''}{repo.language ? ` · ${repo.language}` : ''}
                    </option>
                  ))}
                </select>
              </div>
            ) : (
              <p className="mb-3 flex items-center gap-1.5 text-[11px] text-[var(--text-subtle)]">
                <GitBranch className="h-3 w-3" />
                Connect your GitHub account on the{' '}
                <a href="/github" className="font-medium text-[var(--brand)] hover:underline">GitHub page</a>
                {' '}to pick repos directly (including private ones).
              </p>
            )}

            <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">GitHub repository URL</label>
            <div className="flex gap-2">
              <Input
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/user/repo"
                className="flex-1 font-mono"
                onKeyDown={(e) => { if (e.key === 'Enter') startScan(); }}
              />
              <Input
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="main"
                className="w-28 font-mono"
                aria-label="Branch"
              />
              <select
                value={depth}
                onChange={(e) => setDepth(e.target.value)}
                className="rounded-md border border-[var(--border-light)] bg-[var(--surface-primary)] px-3 py-1.5 text-xs text-[var(--text-default)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]"
              >
                <option value="quick">Quick (10 min)</option>
                <option value="standard">Standard (20 min)</option>
                <option value="full">Full (40 min)</option>
              </select>
              <Button variant="primary" onClick={startScan} disabled={starting || polling || !isValidRepoUrl}>
                {starting ? (
                  <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Starting...</>
                ) : (
                  <><ScanLine className="h-3.5 w-3.5" /> Analyze GitHub Repo</>
                )}
              </Button>
            </div>
            <p className="mt-2 flex items-center gap-1.5 text-[11px] text-[var(--text-subtle)]">
              <GitBranch className="h-3 w-3" />
              Runs Semgrep, TruffleHog, Gitleaks, pip-audit / npm-audit, and IaC rules against the cloned repo.
            </p>
          </div>
        </Panel>

        {error ? <ErrorState title="GitHub repo analysis failed" description={error} /> : null}

        {!scan ? (
          <Panel>
            <EmptyState
              icon={<Code2 className="h-5 w-5" />}
              title="No GitHub repository analyzed yet"
              description="Paste a public GitHub repository URL above (e.g. https://github.com/expressjs/express) and start an analysis."
            />
          </Panel>
        ) : (
          <>
            {/* Scan status */}
            <Panel>
              <div className="p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span
                      className={`flex h-2 w-2 shrink-0 rounded-full ${
                        scan.overall_status === 'complete' ? 'bg-green-500' : active ? 'animate-pulse bg-amber-500' : 'bg-red-500'
                      }`}
                    />
                    <span className="truncate font-mono text-xs text-[var(--text-default)]">{scan.repo_url}</span>
                    <span className="rounded-md bg-[var(--surface-tertiary)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                      {scan.overall_status}
                    </span>
                  </div>
                  {active ? (
                    <div className="flex items-center gap-3">
                      <div className="h-1.5 w-40 overflow-hidden rounded-full bg-[var(--surface-tertiary)]">
                        <div
                          className="h-full rounded-full bg-[var(--brand)] transition-all"
                          style={{ width: `${Math.max(3, scan.overall_progress)}%` }}
                        />
                      </div>
                      <span className="text-[11px] font-medium text-[var(--text-muted)]">{scan.overall_progress}%</span>
                    </div>
                  ) : null}
                  <div className="flex items-center gap-3 text-xs">
                    {scan.overall_status === 'complete' ? (
                      <>
                        <ShieldCheck className="h-4 w-4 text-green-500" />
                        <span className="font-semibold text-[var(--text-default)]">{scan.total_findings} findings</span>
                        <div className="flex gap-1">
                          {Object.entries(scan.findings_by_severity).map(([sev, count]) => (
                            <span key={sev} className={`rounded-md px-1.5 py-0.5 text-[10px] font-bold ${severityColor(sev)}`}>
                              {sev} {count}
                            </span>
                          ))}
                        </div>
                      </>
                    ) : null}
                  </div>
                </div>
              </div>
            </Panel>

            {/* Source phases */}
            {scan.sources.length > 0 ? (
              <Panel>
                <div className="divide-y divide-[var(--border-light)]">
                  {scan.sources.map((source) => (
                    <div key={source.source_type} className="flex items-center justify-between gap-3 p-3">
                      <div className="flex items-center gap-2.5">
                        <FileSearch className="h-4 w-4 text-[var(--text-muted)]" />
                        <span className="text-xs font-medium text-[var(--text-default)]">
                          {toolLabels[source.source_type] ?? source.source_type}
                        </span>
                        <span className="truncate font-mono text-[11px] text-[var(--text-subtle)]">{source.source_identifier}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        {source.findings_count > 0 ? (
                          <span className="text-[11px] font-bold text-[var(--text-default)]">{source.findings_count} findings</span>
                        ) : null}
                        <span
                          className={`rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                            source.status === 'completed'
                              ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                              : source.status === 'running'
                                ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
                                : source.status === 'failed'
                                  ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                                  : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
                          }`}
                        >
                          {source.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
                {scan.sources.some((s) => s.status === 'failed' && s.error_message) ? (
                  <p className="border-t border-[var(--border-light)] px-3 py-2 text-[11px] text-[var(--text-subtle)]">
                    {scan.sources.filter((s) => s.status === 'failed' && s.error_message).map((s) => s.error_message).join(' ')}
                  </p>
                ) : null}
              </Panel>
            ) : null}

            {/* Findings */}
            {scan.overall_status === 'complete' && scan.findings.length === 0 ? (
              <Panel>
                <EmptyState
                  icon={<ShieldCheck className="h-5 w-5" />}
                  title="No findings"
                  description="No secrets, insecure patterns, or vulnerable dependencies were detected in this repository."
                />
              </Panel>
            ) : null}

            {scan.findings.length > 0 ? (
              <Panel>
                <div className="p-3">
                  <h3 className="px-1 pb-2 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">
                    Findings ({scan.findings.length})
                  </h3>
                  <div className="space-y-1.5">
                    {scan.findings.map((finding) => (
                      <button
                        key={finding.id}
                        type="button"
                        onClick={() => setExpanded(expanded === finding.id ? null : finding.id)}
                        className="w-full rounded-xl border border-slate-200 bg-white p-3 text-left shadow-sm transition-colors hover:border-slate-300 hover:bg-slate-50"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <SeverityBadge severity={finding.severity as never} />
                              <span className="text-xs font-semibold text-slate-950">{finding.title}</span>
                            </div>
                            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-slate-500">
                              <span>{finding.category}</span>
                              {finding.module ? <span className="font-mono">{finding.module}</span> : null}
                              {finding.endpoint ? <span className="truncate font-mono">{finding.endpoint}</span> : null}
                              {finding.cwe ? <span className="font-mono">{finding.cwe}</span> : null}
                              {finding.cvss_score != null ? <span>CVSS {finding.cvss_score}</span> : null}
                            </div>
                          </div>
                          {finding.evidence ? <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-slate-400" /> : null}
                        </div>

                        {expanded === finding.id ? (
                          <div className="mt-3 space-y-2 border-t border-slate-200 pt-3">
                            {finding.evidence ? (
                              <pre className="overflow-x-auto rounded-lg bg-slate-50 p-3 font-mono text-[11px] leading-relaxed text-slate-800">
                                {finding.evidence}
                              </pre>
                            ) : null}
                            {finding.impact ? (
                              <p className="text-[11px] text-slate-600">
                                <span className="font-semibold">Impact:</span> {finding.impact}
                              </p>
                            ) : null}
                            {(finding.recommendation || finding.recommended_fix) ? (
                              <p className="text-[11px] text-slate-600">
                                <span className="font-semibold">Fix:</span> {finding.recommendation || finding.recommended_fix}
                              </p>
                            ) : null}
                            {finding.cve_id ? (
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--brand)] hover:underline"
                              >
                                {finding.cve_id} <ExternalLink className="h-3 w-3" />
                              </a>
                            ) : null}
                          </div>
                        ) : null}
                      </button>
                    ))}
                  </div>
                </div>
              </Panel>
            ) : null}
          </>
        )}
      </div>
    </Page>
  );
}
