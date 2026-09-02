import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Check, Loader2, RotateCcw, ShieldCheck, Square } from 'lucide-react';

import { usePhantomData } from '../../hooks/usePhantomData';
import { useScanTelemetry } from '../../hooks/useScanTelemetry';
import { apiErrorMessage, startScan, stopScan } from '../../services/api';
import type { ScanDepth, ScanIntensity, ScanMode, ScanResponse } from '../../types';
import { DEFEND_CHECKS } from '../../types';
import {
  ActivityTimeline,
  Button,
  EmptyState,
  ErrorState,
  Input,
  Page,
  PageHeader,
  Panel,
  ProgressBar,
  SectionHeader,
  Select,
  SeverityBadge,
  StatusBadge,
} from '../../components/ui/Primitives';
import { countBySeverity, targetName } from '../../utils/derived';
import { Link } from 'react-router-dom';
import { clearEnterpriseApproval, getEnterpriseApproval } from '../enterprise/approvalHandoff';

const profiles: Array<{ id: ScanIntensity; label: string; description: string }> = [
  { id: 'low', label: 'Quick', description: 'Baseline checks' },
  { id: 'medium', label: 'Standard', description: 'Balanced assessment' },
  { id: 'high', label: 'Deep', description: 'Full passive analysis' },
];

const scanDepths: Array<{ id: ScanDepth; label: string; description: string }> = [
  { id: 'quick', label: 'Quick', description: 'Essential checks under 60s' },
  { id: 'standard', label: 'Standard', description: 'All core checks' },
  { id: 'deep', label: 'Deep', description: 'Full path enumeration' },
  { id: 'stealth', label: 'Stealth', description: 'Browser-like headers and pacing' },
];

function confidencePercent(finding: ScanResponse['findings'][number]): number {
  if (typeof finding.confidence_percent === 'number') return Math.max(0, Math.min(100, Math.round(finding.confidence_percent)));
  if (typeof finding.confidence_score === 'number') return Math.max(0, Math.min(100, Math.round(finding.confidence_score * 100)));
  const fallback: Record<string, number> = { CONFIRMED: 100, HIGH: 85, MEDIUM: 65, LOW: 40, POTENTIAL: 25 };
  return fallback[finding.confidence] ?? 0;
}

function isVerified(finding: ScanResponse['findings'][number]): boolean {
  if (typeof finding.verified === 'boolean') return finding.verified;
  return finding.confidence === 'CONFIRMED' || finding.verification_status === 'ISSUE_STILL_PRESENT';
}

function findingLocation(finding: ScanResponse['findings'][number]): string | null {
  const location = finding.file_path || finding.endpoint;
  if (!location) return null;
  return finding.file_path && finding.line_number ? `${finding.file_path}:${finding.line_number}` : location;
}

export default function LiveScanPage() {
  const navigate = useNavigate();
  const { refresh, scans, executionStatus, executionActive } = usePhantomData();
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState<ScanIntensity>('medium');
  const [scanDepth, setScanDepth] = useState<ScanDepth>('quick');
  const [confidenceProfile, setConfidenceProfile] = useState<'strict' | 'balanced' | 'aggressive'>('balanced');
  const [mode, setMode] = useState<ScanMode>('defend');
  const [enableExploitation, setEnableExploitation] = useState(false);
  const [enableAIExploitation, setEnableAIExploitation] = useState(false);
  const [activeScan, setActiveScan] = useState<ScanResponse | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approval, setApproval] = useState(() => getEnterpriseApproval(['scan', 'code_audit']));
  const telemetry = useScanTelemetry(activeScan?.scan_id ?? null);
  const displayFindings = telemetry.findings.length ? telemetry.findings : activeScan?.findings ?? [];
  const counts = countBySeverity(displayFindings);
  const currentStatus = telemetry.scanStatus ?? activeScan?.status;
  const displayProgress = telemetry.progress ?? activeScan?.progress ?? 0;
  const displayRequestCount = telemetry.requestCount ?? activeScan?.request_count ?? 0;
  const terminal = currentStatus
    ? ['complete', 'error', 'cancelled'].includes(currentStatus)
    : false;

  useEffect(() => {
    const stored = localStorage.getItem('vulscan:active-defend-scan');
    if (stored) {
      try {
        const parsed = JSON.parse(stored) as ScanResponse;
        setActiveScan(parsed);
        if (parsed.target_url) setTarget(parsed.target_url);
        if (parsed.mode) setMode(parsed.mode);
      }
      catch { localStorage.removeItem('vulscan:active-defend-scan'); }
    }
  }, []);

  useEffect(() => {
    if (approval?.target_url && !target) setTarget(approval.target_url);
  }, [approval, target]);

  useEffect(() => {
    if (activeScan) localStorage.setItem('vulscan:active-defend-scan', JSON.stringify(activeScan));
  }, [activeScan]);

  useEffect(() => {
    if (telemetry.scanStatus && activeScan && activeScan.status !== telemetry.scanStatus) {
      setActiveScan((prev) => (prev ? { ...prev, status: telemetry.scanStatus! } : null));
    }
  }, [telemetry.scanStatus]);

  const latestDefend = useMemo(() => scans.find((s) => s.mode === 'defend'), [scans]);

  const runScan = async () => {
    setError(null);
    setSubmitting(true);
    let formattedTarget = target.trim();
    if (formattedTarget && !formattedTarget.includes('://')) {
      const host = formattedTarget.split('/')[0].split(':')[0].toLowerCase();
      if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0' || host.startsWith('192.168.') || host.startsWith('10.')) {
        formattedTarget = `http://${formattedTarget}`;
      } else {
        formattedTarget = `https://${formattedTarget}`;
      }
      setTarget(formattedTarget);
    }
    try {
      const scan = await startScan({
        target_url: formattedTarget,
        mode,
        scan_depth: scanDepth,
        profile: scanDepth,
        intensity: profile,
        confidence_profile: confidenceProfile,
        enable_exploitation: mode === 'pentest' ? enableExploitation : undefined,
        enable_ai_exploitation: mode === 'pentest' ? enableAIExploitation : undefined,
        selected_tests:
          mode === 'pentest'
            ? ['injection', 'xss', 'access_control', 'csrf', 'path_handling', 'security_headers']
            : undefined,
        authorization_confirmed: mode === 'pentest' ? true : undefined,
        approval_request_id: approval?.id,
      });
      if (approval) {
        clearEnterpriseApproval();
        setApproval(null);
      }
      setActiveScan(scan);
      toast.success('Scan started');
      await refresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'VulScan could not start this assessment.'));
      toast.error('Unable to start scan');
    } finally { setSubmitting(false); }
  };

  const stopActiveScan = async () => {
    if (!activeScan) return;
    try {
      await stopScan(activeScan.scan_id);
      toast.success('Cancellation requested');
      await refresh();
    } catch (err) { toast.error(apiErrorMessage(err, 'Unable to cancel scan.')); }
  };

  const resetScan = () => {
    setActiveScan(null);
    localStorage.removeItem('vulscan:active-defend-scan');
  };

  return (
    <Page>
      <PageHeader
        title={mode === 'pentest' ? 'Pentest Scan' : 'Defend Scan'}
        description={activeScan ? `Scanning ${targetName(activeScan.target_url)}. This task continues in the background while you use other pages.` : mode === 'pentest' ? 'Run active assessments with optional exploit verification against targets.' : 'Run passive security assessments against targets.'}
        action={
          activeScan ? (
            <div className="flex gap-2">
              {!terminal ? (
                <Button variant="danger" onClick={stopActiveScan}>
                  <Square className="h-3.5 w-3.5" />Cancel
                </Button>
              ) : (
                <Button variant="secondary" onClick={() => navigate(`/report/${activeScan.scan_id}`)}>
                  Open Report
                </Button>
              )}
              <Button variant="secondary" onClick={resetScan}>
                <RotateCcw className="h-3.5 w-3.5" />New Target
              </Button>
            </div>
          ) : null
        }
      />

      {/* Two-column layout: config left, activity right */}
      <div className="grid gap-5 lg:grid-cols-[360px_1fr]">
        {/* Left column - Configuration */}
        <div className="space-y-4">
          <Panel>
            <SectionHeader title="Target" description="Configure scan parameters below." />
            <div className="p-4 space-y-3.5">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">Target URL</label>
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com"
                  className="font-mono"
                  disabled={Boolean(activeScan && !terminal)}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">Scan Profile</label>
                <div className="grid gap-2">
                  {profiles.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => setProfile(item.id)}
                      disabled={Boolean(activeScan && !terminal)}
                      className={`rounded-lg border p-3 text-left text-xs transition-colors ${
                        profile === item.id
                          ? 'border-[var(--brand)] bg-[var(--brand-soft)]'
                          : 'border-[var(--border-light)] hover:bg-[var(--surface-hover)]'
                      }`}
                    >
                      <div className="font-semibold text-[var(--text-strong)]">{item.label}</div>
                      <div className="mt-0.5 text-[var(--text-muted)]">{item.description}</div>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">Assessment Mode</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setMode('defend');
                      setEnableExploitation(false);
                      setEnableAIExploitation(false);
                    }}
                    disabled={Boolean(activeScan && !terminal)}
                    className={`rounded-lg border p-2.5 text-left text-xs transition-colors ${
                      mode === 'defend'
                        ? 'border-[var(--brand)] bg-[var(--brand-soft)]'
                        : 'border-[var(--border-light)] hover:bg-[var(--surface-hover)]'
                    }`}
                  >
                    <div className="font-semibold text-[var(--text-strong)]">Defend</div>
                    <div className="mt-0.5 text-[10px] text-[var(--text-muted)]">Passive detection only</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setMode('pentest')}
                    disabled={Boolean(activeScan && !terminal)}
                    className={`rounded-lg border p-2.5 text-left text-xs transition-colors ${
                      mode === 'pentest'
                        ? 'border-[var(--brand)] bg-[var(--brand-soft)]'
                        : 'border-[var(--border-light)] hover:bg-[var(--surface-hover)]'
                    }`}
                  >
                    <div className="font-semibold text-[var(--text-strong)]">Pentest</div>
                    <div className="mt-0.5 text-[10px] text-[var(--text-muted)]">Active + exploit verification</div>
                  </button>
                </div>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">Enumeration Depth</label>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {scanDepths.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setScanDepth(item.id)}
                      disabled={Boolean(activeScan && !terminal)}
                      className={`rounded-lg border p-2.5 text-left text-xs transition-colors ${
                        scanDepth === item.id
                          ? 'border-[var(--brand)] bg-[var(--brand-soft)]'
                          : 'border-[var(--border-light)] hover:bg-[var(--surface-hover)]'
                      }`}
                    >
                      <div className="font-semibold text-[var(--text-strong)]">{item.label}</div>
                      <div className="mt-0.5 text-[10px] text-[var(--text-muted)]">{item.description}</div>
                    </button>
                  ))}
                </div>
                <p className="mt-1 text-[10px] text-[var(--text-subtle)]">
                  Quick keeps routine scans fast. Standard runs all core checks. Deep adds specialised checks. Stealth adds browser-like request shaping when enabled on the backend.
                </p>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">Confidence Sensitivity</label>
                <Select
                  value={confidenceProfile}
                  onChange={(event) => setConfidenceProfile(event.target.value as 'strict' | 'balanced' | 'aggressive')}
                  disabled={Boolean(activeScan && !terminal)}
                >
                  <option value="strict">Strict - fewer findings, highest proof</option>
                  <option value="balanced">Balanced - default precision</option>
                  <option value="aggressive">Aggressive - include weaker signals</option>
                </Select>
                <p className="mt-1 text-[10px] text-[var(--text-subtle)]">Controls how verifier scores become HIGH/MEDIUM/LOW labels for this scan.</p>
              </div>
              <div
                className={`rounded-lg border p-3 space-y-2.5 transition-opacity ${
                  mode === 'pentest'
                    ? 'border-amber-500/30 bg-amber-500/10'
                    : 'border-amber-500/30 bg-amber-500/10 opacity-70'
                }`}
              >
                <label className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    id="enable_exploitation"
                    checked={enableExploitation}
                    onChange={(e) => {
                      setEnableExploitation(e.target.checked);
                      if (!e.target.checked) setEnableAIExploitation(false);
                    }}
                    disabled={Boolean(activeScan && !terminal) || mode !== 'pentest'}
                    className="h-4 w-4 rounded border-[var(--border-default)] text-amber-600 focus:ring-amber-500 disabled:cursor-not-allowed"
                  />
                  <span className="text-xs font-semibold text-amber-400">⚡ Enable Exploitation</span>
                </label>
                {mode === 'pentest' && enableExploitation ? (
                  <label className="flex items-center gap-2.5">
                    <input
                      type="checkbox"
                      id="enable_ai_exploitation"
                      checked={enableAIExploitation}
                      onChange={(e) => setEnableAIExploitation(e.target.checked)}
                      disabled={Boolean(activeScan && !terminal)}
                      className="h-4 w-4 rounded border-[var(--border-default)] text-amber-600 focus:ring-amber-500 disabled:cursor-not-allowed"
                    />
                    <span className="text-xs font-medium text-amber-300/90">Enable AI Exploitation</span>
                  </label>
                ) : null}
                {mode !== 'pentest' ? (
                  <p className="text-[10px] text-amber-300/70">
                    ⚠️ Exploitation is only available in Pentest mode.
                  </p>
                ) : (
                  <p className="text-[10px] text-amber-300/70">
                    Runs exploit verification against critical and high-severity findings. Lab targets recommended.
                  </p>
                )}
              </div>
              <Button
                variant="primary"
                onClick={runScan}
                disabled={submitting || !target.trim() || Boolean(activeScan && !terminal)}
                className="w-full"
              >
                {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                Start Security Scan
              </Button>
              {error ? <ErrorState title="Unable to start scan" description={error} /> : null}
            </div>
          </Panel>

          <Panel>
            <SectionHeader title="Included Checks" description="Passive modules only" />
            <div className="p-4 space-y-1">
              {DEFEND_CHECKS.map((check) => (
                <div key={check} className="flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-[11px] text-[var(--text-muted)] hover:bg-[var(--surface-hover)]">
                  <Check className="h-3 w-3 shrink-0 text-[var(--brand)]" />
                  {check}
                </div>
              ))}
            </div>
          </Panel>

          {latestDefend ? (
            <Panel>
              <div className="p-3.5 text-xs text-[var(--text-muted)]">
                <span className="font-medium text-[var(--text-default)]">Latest scan:</span>{' '}
                {targetName(latestDefend.target_url)} <StatusBadge status={latestDefend.status} />
              </div>
            </Panel>
          ) : null}
        </div>

        {/* Right column - Activity */}
        <div className="space-y-4">
          {executionActive && executionStatus?.execution_type === 'AUTHORIZED_TEST' ? (
            <Panel>
              <div className="flex items-center gap-3 p-3.5">
                <StatusBadge status="RUNNING" />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-semibold text-[var(--warning)]">Authorized Test Active</div>
                  <div className="text-[11px] text-[var(--text-muted)]">
                    {executionStatus.target_url ? targetName(executionStatus.target_url) : ''}
                  </div>
                </div>
                <ProgressBar value={executionStatus.progress_percent} className="hidden w-20 sm:block" />
                <Link to="/authorized-testing" className="text-xs font-semibold text-[var(--warning)]">
                  Open
                </Link>
              </div>
            </Panel>
          ) : null}

          {activeScan ? (
            <>
              <Panel>
                <SectionHeader
                  title="Execution Status"
                  action={<StatusBadge status={telemetry.scanStatus ?? activeScan.status} />}
                />
                <div className="p-4 space-y-3">
                  <div>
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <span className="text-[var(--text-muted)]">Progress</span>
                      <span className="font-medium text-[var(--text-strong)]">{displayProgress}%</span>
                    </div>
                    <ProgressBar value={displayProgress} />
                  </div>
                  <div className="flex gap-4 text-[11px] text-[var(--text-muted)]">
                    <span>{displayRequestCount} requests</span>
                    <span>{telemetry.connectionState}</span>
                    <span>{displayFindings.length} findings</span>
                  </div>
                  {telemetry.error ? <ErrorState title="Connection issue" description={telemetry.error} /> : null}
                </div>
              </Panel>

              <Panel>
                <SectionHeader title="Activity Timeline" />
                <div className="p-3">
                  <ActivityTimeline events={telemetry.events} />
                </div>
              </Panel>

              <Panel>
                <SectionHeader title="Findings" description={`${displayFindings.length} total`} />
                <div className="p-4">
                  {displayFindings.length ? (
                    <div className="space-y-2">
                      {displayFindings.slice(-12).reverse().map((finding) => (
                        <div key={finding.id} className="rounded-lg border border-[var(--border-light)] px-3 py-2.5 transition-colors hover:bg-[var(--surface-hover)]">
                          <div className="flex items-start gap-3">
                            <SeverityBadge severity={finding.severity} compact />
                            <div className="min-w-0 flex-1">
                              <div className="truncate text-xs font-semibold text-[var(--text-strong)]">{finding.title}</div>
                              <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-[var(--text-muted)]">
                                <span>{finding.category}</span>
                                {finding.agent ? <span>{finding.agent}</span> : null}
                                {findingLocation(finding) ? <span className="max-w-full truncate font-mono">{findingLocation(finding)}</span> : null}
                              </div>
                            </div>
                            <StatusBadge status={isVerified(finding) ? 'Verified' : finding.verification_status || 'Open'} />
                          </div>
                          <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] text-[var(--text-muted)]">
                            <span className="rounded bg-[var(--surface-secondary)] px-1.5 py-0.5">Confidence {confidencePercent(finding)}%</span>
                            {finding.confidence_label ? <span>{finding.confidence_label}</span> : <span>{finding.confidence}</span>}
                            {finding.request_id ? <span className="font-mono">request {finding.request_id}</span> : null}
                          </div>
                          {finding.code_snippet ? (
                            <pre className="mt-2 max-h-24 overflow-auto rounded bg-[var(--surface-secondary)] p-2 text-[10px] text-[var(--text-muted)]">
                              {finding.code_snippet}
                            </pre>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="No findings" description="Scan results will appear here." compact />
                  )}
                </div>
              </Panel>
            </>
          ) : (
            <div className="space-y-4">
              <Panel>
                <div className="p-6">
                  <EmptyState
                    title="No active scan"
                    description="Configure a target and scan profile on the left, then start the assessment."
                    action={!target.trim() ? null : <Button variant="primary" onClick={runScan} disabled={submitting}>Start Scan</Button>}
                  />
                </div>
              </Panel>
            </div>
          )}
        </div>
      </div>
    </Page>
  );
}
