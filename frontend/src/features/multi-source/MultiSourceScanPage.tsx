import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  FileCode,
  Loader2,
  ShieldAlert,
  Upload,
  X,
} from 'lucide-react';

import {
  Button,
  EmptyState,
  Input,
  Page,
  PageHeader,
  Panel,
  SectionHeader,
  StatusBadge,
} from '../../components/ui/Primitives';
import {
  apiErrorMessage,
  getMultiSourceHistory,
  getMultiSourceStatus,
  startMultiSourceScan,
  stopMultiSourceScan,
  uploadCodebase,
} from '../../services/api';
import type {
  MultiSourceScanHistoryItem,
  MultiSourceScanResponse,
} from '../../types';
import { relativeTime } from '../../utils/derived';
import { clearEnterpriseApproval, getEnterpriseApproval } from '../enterprise/approvalHandoff';
const DEFAULT_SCAN_DURATION_MINUTES = 120;
const MIN_SCAN_DURATION_MINUTES = 5;
const MAX_SCAN_DURATION_MINUTES = 1440;
const SCAN_DEPTHS = {
  quick: { label: 'Quick (15 min)', minutes: 15 },
  standard: { label: 'Standard (30 min)', minutes: 30 },
  full: { label: 'Full (50 min)', minutes: 50 },
  custom: { label: 'Custom', minutes: DEFAULT_SCAN_DURATION_MINUTES },
} as const;

function clampScanDuration(minutes: number) {
  if (!Number.isFinite(minutes)) return DEFAULT_SCAN_DURATION_MINUTES;
  return Math.min(Math.max(minutes, MIN_SCAN_DURATION_MINUTES), MAX_SCAN_DURATION_MINUTES);
}

export default function MultiSourceScanPage() {
  const navigate = useNavigate();
  const [scanName, setScanName] = useState('');
  const [intensity, setIntensity] = useState<'low' | 'medium' | 'high'>('medium');
  const [correlate, setCorrelate] = useState(true);
  const [dataFlow, setDataFlow] = useState(true);
  const [sarif, setSarif] = useState(true);
  const [depth, setDepth] = useState<keyof typeof SCAN_DEPTHS>('standard');
  const [maxDuration, setMaxDuration] = useState<number>(SCAN_DEPTHS.standard.minutes);
  const [submitting, setSubmitting] = useState(false);
  const [history, setHistory] = useState<MultiSourceScanHistoryItem[]>([]);
  const [activeScan, setActiveScan] = useState<MultiSourceScanResponse | null>(null);

  const [localPath, setLocalPath] = useState('');
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [approval, setApproval] = useState(() => getEnterpriseApproval(['code_audit', 'scan']));

  const load = useCallback(async () => {
    try {
      const historyResult = await getMultiSourceHistory();
      setHistory(historyResult);
    } catch {
      // history may be empty on first run
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (approval?.target_url && !localPath) setLocalPath(approval.target_url);
  }, [approval, localPath]);

  const handleZipUpload = useCallback(async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.zip')) {
      toast.error('Please select a .zip file');
      return;
    }
    setUploading(true);
    try {
      const scanDuration = clampScanDuration(depth === 'custom' ? maxDuration : SCAN_DEPTHS[depth].minutes);
      const result = await uploadCodebase(file, scanDuration, approval?.id);
      if (approval) {
        clearEnterpriseApproval();
        setApproval(null);
      }
      sessionStorage.setItem(`multiSourceScanTimeout:${result.scan_id}`, String(scanDuration));
      if (result.status === 'queued') {
        toast.success('Upload accepted — extraction and scan starting');
      } else {
        toast.success('Zip extracted — scan started');
      }
      void navigate(`/multi-source/${result.scan_id}`);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Upload failed'));
    } finally {
      setUploading(false);
    }
  }, [approval, depth, maxDuration, navigate]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) void handleZipUpload(file);
  }, [handleZipUpload]);

  useEffect(() => {
    if (!activeScan) return;
    if (['complete', 'error', 'cancelled'].includes(activeScan.overall_status)) return;

    const storedTimeout = Number(sessionStorage.getItem(`multiSourceScanTimeout:${activeScan.scan_id}`));
    const timeoutMinutes = clampScanDuration(storedTimeout || maxDuration);
    const timeoutMs = timeoutMinutes * 60 * 1000;

    const startedAt = activeScan.started_at ? Date.parse(activeScan.started_at) : null;
    if (!startedAt || Number.isNaN(startedAt)) return;

    const remainingMs = (startedAt + timeoutMs) - Date.now();
    if (remainingMs <= 0) {
      toast.error(`Scan timed out after ${timeoutMinutes} minutes. Please check scan details.`);
      return;
    }

    const timeout = setTimeout(() => {
      toast.error(`Scan timed out after ${timeoutMinutes} minutes. Please check scan details.`);
    }, remainingMs);

    const interval = setInterval(async () => {
      try {
        const status = await getMultiSourceStatus(activeScan.scan_id);
        setActiveScan(status);
        if (['complete', 'error', 'cancelled'].includes(status.overall_status)) {
          await load();
        }
      } catch {
        // poll failure is non-fatal
      }
    }, 4000);

    return () => {
      clearTimeout(timeout);
      clearInterval(interval);
    };
  }, [activeScan?.scan_id, activeScan?.overall_status, activeScan?.started_at, load, maxDuration]);

  const launchLocalPath = async () => {
    const path = localPath.trim();
    if (!path || submitting) {
      toast.error('Enter an absolute server path or upload a ZIP file.');
      return;
    }
    setSubmitting(true);
    try {
      const scanDuration = clampScanDuration(depth === 'custom' ? maxDuration : SCAN_DEPTHS[depth].minutes);
      const result = await startMultiSourceScan({
        name: scanName || `Local Code Analysis: ${path.split(/[/\\]/).filter(Boolean).pop() || path}`,
        mode: 'multi_agent',
        intensity,
        sources: [{ type: 'local', path, exclude_patterns: [], enabled: true, priority: 1 }],
        correlate_findings: correlate,
        data_flow_tracing: dataFlow,
        generate_sarif: sarif,
        generate_pdf: false,
        max_duration_minutes: scanDuration,
        approval_request_id: approval?.id,
      });
      if (approval) {
        clearEnterpriseApproval();
        setApproval(null);
      }
      sessionStorage.setItem(`multiSourceScanTimeout:${result.scan_id}`, String(scanDuration));
      toast.success(`Local Code Analysis #${result.scan_id} started`);
      setActiveScan(result);
      await load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not start local code analysis.'));
    } finally {
      setSubmitting(false);
    }
  };

  const stopActive = async () => {
    if (!activeScan) return;
    try {
      await stopMultiSourceScan(activeScan.scan_id);
      toast.success('Stop requested');
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not stop the scan.'));
    }
  };

  return (
    <Page>
      <PageHeader
        title="Local Code Analysis"
        description="Run SAST, SCA, secrets and IaC checks against uploaded or local codebases."
      />

      {/* Active scan banner */}
      {activeScan && !['complete', 'error', 'cancelled'].includes(activeScan.overall_status) ? (
        <Panel className="mb-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-[var(--brand-soft)]">
              <Loader2 className="h-4 w-4 animate-spin text-[var(--brand)]" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-xs font-semibold text-[var(--text-strong)]">
                Scan #{activeScan.scan_id} · {activeScan.overall_status}
              </div>
              <div className="mt-0.5 text-[10px] text-[var(--text-muted)]">
                This local analysis continues in the background while you use other pages.
              </div>
              <div className="mt-1 h-1.5 w-full max-w-sm overflow-hidden rounded-full bg-[var(--surface-tertiary)]">
                <div className="h-full rounded-full bg-[var(--brand)] transition-all" style={{ width: `${activeScan.overall_progress}%` }} />
              </div>
            </div>
            <div className="text-[11px] text-[var(--text-muted)]">{activeScan.overall_progress}%</div>
            <Button variant="secondary" onClick={() => { void stopActive(); }}>
              <X className="h-3.5 w-3.5" />Stop
            </Button>
          </div>
        </Panel>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* Scan launcher */}
        <div>
          <Panel>
            <div className="p-4">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-sm font-semibold text-[var(--text-strong)]">Analyze Local Code</h2>
                  <p className="mt-1 text-xs text-[var(--text-muted)]">Upload a ZIP to run the same SAST, secrets, dependency, and IaC checks used by GitHub Repo Analysis.</p>
                </div>
                <select
                  value={depth}
                  onChange={(e) => {
                    const next = e.target.value as keyof typeof SCAN_DEPTHS;
                    setDepth(next);
                    if (next !== 'custom') setMaxDuration(SCAN_DEPTHS[next].minutes);
                  }}
                  className="rounded-md border border-[var(--border-light)] bg-white px-3 py-1.5 text-xs text-[var(--text-default)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]"
                >
                  {Object.entries(SCAN_DEPTHS).map(([key, preset]) => (
                    <option key={key} value={key}>{preset.label}</option>
                  ))}
                </select>
              </div>

              {depth === 'custom' ? (
                <div className="mb-3">
                  <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Scan time limit (minutes)</label>
                  <Input
                    value={maxDuration}
                    onChange={(e) => setMaxDuration(clampScanDuration(Number(e.target.value)))}
                    type="number"
                    min={MIN_SCAN_DURATION_MINUTES}
                    max={MAX_SCAN_DURATION_MINUTES}
                  />
                </div>
              ) : null}

              <div className="mb-3">
                <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Scan name (optional)</label>
                <Input value={scanName} onChange={(e) => setScanName(e.target.value)} placeholder="Local security review" />
              </div>

              <div
                onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={handleDrop}
                className={`relative flex min-h-[170px] flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-8 transition-colors ${
                  dragging
                    ? 'border-[var(--brand)] bg-[var(--brand-soft)]/30'
                    : 'border-[var(--border-default)] bg-[var(--surface-secondary)] hover:border-[var(--brand)]/50 hover:bg-white'
                }`}
              >
                <Upload className={`h-6 w-6 ${dragging ? 'text-[var(--brand)]' : 'text-[var(--text-subtle)]'}`} />
                <div className="text-center">
                  <div className="text-sm font-semibold text-[var(--text-strong)]">Drop a ZIP file here</div>
                  <div className="mt-1 text-xs text-[var(--text-muted)]">or click to browse and start analysis</div>
                </div>
                <input
                  type="file"
                  accept=".zip"
                  className="absolute inset-0 cursor-pointer opacity-0"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) void handleZipUpload(f); e.target.value = ''; }}
                  disabled={uploading}
                />
                {uploading ? (
                  <div className="mt-2 flex items-center gap-1.5 rounded-full bg-[var(--brand-soft)] px-3 py-1 text-[11px] font-medium text-[var(--brand)]">
                    <Loader2 className="h-3 w-3 animate-spin" />Uploading and preparing scan...
                  </div>
                ) : null}
              </div>

              <div className="mt-4 rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">Advanced: server path</div>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <Input value={localPath} onChange={(e) => setLocalPath(e.target.value)} placeholder="C:\\work\\my-app or /home/dev/project" />
                  <Button variant="secondary" onClick={() => { void launchLocalPath(); }} disabled={submitting || !localPath.trim()}>
                    {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileCode className="h-3.5 w-3.5" />}
                    Analyze Path
                  </Button>
                </div>
                <p className="mt-2 text-[10px] text-[var(--text-subtle)]">Use this only for paths readable by the backend server. Browser-local files should be uploaded as ZIP.</p>
              </div>
            </div>
          </Panel>

          <div className="mt-4 rounded-lg border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3 text-sm text-[var(--text-muted)]">
            GitHub repositories are handled separately in <strong>GitHub Repo Analysis</strong>.
          </div>
        </div>

        {/* History sidebar */}
        <div>
          <Panel>
            <SectionHeader title="Recent local code analyses" />
            {history.length ? (
              <div className="space-y-2">
                {history.slice(0, 8).map((item) => (
                  <Link
                    key={item.scan_id}
                    to={`/multi-source/${item.scan_id}`}
                    className="block rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3 transition-colors hover:border-[var(--border-default)]"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-xs font-medium text-[var(--text-strong)]">
                        {item.name}
                      </span>
                      <StatusBadge status={item.overall_status} />
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {item.sources.map((source) => (
                        <span key={source} className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] uppercase text-[var(--text-subtle)]">
                          {source}
                        </span>
                      ))}
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[10px] text-[var(--text-subtle)]">
                      <span>{item.total_findings} findings · {item.correlated_findings} correlations</span>
                      <span>{relativeTime(item.created_at)}</span>
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={<ShieldAlert className="h-6 w-6 text-[var(--text-subtle)]" />}
                title="No local code analyses yet"
                description="Upload a ZIP file or add a local path to get started."
              />
            )}
          </Panel>
        </div>
      </div>
    </Page>
  );
}
