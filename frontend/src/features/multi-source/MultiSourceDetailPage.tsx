import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { AlertTriangle, ArrowLeft, ExternalLink, GitBranch, Link2, Loader2, RefreshCw, ShieldCheck, Workflow } from 'lucide-react';

import {
  Button,
  EmptyState,
  Page,
  PageHeader,
  Panel,
  SeverityBadge,
  StatusBadge,
} from '../../components/ui/Primitives';
import {
  apiErrorMessage,
  getMultiSourceStatus,
  getSourceCorrelations,
} from '../../services/api';
import type {
  Finding,
  MultiSourceScanResponse,
  SourceCorrelationGroup,
  SourceCorrelationsResponse,
} from '../../types';
import { formatDateTime } from '../../utils/derived';

const TERMINAL = new Set(['complete', 'error', 'cancelled', 'failed']);

export default function MultiSourceDetailPage() {
  const { scan_id } = useParams<{ scan_id: string }>();
  const scanId = Number(scan_id);
  const [status, setStatus] = useState<MultiSourceScanResponse | null>(null);
  const [correlations, setCorrelations] = useState<SourceCorrelationsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const loadRef = useRef<() => Promise<void>>(async () => {});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [statusResult, correlationResult] = await Promise.allSettled([
        getMultiSourceStatus(scanId),
        getSourceCorrelations(scanId),
      ]);
      if (statusResult.status === 'fulfilled') setStatus(statusResult.value);
      if (correlationResult.status === 'fulfilled') setCorrelations(correlationResult.value);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not load scan details.'));
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => { loadRef.current = load; }, [load]);
  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    if (!status) return;
    if (TERMINAL.has(status.overall_status)) return;
    const interval = setInterval(() => { void loadRef.current(); }, 4000);
    return () => clearInterval(interval);
  }, [status?.overall_status]);

  if (loading && !status) {
    return (
      <Page>
        <Panel>
          <div className="flex items-center justify-center gap-2 p-8 text-xs text-[var(--text-muted)]">
            <Loader2 className="h-4 w-4 animate-spin text-[var(--brand)]" />Loading scan #{scanId}...
          </div>
        </Panel>
      </Page>
    );
  }

  if (!status) {
    return (
      <Page>
        <Panel>
          <EmptyState icon={<GitBranch className="h-6 w-6 text-[var(--text-subtle)]" />} title="Analysis not found" description={`No local code analysis exists with id ${scanId}.`} />
        </Panel>
      </Page>
    );
  }

  const summary = correlations?.summary;
  const groups: SourceCorrelationGroup[] = correlations?.groups ?? [];
  const findings: Finding[] = status.findings ?? [];
  const active = !TERMINAL.has(status.overall_status);

  return (
    <Page>
      <PageHeader
        title={`Scan #${status.scan_id}`}
        description={status.name}
        action={
          <div className="flex items-center gap-2">
            <Link to="/multi-source">
              <Button variant="secondary"><ArrowLeft className="h-3.5 w-3.5" />Local Analysis</Button>
            </Link>
            <Button variant="secondary" onClick={() => { void load(); }}>
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
        }
      />

      <Panel className="mb-4">
        <div className="p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-2.5">
              <span
                className={`flex h-2 w-2 shrink-0 rounded-full ${
                  status.overall_status === 'complete' ? 'bg-green-500' : active ? 'animate-pulse bg-amber-500' : 'bg-red-500'
                }`}
              />
              <span className="truncate font-mono text-xs text-[var(--text-default)]">{status.name}</span>
              <StatusBadge status={status.overall_status} />
              <span className="text-[11px] text-[var(--text-subtle)]">Created {formatDateTime(status.created_at)}</span>
            </div>
            {active ? (
              <div className="flex items-center gap-3">
                <div className="h-1.5 w-40 overflow-hidden rounded-full bg-[var(--surface-tertiary)]">
                  <div
                    className="h-full rounded-full bg-[var(--brand)] transition-all"
                    style={{ width: `${Math.max(3, status.overall_progress)}%` }}
                  />
                </div>
                <span className="text-[11px] font-medium text-[var(--text-muted)]">{status.overall_progress}%</span>
              </div>
            ) : null}
            <div className="flex items-center gap-3 text-xs">
              {status.overall_status === 'complete' ? (
                <>
                  <ShieldCheck className="h-4 w-4 text-green-500" />
                  <span className="font-semibold text-[var(--text-default)]">{status.total_findings} findings</span>
                </>
              ) : null}
              {status.overall_status === 'error' || status.overall_status === 'failed' ? (
                <span className="font-semibold text-[var(--danger)]">Analysis ended</span>
              ) : null}
            </div>
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
        <div className="space-y-4">
          {/* Source results */}
          <Panel>
            <h3 className="mb-3 text-xs font-semibold text-[var(--text-strong)]">Sources</h3>
            <div className="space-y-2">
              {status.sources.map((source) => {
                const sourceStatus = !active && ['queued', 'running', 'pending'].includes(source.status) ? 'failed' : source.status;
                return (
                <div key={`${source.source_type}-${source.source_identifier}`} className="rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3">
                  <div className="flex items-center gap-2">
                    <StatusBadge status={sourceStatus} />
                    <span className="truncate text-xs font-medium text-[var(--text-strong)]">{source.source_identifier}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <span className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] uppercase text-[var(--text-subtle)]">{source.source_type}</span>
                    <span className="text-[10px] text-[var(--text-muted)]">{source.findings_count} findings</span>
                    {source.scan_duration_seconds > 0 ? (
                      <span className="text-[10px] text-[var(--text-muted)]">{source.scan_duration_seconds.toFixed(1)}s</span>
                    ) : null}
                    {Object.entries(source.findings_by_severity).length ? (
                      <span className="ml-auto flex gap-1">
                        {Object.entries(source.findings_by_severity).map(([severity, count]) => (
                          <span key={severity} className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px]">
                            <SeverityBadge severity={severity as never} compact />
                            <span className="ml-1 text-[var(--text-muted)]">{count}</span>
                          </span>
                        ))}
                      </span>
                    ) : null}
                  </div>
                  {source.error_message ? (
                    <p className="mt-1.5 text-[10px] text-[var(--danger)]">{source.error_message}</p>
                  ) : null}
                </div>
                );
              })}
            </div>
          </Panel>

          {/* Findings */}
          {status.overall_status === 'complete' && findings.length === 0 ? (
            <Panel>
              <EmptyState
                icon={<ShieldCheck className="h-5 w-5" />}
                title="No findings"
                description="No secrets, insecure patterns, vulnerable dependencies, or IaC issues were detected in this uploaded codebase."
              />
            </Panel>
          ) : null}

          {findings.length > 0 ? (
            <Panel>
              <div className="p-3">
                <h3 className="px-1 pb-2 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">
                  Findings ({findings.length})
                </h3>
                <div className="space-y-1.5">
                  {findings.map((finding) => (
                    <button
                      key={finding.id}
                      type="button"
                      onClick={() => setExpandedFinding(expandedFinding === finding.id ? null : finding.id)}
                      className="w-full rounded-xl border border-slate-200 bg-white p-3 text-left shadow-sm transition-colors hover:border-slate-300 hover:bg-slate-50"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <SeverityBadge severity={finding.severity} />
                            <span className="text-xs font-semibold text-slate-950">{finding.title}</span>
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-slate-500">
                            <span>{finding.category}</span>
                            {finding.module ? <span className="font-mono">{finding.module}</span> : null}
                            {finding.file_path ? <span className="truncate font-mono">{finding.file_path}{finding.line_number ? `:${finding.line_number}` : ''}</span> : null}
                            {finding.endpoint && !finding.file_path ? <span className="truncate font-mono">{finding.endpoint}</span> : null}
                            {finding.cwe ? <span className="font-mono">{finding.cwe}</span> : null}
                            {finding.cvss_score != null ? <span>CVSS {finding.cvss_score}</span> : null}
                          </div>
                        </div>
                        {(finding.evidence || finding.code_snippet) ? <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-slate-400" /> : null}
                      </div>

                      {expandedFinding === finding.id ? (
                        <div className="mt-3 space-y-2 border-t border-slate-200 pt-3">
                          {(finding.code_snippet || finding.evidence) ? (
                            <pre className="overflow-x-auto rounded-lg bg-slate-50 p-3 font-mono text-[11px] leading-relaxed text-slate-800">
                              {finding.code_snippet || finding.evidence}
                            </pre>
                          ) : null}
                          {finding.impact ? (
                            <p className="text-[11px] text-slate-600">
                              <span className="font-semibold">Impact:</span> {finding.impact}
                            </p>
                          ) : null}
                          {(finding.recommendation || finding.recommended_fix || finding.fix_recommendation) ? (
                            <p className="text-[11px] text-slate-600">
                              <span className="font-semibold">Fix:</span> {finding.recommendation || finding.recommended_fix || finding.fix_recommendation}
                            </p>
                          ) : null}
                          {finding.cve_id ? (
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--brand)] hover:underline"
                              onClick={(event) => event.stopPropagation()}
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

          {/* Correlated finding groups */}
          <Panel>
            <h3 className="mb-3 flex items-center gap-1.5 text-xs font-semibold text-[var(--text-strong)]">
              <Link2 className="h-3.5 w-3.5 text-[var(--brand)]" />Correlated finding groups ({groups.length})
            </h3>
            {groups.length ? (
              <div className="space-y-2">
                {groups.map((group) => (
                  <div key={group.unified_id} className="rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={group.severity as never} />
                      <span className="min-w-0 flex-1 truncate text-xs font-medium text-[var(--text-strong)]">{group.title}</span>
                      <span className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] text-[var(--text-subtle)]">
                        {(group.confidence * 100).toFixed(0)}% confidence
                      </span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <span className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] uppercase text-[var(--brand)]">
                        {group.correlation_type}
                      </span>
                      {group.sources.map((source) => (
                        <span key={source} className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] uppercase text-[var(--text-subtle)]">
                          {source}
                        </span>
                      ))}
                    </div>
                    <div className="mt-2.5 space-y-1.5 border-t border-[var(--border-light)] pt-2">
                      {group.related_findings.map((finding) => (
                        <Link
                          key={finding.id}
                          to={`/findings`}
                          className="flex items-center gap-2 rounded-lg px-2 py-1.5 transition-colors hover:bg-[var(--surface-hover)]"
                        >
                          <SeverityBadge severity={finding.severity} compact />
                          <span className="truncate text-[11px] text-[var(--text-default)]">{finding.title}</span>
                          <span className="ml-auto text-[10px] text-[var(--text-subtle)]">#{finding.id}</span>
                        </Link>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={<Link2 className="h-6 w-6 text-[var(--text-subtle)]" />}
                title="No correlations yet"
                description="Correlations appear when findings are linked across sources."
              />
            )}
          </Panel>
        </div>

        {/* Correlation summary sidebar */}
        <div className="space-y-4">
          {summary ? (
            <Panel>
              <h3 className="mb-3 flex items-center gap-1.5 text-xs font-semibold text-[var(--text-strong)]">
                <Workflow className="h-3.5 w-3.5 text-[var(--brand)]" />Correlation summary
              </h3>
              <div className="grid grid-cols-2 gap-2">
                {[
                  ['Total', summary.total_correlations],
                  ['High confidence', summary.high_confidence],
                  ['Data flow traces', summary.data_flow_traces],
                  ['Vuln chains', summary.vulnerability_chains],
                ].map(([label, value]) => (
                  <div key={String(label)} className="rounded-lg bg-[var(--surface-tertiary)] p-2.5">
                    <div className="text-[9px] font-semibold uppercase text-[var(--text-subtle)]">{label}</div>
                    <div className="mt-0.5 text-sm font-semibold text-[var(--text-strong)]">{value}</div>
                  </div>
                ))}
              </div>
              {Object.entries(summary.by_source_pair).length ? (
                <div className="mt-3">
                  <div className="mb-1.5 text-[9px] font-semibold uppercase text-[var(--text-subtle)]">Source pairs</div>
                  <div className="space-y-1">
                    {Object.entries(summary.by_source_pair).map(([pair, count]) => (
                      <div key={pair} className="flex items-center justify-between text-[10px]">
                        <span className="text-[var(--text-muted)]">{pair}</span>
                        <span className="font-medium text-[var(--text-strong)]">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </Panel>
          ) : null}

          {status.health_score ? (
            <Panel>
              <h3 className="mb-3 flex items-center gap-1.5 text-xs font-semibold text-[var(--text-strong)]">
                <ShieldCheck className="h-3.5 w-3.5 text-[var(--brand)]" />Health Score
              </h3>
              <div className="flex items-center gap-3">
                <div className="flex h-14 w-14 items-center justify-center rounded-xl border-2 text-lg font-bold"
                  style={{ borderColor: status.health_score.color === 'green' ? '#22c55e' : status.health_score.color === 'blue' ? '#3b82f6' : status.health_score.color === 'yellow' ? '#eab308' : status.health_score.color === 'orange' ? '#f97316' : '#ef4444', color: status.health_score.color === 'green' ? '#22c55e' : status.health_score.color === 'blue' ? '#3b82f6' : status.health_score.color === 'yellow' ? '#eab308' : status.health_score.color === 'orange' ? '#f97316' : '#ef4444' }}>
                  {status.health_score.score}
                </div>
                <div>
                  <div className="text-xs font-semibold text-[var(--text-strong)]">{status.health_score.classification}</div>
                  <div className="mt-0.5 text-[10px] leading-relaxed text-[var(--text-muted)]">{status.health_score.executive_summary}</div>
                </div>
              </div>
              <div className="mt-3 space-y-2">
                {status.health_score.categories.map((cat) => (
                  <div key={cat.name}>
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-[var(--text-muted)]">{cat.name}</span>
                      <span className="font-medium text-[var(--text-strong)]">{cat.score}</span>
                    </div>
                    <div className="mt-0.5 h-1 w-full overflow-hidden rounded-full bg-[var(--surface-tertiary)]">
                      <div className="h-full rounded-full bg-[var(--brand)] transition-all" style={{ width: `${cat.score}%` }} />
                    </div>
                  </div>
                ))}
              </div>
              {status.health_score.top_factors.length ? (
                <div className="mt-3 border-t border-[var(--border-light)] pt-2">
                  <div className="mb-1 text-[9px] font-semibold uppercase text-[var(--text-subtle)]">Top factors</div>
                  {status.health_score.top_factors.map((factor, i) => (
                    <div key={i} className="text-[10px] text-[var(--text-muted)]">{factor}</div>
                  ))}
                </div>
              ) : null}
            </Panel>
          ) : null}

          <Panel>
            <h3 className="mb-2 text-xs font-semibold text-[var(--text-strong)]">Next steps</h3>
            <div className="space-y-1.5 text-[11px] leading-relaxed text-[var(--text-muted)]">
              <p>Review findings in the <Link to="/findings" className="text-[var(--brand)] hover:underline">Findings</Link> page.</p>
              <p>Generate a <Link to={`/report/${scanId}`} className="text-[var(--brand)] hover:underline">security report</Link> for this scan.</p>
              <p>Use the <Link to="/findings" className="text-[var(--brand)] hover:underline">AI Tutor</Link> to learn about each finding.</p>
            </div>
          </Panel>
        </div>
      </div>
    </Page>
  );
}
