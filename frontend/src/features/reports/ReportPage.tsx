import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { ChevronDown, ChevronRight, Copy, Download, GitCompareArrows, Printer, RotateCcw, Sparkles } from 'lucide-react';

import {
  Button,
  cx,
  Drawer,
  EmptyState,
  ErrorState,
  MetricCard,
  Page,
  PageHeader,
  RemediationChecklist,
  Section,
  SectionHeader,
  SeverityBadge,
  StatusBadge,
} from '../../components/ui/Primitives';
import { apiErrorMessage, getAIAnalysis, getScan, getScanArtifacts, startScan } from '../../services/api';
import { usePhantomData } from '../../hooks/usePhantomData';
import type { AISecurityAnalystOutput, BrowserSecurityOutput, Finding, ScanArtifactsResponse, ScanResponse } from '../../types';
import { countBySeverity, previousScanForTarget, scanDuration, securityScore, targetName } from '../../utils/derived';

function text(value: unknown, fallback = ''): string {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'string') return value;
  return String(value);
}

function asArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null) : [];
}

function JsonBlock({ value, label }: { value: unknown; label?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <details open={open} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)} className="group">
      <summary className="flex cursor-pointer items-center gap-1.5 text-xs font-medium text-[var(--text-muted)] hover:text-[var(--text-secondary)]">
        {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        {label || 'Technical Details'}
      </summary>
      <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap rounded-md bg-[var(--bg-inset)] p-3 font-mono text-[10px] text-[var(--text-secondary)]">
        {JSON.stringify(value ?? {}, null, 2)}
      </pre>
    </details>
  );
}

function displayValue(value: unknown): string {
  if (Array.isArray(value)) return value.map((item) => text(item)).filter(Boolean).join(', ') || 'None';
  if (value && typeof value === 'object') return JSON.stringify(value);
  return text(value, 'None');
}

function VerificationTrace({ finding }: { finding: Finding }) {
  const [diffOpen, setDiffOpen] = useState(false);
  const copyCommand = async () => {
    if (!finding.reproduction_command) return;
    await navigator.clipboard.writeText(finding.reproduction_command);
    toast.success('curl command copied');
  };
  if (!finding.reproduction_command && !finding.request_response_diff && !finding.request_id && !finding.verification_hash) return null;
  return (
    <div className="rounded-md border border-[var(--border-subtle)] p-2">
      <div className="mb-1 flex flex-wrap items-center gap-1.5 text-[10px] text-[var(--text-muted)]">
        <span className="font-semibold text-[var(--text-secondary)]">Verification Trace</span>
        {finding.confidence_label ? <StatusBadge status={finding.confidence_label} /> : null}
        {typeof finding.confidence_score === 'number' ? <StatusBadge status={`${Math.round(finding.confidence_score * 100)}%`} /> : null}
        {finding.request_id ? <code>request:{finding.request_id}</code> : null}
        {finding.verification_hash ? <code className="break-all">hash:{finding.verification_hash}</code> : null}
      </div>
      {finding.reproduction_command ? (
        <div>
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="text-[10px] font-semibold text-[var(--text-muted)]">curl</span>
            <Button variant="secondary" onClick={copyCommand}><Copy className="h-3.5 w-3.5" /> Copy</Button>
          </div>
          <pre className="max-h-32 overflow-auto whitespace-pre-wrap rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-secondary)]">{finding.reproduction_command}</pre>
        </div>
      ) : null}
      {finding.request_response_diff ? (
        <div className="mt-1">
          <button className="text-[10px] font-semibold text-[var(--accent-hover)]" onClick={() => setDiffOpen((value) => !value)}>
            {diffOpen ? 'Hide' : 'Show'} diff
          </button>
          {diffOpen ? <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-secondary)]">{finding.request_response_diff}</pre> : null}
        </div>
      ) : null}
    </div>
  );
}

/* ── Executive Summary ── */

function ExecutiveSummary({ counts, score, scan }: { counts: Record<string, number>; score: number; scan: ScanResponse }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return (
    <Section>
      <SectionHeader title="Executive Summary" description="Severity breakdown and overall assessment" />
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
        <MetricCard label="Score" value={`${score}/100`} />
        <MetricCard label="Total" value={total} />
        <MetricCard label="Critical" value={counts.CRITICAL} accent={counts.CRITICAL > 0} />
        <MetricCard label="High" value={counts.HIGH} accent={counts.HIGH > 0} />
        <MetricCard label="Medium" value={counts.MEDIUM} />
        <MetricCard label="Low / Info" value={counts.LOW + counts.INFO} />
      </div>
      {counts.CRITICAL > 0 || counts.HIGH > 0 ? (
        <div className="mt-3 rounded-md border border-[var(--warning-subtle)] px-3 py-2 text-xs text-[var(--warning)]">
          {counts.CRITICAL > 0
            ? 'Critical findings require immediate attention.'
            : 'High-severity findings should be prioritized for remediation.'}
        </div>
      ) : total === 0 ? (
        <div className="mt-3 rounded-md border border-[var(--success-subtle)] px-3 py-2 text-xs text-[var(--success)]">
          No unresolved findings detected.
        </div>
      ) : null}
    </Section>
  );
}

/* ── Findings with progressive disclosure ── */

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const hasDetails = finding.description || finding.evidence || finding.recommendation || finding.fix || finding.how_exploited;
  return (
    <div className="rounded-md border border-[var(--border-default)]">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left transition-colors hover:bg-[var(--bg-hover)]"
        aria-expanded={open}
      >
        <SeverityBadge severity={finding.severity} compact />
        <span className="min-w-0 flex-1 text-xs font-medium text-[var(--text-primary)]">{finding.title}</span>
        <span className="text-[10px] text-[var(--text-muted)]">{finding.module || finding.agent || ''}</span>
        {finding.cve_id ? (
          <span className="font-mono text-[10px] text-[var(--accent-hover)]">{finding.cve_id}</span>
        ) : null}
        {open ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" />}
      </button>
      {open && hasDetails ? (
        <div className="border-t border-[var(--border-subtle)] space-y-2.5 px-3 py-2.5">
          {finding.description ? (
            <div>
              <div className="text-[10px] font-semibold text-[var(--text-muted)]">Description</div>
              <p className="mt-0.5 text-xs text-[var(--text-secondary)]">{finding.description}</p>
            </div>
          ) : null}
          {finding.evidence ? (
            <div>
              <div className="text-[10px] font-semibold text-[var(--text-muted)]">Evidence</div>
              <pre className="mt-0.5 whitespace-pre-wrap rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-secondary)]">{finding.evidence}</pre>
            </div>
          ) : null}
          {finding.endpoint ? (
            <div>
              <div className="text-[10px] font-semibold text-[var(--text-muted)]">Endpoint</div>
              <code className="mt-0.5 block break-all font-mono text-xs text-[var(--accent-hover)]">{finding.endpoint}</code>
            </div>
          ) : null}
          <VerificationTrace finding={finding} />
          {finding.recommendation || finding.fix ? (
            <div>
              <div className="text-[10px] font-semibold text-[var(--text-muted)]">Remediation</div>
              <p className="mt-0.5 text-xs text-[var(--text-secondary)]">{finding.recommendation || finding.fix}</p>
              <div className="mt-2">
                <RemediationChecklist
                  items={(finding.recommendation || finding.fix || '')
                    .split(/\n|\.\s+/)
                    .map((item) => item.trim())
                    .filter(Boolean)
                    .slice(0, 5)}
                />
              </div>
            </div>
          ) : null}
          {finding.how_exploited ? (
            <div>
              <div className="text-[10px] font-semibold text-[var(--text-muted)]">Exploitation</div>
              <p className="mt-0.5 text-xs text-[var(--text-secondary)]">{finding.how_exploited}</p>
            </div>
          ) : null}
          <div className="flex flex-wrap gap-2 text-[10px] text-[var(--text-muted)]">
            {finding.confidence ? <StatusBadge status={finding.confidence} /> : null}
            {finding.remediation_status ? <StatusBadge status={finding.remediation_status} /> : null}
            {finding.risk_status && finding.risk_status !== 'ACTIVE' ? <StatusBadge status={finding.risk_status} /> : null}
            <span className="text-[var(--text-disabled)]">{finding.agent}</span>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/* ── Analyst Report ── */

function AnalystReport({ analysis }: { analysis: AISecurityAnalystOutput | null | undefined }) {
  if (!analysis) {
    return (
      <Section>
        <EmptyState title="No analyst artifact" description="Open or refresh the report after completion." />
      </Section>
    );
  }
  const summary = analysis.security_summary ?? {};
  const priorities = analysis.priorities ?? [];
  const executive = Object.entries(analysis.executive_report ?? {});
  const developer = analysis.developer_report ?? [];

  return (
    <Section>
      <SectionHeader
        title="AI Security Analyst"
        description="Evidence-grounded analysis. Cannot start active tests."
      />
      <div className="mb-3 flex flex-wrap gap-1.5">
        <StatusBadge status={analysis.ai_status ?? 'Deterministic analysis'} />
        <StatusBadge status={analysis.safety?.can_start_active_test === false ? 'Active tests disabled' : 'Active tests unavailable'} />
      </div>
      {analysis.ai_narrative ? (
        <div className="mb-4 rounded-md p-3 text-xs leading-relaxed text-[var(--text-primary)]">{analysis.ai_narrative}</div>
      ) : null}
      <div className="grid gap-2 sm:grid-cols-4">
        <div className="rounded-md p-3">
          <div className="flex items-center gap-1.5 text-xs text-[var(--accent-hover)]">
            <Sparkles className="h-3.5 w-3.5" />Posture
          </div>
          <div className="mt-1 text-xs text-[var(--text-primary)]">{displayValue(summary.overall_security_posture)}</div>
        </div>
        <div className="rounded-md p-3">
          <div className="text-xs text-[var(--text-muted)]">Analyst Score</div>
          <div className="mt-1 text-lg font-semibold text-[var(--text-primary)]">{analysis.score_explanation?.score ?? '--'}</div>
        </div>
        <div className="rounded-md p-3 sm:col-span-2">
          <div className="text-xs text-[var(--text-muted)]">Recommended Next Action</div>
          <div className="mt-1 text-xs text-[var(--text-secondary)]">{displayValue(summary.recommended_next_action)}</div>
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <div>
          <h3 className="mb-2 text-xs font-semibold text-[var(--text-primary)]">Top Priorities</h3>
          <div className="space-y-1.5">
            {priorities.length ? (
              priorities.slice(0, 5).map((item) => (
                <div key={`${item.priority}-${item.finding_id}`} className="rounded-md p-3">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <StatusBadge status={`Priority ${item.priority}`} />
                    <StatusBadge status={text(item.severity, 'INFO')} />
                    <span className="text-xs font-medium text-[var(--text-primary)]">{text(item.title)}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-[var(--text-muted)]">{text(item.recommended_action, 'Review and remediate.')}</p>
                </div>
              ))
            ) : (
              <EmptyState title="No priorities" description="Resolved and accepted-risk findings excluded." compact />
            )}
          </div>
        </div>
        <div>
          <h3 className="mb-2 text-xs font-semibold text-[var(--text-primary)]">Executive Report</h3>
          <div className="space-y-1.5">
            {executive.length ? (
              executive.map(([label, value]) => (
                <div key={label} className="rounded-md p-3">
                  <div className="text-[10px] font-semibold text-[var(--text-disabled)]">{label}</div>
                  <div className="mt-0.5 text-xs text-[var(--text-secondary)]">{displayValue(value)}</div>
                </div>
              ))
            ) : (
              <EmptyState title="No report" description="No executive report generated." compact />
            )}
          </div>
        </div>
      </div>

      {developer.length ? (
        <div className="mt-4">
          <h3 className="mb-2 text-xs font-semibold text-[var(--text-primary)]">Developer Analysis</h3>
          <div className="grid gap-2 lg:grid-cols-2">
            {developer.slice(0, 6).map((item) => (
              <div key={String(item.finding_id)} className="rounded-md p-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  <StatusBadge status={`Finding ${text(item.finding_id)}`} />
                  <StatusBadge status={text(item.severity, 'INFO')} />
                </div>
                <div className="mt-1 break-all font-mono text-[10px] text-[var(--text-muted)]">{text(item.affected_endpoint)}</div>
                <p className="mt-1 text-[11px] text-[var(--text-muted)]">{text(item.remediation, 'No remediation text.')}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </Section>
  );
}

/* ── Browser Observability ── */

type ObsTab = 'Overview' | 'Attack Surface' | 'Browser' | 'Network' | 'Console' | 'APIs' | 'Authentication' | 'Storage' | 'WebSockets' | 'Technologies' | 'Findings';
const obsTabs: ObsTab[] = ['Overview', 'Attack Surface', 'Browser', 'Network', 'Console', 'APIs', 'Authentication', 'Storage', 'WebSockets', 'Technologies', 'Findings'];
const networkFilters = ['All', 'API', 'Auth', 'GraphQL', 'WebSocket', 'Scripts', 'Third Party', 'Errors'];

function networkFilterMatch(entry: Record<string, unknown>, filter: string) {
  const classification = text(entry.classification).toUpperCase();
  const status = Number(entry.status ?? 0);
  if (filter === 'All') return true;
  if (filter === 'API') return classification === 'API';
  if (filter === 'Auth') return classification === 'AUTH';
  if (filter === 'GraphQL') return classification === 'GRAPHQL';
  if (filter === 'WebSocket') return classification === 'WEBSOCKET';
  if (filter === 'Scripts') return classification === 'SCRIPT';
  if (filter === 'Third Party') return classification === 'THIRD_PARTY';
  if (filter === 'Errors') return status >= 400;
  return true;
}

function BrowserObservability({ browserOutput }: { browserOutput: BrowserSecurityOutput | null | undefined }) {
  const [tab, setTab] = useState<ObsTab>('Overview');
  const [networkFilter, setNetworkFilter] = useState('All');
  const [selectedNetwork, setSelectedNetwork] = useState<Record<string, unknown> | null>(null);

  if (!browserOutput) {
    return (
      <Section>
        <EmptyState title="No browser data" description="Run a new scan to collect observability data." />
      </Section>
    );
  }

  const pages = asArray(browserOutput.pages);
  const routes = asArray(browserOutput.routes);
  const network = asArray(browserOutput.network_events);
  const consoleEvents = asArray(browserOutput.console_events);
  const apis = asArray(browserOutput.api_inventory);
  const technologies = asArray(browserOutput.third_party);
  const browserFindings = asArray(browserOutput.findings);
  const filteredNetwork = network.filter((entry) => networkFilterMatch(entry, networkFilter));

  return (
    <Section>
      <SectionHeader title="Browser Observability" description="Browser, network, and DOM evidence from the scan." />

      <div className="mb-3 flex flex-wrap gap-1">
        {obsTabs.map((item) => (
          <button
            key={item}
            onClick={() => setTab(item)}
            className={`rounded-md px-2 py-1 text-[11px] font-medium ${
              tab === item ? 'bg-[var(--accent-subtle)] text-[var(--accent-hover)]' : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
            }`}
          >
            {item}
          </button>
        ))}
      </div>

      {tab === 'Overview' && (
        <div className="grid gap-2 sm:grid-cols-4">
          <div className="rounded-md p-3">
            <div className="text-[11px] text-[var(--text-muted)]">Engine</div>
            <div className="mt-1 text-xs text-[var(--text-primary)]">{text(browserOutput.browser_engine, 'unknown')}</div>
          </div>
          <div className="rounded-md p-3">
            <div className="text-[11px] text-[var(--text-muted)]">Pages</div>
            <div className="mt-1 text-lg font-semibold text-[var(--text-primary)]">{pages.length}</div>
          </div>
          <div className="rounded-md p-3">
            <div className="text-[11px] text-[var(--text-muted)]">Network Events</div>
            <div className="mt-1 text-lg font-semibold text-[var(--text-primary)]">{network.length}</div>
          </div>
          <div className="rounded-md p-3">
            <div className="text-[11px] text-[var(--text-muted)]">APIs</div>
            <div className="mt-1 text-lg font-semibold text-[var(--text-primary)]">{apis.length}</div>
          </div>
        </div>
      )}

      {tab === 'Attack Surface' && (
        <div className="grid gap-2 sm:grid-cols-2">
          {routes.map((route, i) => (
            <div key={i} className="rounded-md p-3">
              <div className="break-all font-mono text-xs text-[var(--text-primary)]">{text(route.route)}</div>
              <div className="mt-1 text-[10px] text-[var(--text-muted)]">{text(route.source, 'observed')}</div>
            </div>
          ))}
        </div>
      )}

      {tab === 'Network' && (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-1">
            {networkFilters.map((item) => (
              <button
                key={item}
                onClick={() => setNetworkFilter(item)}
                className={`rounded-md px-2 py-1 text-[11px] ${networkFilter === item ? 'bg-[var(--accent-subtle)] text-[var(--accent-hover)]' : 'text-[var(--text-muted)]'}`}
              >
                {item}
              </button>
            ))}
          </div>
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {filteredNetwork.map((entry, i) => (
              <button
                key={i}
                onClick={() => setSelectedNetwork(entry)}
                className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs transition-colors hover:bg-[var(--bg-hover)]"
              >
                <span className="font-mono text-[var(--text-primary)]">{text(entry.method)}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-[var(--text-muted)]">{text(entry.url)}</span>
                <StatusBadge status={text(entry.classification, 'UNKNOWN')} />
                <span className="shrink-0 text-[var(--text-muted)]">{text(entry.status, '--')}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {tab === 'Console' && (
        <div className="space-y-1">
          {consoleEvents.length ? (
            consoleEvents.map((event, i) => (
              <div key={i} className="flex items-start gap-2 rounded-md px-3 py-2 text-xs">
                <StatusBadge status={text(event.type, 'log')} />
                <span className="min-w-0 flex-1 text-[var(--text-secondary)]">{text(event.message)}</span>
                <span className="shrink-0 text-[var(--text-muted)]">{text(event.source)}</span>
              </div>
            ))
          ) : (
            <EmptyState title="No console events" description="No browser console messages captured." compact />
          )}
        </div>
      )}

      {tab === 'Technologies' && (
        <div className="grid gap-2 sm:grid-cols-2">
          {technologies.map((item, i) => (
            <div key={i} className="rounded-md p-3">
              <div className="font-mono text-xs text-[var(--text-primary)]">{text(item.domain)}</div>
              <div className="mt-1 text-[11px] text-[var(--text-muted)]">{text(item.purpose, 'unknown')}</div>
            </div>
          ))}
        </div>
      )}

      {tab === 'Findings' && (
        <div className="space-y-1.5">
          {browserFindings.length ? (
            browserFindings.map((finding, i) => (
              <div key={i} className="rounded-md p-3">
                <div className="flex items-center gap-1.5">
                  <StatusBadge status={text(finding.severity, 'INFO')} />
                  <StatusBadge status={text(finding.confidence, 'POTENTIAL')} />
                  <span className="text-xs font-medium text-[var(--text-primary)]">{text(finding.title)}</span>
                </div>
              </div>
            ))
          ) : (
            <EmptyState title="No browser findings" description="Browser observation did not produce additional findings." compact />
          )}
        </div>
      )}

      {['Browser', 'APIs', 'Authentication', 'Storage', 'WebSockets'].includes(tab) && (
        <JsonBlock value={browserOutput} label="Raw Browser Data" />
      )}

      <Drawer title="Request Details" open={Boolean(selectedNetwork)} onClose={() => setSelectedNetwork(null)}>
        {selectedNetwork ? <JsonBlock value={selectedNetwork} /> : null}
      </Drawer>
    </Section>
  );
}

/* ── Main Report Page ── */

export default function ReportPage() {
  const { scan_id } = useParams();
  const { scans, findings, refresh } = usePhantomData();
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [artifacts, setArtifacts] = useState<ScanArtifactsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [compareOpen, setCompareOpen] = useState(false);
  const previous = scan ? previousScanForTarget(scans, scan) : undefined;
  const previousFindings = previous ? findings.filter((f) => f.scan_id === previous.id) : [];

  useEffect(() => {
    if (!scan_id) return;
    let active = true;
    let timer: number | undefined;
    const load = async () => {
      try {
        const [nextScan, nextArtifacts] = await Promise.all([getScan(scan_id), getScanArtifacts(scan_id)]);
        let hydrated = nextArtifacts;
        if (!nextArtifacts.ai_analyst_output && nextScan.status === 'complete') {
          try {
            const analysis = await getAIAnalysis(scan_id);
            hydrated = { ...nextArtifacts, ai_analyst_output: analysis };
          } catch { /* ok */ }
        }
        if (!active) return;
        setScan(nextScan);
        setArtifacts(hydrated);
        setError(null);
        // Stop polling once the scan has reached a terminal state
        if (nextScan.status === 'complete' || nextScan.status === 'error' || nextScan.status === 'cancelled') {
          if (timer) window.clearInterval(timer);
        }
      } catch (err) {
        if (active) setError(apiErrorMessage(err, 'Unable to load report.'));
      }
    };
    void load();
    timer = window.setInterval(() => void load(), 6000);
    return () => { active = false; if (timer) window.clearInterval(timer); };
  }, [scan_id]);

  const counts = useMemo(() => countBySeverity(scan?.findings ?? []), [scan]);
  const score = securityScore(scan?.findings ?? []);
  const activeOutput = artifacts?.active_security_output;
  const previousCounts = countBySeverity(previousFindings);
  const previousScore = securityScore(previousFindings);

  const exportJson = useCallback(() => {
    if (!scan) return;
    const blob = new Blob([JSON.stringify({ scan, artifacts }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulscan-report-${scan.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [scan, artifacts]);

  const rescan = useCallback(async () => {
    if (!scan) return;
    try {
      const next = await startScan({ target_url: scan.target_url, mode: 'defend', intensity: scan.intensity });
      toast.success('Rescan started');
      await refresh();
      window.location.href = `/report/${next.scan_id}`;
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to start rescan.'));
    }
  }, [scan, refresh]);

  if (error) {
    return (
      <ErrorState
        title="Unable to load report"
        description={error}
        action={<Button onClick={() => window.location.reload()}>Retry</Button>}
      />
    );
  }

  if (!scan) {
    return <Section><LoadingReport /></Section>;
  }

  return (
    <Page>
      {/* Report Header */}
      <PageHeader
        title="Security Assessment"
        description={`${targetName(scan.target_url)}`}
        action={
          <div className="flex gap-2">
            <Button variant="secondary" onClick={exportJson}>
              <Download className="h-3.5 w-3.5" />Export
            </Button>
            <Button variant="secondary" onClick={() => window.print()} title="Save as PDF via the print dialog">
              <Printer className="h-3.5 w-3.5" />PDF
            </Button>
            <Button variant="secondary" onClick={rescan}>
              <RotateCcw className="h-3.5 w-3.5" />Rescan
            </Button>
            <Button
              variant="secondary"
              onClick={() => setCompareOpen((v) => !v)}
              disabled={!previous}
            >
              <GitCompareArrows className="h-3.5 w-3.5" />Compare
            </Button>
          </div>
        }
      />

      {/* Scan metadata badges */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <StatusBadge status={scan.status} />
        <StatusBadge status={scan.mode === 'pentest' ? 'Authorized Testing' : scan.mode === 'multi_agent' ? 'Multi-Agent' : 'Defend'} />
        <span className="text-[var(--text-muted)]">Scan #{scan.scan_id}</span>
        <span className="text-[var(--text-muted)]">·</span>
        <span className="text-[var(--text-muted)]">{new Date(scan.created_at).toLocaleString()}</span>
        {scan.completed_at ? (
          <>
            <span className="text-[var(--text-muted)]">·</span>
            <span className="text-[var(--text-muted)]">{scanDuration(scan)}</span>
          </>
        ) : null}
      </div>

      {/* Executive Summary */}
      <ExecutiveSummary counts={counts} score={score} scan={scan} />

      {/* Comparison */}
      {compareOpen && previous ? (
        <Section>
          <SectionHeader title="Scan Comparison" description={`Previous scan ${previous.id} vs current ${scan.scan_id}`} />
          <div className="grid gap-2 sm:grid-cols-5">
            {([
              ['Score', String(previousScore), String(score)],
              ['Critical', String(previousCounts.CRITICAL), String(counts.CRITICAL)],
              ['High', String(previousCounts.HIGH), String(counts.HIGH)],
              ['Resolved', String(previousFindings.length), String(Math.max(0, previousFindings.length - scan.findings.length))],
              ['New', '0', String(Math.max(0, scan.findings.length - previousFindings.length))],
            ] as const).map(([label, before, after]) => (
              <div key={label} className="rounded-md p-3">
                <div className="text-xs text-[var(--text-muted)]">{label}</div>
                <div className="mt-1 text-sm font-semibold text-[var(--text-primary)]">{before} → {after}</div>
              </div>
            ))}
          </div>
        </Section>
      ) : null}

      {/* Findings */}
      <Section>
        <SectionHeader title="Findings" description={`${scan.findings.length} total`} />
        {scan.findings.length ? (
          <div className="space-y-1.5">
            {scan.findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        ) : (
          <EmptyState title="No findings" description="The scan did not detect any issues." />
        )}
      </Section>

      {/* Remediation Section */}
      {(() => {
        const actionable = scan.findings.filter(
          (f) => f.recommendation || f.fix
        );
        if (!actionable.length) return null;
        return (
          <Section>
            <SectionHeader title="Remediation Actions" description="Recommended fixes from findings" />
            <div className="space-y-2">
              {actionable.slice(0, 8).map((finding) => (
                <div key={finding.id} className="rounded-md border border-[var(--border-default)] p-3">
                  <div className="flex items-center gap-2 mb-1.5">
                    <SeverityBadge severity={finding.severity} compact />
                    <span className="text-xs font-medium text-[var(--text-primary)]">{finding.title}</span>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] mb-2">{finding.recommendation || finding.fix}</p>
                  <RemediationChecklist
                    items={(finding.recommendation || finding.fix || '')
                      .split(/\n|\.\s+/)
                      .map((item) => item.trim())
                      .filter(Boolean)
                      .slice(0, 5)}
                  />
                </div>
              ))}
            </div>
          </Section>
        );
      })()}

      <AnalystReport analysis={artifacts?.ai_analyst_output} />

      {/* Active security output */}
      {activeOutput ? (
        <Section>
          <SectionHeader title="Active Security Evidence" description="Results from the sandboxed active test." />
          <div className="grid gap-2 sm:grid-cols-4">
            <MetricCard label="Score" value={activeOutput.score?.score ?? '--'} />
            <MetricCard label="Modules" value={activeOutput.test_plan?.modules?.length ?? 0} />
            <MetricCard label="Events" value={activeOutput.events?.length ?? 0} />
            <MetricCard label="Sandbox" value={activeOutput.sandbox_id?.slice(0, 16) ?? 'N/A'} />
          </div>
          {activeOutput.evidence?.length ? (
            <div className="mt-4 space-y-2">
              {activeOutput.evidence.slice(0, 8).map((item, i) => (
                <div key={i} className="rounded-md bg-[var(--bg-inset)] p-3">
                  <div className="text-xs font-medium text-[var(--text-primary)]">{String(item.title ?? `Evidence ${i + 1}`)}</div>
                  <div className="mt-1 break-all font-mono text-[10px] text-[var(--text-muted)]">{String(item.endpoint ?? '')}</div>
                  <p className="mt-1 whitespace-pre-wrap text-[11px] text-[var(--text-secondary)]">{String(item.evidence ?? '')}</p>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No evidence" description="No finding-specific evidence records." compact />
          )}
        </Section>
      ) : null}

      <BrowserObservability browserOutput={artifacts?.browser_security_output} />

      {/* Report artifacts - behind accordion */}
      {artifacts?.markdown_report ? (
        <Section>
          <JsonBlock value={artifacts.markdown_report} label="Markdown Report" />
        </Section>
      ) : null}

      <div className="text-xs text-[var(--text-muted)]">
        <Link to="/history" className="text-[var(--accent-hover)] hover:text-[var(--accent)]">Back to Scan History</Link>
      </div>
    </Page>
  );
}

function LoadingReport() {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[var(--border-default)] px-6 py-8 text-center">
      <div className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--border-default)] border-t-[var(--accent)] mb-3" />
      <h3 className="text-sm font-semibold text-[var(--text-primary)]">Loading report</h3>
      <p className="mt-1 max-w-sm text-xs text-[var(--text-muted)]">Retrieving scan evidence from the backend.</p>
    </div>
  );
}
