import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Database, FileSearch, Loader2, Search as SearchIcon, ShieldCheck, Sparkles } from 'lucide-react';

import { usePhantomData } from '../../hooks/usePhantomData';
import type { AISecurityAnalystOutput, ExploitationResultData, Finding, RiskStatus, Severity } from '../../types';
import {
  Button,
  Drawer,
  EmptyState,
  Input,
  Page,
  PageHeader,
  Panel,
  RemediationChecklist,
  SectionHeader,
  Select,
  SeverityBadge,
  StatusBadge,
} from '../../components/ui/Primitives';
import {
  default as apiClient,
  apiErrorMessage,
  updateFindingRemediation,
  updateFindingRiskStatus,
  verifyFindingFix,
} from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { formatDateTime, relativeTime, severityOrder, targetName } from '../../utils/derived';
import { AITutorChat } from './AITutorChat';

function checklist(finding: Finding) {
  const fix = finding.fix_recommendation || finding.recommended_fix || finding.recommendation || finding.fix || 'Review and remediate this finding.';
  return fix.split(/\n|\.\s+/).map((item) => item.trim().replace(/^[-*\d.)\s]+/, '')).filter(Boolean).slice(0, 6);
}

function text(value: unknown, fallback = 'Not available'): string {
  if (value === null || value === undefined || value === '') return fallback;
  return typeof value === 'string' ? value : String(value);
}

function sameId(value: unknown, id: number): boolean {
  return String(value ?? '') === String(id);
}

function relatedChainsFor(analyst: AISecurityAnalystOutput | null | undefined, id: number) {
  return (analyst?.related_security_chains ?? []).filter((chain) => {
    const primary = chain.primary as Record<string, unknown> | undefined;
    const related = Array.isArray(chain.related) ? (chain.related as Array<Record<string, unknown>>) : [];
    return sameId(primary?.id, id) || related.some((item) => sameId(item.id, id));
  });
}

function remediationPlanFor(analyst: AISecurityAnalystOutput | null | undefined, id: number) {
  return Object.entries(analyst?.remediation_plan ?? {}).flatMap(([bucket, items]) =>
    (items ?? []).filter((item) => sameId(item.finding_id, id)).map((item) => ({ bucket, item })),
  );
}

function FindingDrawer({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const { artifactsByScanId, refresh } = usePhantomData();
  const { user } = useAuth();
  const [action, setAction] = useState<string | null>(null);
  const analyst = finding ? artifactsByScanId[finding.scan_id]?.ai_analyst_output : null;
  const priority = finding ? analyst?.priorities?.find((item) => sameId(item.finding_id, finding.id)) : undefined;
  const developerAnalysis = finding ? analyst?.developer_report?.find((item) => sameId(item.finding_id, finding.id)) : undefined;
  const relatedChains = finding ? relatedChainsFor(analyst, finding.id) : [];
  const planItems = finding ? remediationPlanFor(analyst, finding.id) : [];

  const markInProgress = async () => {
    if (!finding) return;
    setAction('progress');
    try {
      await updateFindingRemediation(finding.id, 'IN_PROGRESS');
      toast.success('Marked in progress');
      await refresh();
    } catch (err) { toast.error(apiErrorMessage(err, 'Unable to update.')); }
    finally { setAction(null); }
  };

  const verifyFixAction = async () => {
    if (!finding) return;
    setAction('verify');
    try {
      const result = await verifyFindingFix(finding.id);
      toast.success(result.status === 'FIX_VERIFIED' ? 'Fix verified' : 'Still present');
      await refresh();
    } catch (err) { toast.error(apiErrorMessage(err, 'Unable to verify.')); }
    finally { setAction(null); }
  };

  const updateRisk = async (riskStatus: RiskStatus) => {
    if (!finding) return;
    setAction(riskStatus);
    try {
      await updateFindingRiskStatus(finding.id, riskStatus);
      toast.success(riskStatus === 'ACTIVE' ? 'Reactivated' : 'Excluded');
      await refresh();
    } catch (err) { toast.error(apiErrorMessage(err, 'Unable to update.')); }
    finally { setAction(null); }
  };

  const requestChange = async () => {
    if (!finding) return;
    const proposedChange = window.prompt(
      'Describe the exact text, configuration, or manual change for approval:',
      finding.fix_recommendation || finding.recommended_fix || finding.recommendation || finding.fix || '',
    );
    if (!proposedChange?.trim()) return;
    setAction('request-change');
    try {
      await apiClient.post('/api/enterprise/request', {
        request_type: 'remediation',
        target_url: finding.target,
        urgency: ['CRITICAL', 'HIGH'].includes(finding.severity) ? 'high' : 'normal',
        details: {
          finding_id: finding.id,
          change_type: finding.file_path ? 'text_update' : 'manual',
          proposed_change: proposedChange.trim(),
          file_path: finding.file_path,
        },
      });
      toast.success('Change submitted for approval');
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to request change.'));
    } finally {
      setAction(null);
    }
  };

  return (
    <Drawer title={finding?.title ?? 'Finding'} open={Boolean(finding)} onClose={onClose}>
      {finding ? (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-1.5">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.remediation_status ?? 'OPEN'} />
            <StatusBadge status={finding.verification_status ?? 'NOT_VERIFIED'} />
            <StatusBadge status={finding.risk_status ?? 'ACTIVE'} />
            <StatusBadge status={finding.confidence} />
          </div>

          {/* Overview */}
          <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5">
            <h3 className="text-xs font-semibold text-[var(--text-strong)] mb-1">Overview</h3>
            <p className="text-xs leading-relaxed text-[var(--text-muted)]">
              {finding.description || finding.evidence || 'No overview persisted.'}
            </p>
          </div>

          {/* Details grid */}
          <div className="grid grid-cols-2 gap-2">
            {[
              ['Asset', targetName(finding.target)],
              ['Endpoint', finding.endpoint || finding.target],
              ['Category', finding.category],
              ['Confidence', finding.confidence],
              ['Module', finding.module || 'N/A'],
              ['Parameter', finding.parameter || 'N/A'],
              ['Detected by', finding.agent],
              ['First detected', formatDateTime(finding.timestamp)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg bg-[var(--surface-secondary)] p-2.5">
                <div className="text-[10px] font-semibold text-[var(--text-subtle)]">{label}</div>
                <div className="mt-1 break-words text-xs text-[var(--text-default)]">{value}</div>
              </div>
            ))}
          </div>

          {/* Source Location */}
          {(finding.file_path || finding.line_number) && (
            <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5">
              <h3 className="text-xs font-semibold text-[var(--text-strong)] mb-1">Source Location</h3>
              <div className="flex flex-wrap gap-3 text-xs text-[var(--text-default)]">
                {finding.file_path && (
                  <span className="font-mono break-all">
                    <span className="text-[var(--text-subtle)]">File:</span> {finding.file_path}
                  </span>
                )}
                {finding.line_number && (
                  <span className="font-mono">
                    <span className="text-[var(--text-subtle)]">Line:</span> {finding.line_number}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Code Snippet */}
          {finding.code_snippet && (
            <div>
              <h3 className="mb-1.5 text-xs font-semibold text-[var(--text-strong)]">Code Snippet</h3>
              <pre className="whitespace-pre-wrap rounded-xl bg-[var(--surface-tertiary)] p-3.5 font-mono text-[11px] text-[var(--text-default)] max-h-48 overflow-y-auto">
                {finding.code_snippet}
              </pre>
            </div>
          )}

          {/* Exploitation Result */}
          {finding.exploited && finding.exploitation_result ? (
            <div className="rounded-xl border border-green-500/30 bg-green-500/10 p-3.5">
              <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-green-600 dark:text-green-400">
                <Database className="h-3.5 w-3.5" /> Exploitation Result
              </h3>
              <div className="space-y-2 text-xs">
                <div className="flex gap-2">
                  <span className="font-medium text-[var(--text-strong)]">Database:</span>
                  <span className="text-[var(--text-default)]">{finding.exploitation_result.database_type || 'Unknown'}</span>
                  <span className="font-medium text-[var(--text-strong)]">Status:</span>
                  <span className={`${finding.exploitation_result.status === 'completed' ? 'text-green-600' : 'text-red-600'}`}>
                    {finding.exploitation_result.status}
                  </span>
                </div>
                {finding.exploitation_result.tables && finding.exploitation_result.tables.length > 0 ? (
                  <div>
                    <span className="font-medium text-[var(--text-strong)]">Tables ({finding.exploitation_result.tables.length}):</span>{' '}
                    <span className="text-[var(--text-default)]">{finding.exploitation_result.tables.join(', ')}</span>
                  </div>
                ) : null}
                {finding.exploitation_result.data?.map((td: ExploitationResultData) => (
                  <div key={td.table} className="rounded-lg bg-[var(--surface-tertiary)] p-2.5">
                    <div className="mb-1 font-medium text-[var(--text-strong)]">📊 {td.table}</div>
                    {td.rows && td.rows.length > 0 ? (
                      <pre className="overflow-auto whitespace-pre-wrap font-mono text-[10px] text-[var(--text-muted)]">
                        {JSON.stringify(td.rows, null, 2)}
                      </pre>
                    ) : (
                      <span className="text-[var(--text-subtle)]">No rows extracted</span>
                    )}
                  </div>
                ))}
                {finding.exploitation_result.error ? (
                  <div className="text-red-500">Error: {finding.exploitation_result.error}</div>
                ) : null}
              </div>
            </div>
          ) : null}

          {/* Evidence */}
          <div>
            <h3 className="mb-1.5 text-xs font-semibold text-[var(--text-strong)]">Evidence</h3>
            <pre className="whitespace-pre-wrap rounded-xl bg-[var(--surface-tertiary)] p-3.5 font-mono text-[11px] text-[var(--text-default)]">
              {finding.evidence || finding.description || 'No evidence persisted.'}
            </pre>
          </div>

          {/* Risk */}
          <div className="rounded-xl border border-[var(--danger-soft)] bg-[var(--danger-soft)]/30 p-3.5">
            <h3 className="text-xs font-semibold text-[var(--danger)] mb-1">Risk / Impact</h3>
            <p className="text-xs leading-relaxed text-[var(--text-default)]">
              {finding.impact || finding.how_exploited || 'Not persisted.'}
            </p>
          </div>

          {/* AI Explanation */}
          <div>
            <h3 className="text-xs font-semibold text-[var(--text-strong)] mb-1.5">AI Explanation</h3>
            <p className="whitespace-pre-wrap text-xs leading-relaxed text-[var(--text-muted)]">
              {finding.how_exploited || finding.impact || 'Not persisted.'}
            </p>
          </div>

          {/* AI Tutor Chat */}
          <div>
            <AITutorChat finding={finding} />
          </div>

          {/* AI Security Analyst */}
          {analyst ? (
            <div>
              <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-[var(--text-strong)]">
                <Sparkles className="h-3.5 w-3.5 text-[var(--brand)]" />AI Security Analyst
              </h3>
              <div className="space-y-2">
                <div className="grid grid-cols-3 gap-2">
                  <div className="rounded-lg bg-[var(--surface-secondary)] p-2.5">
                    <div className="text-[10px] text-[var(--text-muted)]">Priority</div>
                    <div className="mt-0.5 text-sm font-semibold text-[var(--text-strong)]">{priority ? `#${priority.priority}` : '--'}</div>
                  </div>
                  <div className="rounded-lg bg-[var(--surface-secondary)] p-2.5">
                    <div className="text-[10px] text-[var(--text-muted)]">Score</div>
                    <div className="mt-0.5 text-sm font-semibold text-[var(--text-strong)]">{priority?.score ?? '--'}</div>
                  </div>
                  <div className="rounded-lg bg-[var(--surface-secondary)] p-2.5">
                    <div className="text-[10px] text-[var(--text-muted)]">Active Tests</div>
                    <div className="mt-0.5 text-xs text-[var(--text-default)]">{analyst.safety?.can_start_active_test === false ? 'Disabled' : 'N/A'}</div>
                  </div>
                </div>
                {priority?.factors?.length ? (
                  <div className="flex flex-wrap gap-1">
                    {priority.factors.map((factor) => (<StatusBadge key={factor} status={factor} />))}
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}

          {/* Remediation */}
          <div className="rounded-xl border border-[var(--brand-soft)] bg-[var(--brand-soft)]/30 p-3.5">
            <h3 className="text-xs font-semibold text-[var(--brand)] mb-1.5">Recommended Fix</h3>
            <RemediationChecklist items={checklist(finding)} />
          </div>

          {/* Verification */}
          <div>
            <h3 className="mb-1 text-xs font-semibold text-[var(--text-strong)]">Verification</h3>
            <p className="text-xs text-[var(--text-muted)]">{finding.verification || 'Rerun the relevant check after remediation.'}</p>
          </div>

          {/* Actions */}
          <div>
            <h3 className="mb-2 text-xs font-semibold text-[var(--text-strong)]">Actions</h3>
            <div className="grid grid-cols-2 gap-2">
              <Button onClick={markInProgress} disabled={action === 'progress' || finding.remediation_status === 'RESOLVED'}>
                {action === 'progress' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}In Progress
              </Button>
              <Button variant="amber" onClick={verifyFixAction} disabled={action === 'verify'}>
                {action === 'verify' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}Verify Fix
              </Button>
            </div>
            {user?.enterpriseId ? (
              <Button className="mt-2 w-full" variant="primary" onClick={requestChange} disabled={action === 'request-change'}>
                {action === 'request-change' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                Request Change Approval
              </Button>
            ) : null}
            <div className="mt-2 grid grid-cols-3 gap-2">
              <Button variant="secondary" onClick={() => updateRisk('ACTIVE')} disabled={action === 'ACTIVE' || (finding.risk_status ?? 'ACTIVE') === 'ACTIVE'}>Active</Button>
              <Button variant="secondary" onClick={() => updateRisk('FALSE_POSITIVE')} disabled={action === 'FALSE_POSITIVE' || finding.risk_status === 'FALSE_POSITIVE'}>FP</Button>
              <Button variant="secondary" onClick={() => updateRisk('ACCEPTED_RISK')} disabled={action === 'ACCEPTED_RISK' || finding.risk_status === 'ACCEPTED_RISK'}>Accept</Button>
            </div>
          </div>

          <div className="rounded-xl bg-[var(--surface-secondary)] p-3 text-xs text-[var(--text-muted)]">
            Detected {formatDateTime(finding.timestamp)} by {finding.agent}.
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

export default function FindingsPage() {
  const { findings } = usePhantomData();
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL');
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('All');
  const [selected, setSelected] = useState<Finding | null>(null);
  const categories = useMemo(() => ['All', ...Array.from(new Set(findings.map((f) => f.category))).sort()], [findings]);

  const filtered = findings.filter((finding) => {
    const ms = severity === 'ALL' || finding.severity === severity;
    const mc = category === 'All' || finding.category === category;
    const haystack = `${finding.title} ${finding.target} ${finding.endpoint} ${finding.category} ${finding.agent} ${finding.cve_id ?? ''}`.toLowerCase();
    return ms && mc && haystack.includes(query.toLowerCase());
  });

  return (
    <Page>
      <PageHeader
        title="Findings"
        description={`${findings.length} total findings across all scans`}
        action={
          <div className="relative w-56">
            <SearchIcon className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-subtle)]" />
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search findings..." className="pl-8" />
          </div>
        }
      />

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex gap-1">
          {['ALL', ...severityOrder].map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s as Severity | 'ALL')}
              className={`rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors ${
                severity === s ? 'bg-[var(--brand-soft)] text-[var(--brand)]' : 'text-[var(--text-muted)] hover:bg-[var(--surface-hover)]'
              }`}
            >
              {s === 'ALL' ? 'All' : s}
            </button>
          ))}
        </div>
        <Select value={category} onChange={(e) => setCategory(e.target.value)} className="w-36">
          {categories.map((c) => <option key={c}>{c}</option>)}
        </Select>
      </div>

      {/* Findings table */}
      <Panel>
        {filtered.length ? (
          <>
            {/* Desktop table */}
            <div className="hidden md:block">
              <div
                className="grid gap-3 border-b border-[var(--border-light)] bg-[var(--surface-secondary)] px-4 py-2.5 text-[11px] font-semibold text-[var(--text-muted)] tracking-wide"
                style={{ gridTemplateColumns: '80px 1.5fr 1fr 120px 85px 100px' }}
              >
                <span>Severity</span><span>Finding</span><span>Asset</span><span>Category</span><span>Status</span><span>Detected</span>
              </div>
              <div className="divide-y divide-[var(--border-light)]">
                {filtered.map((finding) => (
                  <button
                    key={finding.id}
                    onClick={() => setSelected(finding)}
                    className="grid w-full gap-3 px-4 py-2.5 text-left transition-colors hover:bg-[var(--surface-hover)]"
                    style={{ gridTemplateColumns: '80px 1.5fr 1fr 120px 85px 100px' }}
                  >
                    <SeverityBadge severity={finding.severity} compact />
                    <span className="truncate text-xs font-medium text-[var(--text-strong)]">{finding.title}</span>
                    <span className="truncate text-xs text-[var(--text-muted)]">{targetName(finding.target)}</span>
                    <span className="truncate text-xs text-[var(--text-muted)]">{finding.category}</span>
                    <StatusBadge status={finding.remediation_status ?? 'OPEN'} />
                    <span className="text-xs text-[var(--text-muted)]">{relativeTime(finding.timestamp)}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Mobile cards */}
            <div className="space-y-2 p-4 md:hidden">
              {filtered.map((finding) => (
                <button key={finding.id} onClick={() => setSelected(finding)} className="w-full rounded-xl border border-[var(--border-light)] p-3.5 text-left">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <SeverityBadge severity={finding.severity} compact />
                    <StatusBadge status={finding.remediation_status ?? 'OPEN'} />
                  </div>
                  <div className="text-xs font-medium text-[var(--text-strong)]">{finding.title}</div>
                  <div className="mt-1 text-[11px] text-[var(--text-muted)]">{targetName(finding.target)}</div>
                  <div className="mt-1 text-[10px] text-[var(--text-subtle)]">{relativeTime(finding.timestamp)}</div>
                </button>
              ))}
            </div>
          </>
        ) : (
          <div className="p-5">
            <EmptyState
              icon={<FileSearch className="h-6 w-6 text-[var(--text-subtle)]" />}
              title="No findings"
              description={findings.length ? 'No findings match the current filters.' : 'Your scans found no issues.'}
            />
          </div>
        )}
      </Panel>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </Page>
  );
}
