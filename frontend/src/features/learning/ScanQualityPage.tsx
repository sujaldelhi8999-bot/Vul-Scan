import { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { BrainCircuit, Check, EyeOff, Loader2, RefreshCw } from 'lucide-react';

import {
  Button,
  EmptyState,
  ErrorState,
  MetricCard,
  Page,
  PageHeader,
  Panel,
  SectionHeader,
  StatusBadge,
  cx,
} from '../../components/ui/Primitives';
import {
  apiErrorMessage,
  applyLearningInsight,
  dismissLearningInsight,
  getLearningInsights,
  getScanQualityReport,
} from '../../services/api';
import type { LearningInsight, ScanQualityReport } from '../../types';

const ACTION_STYLES: Record<string, string> = {
  disable: 'bg-[var(--danger-soft)] text-[var(--danger)] border-[var(--danger)]/40',
  tune: 'bg-[var(--warning-subtle)] text-[var(--warning)] border-[var(--warning)]/40',
  review: 'bg-[var(--info-subtle)] text-[var(--info)] border-[var(--info)]/40',
  keep: 'bg-[var(--success-subtle)] text-[var(--success)] border-[var(--success)]/40',
};

function ActionBadge({ action }: { action: string }) {
  const style = ACTION_STYLES[action] ?? ACTION_STYLES.keep;
  return (
    <span className={cx('rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide', style)}>
      {action}
    </span>
  );
}

function rateBar(rate: number, invert = false) {
  const pct = Math.max(0, Math.min(100, Math.round(rate * 100)));
  const color = invert
    ? pct >= 80 ? 'var(--danger)' : pct >= 50 ? 'var(--warning)' : 'var(--success)'
    : pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
  return (
    <div className="h-1.5 w-full rounded-full bg-[var(--bg-hover)]">
      <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

export default function ScanQualityPage() {
  const [report, setReport] = useState<ScanQualityReport | null>(null);
  const [insights, setInsights] = useState<LearningInsight[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [quality, pending] = await Promise.all([
        getScanQualityReport(),
        getLearningInsights(undefined, 'pending'),
      ]);
      setReport(quality);
      setInsights(pending);
    } catch (err) {
      setError(apiErrorMessage(err, 'Unable to load scan quality report.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleApply = async (insight: LearningInsight) => {
    setActing(insight.id);
    try {
      await applyLearningInsight(insight.id);
      toast.success(`Applied tuning for ${insight.module}`);
      await load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to apply insight.'));
    } finally {
      setActing(null);
    }
  };

  const handleDismiss = async (insight: LearningInsight) => {
    setActing(insight.id);
    try {
      await dismissLearningInsight(insight.id);
      toast.success(`Dismissed ${insight.module} recommendation`);
      await load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to dismiss insight.'));
    } finally {
      setActing(null);
    }
  };

  const total = report?.modules.reduce((sum, m) => sum + m.total_count, 0) ?? 0;
  const totalTp = report?.modules.reduce((sum, m) => sum + m.true_positives, 0) ?? 0;
  const totalFp = report?.modules.reduce((sum, m) => sum + m.false_positives, 0) ?? 0;

  return (
    <Page>
      <PageHeader
        title="Scan Quality Report"
        description="Post-scan learning: true/false positive accuracy per module and tuning recommendations."
        action={
          <Button variant="secondary" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Refresh
          </Button>
        }
      />

      {error ? <ErrorState title="Error" description={error} /> : null}

      {!loading && !error ? (
        <>
          <div className="mb-4 grid gap-3 sm:grid-cols-4">
            <MetricCard label="Rated Findings" value={String(total)} />
            <MetricCard label="True Positives" value={String(totalTp)} accent={totalTp > 0} />
            <MetricCard label="False Positives" value={String(totalFp)} accent={totalFp > 0} />
            <MetricCard
              label="Precision"
              value={`${total > 0 ? Math.round((totalTp / total) * 100) : 0}%`}
              accent={total > 0 && totalTp / total >= 0.5}
            />
          </div>

          {/* Module accuracy */}
          <Panel>
            <div className="p-3">
              <SectionHeader
                title="Module Accuracy"
                description="True/false positive rates per test module across all scans."
              />
              {report && report.modules.length === 0 ? (
                <EmptyState
                  title="No learning data yet"
                  description="Completed pentest scans will generate module insights here."
                  compact
                />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-[var(--border-light)] text-[10px] uppercase tracking-wider text-[var(--text-subtle)]">
                        <th className="px-3 py-2 font-semibold">Module</th>
                        <th className="px-3 py-2 font-semibold text-right">Total</th>
                        <th className="px-3 py-2 font-semibold text-right">TP</th>
                        <th className="px-3 py-2 font-semibold text-right">FP</th>
                        <th className="px-3 py-2 font-semibold">TP Rate</th>
                        <th className="px-3 py-2 font-semibold">FP Rate</th>
                        <th className="px-3 py-2 font-semibold">Recommendation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-light)]">
                      {report?.modules.map((row) => (
                        <tr key={row.module}>
                          <td className="px-3 py-2.5 font-mono text-[var(--text-secondary)]">{row.module}</td>
                          <td className="px-3 py-2.5 text-right text-[var(--text-primary)]">{row.total_count}</td>
                          <td className="px-3 py-2.5 text-right text-[var(--success)]">{row.true_positives}</td>
                          <td className="px-3 py-2.5 text-right text-[var(--danger)]">{row.false_positives}</td>
                          <td className="w-28 px-3 py-2.5">
                            <div className="flex items-center gap-2">
                              <div className="w-16">{rateBar(row.true_positive_rate)}</div>
                              <span className="text-[10px] text-[var(--text-muted)]">
                                {Math.round(row.true_positive_rate * 100)}%
                              </span>
                            </div>
                          </td>
                          <td className="w-28 px-3 py-2.5">
                            <div className="flex items-center gap-2">
                              <div className="w-16">{rateBar(row.false_positive_rate, true)}</div>
                              <span className="text-[10px] text-[var(--text-muted)]">
                                {Math.round(row.false_positive_rate * 100)}%
                              </span>
                            </div>
                          </td>
                          <td className="px-3 py-2.5">
                            <StatusBadge
                              status={
                                row.false_positive_rate >= 0.8
                                  ? 'HIGH FP'
                                  : row.false_positive_rate >= 0.5
                                    ? 'ELEVATED FP'
                                    : row.true_positive_rate === 0 && row.total_count > 0
                                      ? 'NO TP'
                                      : 'HEALTHY'
                              }
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </Panel>

          {/* Pending recommendations */}
          <Panel>
            <div className="p-3">
              <SectionHeader
                title="Learning Recommendations"
                description="Apply or dismiss AI/rule-based tuning suggestions. Applied insights shape future scans."
                action={
                  <span className="flex items-center gap-1.5 text-[11px] text-[var(--text-muted)]">
                    <BrainCircuit className="h-3.5 w-3.5" />
                    {insights.length} pending
                  </span>
                }
              />
              {insights.length === 0 ? (
                <EmptyState
                  title="Nothing pending"
                  description="All recommendations have been reviewed."
                  compact
                />
              ) : (
                <div className="space-y-2">
                  {insights.map((insight) => (
                    <div
                      key={insight.id}
                      className="rounded-xl border border-[var(--border-default)] p-3"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">
                          {insight.module}
                        </span>
                        <ActionBadge action={insight.recommendation_data?.action ?? 'keep'} />
                        <span className="text-[10px] text-[var(--text-muted)]">
                          {insight.total_count} finding{insight.total_count !== 1 ? 's' : ''} · {insight.true_positives} TP ·{' '}
                          {insight.false_positives} FP
                        </span>
                        {insight.scan_id ? (
                          <span className="ml-auto text-[10px] text-[var(--text-muted)]">scan #{insight.scan_id}</span>
                        ) : null}
                      </div>
                      <div className="mt-1.5 text-xs text-[var(--text-secondary)]">
                        {insight.recommendation ?? insight.recommendation_data?.rationale ?? 'No rationale recorded.'}
                      </div>
                      <div className="mt-2 flex gap-2">
                        <Button
                          variant="primary"
                          disabled={acting === insight.id}
                          onClick={() => void handleApply(insight)}
                        >
                          {acting === insight.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
                          Apply
                        </Button>
                        <Button
                          variant="secondary"
                          disabled={acting === insight.id}
                          onClick={() => void handleDismiss(insight)}
                        >
                          <EyeOff className="h-3.5 w-3.5" />
                          Dismiss
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              <div className="mt-3 rounded-md bg-[var(--bg-inset)] px-3 py-2 text-[10px] leading-relaxed text-[var(--text-muted)]">
                Applied tunings are consumed by the Adaptive Scan Planner: disabled modules are skipped,
                high-FP modules are deprioritized, and the request profile adapts to target complexity.
              </div>
            </div>
          </Panel>
        </>
      ) : null}
    </Page>
  );
}
