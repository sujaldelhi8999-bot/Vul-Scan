import { EmptyState, MetricCard, Page, PageHeader, Panel, SectionHeader, StatusBadge } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { countBySeverity, formatDateTime, securityScore } from '../../utils/derived';

const categories = ['API', 'Dependencies', 'Secrets', 'Docker', 'Authentication', 'Database', 'Headers', 'TLS', 'Configuration'];

export default function SelfAuditPage() {
  const { selfAudit, findings } = usePhantomData();
  const auditFindings = selfAudit?.scan_id ? findings.filter((f) => f.scan_id === selfAudit.scan_id) : [];
  const counts = countBySeverity(auditFindings);
  const score = securityScore(auditFindings);

  return (
    <Page>
      <PageHeader title="Self Audit" description="VulScan continuously evaluates its own security posture." />

      {selfAudit && selfAudit.status !== 'never_run' ? (
        <>
          {/* Status bar */}
          <Panel>
            <div className="p-4 flex flex-wrap items-center gap-3 text-xs">
              <StatusBadge status={selfAudit.status} />
              <span className="text-[var(--text-muted)]">Scan #{selfAudit.scan_id}</span>
              {selfAudit.completed_at ? (
                <>
                  <span className="text-[var(--text-muted)]">|</span>
                  <span className="text-[var(--text-muted)]">Completed {formatDateTime(selfAudit.completed_at)}</span>
                </>
              ) : null}
              <span className="text-[var(--text-muted)]">|</span>
              <span className="text-[var(--text-muted)]">{auditFindings.length} findings</span>
            </div>
          </Panel>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            <MetricCard label="Score" value={`${score}/100`} />
            <MetricCard label="Last Audit" value={formatDateTime(selfAudit.completed_at ?? selfAudit.created_at)} />
            <MetricCard label="Critical" value={counts.CRITICAL} accent={counts.CRITICAL > 0} />
            <MetricCard label="High" value={counts.HIGH} accent={counts.HIGH > 0} />
            <MetricCard label="Medium" value={counts.MEDIUM} />
          </div>

          <Panel>
            <SectionHeader title="Categories" description="Status derived from finding categories." />
            <div className="p-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {categories.map((category) => {
                const affected = auditFindings.some((f) => f.category.toLowerCase().includes(category.toLowerCase()));
                return (
                  <div key={category} className="flex items-center justify-between rounded-lg bg-[var(--surface-secondary)] px-3 py-2.5">
                    <span className="text-xs text-[var(--text-default)]">{category}</span>
                    <StatusBadge status={affected ? 'Attention Required' : 'Healthy'} />
                  </div>
                );
              })}
            </div>
          </Panel>

          {auditFindings.length ? (
            <Panel>
              <SectionHeader title="Findings" description="From the latest self-audit scan." />
              <div className="p-4 space-y-1.5">
                {auditFindings.map((finding) => (
                  <div key={finding.id} className="rounded-xl bg-[var(--surface-secondary)] p-3.5">
                    <div className="flex items-center gap-2 mb-1">
                      <StatusBadge status={finding.severity} />
                      <span className="text-xs font-medium text-[var(--text-strong)]">{finding.title}</span>
                    </div>
                    <div className="text-[11px] text-[var(--text-muted)]">{finding.category}</div>
                    {finding.description ? <p className="mt-1 text-[11px] text-[var(--text-default)]">{finding.description}</p> : null}
                    {finding.recommendation ? <p className="mt-1 text-[11px] text-[var(--brand)]">{finding.recommendation}</p> : null}
                  </div>
                ))}
              </div>
            </Panel>
          ) : (
            <Panel>
              <div className="p-4"><EmptyState title="No findings" description="Self-audit scan completed with no unresolved findings." compact /></div>
            </Panel>
          )}
        </>
      ) : (
        <EmptyState title="No self-audit data" description="Run a self-audit scan to evaluate VulScan's own posture." />
      )}
    </Page>
  );
}
