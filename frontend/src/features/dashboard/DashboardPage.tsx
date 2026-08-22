import { Link } from 'react-router-dom';
import { ArrowUpRight, Shield, Activity, AlertTriangle, CheckCircle2 } from 'lucide-react';

import { usePhantomData } from '../../hooks/usePhantomData';
import {
  ActivityTimeline,
  AgentCard,
  Button,
  EmptyState,
  LoadingSkeleton,
  MetricCard,
  Page,
  PageHeader,
  Panel,
  PanelSkeleton,
  ProgressBar,
  SectionHeader,
  SeverityBadge,
  StatusBadge,
} from '../../components/ui/Primitives';
import {
  agentSummary,
  countBySeverity,
  deriveAssets,
  formatDateTime,
  latestCompletedScan,
  relativeTime,
  securityScore,
  targetName,
} from '../../utils/derived';

export default function DashboardPage() {
  const { scans, findings, agents, logs, health, loading, artifactsByScanId, executionStatus, executionActive } = usePhantomData();
  const latestScan = latestCompletedScan(scans);
  const latestFindings = latestScan ? findings.filter((f) => f.scan_id === latestScan.id) : findings;
  const analyst = latestScan ? artifactsByScanId[latestScan.id]?.ai_analyst_output : null;
  const topPriority = analyst?.priorities?.[0];
  const analystSummary = analyst?.security_summary;
  const score = securityScore(latestFindings);
  const counts = countBySeverity(latestFindings);
  const assets = deriveAssets(scans, findings);
  const summary = agentSummary(agents);
  const totalIssues = counts.CRITICAL + counts.HIGH;

  const timeline = logs.slice(-8).map((log) => ({
    id: `log-${log.id}`,
    timestamp: new Date(log.timestamp).toLocaleTimeString('en-GB', { hour12: false }),
    title: log.action.replace(/_/g, ' '),
    detail: log.details,
    agent: log.agent_name,
    tone: /error|failed|cancel/i.test(log.action) ? ('red' as const) : /complete|delivered/i.test(log.action) ? ('green' as const) : ('purple' as const),
  }));

  if (loading) {
    return (
      <Page>
        <PageHeader title="Security Overview" />
        <div className="h-32 animate-pulse rounded-xl bg-[var(--surface-primary)] border border-[var(--border-light)]" />
        <div className="grid gap-4 sm:grid-cols-3">
          <div className="sm:col-span-2"><PanelSkeleton rows={4} /></div>
          <PanelSkeleton rows={4} />
        </div>
      </Page>
    );
  }

  return (
    <Page>
      <PageHeader
        title="Security Overview"
        description={latestScan ? `Last assessed ${relativeTime(latestScan.created_at)}` : 'Run your first scan to establish a baseline.'}
        action={
          <div className="flex gap-2">
            <Link to="/scan"><Button variant="primary">Start Defend Scan</Button></Link>
            <Link to="/findings"><Button variant="secondary">View Findings</Button></Link>
          </div>
        }
      />

      {/* Security Posture Band - large structured panel */}
      <Panel>
        <div className="p-3.5">
          {executionActive && executionStatus ? (
            <div className="flex items-center gap-4">
              <span className="flex h-3 w-3">
                <span className="absolute h-3 w-3 rounded-full bg-[var(--warning)] opacity-40 animate-ping" />
                <span className="relative h-3 w-3 rounded-full bg-[var(--warning)]" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold text-[var(--text-strong)]">
                  {executionStatus.execution_type === 'AUTHORIZED_TEST' ? 'Authorized Test Active' : 'Defend Scan Active'}
                </div>
                <div className="text-xs text-[var(--text-muted)] mt-0.5">
                  {executionStatus.target_url ? targetName(executionStatus.target_url) : ''}
                  {executionStatus.current_phase ? ` \u00B7 ${executionStatus.current_phase}` : ''}
                </div>
              </div>
              <div className="hidden sm:flex items-center gap-3">
                <div className="text-right">
                  <div className="text-[11px] text-[var(--text-muted)]">Progress</div>
                  <div className="text-sm font-semibold text-[var(--text-strong)]">{executionStatus.progress_percent}%</div>
                </div>
                <ProgressBar value={executionStatus.progress_percent} className="w-24" />
              </div>
              <Link to={executionStatus.execution_type === 'AUTHORIZED_TEST' ? '/authorized-testing' : '/scan'} className="flex items-center gap-1 rounded px-2 py-1 text-xs font-semibold text-[var(--brand)] hover:bg-[var(--brand-soft)]">
                Open <ArrowUpRight className="h-3 w-3" />
              </Link>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold text-[var(--text-strong)]">No active security operation</div>
                <div className="text-xs text-[var(--text-muted)] mt-0.5">Start a scan or begin an authorized test.</div>
              </div>
              <div className="flex gap-2">
                <Link to="/scan"><Button variant="primary">Start Scan</Button></Link>
                <Link to="/authorized-testing"><Button variant="amber">Authorized Testing</Button></Link>
              </div>
            </div>
          )}
        </div>
      </Panel>

      {/* Three-column metric strip */}
      <div className="grid gap-3 sm:grid-cols-3">
        <Panel>
          <div className="p-3">
            <div className="flex items-center gap-2.5 mb-2.5">
              <div className="flex h-7 w-7 items-center justify-center rounded bg-[var(--brand-soft)]">
                <Shield className="h-3.5 w-3.5 text-[var(--brand)]" />
              </div>
              <div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Security Score</div>
                <div className="text-lg font-bold font-mono tracking-tight text-[var(--text-strong)]">{latestScan ? score : '--'}</div>
              </div>
            </div>
            <div className="h-1.5 rounded-full bg-[var(--surface-tertiary)] overflow-hidden">
              <div className="h-full rounded-full bg-[var(--brand)] transition-all" style={{ width: `${score}%` }} />
            </div>
            <div className="flex justify-between mt-1.5 text-[10px] text-[var(--text-muted)]">
              <span>0</span>
              <span>Posture Score</span>
              <span>100</span>
            </div>
            {analystSummary?.overall_security_posture ? (
              <div className="mt-2 text-[11px] text-[var(--text-muted)] leading-relaxed">
                {String(analystSummary.overall_security_posture)}
              </div>
            ) : null}
          </div>
        </Panel>

        <Panel>
          <div className="p-3">
            <div className="flex items-center gap-2.5 mb-2.5">
              <div className="flex h-7 w-7 items-center justify-center rounded bg-[var(--danger-soft)]">
                <AlertTriangle className="h-3.5 w-3.5 text-[var(--danger)]" />
              </div>
              <div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Open Issues</div>
                <div className="text-lg font-bold font-mono tracking-tight text-[var(--text-strong)]">{totalIssues}</div>
              </div>
            </div>
            <div className="flex gap-2.5">
              {(['CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                <div key={sev} className="flex-1">
                  <SeverityBadge severity={sev} compact />
                  <div className="text-xs font-bold font-mono text-[var(--text-strong)] mt-1">{counts[sev]}</div>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        <Panel>
          <div className="p-3">
            <div className="flex items-center gap-2.5 mb-2.5">
              <div className="flex h-7 w-7 items-center justify-center rounded bg-[var(--success-soft)]">
                <Activity className="h-3.5 w-3.5 text-[var(--success)]" />
              </div>
              <div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Latest Scan</div>
                <div className="text-xs font-semibold text-[var(--text-strong)] truncate max-w-[140px]">{latestScan ? targetName(latestScan.target_url) : 'No scans'}</div>
              </div>
            </div>
            {latestScan ? (
              <div className="flex gap-3 text-[10px] text-[var(--text-muted)] font-medium">
                <span className="font-mono">{formatDateTime(latestScan.created_at)}</span>
                <span className="capitalize">{latestScan.mode}</span>
                <StatusBadge status={latestScan.status} />
              </div>
            ) : null}
            <div className="mt-2 flex gap-2 text-[10px] text-[var(--text-muted)] font-medium">
              <span><span className="font-mono">{assets.length}</span> assets</span>
              <span className="text-[var(--border-light)]">|</span>
              <span><span className="font-mono">{findings.length}</span> findings</span>
            </div>
          </div>
        </Panel>
      </div>

      {/* Main content area - asymmetric layout */}
      <div className="grid gap-3 lg:grid-cols-7">
        {/* Left column - Recent Findings */}
        <div className="lg:col-span-4">
          <Panel>
            <SectionHeader
              title="Recent Findings"
              description="Latest detections across monitored assets"
              action={<Link to="/findings"><Button variant="ghost" className="text-xs">View All</Button></Link>}
            />
            <div className="px-3 py-1.5 bg-white">
              {findings.length ? (
                <div className="divide-y divide-[var(--border-light)]">
                  {findings.slice(-7).reverse().map((finding) => (
                    <Link
                      key={finding.id}
                      to="/findings"
                      className="flex items-center gap-2.5 py-1.5 text-xs transition-colors hover:bg-[var(--surface-hover)] -mx-1 px-1 rounded-[var(--radius-control)]"
                    >
                      <SeverityBadge severity={finding.severity} compact />
                      <span className="min-w-0 flex-1 truncate font-semibold text-[var(--text-strong)]">{finding.title}</span>
                      <span className="shrink-0 text-[10px] text-[var(--text-muted)] hidden sm:inline">{finding.category}</span>
                      <span className="shrink-0 text-[10px] font-mono text-[var(--text-subtle)]">{relativeTime(finding.timestamp)}</span>
                    </Link>
                  ))}
                </div>
              ) : (
                <EmptyState title="No findings" description="No actionable issues detected." compact />
              )}
            </div>
          </Panel>
        </div>

        {/* Right column - Agent Activity */}
        <div className="lg:col-span-3">
          <Panel>
            <SectionHeader
              title="Agent Activity"
              description={`${summary.active} active, ${summary.waiting} idle`}
              action={<Link to="/agents"><Button variant="ghost" className="text-xs">View All</Button></Link>}
            />
            <div className="p-3">
              {executionStatus?.agents?.length ? (
                <div className="space-y-2">
                  {executionStatus.agents.slice(0, 4).map((agent) => (
                    <AgentCard key={agent.name} agent={agent} />
                  ))}
                </div>
              ) : (
                <div className="space-y-1">
                  {agents.slice(0, 6).map((agent) => (
                    <div key={agent.name} className="flex items-center justify-between px-2 py-1.5 text-xs">
                      <span className="text-[var(--text-default)]">{agent.name}</span>
                      <StatusBadge status={agent.status} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Panel>
        </div>
      </div>

      {/* Bottom row - activity timeline + system health */}
      <div className="grid gap-3 lg:grid-cols-7">
        <div className="lg:col-span-4">
          <Panel>
            <SectionHeader
              title="Recent Activity"
              description="Audit events from security operations"
              action={<Link to="/audit-logs"><Button variant="ghost" className="text-xs">View All</Button></Link>}
            />
            <div className="p-3">
              <ActivityTimeline events={timeline} />
            </div>
          </Panel>
        </div>

        <div className="lg:col-span-3">
          <Panel>
            <SectionHeader
              title="System Health"
              description={health?.status === 'ok' ? 'All systems operational' : 'Issues detected'}
              action={<Link to="/system-health"><Button variant="ghost" className="text-xs">Details</Button></Link>}
            />
            <div className="p-3 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-[var(--text-muted)]">Database</span>
                <StatusBadge status={health?.database === 'available' ? 'Healthy' : 'Unavailable'} />
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-[var(--text-muted)]">Agents</span>
                <StatusBadge status={health?.agents === 'available' ? 'Available' : 'Unavailable'} />
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-[var(--text-muted)]">Scheduler</span>
                <StatusBadge status={health?.scheduler ?? 'N/A'} />
              </div>
              {executionStatus?.agents?.length ? (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[var(--text-muted)]">Active Agents</span>
                  <StatusBadge status={`${executionStatus.agents.filter(a => a.applicability === 'RUNNING').length} running`} />
                </div>
              ) : null}
              {analyst?.ai_status ? (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[var(--text-muted)]">AI Status</span>
                  <StatusBadge status={analyst.ai_status} />
                </div>
              ) : null}
            </div>
          </Panel>
        </div>
      </div>
    </Page>
  );
}
