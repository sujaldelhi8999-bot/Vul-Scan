import { useMemo, useState } from 'react';
import { AgentCard, Drawer, EmptyState, Page, PageHeader, Panel, SectionHeader, StatusBadge } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import type { AgentStateDetail, AgentStatus } from '../../types';
import { formatDateTime } from '../../utils/derived';

export default function AgentsPage() {
  const { agents, logs, executionStatus } = usePhantomData();
  const [selected, setSelected] = useState<AgentStateDetail | AgentStatus | null>(null);

  const agentDetails: AgentStateDetail[] = useMemo(() => {
    if (executionStatus?.agents && executionStatus.agents.length > 0) {
      return executionStatus.agents;
    }
    return agents.map((a) => ({
      name: a.name,
      applicability: mapAgentState(a.status),
      responsibility: '',
      current_module: null,
      progress: 0,
      last_updated: null,
      detail: '',
    }));
  }, [agents, executionStatus]);

  const summary = useMemo(() => {
    const counts = { running: 0, queued: 0, completed: 0, failed: 0, idle: 0, na: 0 };
    for (const a of agentDetails) {
      if (a.applicability === 'RUNNING') counts.running++;
      else if (a.applicability === 'QUEUED' || a.applicability === 'WAITING') counts.queued++;
      else if (a.applicability === 'COMPLETED') counts.completed++;
      else if (a.applicability === 'FAILED') counts.failed++;
      else if (a.applicability === 'IDLE') counts.idle++;
      else if (a.applicability === 'NOT_APPLICABLE') counts.na++;
    }
    return counts;
  }, [agentDetails]);

  const selectedLogs = useMemo(
    () => (selected ? logs.filter((log) => log.agent_name === selected.name).slice(-20).reverse() : []),
    [logs, selected],
  );

  return (
    <Page>
      <PageHeader title="Agents" description={`${agentDetails.length} agents · ${summary.running} running, ${summary.completed} completed`} />

      {/* Agent summary bar */}
      <Panel>
        <SectionHeader title="Agent Summary" />
        <div className="grid grid-cols-3 sm:grid-cols-6 divide-x divide-[var(--border-light)]">
          <div className="px-4 py-3">
            <div className="text-[11px] font-medium text-[var(--brand)]">Running</div>
            <div className="mt-0.5 text-lg font-semibold text-[var(--text-strong)]">{summary.running}</div>
          </div>
          <div className="px-4 py-3">
            <div className="text-[11px] font-medium text-[var(--warning)]">Queued</div>
            <div className="mt-0.5 text-lg font-semibold text-[var(--text-strong)]">{summary.queued}</div>
          </div>
          <div className="px-4 py-3">
            <div className="text-[11px] font-medium text-[var(--success)]">Completed</div>
            <div className="mt-0.5 text-lg font-semibold text-[var(--text-strong)]">{summary.completed}</div>
          </div>
          <div className="px-4 py-3">
            <div className="text-[11px] font-medium text-[var(--danger)]">Failed</div>
            <div className="mt-0.5 text-lg font-semibold text-[var(--text-strong)]">{summary.failed}</div>
          </div>
          <div className="px-4 py-3">
            <div className="text-[11px] font-medium text-[var(--text-muted)]">Idle</div>
            <div className="mt-0.5 text-lg font-semibold text-[var(--text-strong)]">{summary.idle}</div>
          </div>
          <div className="px-4 py-3">
            <div className="text-[11px] font-medium text-[var(--text-subtle)]">N/A</div>
            <div className="mt-0.5 text-lg font-semibold text-[var(--text-strong)]">{summary.na}</div>
          </div>
        </div>
      </Panel>

      {/* Agent list */}
      {agentDetails.length ? (
        <Panel>
          <SectionHeader title="Agent Status" description="Real-time agent applicability and progress." />
          <div className="p-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {agentDetails.map((agent) => (
              <AgentCard key={agent.name} agent={agent} onClick={() => setSelected(agent)} />
            ))}
          </div>
        </Panel>
      ) : (
        <EmptyState title="No agents" description="Agent status appears after the backend responds." />
      )}

      {/* Agent detail drawer */}
      <Drawer title={selected?.name ?? 'Agent'} open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected ? (
          <div className="space-y-4">
            <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5">
              <div className="text-[10px] text-[var(--text-muted)]">Status</div>
              <div className="mt-1"><StatusBadge status={'applicability' in selected ? selected.applicability : selected.status} /></div>
            </div>

            {'responsibility' in selected && selected.responsibility ? (
              <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5">
                <div className="text-[10px] text-[var(--text-muted)]">Responsibility</div>
                <div className="mt-1 text-xs text-[var(--text-default)]">{selected.responsibility}</div>
              </div>
            ) : null}

            {'current_module' in selected && selected.current_module ? (
              <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5">
                <div className="text-[10px] text-[var(--text-muted)]">Current Module</div>
                <div className="mt-1 font-mono text-xs text-[var(--brand)]">{selected.current_module.replace(/_/g, ' ')}</div>
              </div>
            ) : null}

            {'detail' in selected && selected.detail ? (
              <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5">
                <div className="text-[10px] text-[var(--text-muted)]">Detail</div>
                <div className="mt-1 text-xs text-[var(--text-muted)]">{selected.detail}</div>
              </div>
            ) : null}

            <div>
              <h3 className="mb-2 text-xs font-semibold text-[var(--text-strong)]">Recent Activity</h3>
              {selectedLogs.length ? (
                <div className="space-y-1.5">
                  {selectedLogs.map((log) => (
                    <div key={log.id} className="rounded-xl bg-[var(--surface-secondary)] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-medium text-[var(--text-strong)]">{log.action.replace(/_/g, ' ')}</span>
                        <span className="text-[10px] text-[var(--text-muted)]">{formatDateTime(log.timestamp)}</span>
                      </div>
                      <div className="mt-1 text-[11px] text-[var(--text-muted)] leading-relaxed">{log.details}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState title="No activity" description="No audit entries for this agent." compact />
              )}
            </div>
          </div>
        ) : null}
      </Drawer>
    </Page>
  );
}

function mapAgentState(status: string): AgentStateDetail['applicability'] {
  switch (status) {
    case 'active': return 'RUNNING';
    case 'idle': return 'IDLE';
    case 'complete': return 'COMPLETED';
    case 'error': return 'FAILED';
    default: return 'IDLE';
  }
}
