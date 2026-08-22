import { RefreshCw } from 'lucide-react';
import { usePhantomData } from '../../hooks/usePhantomData';
import { Button, Page, PageHeader, Panel, SectionHeader, StatusBadge } from '../../components/ui/Primitives';

export default function SystemHealthPage() {
  const { health, realtimeState, realtimeHealthy, refresh, refreshing } = usePhantomData();

  const services = [
    ['Backend API', health ? 'Connected' : 'Unavailable'],
    ['WebSocket', realtimeState === 'open' ? 'Connected' : realtimeState === 'connecting' ? 'Connecting' : realtimeState === 'error' ? 'Error' : 'Disconnected'],
    ['Database', health?.database ?? 'unavailable'],
    ['Agents', health?.agents ?? 'unavailable'],
    ['Scheduler', health?.scheduler ?? 'unavailable'],
  ];

  const aiInfo = health ? [
    ['Provider', health.ai_provider],
    ['Model', health.ai_model],
    ['Status', health.ai_status === 'connected' ? 'Connected' : 'Offline'],
  ] : [];

  return (
    <Page>
      <PageHeader
        title="System Health"
        description="Connectivity from REST health and realtime status."
        action={<Button onClick={() => void refresh()} disabled={refreshing}><RefreshCw className={refreshing ? 'animate-spin' : ''} />Refresh</Button>}
      />

      <Panel>
        <SectionHeader title="Services" />
        <div className="p-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
          {services.map(([label, value]) => (
            <div key={label} className="rounded-lg bg-[var(--surface-secondary)] p-3">
              <div className="text-xs text-[var(--text-muted)]">{label}</div>
              <div className="mt-2"><StatusBadge status={value} /></div>
            </div>
          ))}
        </div>
      </Panel>

      {aiInfo.length ? (
        <Panel>
          <SectionHeader title="AI Integration" description="OpenRouter with configurable models." />
          <div className="p-4 grid gap-2 sm:grid-cols-3">
            {aiInfo.map(([label, value]) => (
              <div key={label} className="rounded-lg bg-[var(--surface-secondary)] p-3">
                <div className="text-xs text-[var(--text-muted)]">{label}</div>
                <div className="mt-2"><StatusBadge status={value} /></div>
              </div>
            ))}
          </div>
        </Panel>
      ) : null}

      <Panel>
        <SectionHeader title="Overall Status" />
        <div className="p-4">
          <div className="flex items-center gap-3">
            <span className={realtimeHealthy ? 'h-2.5 w-2.5 rounded-full bg-[var(--success)]' : 'h-2.5 w-2.5 rounded-full bg-[var(--warning)]'} />
            <span className="text-sm font-semibold text-[var(--text-strong)]">
              {realtimeHealthy ? 'All Systems Online' : 'Connection Issue Detected'}
            </span>
          </div>
          <p className="mt-1 text-xs text-[var(--text-muted)]">
            Green state requires both REST API and WebSocket health.
          </p>
        </div>
      </Panel>
    </Page>
  );
}
