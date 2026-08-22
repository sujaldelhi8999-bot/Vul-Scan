import { useState } from 'react';
import { Copy } from 'lucide-react';
import toast from 'react-hot-toast';

import { DataTable, Drawer, EmptyState, Page, PageHeader, Panel } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import type { AuditLog } from '../../types';
import { formatDateTime, targetName } from '../../utils/derived';

export default function AuditLogsPage() {
  const { logs } = usePhantomData();
  const [selected, setSelected] = useState<AuditLog | null>(null);

  const columns = [
    { key: 'time', label: 'Time', width: '130px' },
    { key: 'event', label: 'Event' },
    { key: 'source', label: 'Source', width: '150px' },
    { key: 'target', label: 'Target', width: '150px' },
    { key: 'status', label: 'Status', width: '100px' },
  ];

  const rows = logs.slice().reverse().map((log) => ({
    id: log.id,
    cells: {
      time: <span className="font-mono text-[11px] text-[var(--text-muted)]">{formatDateTime(log.timestamp)}</span>,
      event: (
        <span className="text-xs text-[var(--text-strong)]">
          {log.action.replace(/_/g, ' ')}
          {log.result ? <span className="ml-1.5 text-[10px] text-[var(--text-muted)]">&mdash; {log.result}</span> : null}
        </span>
      ),
      source: <span className="truncate text-xs text-[var(--text-default)]">{log.agent_name}</span>,
      target: <span className="truncate font-mono text-xs text-[var(--text-muted)]">{log.target ? targetName(log.target) : `Scan ${log.scan_id}`}</span>,
      status: log.authorization_status ? (
        <span className="inline-flex items-center rounded bg-[var(--surface-secondary)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--text-muted)]">
          {log.authorization_status}
        </span>
      ) : null,
    },
  }));

  const copyField = async (value: string) => {
    try { await navigator.clipboard.writeText(value); toast.success('Copied'); }
    catch { toast.error('Unable to copy'); }
  };

  return (
    <Page>
      <PageHeader title="Audit Logs" description={`${logs.length} append-only records.`} />
      <Panel>
        {logs.length ? (
          <DataTable columns={columns} rows={rows} onRowClick={(id) => { const log = logs.find((l) => l.id === id); if (log) setSelected(log); }} />
        ) : (
          <div className="p-5"><EmptyState title="No logs" description="Audit entries appear after scans or system events." /></div>
        )}
      </Panel>

      <Drawer title="Audit Record" open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected ? (
          <div className="space-y-2">
            {[
              ['Timestamp', formatDateTime(selected.timestamp)],
              ['Agent', selected.agent_name],
              ['Action', selected.action.replace(/_/g, ' ')],
              ['Target', selected.target || `Scan ${selected.scan_id}`],
              ['User', selected.user_id || 'local-user'],
              ['Result', selected.result],
              ['Module', selected.selected_module || ''],
              ['Authorization', selected.authorization_status || ''],
              ['Details', selected.details],
              ['Request Count', selected.request_count?.toString() ?? ''],
              ['Sandbox', selected.sandbox_id || ''],
            ].filter((pair): pair is [string, string] => Boolean(pair[1])).map(([key, value]) => (
              <div key={key} className="rounded-xl bg-[var(--surface-secondary)] p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-[10px] font-semibold text-[var(--text-muted)]">{key}</div>
                  {['Details', 'Target', 'Agent'].includes(key) ? (
                    <button onClick={() => void copyField(String(value))} className="rounded p-0.5 text-[var(--text-muted)] hover:text-[var(--text-default)]" aria-label={`Copy ${key}`}>
                      <Copy className="h-3 w-3" />
                    </button>
                  ) : null}
                </div>
                <div className="mt-0.5 break-words text-xs text-[var(--text-default)]">
                  {String(value ?? '') || <span className="text-[var(--text-subtle)]">Not set</span>}
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </Drawer>
    </Page>
  );
}
