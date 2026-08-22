import { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';

import apiClient, { apiErrorMessage } from '../../services/api';
import { EmptyState, Panel, PanelSkeleton } from '../../components/ui/Primitives';

interface AuditEntry {
  id: number;
  user_id: string;
  action: string;
  resource: string | null;
  details: string | null;
  ip_address: string | null;
  timestamp: string;
  user_email: string | null;
  user_name: string | null;
}

export default function AuditLogs() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get<AuditEntry[]>('/api/enterprise/audit-logs', { params: { limit: 200 } });
      setEntries(res.data);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to load audit logs'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (loading) {
    return <Panel><PanelSkeleton rows={6} /></Panel>;
  }

  return (
    <Panel>
      <div className="p-3.5">
        <h3 className="text-xs font-semibold text-[var(--text-strong)]">Enterprise Audit Log ({entries.length})</h3>
      </div>
      <div className="border-t border-[var(--border-light)]">
        {entries.length === 0 ? (
          <EmptyState title="No audit entries" description="Enterprise actions will be recorded here." compact />
        ) : (
          <div className="divide-y divide-[var(--border-light)]">
            {entries.map((entry) => (
              <div key={entry.id} className="flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 px-3.5 py-2">
                <span className="font-mono text-[10px] text-[var(--text-subtle)]">
                  {new Date(entry.timestamp.endsWith('Z') || entry.timestamp.includes('T') ? entry.timestamp : entry.timestamp.replace(' ', 'T') + 'Z').toLocaleString()}
                </span>
                <span className="text-xs font-semibold text-[var(--text-strong)]">{entry.action.replace(/_/g, ' ')}</span>
                <span className="text-[11px] text-[var(--text-muted)]">{entry.user_name || entry.user_email || entry.user_id}</span>
                {entry.resource ? <span className="truncate font-mono text-[11px] text-[var(--text-subtle)]">{entry.resource}</span> : null}
                {entry.ip_address ? <span className="ml-auto font-mono text-[10px] text-[var(--text-subtle)]">{entry.ip_address}</span> : null}
              </div>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}
