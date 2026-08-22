import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2 } from 'lucide-react';
import toast from 'react-hot-toast';

import apiClient, { apiErrorMessage } from '../../services/api';
import { Button, EmptyState, Panel, PanelSkeleton } from '../../components/ui/Primitives';

interface ApprovalItem {
  id: number;
  employee_id: string;
  request_type: string;
  target_url: string | null;
  details: Record<string, unknown>;
  urgency: string;
  status: string;
  created_at: string;
  employee_email: string | null;
  employee_name: string | null;
}

const URGENCY_STYLES: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  normal: 'bg-blue-100 text-blue-700',
  low: 'bg-gray-100 text-gray-600',
};

export default function ApprovalWorkflow() {
  const [items, setItems] = useState<ApprovalItem[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get<ApprovalItem[]>('/api/enterprise/approvals');
      setItems(res.data);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to load approvals'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const decide = async (id: number, action: 'approve' | 'reject') => {
    let comment: string | null = null;
    if (action === 'reject') {
      comment = window.prompt('Reason for rejection:');
      if (comment === null) return;
    }
    try {
      await apiClient.put(`/api/enterprise/approvals/${id}`, { action, comment });
      toast.success(`Request ${action}d`);
      void load();
    } catch (err) {
      toast.error(apiErrorMessage(err, `Failed to ${action} request`));
    }
  };

  if (loading) {
    return <Panel><PanelSkeleton rows={4} /></Panel>;
  }

  return (
    <Panel>
      <div className="p-3.5">
        <h3 className="text-xs font-semibold text-[var(--text-strong)]">Pending Approvals ({items.length})</h3>
      </div>

      {items.length === 0 ? (
        <div className="border-t border-[var(--border-light)] p-2">
          <EmptyState
            icon={<CheckCircle2 className="h-5 w-5" />}
            title="No pending approvals"
            description="Employee requests will appear here for review."
            compact
          />
        </div>
      ) : (
        <div className="divide-y divide-[var(--border-light)] border-t border-[var(--border-light)]">
          {items.map((item) => (
            <div key={item.id} className="flex flex-wrap items-start justify-between gap-3 px-3.5 py-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wide text-[var(--text-strong)]">
                    {item.request_type.replace(/_/g, ' ')}
                  </span>
                  <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${URGENCY_STYLES[item.urgency] ?? URGENCY_STYLES.low}`}>
                    {item.urgency}
                  </span>
                </div>
                <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                  {item.employee_name || item.employee_email || item.employee_id}
                  {' · '}
                  {new Date(item.created_at).toLocaleString()}
                </div>
                {item.target_url ? (
                  <div className="mt-0.5 truncate font-mono text-[11px] text-[var(--text-subtle)]">{item.target_url}</div>
                ) : null}
                {Object.keys(item.details).length ? (
                  <pre className="mt-1.5 max-h-24 overflow-auto rounded-lg bg-[var(--surface-tertiary)] p-2 font-mono text-[10px] leading-relaxed text-[var(--text-muted)]">
                    {JSON.stringify(item.details, null, 2)}
                  </pre>
                ) : null}
              </div>

              <div className="flex shrink-0 gap-1.5">
                <Button variant="primary" onClick={() => decide(item.id, 'approve')}>Approve</Button>
                <Button variant="danger" onClick={() => decide(item.id, 'reject')}>Reject</Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
