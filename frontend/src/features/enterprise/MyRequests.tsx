import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ClipboardList, Plus, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

import { Button, EmptyState, Input, Panel, PanelSkeleton, Select, StatusBadge } from '../../components/ui/Primitives';
import apiClient, { apiErrorMessage } from '../../services/api';
import { storeEnterpriseApproval, type EnterpriseApprovalHandoff } from './approvalHandoff';

interface RequestItem {
  id: number;
  request_type: string;
  target_url: string | null;
  details: Record<string, unknown>;
  status: string;
  urgency: string;
  comment: string | null;
  decided_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  execution_result: string | null;
  created_at: string;
}

interface RequestForm {
  finding_id: string;
  change_type: string;
  urgency: string;
  proposed_change: string;
  file_path: string;
  patch: string;
}

const EMPTY_FORM: RequestForm = {
  finding_id: '',
  change_type: 'manual',
  urgency: 'normal',
  proposed_change: '',
  file_path: '',
  patch: '',
};

const REQUEST_LABELS: Record<string, string> = {
  code_fix: 'Code change',
  remediation: 'Remediation change',
};

export default function MyRequests() {
  const navigate = useNavigate();
  const [items, setItems] = useState<RequestItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<RequestForm>(EMPTY_FORM);

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get<RequestItem[]>('/api/enterprise/requests');
      setItems(res.data);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to load your requests'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      const findingId = Number(form.finding_id);
      if (!Number.isInteger(findingId) || findingId < 1) {
        toast.error('Enter a valid finding ID');
        return;
      }
      if (!form.proposed_change.trim()) {
        toast.error('Describe the proposed change');
        return;
      }
      if (form.change_type === 'code_patch' && (!form.file_path.trim() || !form.patch.trim())) {
        toast.error('Code patches require a file path and unified diff');
        return;
      }
      const details: Record<string, unknown> = {
        finding_id: findingId,
        change_type: form.change_type,
        proposed_change: form.proposed_change.trim(),
      };
      if (form.file_path.trim()) details.file_path = form.file_path.trim();
      if (form.patch.trim()) details.patch = form.patch;

      await apiClient.post('/api/enterprise/request', {
        request_type: form.change_type === 'code_patch' ? 'code_fix' : 'remediation',
        target_url: null,
        urgency: form.urgency,
        details,
      });
      toast.success('Request submitted for approval');
      setForm(EMPTY_FORM);
      setShowForm(false);
      void load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to submit request'));
    } finally {
      setSubmitting(false);
    }
  };

  const startApproved = async (id: number) => {
    try {
      const { data } = await apiClient.post<EnterpriseApprovalHandoff>(`/api/enterprise/requests/${id}/start`);
      storeEnterpriseApproval(data);
      toast.success('Approval ready');
       if (['code_fix', 'remediation'].includes(data.request_type)) navigate('/remediation');
      else void load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to start approved request'));
    }
  };

  if (loading) {
    return <Panel><PanelSkeleton rows={5} /></Panel>;
  }

  return (
    <div className="space-y-3">
      <Panel>
        <div className="flex items-center justify-between gap-3 p-3.5">
          <div>
            <h3 className="flex items-center gap-2 text-xs font-semibold text-[var(--text-strong)]">
              <ClipboardList className="h-4 w-4 text-[var(--text-subtle)]" />
              My Requests ({items.length})
            </h3>
            <p className="mt-1 text-[11px] text-[var(--text-muted)]">Scans run directly. Only proposed finding changes require another member's approval.</p>
          </div>
          <div className="flex gap-1.5">
            <Button variant="ghost" onClick={() => void load()} aria-label="Refresh requests">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
            <Button variant={showForm ? 'ghost' : 'primary'} onClick={() => setShowForm((value) => !value)}>
              <Plus className="h-3.5 w-3.5" />
              {showForm ? 'Cancel' : 'New Request'}
            </Button>
          </div>
        </div>

        {showForm ? (
          <form onSubmit={submit} className="space-y-2.5 border-t border-[var(--border-light)] p-3.5">
            <div className="grid gap-2 sm:grid-cols-3">
              <Input type="number" min="1" required value={form.finding_id} onChange={(event) => setForm({ ...form, finding_id: event.target.value })} placeholder="Finding ID" aria-label="Finding ID" />
              <Select value={form.change_type} onChange={(event) => setForm({ ...form, change_type: event.target.value })} aria-label="Change type">
                <option value="manual">Manual action</option>
                <option value="text_update">Text or configuration update</option>
                <option value="code_patch">Code patch</option>
              </Select>
              <Select value={form.urgency} onChange={(event) => setForm({ ...form, urgency: event.target.value })} aria-label="Urgency">
                <option value="low">Low urgency</option>
                <option value="normal">Normal urgency</option>
                <option value="high">High urgency</option>
                <option value="critical">Critical urgency</option>
              </Select>
            </div>
            <textarea
              value={form.proposed_change}
              onChange={(event) => setForm({ ...form, proposed_change: event.target.value })}
              placeholder="Describe the exact code, text, configuration, or manual change"
              className="min-h-20 w-full rounded-[var(--radius-control)] border border-[var(--border-default)] bg-white px-2.5 py-2 text-[11px] text-[var(--text-default)] outline-none focus:border-[var(--brand)] focus:ring-2 focus:ring-[var(--brand)]/8"
              aria-label="Proposed change"
              required
            />
            {form.change_type === 'code_patch' ? (
              <div className="space-y-2">
                <Input value={form.file_path} onChange={(event) => setForm({ ...form, file_path: event.target.value })} placeholder="Relative file path" aria-label="File path" required />
               <textarea
                  value={form.patch}
                  onChange={(event) => setForm({ ...form, patch: event.target.value })}
                  placeholder="Unified diff patch"
                  className="min-h-28 w-full rounded-[var(--radius-control)] border border-[var(--border-default)] bg-white px-2.5 py-2 font-mono text-[11px] text-[var(--text-default)] outline-none focus:border-[var(--brand)] focus:ring-2 focus:ring-[var(--brand)]/8"
                  aria-label="Unified diff patch"
                  required
               />
              </div>
            ) : null}
            <div className="flex justify-end">
              <Button type="submit" variant="primary" disabled={submitting}>
                {submitting ? 'Submitting...' : 'Submit for Approval'}
              </Button>
            </div>
          </form>
        ) : null}

        {items.length === 0 ? (
          <div className="border-t border-[var(--border-light)] p-2">
            <EmptyState title="No requests yet" description="Submit a proposed finding change when remediation needs review." compact />
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-light)] border-t border-[var(--border-light)]">
            {items.map((item) => {
              return (
                <div key={item.id} className="flex flex-wrap items-start justify-between gap-3 px-3.5 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-bold text-[var(--text-strong)]">{REQUEST_LABELS[item.request_type] ?? item.request_type.replace(/_/g, ' ')}</span>
                      <StatusBadge status={item.status} />
                      <span className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">{item.urgency}</span>
                    </div>
                    <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                      Requested {new Date(item.created_at).toLocaleString()}
                      {item.decided_at ? ` · Decided ${new Date(item.decided_at).toLocaleString()}` : ''}
                    </div>
                    <div className="mt-0.5 text-[11px] text-[var(--text-subtle)]">Finding #{String(item.details.finding_id ?? '')} · {String(item.details.change_type ?? 'manual').replace(/_/g, ' ')}</div>
                    {item.details.proposed_change ? <div className="mt-1 text-[11px] text-[var(--text-muted)]">{String(item.details.proposed_change)}</div> : null}
                    {item.comment ? <div className="mt-1 text-[11px] text-[var(--text-muted)]">Comment: {item.comment}</div> : null}
                  </div>
                   {item.status === 'approved' && item.details.change_type === 'code_patch' ? (
                     <Button variant="primary" onClick={() => void startApproved(item.id)}>Apply Patch</Button>
                   ) : null}
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}
