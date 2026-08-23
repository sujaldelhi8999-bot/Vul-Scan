import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { ClipboardList, Plus, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

import { Button, EmptyState, Input, Panel, PanelSkeleton, Select, StatusBadge } from '../../components/ui/Primitives';
import apiClient, { apiErrorMessage, getFindings } from '../../services/api';
import type { Finding } from '../../types';
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

const STATUS_HELP: Record<string, string> = {
  pending: 'Waiting for enterprise owner approval',
  approved: 'Approved by owner and ready to use',
  rejected: 'Rejected by owner',
  started: 'Approved work has started',
  completed: 'Approved work is complete',
  cancelled: 'Request was cancelled',
};

function formatDate(value: string | null) {
  return value ? new Date(value).toLocaleString() : null;
}

function formatExecutionResult(value: string | null) {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return Object.entries(parsed)
      .map(([key, entry]) => `${key.replace(/_/g, ' ')}: ${String(entry)}`)
      .join(' · ');
  } catch {
    return value;
  }
}

export default function MyRequests() {
  const navigate = useNavigate();
  const mountedRef = useRef(false);
  const [items, setItems] = useState<RequestItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<RequestForm>(EMPTY_FORM);

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get<RequestItem[]>('/api/enterprise/requests');
      if (!mountedRef.current) return;
      setItems(res.data);
    } catch (err) {
      if (!mountedRef.current) return;
      toast.error(apiErrorMessage(err, 'Failed to load your requests'));
    } finally {
      if (!mountedRef.current) return;
      setLoading(false);
    }
  }, []);

  const loadFindings = useCallback(async () => {
    try {
      const data = await getFindings();
      if (!mountedRef.current) return;
      setFindings(data);
    } catch (err) {
      if (!mountedRef.current) return;
      toast.error(apiErrorMessage(err, 'Failed to load findings'));
    } finally {
      if (!mountedRef.current) return;
      setFindingsLoading(false);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void load();
    void loadFindings();
    return () => {
      mountedRef.current = false;
    };
  }, [load, loadFindings]);

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
      if (!mountedRef.current) return;
      setForm(EMPTY_FORM);
      setShowForm(false);
      void load();
    } catch (err) {
      if (!mountedRef.current) return;
      toast.error(apiErrorMessage(err, 'Failed to submit request'));
    } finally {
      if (!mountedRef.current) return;
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
              <Select required value={form.finding_id} onChange={(event) => setForm({ ...form, finding_id: event.target.value })} aria-label="Finding">
                <option value="">{findingsLoading ? 'Loading findings...' : 'Select a finding'}</option>
                {findings.map((finding) => (
                  <option key={finding.id} value={finding.id}>
                    #{finding.id} · {finding.severity} · {finding.title}
                  </option>
                ))}
              </Select>
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
              <Button type="submit" variant="primary" disabled={submitting || findingsLoading || findings.length === 0}>
                {submitting ? 'Submitting...' : 'Submit for Approval'}
              </Button>
            </div>
            {!findingsLoading && findings.length === 0 ? (
              <div className="text-[11px] text-[var(--text-muted)]">No enterprise findings are available for requests yet.</div>
            ) : null}
          </form>
        ) : null}

        {items.length === 0 ? (
          <div className="border-t border-[var(--border-light)] p-2">
            <EmptyState title="No requests yet" description="Submit a proposed finding change and track owner approval status here." compact />
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-light)] border-t border-[var(--border-light)]">
            {items.map((item) => {
              const decidedAt = formatDate(item.decided_at);
              const startedAt = formatDate(item.started_at);
              const completedAt = formatDate(item.completed_at);
              const executionResult = formatExecutionResult(item.execution_result);
              return (
                <div key={item.id} className="flex flex-wrap items-start justify-between gap-3 px-3.5 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-bold text-[var(--text-strong)]">{REQUEST_LABELS[item.request_type] ?? item.request_type.replace(/_/g, ' ')}</span>
                      <StatusBadge status={item.status} />
                      <span className="text-[10px] uppercase tracking-wide text-[var(--text-subtle)]">{item.urgency}</span>
                    </div>
                    <div className="mt-1 text-[11px] font-medium text-[var(--text-muted)]">
                      {STATUS_HELP[item.status] ?? item.status}
                    </div>
                    <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                      Requested {new Date(item.created_at).toLocaleString()}
                      {decidedAt ? ` · Decided ${decidedAt}` : ''}
                      {startedAt ? ` · Started ${startedAt}` : ''}
                      {completedAt ? ` · Completed ${completedAt}` : ''}
                    </div>
                    <div className="mt-0.5 text-[11px] text-[var(--text-subtle)]">Finding #{String(item.details.finding_id ?? '')} · {String(item.details.change_type ?? 'manual').replace(/_/g, ' ')}</div>
                    {item.details.proposed_change ? <div className="mt-1 text-[11px] text-[var(--text-muted)]">{String(item.details.proposed_change)}</div> : null}
                    {item.comment ? <div className="mt-1 text-[11px] text-[var(--text-muted)]">Owner comment: {item.comment}</div> : null}
                    {executionResult ? <div className="mt-1 text-[11px] text-[var(--text-muted)]">Result: {executionResult}</div> : null}
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
