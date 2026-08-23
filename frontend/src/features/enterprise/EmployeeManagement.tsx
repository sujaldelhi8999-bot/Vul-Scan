import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Copy, Eye, EyeOff, KeyRound, RefreshCw, UserPlus, Users } from 'lucide-react';
import toast from 'react-hot-toast';

import apiClient, { apiErrorMessage } from '../../services/api';
import {
  Button,
  cx,
  Drawer,
  EmptyState,
  Input,
  Panel,
  PanelSkeleton,
} from '../../components/ui/Primitives';

interface EnterpriseUser {
  id: string;
  email: string;
  name: string | null;
  role: string;
  max_severity: string;
  can_request_audit: number;
  can_request_fix: number;
  can_approve: number;
  is_active: number;
  created_at: string;
  last_login: string | null;
}

const EMPTY_FORM = {
  email: '', name: '', password: '',
};

export default function EmployeeManagement() {
  const [employees, setEmployees] = useState<EnterpriseUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [issuedPassword, setIssuedPassword] = useState<{ email: string; password: string } | null>(null);

  // Password management modal state
  const [pwTarget, setPwTarget] = useState<EnterpriseUser | null>(null);
  const [generatedPw, setGeneratedPw] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [customPw, setCustomPw] = useState('');
  const [pwBusy, setPwBusy] = useState<'reset' | 'set' | null>(null);

  const openPasswordModal = (emp: EnterpriseUser) => {
    setPwTarget(emp);
    setGeneratedPw('');
    setShowPw(false);
    setCustomPw('');
  };

  const closePasswordModal = () => {
    setPwTarget(null);
    setGeneratedPw('');
    setShowPw(false);
    setCustomPw('');
  };

  const handleResetPassword = async () => {
    if (!pwTarget) return;
    setPwBusy('reset');
    try {
      const res = await apiClient.post(`/api/enterprise/users/${pwTarget.id}/reset-password`);
      setGeneratedPw(res.data.new_password);
      setShowPw(true);
      toast.success(`Password reset for ${res.data.email} — copy it now`);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to reset password'));
    } finally {
      setPwBusy(null);
    }
  };

  const handleSetPassword = async () => {
    if (!pwTarget) return;
    if (customPw.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }
    setPwBusy('set');
    try {
      await apiClient.post(`/api/enterprise/users/${pwTarget.id}/set-password`, { new_password: customPw });
      toast.success(`Password updated for ${pwTarget.email}`);
      closePasswordModal();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to set password'));
    } finally {
      setPwBusy(null);
    }
  };

  const copyPassword = async () => {
    const value = generatedPw || customPw;
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      toast.success('Copied to clipboard');
    } catch {
      toast.error('Clipboard unavailable — select and copy manually');
    }
  };

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get<EnterpriseUser[]>('/api/enterprise/users');
      setEmployees(res.data);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to load employees'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      const res = await apiClient.post('/api/enterprise/users', form);
      setIssuedPassword({ email: res.data.email, password: form.password });
      toast.success(`Employee ${res.data.email} created`);
      setForm(EMPTY_FORM);
      setShowForm(false);
      void load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to create employee'));
    } finally {
      setCreating(false);
    }
  };

  const handleToggleActive = async (emp: EnterpriseUser) => {
    try {
      if (emp.is_active) {
        await apiClient.delete(`/api/enterprise/users/${emp.id}`);
      } else {
        await apiClient.put(`/api/enterprise/users/${emp.id}`, { is_active: true });
      }
      toast.success(emp.is_active ? `${emp.email} deactivated` : `${emp.email} reactivated`);
      void load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to update employee'));
    }
  };

  if (loading) {
    return <Panel><PanelSkeleton rows={5} /></Panel>;
  }

  return (
    <div className="space-y-3">
      {issuedPassword ? (
        <div className="rounded-xl border border-[var(--info-soft)] bg-[var(--info-soft)]/30 p-3.5 text-xs">
           <div className="font-semibold text-[var(--text-strong)]">Permanent password for {issuedPassword.email}</div>
          <code className="mt-1 block rounded bg-[var(--surface-tertiary)] px-2 py-1 font-mono text-sm">{issuedPassword.password}</code>
           <p className="mt-1 text-[var(--text-muted)]">This is the permanent password supplied by the administrator.</p>
        </div>
      ) : null}

      <Panel>
        <div className="flex items-center justify-between p-3.5">
          <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-strong)]">
            <Users className="h-4 w-4 text-[var(--text-subtle)]" />
            Employees ({employees.length})
          </div>
          <Button variant={showForm ? 'ghost' : 'primary'} onClick={() => { setShowForm(!showForm); setIssuedPassword(null); }}>
            {showForm ? 'Cancel' : (<><UserPlus className="h-3.5 w-3.5" /> Add Employee</>)}
          </Button>
        </div>

        {showForm ? (
          <form onSubmit={handleCreate} className="border-t border-[var(--border-light)] p-3.5">
            <div className="grid gap-2 sm:grid-cols-3">
              <Input type="email" required placeholder="Email" value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })} />
              <Input required placeholder="Full name" value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
              <Input type="password" required minLength={8} placeholder="Permanent password" value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })} />
            </div>
            <div className="mt-2.5 flex items-center justify-between">
              <p className="text-[10px] text-[var(--text-subtle)]">
                Employees can request approval for protected enterprise actions. Only the owner or platform admin manages members and settings.
              </p>
              <Button type="submit" variant="primary" disabled={creating}>
                {creating ? 'Creating...' : 'Create Employee'}
              </Button>
            </div>
          </form>
        ) : null}

        <div className="border-t border-[var(--border-light)]">
          {employees.length === 0 ? (
            <EmptyState title="No employees yet" description="Add your first team member above." compact />
          ) : (
            <div className="divide-y divide-[var(--border-light)]">
              {employees.map((emp) => (
                <div key={emp.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-3.5 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`h-1.5 w-1.5 rounded-full ${emp.is_active ? 'bg-green-500' : 'bg-gray-400'}`} />
                      <span className="truncate text-xs font-semibold text-[var(--text-strong)]">{emp.name || emp.email}</span>
                      <span className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[10px] font-semibold uppercase text-[var(--text-muted)]">
                        Enterprise Employee
                      </span>
                    </div>
                    <div className="mt-0.5 truncate pl-3.5 text-[11px] text-[var(--text-subtle)]">{emp.email}</div>
                  </div>

                  <span className="text-[10px] font-semibold text-[var(--text-subtle)]">Enterprise Employee · approval required</span>

                  <Button variant="ghost" onClick={() => openPasswordModal(emp)} title="Manage password" aria-label={`Manage password for ${emp.email}`}>
                    <KeyRound className="h-3.5 w-3.5" />
                  </Button>

                  <Button variant={emp.is_active ? 'danger' : 'secondary'} onClick={() => handleToggleActive(emp)}>
                    {emp.is_active ? 'Deactivate' : 'Reactivate'}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>

      <Drawer title={`Password — ${pwTarget?.email ?? ''}`} open={!!pwTarget} onClose={closePasswordModal}>
        {pwTarget ? (
          <div className="space-y-4">
            {/* Generated / current password display */}
            <div>
              <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">
                Generated password
              </div>
              <div className="flex items-center gap-1.5 rounded-[var(--radius-control)] border border-[var(--border-light)] bg-white px-2.5 py-2">
                <code className="min-w-0 flex-1 truncate font-mono text-sm">
                  {generatedPw ? (showPw ? generatedPw : '•'.repeat(Math.min(generatedPw.length, 18))) : '—'}
                </code>
                {generatedPw ? (
                  <>
                    <button
                      onClick={() => setShowPw(!showPw)}
                      className="rounded p-1 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]"
                      aria-label={showPw ? 'Hide password' : 'Show password'}
                    >
                      {showPw ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                    <button
                      onClick={copyPassword}
                      className="rounded p-1 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]"
                      aria-label="Copy password"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  </>
                ) : null}
              </div>
              {!generatedPw ? (
                <p className="mt-1 text-[10px] text-[var(--text-subtle)]">
                  Existing passwords are stored as one-way bcrypt hashes and cannot be viewed. Generate a new one or set a custom password below.
                </p>
              ) : (
                <p className="mt-1 text-[10px] font-medium text-[var(--warning)]">
                  Shown only once — copy it before closing.
                </p>
              )}
            </div>

            <Button variant="amber" onClick={handleResetPassword} disabled={pwBusy !== null} className="w-full">
              <RefreshCw className={cx('h-3.5 w-3.5', pwBusy === 'reset' && 'animate-spin')} />
              Generate New Password
            </Button>

            {/* Set custom password */}
            <div>
              <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">
                Set a specific password (min 8 chars)
              </div>
              <form onSubmit={(e) => { e.preventDefault(); void handleSetPassword(); }} className="flex gap-1.5">
                <Input
                  type="text"
                  value={customPw}
                  onChange={(e) => setCustomPw(e.target.value)}
                  placeholder="Enter new password..."
                  autoComplete="off"
                />
                <Button type="submit" variant="primary" disabled={pwBusy !== null || customPw.length < 8}>
                  Set
                </Button>
              </form>
            </div>

            <div className="rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3 text-[11px] leading-relaxed text-[var(--text-muted)]">
              Every reset is recorded in the enterprise audit log under the acting owner/admin account.
            </div>
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
