import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Archive,
  ChevronRight,
  Copy,
  Crosshair,
  Download,
  FileDown,
  Flame,
  Lock,
  MoveRight,
  Play,
  RefreshCw,
  ShieldAlert,
  Skull,
  Terminal,
  Unlock,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { useAuth } from '../../context/AuthContext';
import apiClient, { apiErrorMessage } from '../../services/api';
import {
  Button,
  EmptyState,
  ErrorState,
  Input,
  Page,
  PageHeader,
  Panel,
  Select,
} from '../../components/ui/Primitives';
import ShellConsole from './ShellConsole';

interface GateStatus {
  enabled: boolean;
  admin: boolean;
  requirements: { env_flag: boolean; admin_role: boolean; private_scope_target: boolean; ownership_ack: boolean };
  supported_categories: Record<string, string>;
}

interface TimelineEvent {
  ts: number;
  action: string;
  status: string;
  detail: string;
}

interface LootItem {
  kind: string;
  name: string;
  content: string;
  source: string;
}

interface BrutalSession {
  session_id: string;
  target_url: string;
  actor: string;
  created_at: number;
  status: string;
  simulation?: boolean;
  sim_intel?: {
    hostname?: string;
    target_url?: string;
    ip?: string;
    tech_stack?: string[];
    dns?: Record<string, unknown>;
    http?: Record<string, unknown>;
    ports?: Array<{ port: number; service: string; state: string }>;
    endpoints?: Array<{ path: string; status: string; interest: boolean }>;
  };
  timeline: TimelineEvent[];
  loot_count: number;
  loot: LootItem[];
}

interface ScopeEntry {
  id: number;
  target_url: string;
}

interface ShellInfo {
  shell_id: string;
  session_id: string;
  closed: boolean;
  command_count: number;
  remaining_budget: number;
  last_output: string;
}

const statusColor: Record<string, string> = {
  success: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  running: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  pending: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
  denied: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
};

const LAB_HOSTNAMES = ['localhost', '127.0.0.1', '::1'];

function isLabTarget(url: string): boolean {
  try {
    const host = new URL(url.includes('://') ? url : `https://${url}`).hostname.toLowerCase();
    return LAB_HOSTNAMES.includes(host);
  } catch {
    return false;
  }
}

const actionLabel: Record<string, string> = {
  session_established: 'Session established',
  exploit_started: 'Exploitation started',
  exploited: 'Exploited',
  exploit_failed: 'Exploitation failed',
  shell_opened: 'Shell obtained',
  post_exploit_enum: 'Enumerated',
  privesc_check: 'Privesc check',
  ssh_keys_harvested: 'SSH keys harvested',
  network_mapped: 'Network mapped',
  pivot_succeeded: 'Pivot succeeded',
  pivot_failed: 'Pivot failed',
  persistence_installed: 'Persistence installed',
  exfil_complete: 'Data exfiltrated',
  ai_payload: 'AI payload',
};

function formatTime(ts: number) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function copyText(text: string, label = 'Copied') {
  void navigator.clipboard.writeText(text);
  toast.success(label);
}

export default function BrutalMode() {
  const { user } = useAuth();
  const [status, setStatus] = useState<GateStatus | null>(null);
  const [statusError, setStatusError] = useState('');
  const [scope, setScope] = useState<ScopeEntry[]>([]);
  const [target, setTarget] = useState('');
  const [ack, setAck] = useState(false);
  const [session, setSession] = useState<BrutalSession | null>(null);
  const [simulation, setSimulation] = useState(false);
  const [busy, setBusy] = useState('');
  const [shell, setShell] = useState<ShellInfo | null>(null);
  const [shellOpen, setShellOpen] = useState(false);
  const [payloads, setPayloads] = useState<{ reverse_shell: Array<{ os: string; label: string; payload: string }> } | null>(null);
  const [exfilResult, setExfilResult] = useState<{ file_id: string; filename: string; size_bytes: number; sha256: string } | null>(null);
  const [banner, setBanner] = useState('');
  const [opsLog, setOpsLog] = useState<Array<{ id: number; action: string; status: string; detail: string; created_at: string }>>([]);

  const loadStatus = useCallback(async () => {
    try {
      const response = await apiClient.get<GateStatus>('/api/brutal/status');
      setStatus(response.data);
    } catch (err) {
      setStatusError(apiErrorMessage(err, 'Failed to load Brutal Mode status'));
    }
  }, []);

  const loadScope = useCallback(async () => {
    try {
      const response = await apiClient.get<ScopeEntry[]>('/api/admin/scope/list');
      setScope(response.data);
    } catch {
      /* non-admin or unavailable */
    }
  }, []);

  useEffect(() => {
    void loadStatus();
    void loadScope();
  }, [loadStatus, loadScope]);

  const flashBanner = (text: string) => {
    setBanner(text);
    toast(text, { icon: '🚨' });
    setTimeout(() => setBanner(''), 6000);
  };

  const isAdmin = user?.role === 'admin' || Boolean(user?.enterpriseId);
  const targetInScope = scope.some((entry) => entry.target_url === target.trim()) || isLabTarget(target);
  const autoConfirm = isAdmin && targetInScope;

  const establishSession = async () => {
    if (!ack && !autoConfirm) {
      toast.error('You must confirm target ownership before establishing a session');
      return;
    }
    setBusy('session');
    try {
      const response = await apiClient.post<BrutalSession>('/api/brutal/sessions', {
        target_url: target.trim(),
        ownership_ack: true,
        simulation,
      });
      setSession(response.data);
      setExfilResult(null);
      flashBanner(`SESSION ESTABLISHED — ${simulation ? 'simulation' : 'lab'} mode`);
      toast.success(`Session ${response.data.session_id.slice(0, 8)} established`);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to establish session'));
    } finally {
      setBusy('');
    }
  };

  const refreshSession = useCallback(async () => {
    if (!session) return;
    try {
      const response = await apiClient.get<BrutalSession>(`/api/brutal/sessions/${session.session_id}`);
      setSession(response.data);
    } catch {
      /* session may be gone */
    }
  }, [session]);

  useEffect(() => {
    const timer = setInterval(() => void refreshSession(), 4000);
    return () => clearInterval(timer);
  }, [refreshSession]);

  const runAction = async (action: string, url: string, body?: Record<string, unknown>) => {
    setBusy(action);
    try {
      const response = await apiClient.post<Record<string, unknown>>(url, body ?? {});
      if (action === 'exfil') {
        setExfilResult(response.data as unknown as typeof exfilResult);
        flashBanner('DATA EXFILTRATED — loot archive ready for download');
      }
      if (action === 'exploit') {
        const data = response.data as { shell_recommended?: boolean; summary?: string };
        if (data.shell_recommended) flashBanner('SHELL ACCESS RECOMMENDED — open the shell console');
      }
      if (action === 'lateral') {
        const data = response.data as { pivot?: { authenticated?: boolean } };
        if (data.pivot?.authenticated) flashBanner('PIVOT SUCCEEDED — moved to internal host');
      }
      if (action === 'persist') flashBanner('PERSISTENCE INSTALLED');
      await refreshSession();
      await loadOps();
    } catch (err) {
      toast.error(apiErrorMessage(err, `Failed: ${action}`));
    } finally {
      setBusy('');
    }
  };

  const openShell = async () => {
    if (!session) return;
    setBusy('shell');
    try {
      const response = await apiClient.post<ShellInfo>(`/api/brutal/sessions/${session.session_id}/shell`, { os_hint: 'auto' });
      setShell(response.data);
      setShellOpen(true);
      setPayloads(null);
      flashBanner('SHELL OBTAINED — interactive console ready');
      const payloadResponse = await apiClient.get<typeof payloads>(`/api/brutal/shell/${response.data.shell_id}/payloads`);
      setPayloads(payloadResponse.data);
      await refreshSession();
      await loadOps();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to open shell'));
    } finally {
      setBusy('');
    }
  };

  const loadOps = useCallback(async () => {
    try {
      const response = await apiClient.get<typeof opsLog>('/api/brutal/ops', { params: { limit: 50 } });
      setOpsLog(response.data);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    void loadOps();
    const timer = setInterval(() => void loadOps(), 8000);
    return () => clearInterval(timer);
  }, [loadOps]);

  if (!status) {
    return (
      <Page>
        <PageHeader title="Brutal Mode" description="Active exploitation framework" />
        {statusError ? <ErrorState title="Cannot reach backend" description={statusError} /> : <EmptyState title="Loading..." description="Querying the Brutal Mode gate." />}
      </Page>
    );
  }

  if (!status.admin) {
    return (
      <Page>
        <PageHeader title="Brutal Mode" description="Admin-only capability" />
        <Panel>
          <div className="flex items-center gap-3 p-6">
            <Lock className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-sm font-semibold text-red-600 dark:text-red-400">Admin access required</p>
              <p className="text-xs text-[var(--text-muted)]">
                Brutal Mode performs active exploitation and requires a Private Scope admin account.
              </p>
            </div>
          </div>
        </Panel>
      </Page>
    );
  }

  if (!status.enabled) {
    return (
      <Page>
        <PageHeader title="Brutal Mode" description="Active exploitation framework — currently disabled" />
        <Panel>
          <div className="p-6">
            <div className="flex items-center gap-3">
              <Skull className="h-6 w-6 text-red-500" />
              <div>
                <p className="text-sm font-semibold text-red-600 dark:text-red-400">Brutal Mode is disabled</p>
                <p className="text-xs text-[var(--text-muted)]">
                  This is the global kill switch. Set <code className="font-mono">BRUTAL_MODE_ENABLED=1</code> in{' '}
                  <code className="font-mono">backend/.env</code> and restart the backend to activate.
                </p>
              </div>
            </div>
          </div>
        </Panel>
      </Page>
    );
  }

  const categories = Object.entries(status.supported_categories ?? {});

  return (
    <Page>
      <PageHeader title="Brutal Mode" description="Active exploitation, shells, post-exploitation, lateral movement & exfiltration." />

      {banner ? (
        <div className="flex items-center gap-2 rounded-xl border border-red-500/40 bg-red-950/20 px-4 py-3">
          <ShieldAlert className="h-4 w-4 text-red-500" />
          <span className="text-xs font-bold text-red-400">{banner}</span>
        </div>
      ) : null}

      {!session ? (
        <Panel>
          <div className="p-4 space-y-4">
            <div className="flex items-start gap-3">
              <Flame className="h-5 w-5 shrink-0 text-amber-500" />
              <div className="text-xs text-[var(--text-muted)]">
                <p className="font-semibold text-[var(--text-default)]">Establish a session against an authorized target</p>
                <p className="mt-1">
                  Brutal Mode only targets the PhantomBank Lab or hosts in your Private Scope. Every action is written to the
                  audit trail. For a full demo, add <code className="font-mono">localhost</code> to Private Scope and run
                  <code className="font-mono"> /lab/phantombank</code> scans first so findings exist to exploit.
                </p>
              </div>
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="http://localhost:8000/lab/phantombank"
                className="font-mono"
              />
              <Select value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Pick from Private Scope…</option>
                {scope.map((entry) => (
                  <option key={entry.id} value={entry.target_url}>
                    {entry.target_url}
                  </option>
                ))}
              </Select>
            </div>

            <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-red-500/30 bg-red-950/10 p-3">
              <input
                type="checkbox"
                checked={ack || autoConfirm}
                onChange={(e) => setAck(e.target.checked)}
                disabled={autoConfirm}
                className="mt-0.5 accent-red-600"
              />
              <span className="text-xs text-[var(--text-muted)]">
                <span className="font-semibold text-red-500">Ownership confirmation.</span> I confirm that{' '}
                <code className="font-mono">{target || 'this target'}</code> is owned by me or that I have explicit written
                permission to perform active exploitation against it. Unauthorized exploitation is illegal.
                {autoConfirm ? (
                  <span className="mt-1 block text-[10px] font-semibold text-green-600 dark:text-green-400">
                    Auto-confirmed — admin account, target already in Private Scope (or PhantomBank Lab).
                  </span>
                ) : null}
              </span>
            </label>

            <label className="flex cursor-pointer items-center gap-2.5 rounded-xl border border-amber-500/30 bg-amber-950/10 p-3">
              <input
                type="checkbox"
                checked={simulation}
                onChange={(e) => setSimulation(e.target.checked)}
                className="mt-0.5 accent-amber-600"
              />
              <span className="text-xs text-[var(--text-muted)]">
                <span className="font-semibold text-amber-500">Simulation Mode.</span> Passive reconnaissance only — real DNS
                resolution and a single HTTP request (like a browser) against any website in Private Scope. No exploitation,
                shells, or loot; the session just reports the target's real intel.
              </span>
            </label>

            <div className="flex items-center gap-2">
              <Button variant="danger" onClick={establishSession} disabled={busy === 'session' || !target.trim()}>
                {busy === 'session' ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Unlock className="h-3.5 w-3.5" />}
                Establish Session
              </Button>
              {scope.length === 0 ? (
                <span className="text-[11px] text-[var(--text-subtle)]">No Private Scope targets yet — add one first (or use the lab).</span>
              ) : null}
            </div>
          </div>
        </Panel>
      ) : (
        <>
          {/* Session header */}
          <Panel>
            <div className="p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Crosshair className="h-4 w-4 text-red-500" />
                    <span className="truncate font-mono text-xs font-semibold text-[var(--text-default)]">{session.target_url}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-[var(--text-subtle)]">
                    session {session.session_id.slice(0, 8)} · {session.loot_count} loot items ·{' '}
                    {new Date(session.created_at * 1000).toLocaleString()}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {!session.simulation ? (
                    <>
                      <Button variant="primary" onClick={openShell} disabled={busy === 'shell'}>
                        <Terminal className="h-3.5 w-3.5" /> Open Shell
                      </Button>
                      <Button variant="secondary" onClick={() => runAction('lateral', `/api/brutal/sessions/${session.session_id}/lateral`)} disabled={busy === 'lateral'}>
                        <MoveRight className="h-3.5 w-3.5" /> Lateral Movement
                      </Button>
                      <Button variant="secondary" onClick={() => runAction('persist', `/api/brutal/sessions/${session.session_id}/persist`, { kind: 'cron' })} disabled={busy === 'persist'}>
                        <Flame className="h-3.5 w-3.5" /> Persistence
                      </Button>
                      <Button variant="secondary" onClick={() => runAction('exfil', `/api/brutal/sessions/${session.session_id}/exfil`)} disabled={busy === 'exfil'}>
                        <Archive className="h-3.5 w-3.5" /> Exfiltrate
                      </Button>
                    </>
                  ) : (
                    <span className="self-center text-[11px] text-[var(--text-subtle)]">
                      Passive-intel session — exploitation, shells, and exfiltration are disabled.
                    </span>
                  )}
                </div>
              </div>

              {exfilResult ? (
                <div className="mt-3 flex flex-wrap items-center gap-3 rounded-xl border border-green-500/30 bg-green-950/10 px-3 py-2">
                  <FileDown className="h-4 w-4 text-green-500" />
                  <span className="font-mono text-[11px] text-[var(--text-default)]">{exfilResult.filename}</span>
                  <span className="text-[11px] text-[var(--text-subtle)]">{(exfilResult.size_bytes / 1024).toFixed(1)} KB</span>
                  <span className="font-mono text-[10px] text-[var(--text-subtle)]">sha256:{exfilResult.sha256.slice(0, 12)}…</span>
                  <a href={`/api/brutal/exfil/${exfilResult.file_id}`} className="inline-flex items-center gap-1 text-[11px] font-semibold text-green-600 dark:text-green-400 hover:underline">
                    <Download className="h-3 w-3" /> Download
                  </a>
                </div>
              ) : null}
            </div>
          </Panel>

          <div className="grid gap-5 lg:grid-cols-2">
            {/* Exploit + payload panel */}
            <div className="space-y-5">
              <Panel>
                <div className="p-4">
                  {session.simulation ? (
                    <>
                      <h3 className="pb-2 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">Target Intelligence</h3>
                      <p className="pb-3 text-[11px] text-[var(--text-subtle)]">
                        Real passive recon only — DNS resolution and a single HTTP request (exactly what a browser does). No
                        exploitation was performed.
                      </p>
                      <div className="space-y-2 text-[11px]">
                        <div className="flex justify-between gap-3">
                          <span className="text-[var(--text-subtle)]">Hostname</span>
                          <span className="font-mono text-[var(--text-default)]">{session.sim_intel?.hostname ?? '—'}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-[var(--text-subtle)]">IP</span>
                          <span className="font-mono text-[var(--text-default)]">{session.sim_intel?.ip ?? '—'}</span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-[var(--text-subtle)]">Tech stack</span>
                          <span className="font-mono text-[var(--text-default)]">
                            {(session.sim_intel?.tech_stack?.length ? session.sim_intel.tech_stack.join(', ') : '—')}
                          </span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-[var(--text-subtle)]">HTTP status</span>
                          <span className="font-mono text-[var(--text-default)]">
                            {String(session.sim_intel?.http?.status_code ?? '—')}
                          </span>
                        </div>
                        <div className="flex justify-between gap-3">
                          <span className="text-[var(--text-subtle)]">Server</span>
                          <span className="font-mono text-[var(--text-default)]">{String(session.sim_intel?.http?.server ?? '—')}</span>
                        </div>
                      </div>
                      {session.sim_intel?.ports?.length ? (
                        <div className="mt-3">
                          <h4 className="pb-1 text-[10px] font-bold uppercase tracking-wide text-[var(--text-muted)]">Detected ports</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {session.sim_intel.ports.map((p) => (
                              <span key={p.port} className="rounded-md bg-[var(--surface-tertiary)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-muted)]">
                                {p.port}/{p.service}
                              </span>
                            ))}
                          </div>
                        </div>
                      ) : null}
                      {session.sim_intel?.endpoints?.length ? (
                        <div className="mt-3">
                          <h4 className="pb-1 text-[10px] font-bold uppercase tracking-wide text-[var(--text-muted)]">Probed endpoints</h4>
                          <div className="space-y-1">
                            {session.sim_intel.endpoints.map((e) => (
                              <div key={e.path} className="flex justify-between gap-3 font-mono text-[10px] text-[var(--text-muted)]">
                                <span>{e.path}</span>
                                <span className={e.interest ? 'text-amber-500' : ''}>{e.status}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null}
                    </>
                  ) : (
                    <>
                      <h3 className="pb-2 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">Auto-Exploitation</h3>
                      <div className="grid grid-cols-2 gap-2">
                        {categories.map(([key, label]) => (
                          <button
                            key={key}
                            type="button"
                            onClick={() => runAction('exploit', `/api/brutal/sessions/${session.session_id}/exploit`, { category: key })}
                            disabled={busy === 'exploit'}
                            className="flex items-center gap-2 rounded-xl border border-[var(--border-light)] px-3 py-2.5 text-left text-xs font-medium text-[var(--text-default)] transition-colors hover:border-red-500/50 hover:bg-red-950/10 disabled:opacity-40"
                          >
                            <Play className="h-3.5 w-3.5 text-red-500" />
                            <span className="truncate">{label}</span>
                            <ChevronRight className="ml-auto h-3.5 w-3.5 text-[var(--text-subtle)]" />
                          </button>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              </Panel>

              {/* Shell */}
              {shell && shellOpen ? (
                <div className="space-y-3">
                  <ShellConsole shellId={shell.shell_id} onClose={() => setShellOpen(false)} />
                  {payloads ? (
                    <Panel>
                      <div className="p-3">
                        <h3 className="pb-2 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">Reverse Shell Payloads</h3>
                        <div className="space-y-2">
                          {payloads.reverse_shell.map((payload) => (
                            <div key={payload.label} className="flex items-center gap-2 rounded-lg border border-[var(--border-light)] px-3 py-2">
                              <span className="w-24 shrink-0 text-[11px] font-semibold text-[var(--text-default)]">{payload.label}</span>
                              <code className="flex-1 truncate font-mono text-[10px] text-[var(--text-muted)]">{payload.payload}</code>
                              <Button variant="ghost" className="!px-2 !py-1 text-[10px]" onClick={() => copyText(payload.payload, 'Payload copied')}>
                                <Copy className="h-3 w-3" />
                              </Button>
                            </div>
                          ))}
                        </div>
                        <p className="mt-2 text-[10px] text-[var(--text-subtle)]">
                          Paste into the target to establish a connect-back. The lab console simulates the compromised host directly.
                        </p>
                      </div>
                    </Panel>
                  ) : null}
                </div>
              ) : null}

              {/* Post exploit */}
              {!session.simulation ? (
                <Panel>
                  <div className="p-4">
                    <h3 className="pb-2 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">Post-Exploitation</h3>
                    <p className="pb-3 text-[11px] text-[var(--text-subtle)]">
                      Requires an open shell. Enumerates users, network, processes and privilege-escalation surface.
                    </p>
                    <Button
                      variant="secondary"
                      onClick={() => runAction('post', `/api/brutal/sessions/${session.session_id}/post-exploit`)}
                      disabled={busy === 'post'}
                    >
                      <Terminal className="h-3.5 w-3.5" /> Run Enumeration + Privesc Checks
                    </Button>
                  </div>
                </Panel>
              ) : null}
            </div>

            {/* Timeline + loot */}
            <div className="space-y-5">
              <Panel>
                <div className="p-4">
                  <h3 className="pb-3 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">Exploitation Timeline</h3>
                  {session.timeline.length === 0 ? (
                    <EmptyState title="No operations yet" description="Run an exploitation flow to start the timeline." />
                  ) : (
                    <div className="space-y-1">
                      {[...session.timeline].reverse().map((event, index) => (
                        <div key={index} className="flex items-start gap-2.5 rounded-lg px-2 py-1.5 hover:bg-[var(--surface-hover)]">
                          <span className={`mt-0.5 shrink-0 rounded-md px-1.5 py-0.5 text-[9px] font-bold uppercase ${statusColor[event.status] ?? statusColor.pending}`}>
                            {event.status}
                          </span>
                          <div className="min-w-0">
                            <p className="text-[11px] font-medium text-[var(--text-default)]">
                              {actionLabel[event.action] ?? event.action}
                            </p>
                            <p className="truncate text-[10px] text-[var(--text-subtle)]">{event.detail}</p>
                          </div>
                          <span className="ml-auto shrink-0 font-mono text-[9px] text-[var(--text-subtle)]">{formatTime(event.ts)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </Panel>

              <Panel>
                <div className="p-4">
                  <h3 className="pb-3 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">
                    Loot ({session.loot_count})
                  </h3>
                  {session.loot.length === 0 ? (
                    <EmptyState title="Nothing collected yet" description="Exploit flows automatically capture loot (DB dumps, configs, keys, metadata)." />
                  ) : (
                    <div className="space-y-1.5">
                      {session.loot.map((item, index) => (
                        <details key={index} className="rounded-lg border border-[var(--border-light)]">
                          <summary className="flex cursor-pointer items-center gap-2 px-3 py-2 text-[11px] font-medium text-[var(--text-default)] hover:bg-[var(--surface-hover)]">
                            <span className="rounded-md bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] font-bold uppercase text-[var(--text-muted)]">
                              {item.kind}
                            </span>
                            <span className="truncate font-mono">{item.name}</span>
                            <span className="ml-auto text-[10px] text-[var(--text-subtle)]">{item.source}</span>
                          </summary>
                          <pre className="overflow-x-auto border-t border-[var(--border-light)] bg-[var(--surface-tertiary)] p-3 font-mono text-[10px] text-[var(--text-default)]">
                            {item.content}
                          </pre>
                        </details>
                      ))}
                    </div>
                  )}
                </div>
              </Panel>
            </div>
          </div>

          {/* Ops log */}
          <Panel>
            <div className="p-4">
              <h3 className="pb-3 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">Audit Trail (brutal_ops)</h3>
              {opsLog.length === 0 ? (
                <EmptyState title="No recorded operations" description="Actions will appear here once exploitation begins." />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[11px]">
                    <thead>
                      <tr className="text-[10px] uppercase text-[var(--text-subtle)]">
                        <th className="pb-2 pr-3">#</th>
                        <th className="pb-2 pr-3">Time</th>
                        <th className="pb-2 pr-3">Action</th>
                        <th className="pb-2 pr-3">Status</th>
                        <th className="pb-2">Detail</th>
                      </tr>
                    </thead>
                    <tbody>
                      {opsLog.map((op) => (
                        <tr key={op.id} className="border-t border-[var(--border-light)]">
                          <td className="py-1.5 pr-3 font-mono text-[var(--text-subtle)]">{op.id}</td>
                          <td className="py-1.5 pr-3 font-mono text-[var(--text-subtle)]">{op.created_at}</td>
                          <td className="py-1.5 pr-3 font-medium">{actionLabel[op.action] ?? op.action}</td>
                          <td className="py-1.5 pr-3">
                            <span className={`rounded-md px-1.5 py-0.5 text-[9px] font-bold uppercase ${statusColor[op.status] ?? statusColor.pending}`}>
                              {op.status}
                            </span>
                          </td>
                          <td className="max-w-[320px] truncate py-1.5 text-[var(--text-muted)]">{op.detail}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </Panel>
        </>
      )}

      <div className="flex items-start gap-2 rounded-xl border border-[var(--border-light)] bg-[var(--surface-tertiary)]/50 p-3">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
        <p className="text-[11px] text-[var(--text-subtle)]">
          Brutal Mode is restricted to the PhantomBank Lab and Private Scope targets, requires admin access and an explicit
          ownership acknowledgment, and records every action in the <code className="font-mono">brutal_ops</code> audit table.
          The lab simulation never touches real files, processes, or network hosts.
        </p>
      </div>
    </Page>
  );
}
