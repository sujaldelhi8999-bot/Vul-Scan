import { AnimatePresence, motion } from 'framer-motion';
import Layout from './Layout';
import UserMenu from './UserMenu';
import {
  Activity,
  Bell,
  Bomb,
  BrainCircuit,
  Bug,
  Building2,
  ChevronLeft,
  ClipboardList,
  Command,
  FileClock,
  FileSearch,
  FileText,
  GitBranch,
  HeartPulse,
  History,
  Home,
  Layers3,
  LockKeyhole,
  Menu,
  Network,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
  Skull,
  Sparkles,
  Stethoscope,
  Wrench,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';

import { usePhantomData } from '../../hooks/usePhantomData';
import { apiErrorMessage, askVulScan } from '../../services/api';
import { hasElevatedAccess } from '../../utils/access';
import { deriveAssets, deriveNotifications, deriveTechnologies, relativeTime, targetName } from '../../utils/derived';
import { Button, cx, Drawer, EmptyState, Select, StatusBadge } from '../ui/Primitives';
import { useAuth } from '../../context/AuthContext';
import LoginModal from '../LoginModal';

interface NavItem {
  label: string;
  path: string;
  icon: typeof Home;
}

const navGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'Overview',
    items: [
      { label: 'Dashboard', path: '/dashboard', icon: Home },
      { label: 'Defend Scan', path: '/scan', icon: Activity },
      { label: 'Local Code Analysis', path: '/multi-source', icon: Layers3 },
    ],
  },
  {
    label: 'Security',
    items: [
      { label: 'Findings', path: '/findings', icon: ShieldAlert },
      { label: 'Assets', path: '/assets', icon: Layers3 },
      { label: 'Reports', path: '/history', icon: FileText },
      { label: 'Agents', path: '/agents', icon: Network },
      { label: 'GitHub', path: '/github', icon: GitBranch },
    ],
  },
  {
    label: 'Operations',
    items: [
      { label: 'Authorized Testing', path: '/authorized-testing', icon: LockKeyhole },
      { label: 'DoS Testing', path: '/private/dos', icon: Bomb },
      { label: 'GitHub Repo Analysis', path: '/code-analysis', icon: FileSearch },
      { label: 'Brutal Mode', path: '/brutal', icon: Skull },
    ],
  },
  {
    label: 'System',
    items: [
      { label: 'Attack Intelligence', path: '/intelligence', icon: BrainCircuit },
      { label: 'Attack Planner', path: '/attack-planner', icon: Bug },
      { label: 'Scan Quality', path: '/quality', icon: ClipboardList },
      { label: 'Enterprise', path: '/enterprise', icon: Building2 },
      { label: 'System Health', path: '/system-health', icon: HeartPulse },
      { label: 'Notifications', path: '/notifications', icon: Bell },
      { label: 'Settings', path: '/settings', icon: Settings },
    ],
  },
];

const routeDetails: Record<string, { title: string; description: string }> = {
  '/dashboard': { title: 'Security Overview', description: 'Monitor posture, active operations, findings, and recent security activity.' },
  '/scan': { title: 'Defend Scan', description: 'Run passive security assessments against targets.' },
  '/findings': { title: 'Findings', description: 'Triage detected vulnerabilities and risks.' },
  '/assets': { title: 'Assets', description: 'Monitored targets from scan history.' },
  '/cve': { title: 'CVE Intelligence', description: 'Technology correlation with known vulnerabilities.' },
  '/remediation': { title: 'Remediation', description: 'Prioritize and verify fixes.' },
  '/agents': { title: 'Agents', description: 'Observe agent operations and status.' },
  '/history': { title: 'Reports & History', description: 'Browse past assessments and reports.' },
  '/audit-logs': { title: 'Audit Logs', description: 'Append-only operational records.' },
  '/self-audit': { title: 'Self Audit', description: 'VulScan evaluates itself.' },
  '/notifications': { title: 'Notifications', description: 'Events from findings and system activity.' },
  '/system-health': { title: 'System Health', description: 'Backend, realtime, and agent availability.' },
  '/settings': { title: 'Settings', description: 'Runtime configuration reference.' },
  '/multi-source': { title: 'Local Code Analysis', description: 'Run local ZIP and path-based code analysis.' },
  '/authorized-testing': { title: 'Authorized Testing', description: 'Controlled security testing for approved targets.' },
  '/private/dos': { title: 'DoS Testing', description: 'Simulate Denial of Service attacks on authorized targets.' },
  '/code-analysis': { title: 'GitHub Repo Analysis', description: 'Scan GitHub repositories for secrets, insecure patterns, and vulnerable dependencies.' },
  '/brutal': { title: 'Brutal Mode', description: 'Active exploitation, interactive shells, post-exploitation, lateral movement & exfiltration.' },
  '/attack-planner': { title: 'Attack Planner', description: 'Analyze targets and generate prioritized attack plans with realistic commands.' },
  '/quality': { title: 'Scan Quality', description: 'Learning-driven accuracy and tuning recommendations.' },
  '/profile': { title: 'Profile', description: 'Your account details and session information.' },
  '/enterprise': { title: 'Enterprise Workspace', description: 'Enterprise requests, approvals, and notifications.' },
};

function currentRoute(pathname: string) {
  if (pathname.startsWith('/report/')) return { title: 'Security Assessment', description: 'Completed scan report and evidence.' };
  return routeDetails[pathname] ?? routeDetails['/dashboard'];
}

/* ── Sidebar ── */

function Sidebar({
  collapsed,
  mobileOpen,
  onCloseMobile,
  onToggleCollapse,
}: {
  collapsed: boolean;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onToggleCollapse: () => void;
}) {
  const location = useLocation();
  const { user } = useAuth();
  const sidebar = (
    <div className="flex h-full flex-col bg-[var(--sidebar-canvas)]">
      {/* Logo area */}
      <div className="flex items-center justify-between px-4 py-4">
        <Link to="/" className="min-w-0" onClick={onCloseMobile}>
          <div className="flex items-center gap-2.5">
            <div className="flex h-7 w-7 items-center justify-center overflow-hidden rounded-lg">
              <img src="/favicon.png" alt="VulScan logo" className="h-full w-full object-contain" />
            </div>
            {!collapsed ? (
              <div>
                <div className="text-sm font-bold tracking-tight text-[var(--text-strong)]">VulScan</div>
                <div className="text-[9px] font-medium text-[var(--text-subtle)]">Security Operations</div>
              </div>
            ) : null}
          </div>
        </Link>
        <button
          className="rounded-md p-1.5 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)] lg:hidden"
          onClick={onCloseMobile}
          aria-label="Close navigation"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 pb-4 scrollbar-compact">
        {navGroups.map((group) => {
          const items = group.items.filter(
            (item) => {
              // Admin-only pages
              const elevatedOnly = ['/code-analysis', '/brutal', '/private/dos', '/intelligence', '/attack-planner', '/quality'];
              if (elevatedOnly.includes(item.path) && !hasElevatedAccess(user)) return false;
              if (item.path === '/enterprise' && !user?.enterpriseId) return false;
              return true;
            },
          );
          if (items.length === 0) return null;
          return (
          <div key={group.label} className="mt-5 first:mt-0">
            {!collapsed ? (
              <div className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--text-subtle)]">
                {group.label}
              </div>
            ) : null}
            <div className="space-y-0.5">
              {items.map((item) => {
                const Icon = item.icon;
                const isActive = item.path === '/'
                  ? location.pathname === '/'
                  : location.pathname.startsWith(item.path);
                return (
                  <NavLink
                    key={`${group.label}-${item.path}`}
                    to={item.path}
                    end={item.path === '/'}
                    onClick={onCloseMobile}
                    className={cx(
                      'group relative flex items-center gap-2.5 rounded-[var(--radius-control)] px-2 py-1.5 text-xs font-semibold transition-all duration-150 active:scale-[0.98] active:translate-y-[0.5px]',
                      isActive
                        ? 'bg-[var(--surface-selected)] text-[var(--brand)]'
                        : 'text-[var(--text-muted)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-strong)]',
                      collapsed && 'justify-center',
                    )}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    {!collapsed ? <span className="truncate">{item.label}</span> : null}
                    {isActive ? (
                      <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-r-full bg-[var(--brand)]" />
                    ) : null}
                  </NavLink>
                );
              })}
            </div>
          </div>
          );
        })}
      </nav>

      {/* Bottom area */}
      <div className="border-t border-[var(--border-light)] p-3">
        <button
          onClick={onToggleCollapse}
          className="flex w-full items-center justify-center gap-2 rounded-lg px-2 py-2 text-xs text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]"
        >
          <ChevronLeft className={cx('h-3.5 w-3.5 transition-transform', collapsed && 'rotate-180')} />
          {!collapsed ? 'Collapse' : null}
        </button>
      </div>
    </div>
  );

  return (
    <>
      <aside
        className={cx(
          'fixed inset-y-0 left-0 z-30 hidden border-r border-[var(--border-light)] transition-all duration-200 lg:block',
          collapsed ? 'w-[56px]' : 'w-[232px]',
        )}
      >
        {sidebar}
      </aside>
      <AnimatePresence>
        {mobileOpen ? (
          <>
            <motion.div
              className="fixed inset-0 z-40 bg-black/50 lg:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={onCloseMobile}
            />
            <motion.aside
              className="fixed inset-y-0 left-0 z-50 w-[272px] border-r border-[var(--border-light)] bg-[var(--sidebar-canvas)] lg:hidden"
              initial={{ x: -300 }}
              animate={{ x: 0 }}
              exit={{ x: -300 }}
              transition={{ duration: 0.2 }}
            >
              {sidebar}
            </motion.aside>
          </>
        ) : null}
      </AnimatePresence>
    </>
  );
}

/* ── System Status Popover ── */

function SystemStatusPopover({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { health, realtimeState, realtimeHealthy } = usePhantomData();
  if (!open) return null;
  const rows: Array<[string, string]> = [
    ['Backend API', health ? 'Connected' : 'Unavailable'],
    ['WebSocket', realtimeState === 'open' ? 'Connected' : realtimeState],
    ['Database', health?.database === 'available' ? 'Healthy' : 'Unavailable'],
    ['Agents', health?.agents === 'available' ? 'Available' : 'Unavailable'],
    ['Scheduler', health?.scheduler ?? 'unavailable'],
  ];
  return (
    <div className="absolute right-0 top-10 z-30 w-72 rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)] p-3.5 shadow-[var(--shadow-float)]">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-xs font-semibold text-[var(--text-strong)]">System Status</div>
        <button onClick={onClose} className="rounded p-0.5 text-[var(--text-subtle)] hover:text-[var(--text-default)]" aria-label="Close">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="space-y-1">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between rounded px-2.5 py-1.5 text-xs">
            <span className="text-[var(--text-muted)]">{label}</span>
            <StatusBadge status={value} />
          </div>
        ))}
      </div>
      <div className="mt-2.5 text-[10px] text-[var(--text-subtle)]">
        Overall: {realtimeHealthy ? 'All systems online' : 'Connection issue detected'}
      </div>
    </div>
  );
}

/* ── Global Search ── */

function GlobalSearch() {
  const navigate = useNavigate();
  const { scans, findings, agents, artifactsByScanId } = usePhantomData();
  const [query, setQuery] = useState('');
  const assets = useMemo(() => deriveAssets(scans, findings), [scans, findings]);
  const technologies = useMemo(() => deriveTechnologies(artifactsByScanId), [artifactsByScanId]);
  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return [];
    return [
      ...findings
        .filter((item) => `${item.title} ${item.category} ${item.target} ${item.cve_id ?? ''}`.toLowerCase().includes(needle))
        .slice(0, 4)
        .map((finding) => ({ label: finding.title, detail: finding.target, path: '/findings', icon: ShieldAlert })),
      ...assets
        .filter((asset) => `${asset.name} ${asset.target_url}`.toLowerCase().includes(needle))
        .slice(0, 3)
        .map((asset) => ({ label: asset.name, detail: `${asset.findings.length} findings`, path: '/assets', icon: Layers3 })),
      ...scans
        .filter((scan) => `${scan.target_url} ${scan.mode} ${scan.status}`.toLowerCase().includes(needle))
        .slice(0, 3)
        .map((scan) => ({ label: targetName(scan.target_url), detail: `${scan.status}`, path: `/report/${scan.id}`, icon: FileText })),
      ...technologies
        .filter((tech) => tech.name.toLowerCase().includes(needle))
        .slice(0, 3)
        .map((tech) => ({ label: tech.name, detail: 'Technology', path: '/cve', icon: Bug })),
      ...agents
        .filter((agent) => agent.name.toLowerCase().includes(needle))
        .slice(0, 3)
        .map((agent) => ({ label: agent.name, detail: agent.status, path: '/agents', icon: Network })),
    ];
  }, [agents, assets, findings, query, scans, technologies]);

  return (
    <div className="relative w-[200px] lg:w-[260px]">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-subtle)]" />
      <input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search targets, findings, agents..."
        className="h-8 w-full rounded-[var(--radius-control)] border border-[var(--border-light)] bg-[var(--surface-secondary)] pl-8 pr-3 text-xs text-[var(--text-default)] outline-none transition-colors placeholder:text-[var(--text-subtle)] focus:border-[var(--brand)] focus:bg-white focus:ring-2 focus:ring-[var(--brand)]/10"
      />
      {query ? (
        <div className="absolute right-0 top-9 z-30 w-full overflow-hidden rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)] p-1.5 shadow-[var(--shadow-float)]">
          {results.length ? (
            results.map((r) => {
              const Icon = r.icon;
              return (
                <button
                  key={`${r.path}-${r.label}`}
                  onClick={() => { navigate(r.path); setQuery(''); }}
                  className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left hover:bg-[var(--surface-hover)]"
                >
                  <Icon className="h-3.5 w-3.5 shrink-0 text-[var(--brand)]" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs text-[var(--text-strong)]">{r.label}</span>
                    <span className="block truncate text-[10px] text-[var(--text-muted)]">{r.detail}</span>
                  </span>
                </button>
              );
            })
          ) : (
            <div className="px-3 py-5 text-center text-xs text-[var(--text-muted)]">No results found.</div>
          )}
        </div>
      ) : null}
    </div>
  );
}

/* ── Command Palette ── */

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const { scans } = usePhantomData();
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const lastScan = scans[0];

  const actionGroups = [
    {
      label: 'Navigation',
      actions: [
        { label: 'Dashboard', path: '/dashboard', icon: Home, shortcut: 'G D' },
        { label: 'Findings', path: '/findings', icon: ShieldAlert, shortcut: 'G F' },
        { label: 'Assets', path: '/assets', icon: Layers3, shortcut: 'G A' },
        { label: 'Remediation', path: '/remediation', icon: Wrench, shortcut: 'G R' },
        { label: 'Agents', path: '/agents', icon: Network, shortcut: 'G N' },
      ],
    },
    {
      label: 'Actions',
      actions: [
        { label: 'Start Defend Scan', path: '/scan', icon: Activity, shortcut: 'S S' },
        { label: 'Authorized Testing', path: '/authorized-testing', icon: LockKeyhole, shortcut: 'S T' },
        { label: 'Self Audit', path: '/self-audit', icon: Stethoscope, shortcut: 'S A' },
        { label: 'Last Scan Report', path: lastScan ? `/report/${lastScan.id}` : '/history', icon: FileClock, shortcut: 'S L' },
      ],
    },
  ];

  const filtered = actionGroups
    .map((g) => ({
      ...g,
      actions: g.actions.filter((a) => a.label.toLowerCase().includes(query.toLowerCase())),
    }))
    .filter((g) => g.actions.length > 0);

  useEffect(() => { setActiveIndex(0); }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    const total = filtered.reduce((sum, g) => sum + g.actions.length, 0);
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIndex((prev) => Math.min(prev + 1, total - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIndex((prev) => Math.max(prev - 1, 0)); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      let idx = 0;
      for (const group of filtered) {
        for (const action of group.actions) {
          if (idx === activeIndex) { navigate(action.path); onClose(); return; }
          idx++;
        }
      }
    }
  };

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 px-4 pt-[12vh]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            className="w-full max-w-md overflow-hidden rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)] shadow-[var(--shadow-float)]"
            initial={{ y: 12, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 12, opacity: 0 }}
            transition={{ duration: 0.15 }}
            onClick={(e) => e.stopPropagation()}
            onKeyDown={handleKeyDown}
            role="combobox"
            aria-expanded="true"
            aria-haspopup="listbox"
          >
            <div className="flex items-center gap-2.5 border-b border-[var(--border-light)] px-4 py-2.5">
              <Command className="h-4 w-4 shrink-0 text-[var(--text-subtle)]" />
              <input
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search pages and actions..."
                className="flex-1 bg-transparent text-xs text-[var(--text-strong)] outline-none placeholder:text-[var(--text-subtle)]"
                aria-label="Command search"
              />
              <kbd className="hidden rounded border border-[var(--border-light)] px-1.5 py-0.5 text-[10px] text-[var(--text-subtle)] md:inline-block">ESC</kbd>
            </div>
            <div className="max-h-80 overflow-y-auto p-1.5" role="listbox">
              {filtered.length ? (
                filtered.map((group, gi) => (
                  <div key={group.label}>
                    <div className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">
                      {group.label}
                    </div>
                    {group.actions.map((action, ai) => {
                      const globalIdx = filtered.slice(0, gi).reduce((sum, g) => sum + g.actions.length, 0) + ai;
                      const Icon = action.icon;
                      const isActive = globalIdx === activeIndex;
                      return (
                        <button
                          key={action.path}
                          role="option"
                          aria-selected={isActive}
                          onClick={() => { navigate(action.path); onClose(); }}
                          onMouseEnter={() => setActiveIndex(globalIdx)}
                          className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-xs transition-colors ${
                            isActive ? 'bg-[var(--surface-selected)] text-[var(--brand)]' : 'text-[var(--text-default)] hover:bg-[var(--surface-hover)]'
                          }`}
                        >
                          <Icon className={`h-3.5 w-3.5 ${isActive ? 'text-[var(--brand)]' : 'text-[var(--text-muted)]'}`} />
                          <span className="flex-1">{action.label}</span>
                          {action.shortcut ? (
                            <kbd className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${
                              isActive ? 'border-[var(--brand)]/30 text-[var(--brand)]' : 'border-[var(--border-light)] text-[var(--text-subtle)]'
                            }`}>{action.shortcut}</kbd>
                          ) : null}
                        </button>
                      );
                    })}
                  </div>
                ))
              ) : (
                <div className="px-3 py-6 text-center text-xs text-[var(--text-muted)]">
                  No results for &quot;{query}&quot;
                </div>
              )}
            </div>
            {!query ? (
              <div className="border-t border-[var(--border-light)] px-4 py-2 text-[10px] text-[var(--text-subtle)]">
                Use ↑ ↓ to navigate, Enter to select, Esc to close
              </div>
            ) : null}
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}

/* ── Notification Drawer ── */

function NotificationDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { findings, logs } = usePhantomData();
  const notices = useMemo(() => deriveNotifications(findings, logs), [findings, logs]);
  return (
    <Drawer title="Notifications" open={open} onClose={onClose}>
      <div className="space-y-2">
        {notices.length ? (
          notices.map((notice) => (
            <div key={notice.id} className="rounded-xl border border-[var(--border-light)] p-3.5">
              <div className="flex items-center justify-between gap-3">
                <span className="text-[10px] font-semibold text-[var(--text-muted)]">{notice.type}</span>
                <span className="text-[10px] text-[var(--text-muted)]">{relativeTime(notice.timestamp)}</span>
              </div>
              <div className="mt-1.5 text-xs font-medium text-[var(--text-strong)]">{notice.title}</div>
              <div className="mt-1 text-xs text-[var(--text-muted)] leading-relaxed">{notice.detail}</div>
            </div>
          ))
        ) : (
          <EmptyState title="No notifications" description="No notifications yet." compact />
        )}
      </div>
    </Drawer>
  );
}

/* ── Ask VulScan Drawer ── */

function AskVulScanDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { scans, artifactsByScanId } = usePhantomData();
  const completedScans = useMemo(() => scans.filter((scan) => scan.status === 'complete'), [scans]);
  const [scanId, setScanId] = useState<number>(0);
  useEffect(() => {
    if (!scanId && completedScans[0]) setScanId(completedScans[0].id);
  }, [completedScans, scanId]);
  const selectedScan = completedScans.find((scan) => scan.id === scanId) ?? completedScans[0];
  const prompts = selectedScan ? artifactsByScanId[selectedScan.id]?.ai_analyst_output?.suggested_prompts ?? [] : [];
  const [question, setQuestion] = useState('What should I update to fix these findings?');
  const [answer, setAnswer] = useState<string | null>(null);
  const [citations, setCitations] = useState<Array<{ label?: string; title?: string; endpoint?: string }>>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [aiNote, setAiNote] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setLoading(false);
      setError(null);
      setAiNote(null);
    }
  }, [open]);

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!selectedScan || !question.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const response = await askVulScan(selectedScan.id, question.trim());
      setAnswer(response.answer);
      setAiNote(response.ai_note ?? null);
      setCitations(response.citations.map((c) => ({ label: c.label, title: c.title, endpoint: c.endpoint })));
    } catch (err) {
      setError(apiErrorMessage(err, 'Ask VulScan could not answer from current evidence.'));
    } finally { setLoading(false); }
  };

  return (
    <Drawer title="Ask VulScan" open={open} onClose={onClose}>
      {selectedScan ? (
        <div className="space-y-4">
          <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5 text-xs text-[var(--text-muted)]">
            Answers grounded in scan {selectedScan.id} for {targetName(selectedScan.target_url)}.
          </div>
          <div>
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">Scan</div>
            <Select value={selectedScan.id} onChange={(e) => { setScanId(Number(e.target.value)); setAnswer(null); setCitations([]); setAiNote(null); }}>
              {completedScans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} — {targetName(scan.target_url)}
                </option>
              ))}
            </Select>
          </div>
          <form onSubmit={submit} className="space-y-2">
            <textarea
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              className="min-h-20 w-full rounded-[var(--radius-control)] border border-[var(--border-light)] bg-white p-3 text-xs text-[var(--text-default)] outline-none transition-colors placeholder:text-[var(--text-subtle)] focus:border-[var(--brand)] focus:ring-2 focus:ring-[var(--brand)]/10"
              placeholder="Ask about priorities, score, or remediation..."
            />
            <Button type="submit" disabled={loading || !question.trim()}>
              {loading ? 'Thinking...' : 'Ask'}
            </Button>
          </form>
          {prompts.length ? (
            <div>
              <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">Suggested</div>
              <div className="flex flex-wrap gap-1.5">
                {prompts.slice(0, 6).map((prompt) => (
                  <button
                    key={prompt}
                    onClick={() => setQuestion(prompt)}
                    className="rounded-lg bg-[var(--surface-hover)] px-2.5 py-1 text-[10px] text-[var(--text-muted)] hover:bg-[var(--surface-tertiary)]"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : null}
          {error ? <ErrorState title="Error" description={error} /> : null}
          {aiNote ? (
            <div className="rounded-xl border border-[var(--warning-soft)] bg-[var(--warning-soft)]/40 p-3.5 text-xs text-[var(--warning)]">
              <div className="mb-1 font-semibold">AI unavailable</div>
              <div>{aiNote}</div>
            </div>
          ) : null}
          {answer ? (
            <div className="rounded-xl bg-[var(--surface-secondary)] p-3.5 text-xs leading-relaxed text-[var(--text-default)]">{answer}</div>
          ) : null}
          {citations.length ? (
            <div>
              <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">Citations</div>
              {citations.map((c, i) => (
                <div key={`${c.label}-${i}`} className="mb-1 rounded-xl bg-[var(--surface-secondary)] p-3 text-[10px] text-[var(--text-muted)]">
                  <div className="font-medium text-[var(--text-default)]">{c.label ?? `Citation ${i + 1}`}</div>
                  <div>{c.title}</div>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      ) : (
        <EmptyState title="No scan data" description="Run a scan before asking questions." compact />
      )}
    </Drawer>
  );
}

function ErrorState({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-xl border border-[var(--danger-soft)] bg-[var(--danger-soft)]/30 p-3.5 text-xs text-[var(--danger)]">
      <div className="flex items-start gap-2">
        <span className="mt-0.5 shrink-0 font-bold">!</span>
        <div>
          <div className="font-semibold">{title}</div>
          <div className="mt-0.5 text-[var(--text-default)]">{description}</div>
        </div>
      </div>
    </div>
  );
}

/* ── Main App Shell ── */

export default function AppShell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const { health, realtimeHealthy, realtimeState, refresh, refreshing, executionStatus, executionActive } = usePhantomData();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('vulscan:sidebar') === 'collapsed');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [askOpen, setAskOpen] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);
  const { user } = useAuth();
  const details = currentRoute(location.pathname);

  const sidebarWidth = collapsed ? 56 : 232;

  useEffect(() => { localStorage.setItem('vulscan:sidebar', collapsed ? 'collapsed' : 'expanded'); }, [collapsed]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setCommandOpen(true); }
      if (e.key === 'Escape') { setCommandOpen(false); setNotificationsOpen(false); setAskOpen(false); setStatusOpen(false); }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="min-h-screen bg-[var(--app-canvas)] text-[var(--text-default)]">
      <Sidebar
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
        onToggleCollapse={() => setCollapsed((v) => !v)}
      />

      <div className={cx('min-h-screen transition-all duration-200', collapsed ? 'lg:pl-14' : 'lg:pl-56')}>
        {/* Top bar */}
        <header className="sticky top-0 z-20 border-b border-[var(--border-light)] bg-[var(--topbar-canvas)] backdrop-blur-[8px]">
          <div className="flex h-[48px] items-center gap-3 px-5">
            <button
              className="rounded-[var(--radius-control)] border border-[var(--border-light)] p-2 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] lg:hidden"
              onClick={() => setMobileOpen(true)}
              aria-label="Open navigation"
            >
              <Menu className="h-4 w-4" />
            </button>

            {/* Breadcrumb-style title */}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <h1 className="truncate text-sm font-semibold text-[var(--text-strong)]">{details.title}</h1>
              </div>
            </div>

            {/* Execution indicator */}
            {executionActive && executionStatus ? (
              <Link
                to={executionStatus.execution_type === 'AUTHORIZED_TEST' ? '/authorized-testing' : '/scan'}
                className="flex items-center gap-1.5 rounded-[var(--radius-control)] border border-[var(--warning-soft)] px-2.5 py-1.5 text-[10px] font-semibold text-[var(--warning)] hover:bg-[var(--warning-soft)]"
              >
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--warning)]" />
                <span className="hidden sm:inline">
                  {executionStatus.execution_type === 'AUTHORIZED_TEST' ? 'Active Test' : executionStatus.execution_type === 'DEFEND_SCAN' ? 'Scanning' : 'Running'}
                </span>
                <span className="font-mono">{executionStatus.progress_percent}%</span>
              </Link>
            ) : null}



            {/* Command palette trigger */}
            <button
              onClick={() => setCommandOpen(true)}
              className="hidden md:inline-flex items-center gap-1.5 rounded-[var(--radius-control)] border border-[var(--border-light)] px-2.5 py-1.5 text-xs text-[var(--text-subtle)] hover:bg-[var(--surface-hover)]"
            >
              <Command className="h-3 w-3" />
              <kbd className="text-[10px] text-[var(--text-subtle)]">K</kbd>
            </button>

            <button
              onClick={() => setAskOpen(true)}
              className="rounded-[var(--radius-control)] p-1.5 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]"
              aria-label="Ask VulScan"
            >
              <Sparkles className="h-4 w-4" />
            </button>

            <button
              onClick={() => setNotificationsOpen(true)}
              className="rounded-[var(--radius-control)] p-1.5 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]"
              aria-label="Notifications"
            >
              <Bell className="h-4 w-4" />
            </button>

            <div className="relative">
              <button
                onClick={() => setStatusOpen((v) => !v)}
                className="flex items-center gap-1.5 rounded-[var(--radius-control)] border border-[var(--border-light)] px-2.5 py-1.5 text-xs text-[var(--text-subtle)] hover:bg-[var(--surface-hover)]"
                aria-label="System status"
              >
                <span className={cx('h-2 w-2 rounded-full', realtimeHealthy ? 'bg-[var(--success)]' : 'bg-[var(--warning)]')} />
                <span className="hidden sm:inline text-[var(--text-muted)]">{realtimeHealthy ? 'Online' : 'Issue'}</span>
              </button>
              <SystemStatusPopover open={statusOpen} onClose={() => setStatusOpen(false)} />
            </div>

            {user ? (
              <UserMenu />
            ) : (
              <button
                onClick={() => setShowLoginModal(true)}
                className="ml-2 inline-flex items-center gap-1.5 rounded-[var(--radius-control)] border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-800 hover:bg-amber-100 hover:border-amber-300 transition-all active:scale-[0.98] active:translate-y-[0.5px]"
              >
                <LockKeyhole className="h-3.5 w-3.5" /> Private Console
              </button>
            )}

            <button
              onClick={() => void refresh()}
              className="rounded-[var(--radius-control)] p-1.5 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)] transition-colors"
              disabled={refreshing}
              aria-label="Refresh data"
              title="Refresh Data"
            >
              <RefreshCw className={cx('h-3.5 w-3.5', refreshing && 'animate-spin')} />
            </button>
          </div>
        </header>

        {/* Degraded banner — only when backend health endpoint reports degraded */}
        {health?.status === 'degraded' ? (
          <div className="mx-5 mt-4 rounded-xl border border-[var(--warning-soft)] bg-[var(--warning-soft)]/40 px-4 py-2.5 text-xs text-[var(--warning)]">
            Backend telemetry is degraded. Data reflects the latest reachable state.
          </div>
        ) : null}

        {/* Main content */}
        <main className="px-5 py-6 lg:px-6">{children}</main>
      </div>

      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} />
      <NotificationDrawer open={notificationsOpen} onClose={() => setNotificationsOpen(false)} />
      <AskVulScanDrawer open={askOpen} onClose={() => setAskOpen(false)} />
      <LoginModal isOpen={showLoginModal} onClose={() => setShowLoginModal(false)} />
    </div>
  );
}
