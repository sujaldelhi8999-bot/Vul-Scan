import { AnimatePresence, motion } from 'framer-motion';
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  Info,
  Loader2,
  ShieldCheck,
  X,
  XCircle,
} from 'lucide-react';

import type { AgentApplicability, AgentStateDetail, Severity } from '../../types';

export function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(' ');
}

export function Page({ children }: { children: ReactNode }) {
  return <div className="space-y-6">{children}</div>;
}

export function PageHeader({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-[var(--text-strong)]">{title}</h1>
        {description ? <p className="mt-1 text-sm leading-relaxed text-[var(--text-muted)]">{description}</p> : null}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </div>
  );
}

export function Section({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx('rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)]', className)}>
      {children}
    </div>
  );
}

export function Panel({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx('rounded-[var(--radius-panel)] border border-[var(--border-light)] bg-[var(--surface-primary)] shadow-[var(--shadow-card)] overflow-hidden', className)}>
      {children}
    </div>
  );
}

export function SectionHeader({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-2 border-b border-[var(--border-light)] bg-[var(--surface-secondary)]/60">
      <div className="min-w-0">
        <h3 className="text-[11px] font-semibold text-[var(--text-strong)] uppercase tracking-wider">{title}</h3>
        {description ? <p className="mt-0.5 text-[10px] text-[var(--text-muted)] leading-tight">{description}</p> : null}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </div>
  );
}

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'amber';

export function Button({
  children,
  variant = 'secondary',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      {...props}
      className={cx(
        'inline-flex items-center justify-center gap-1.5 rounded-[var(--radius-control)] px-3 py-1.5 text-xs font-medium transition-all duration-150',
        'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--brand)]/50',
        'disabled:pointer-events-none disabled:opacity-40',
        'active:scale-[0.98] active:translate-y-[0.5px]',
        variant === 'primary' && 'bg-[var(--brand)] text-white shadow-[0_1px_2px_rgba(37,99,235,0.2)] hover:bg-[var(--brand-hover)]',
        variant === 'secondary' && 'border border-[var(--border-default)] bg-white text-[var(--text-default)] hover:bg-[var(--surface-hover)] hover:border-[var(--border-strong)]',
        variant === 'ghost' && 'text-[var(--text-muted)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]',
        variant === 'danger' && 'border border-[var(--danger-border)] bg-[var(--danger-soft)] text-[var(--danger)] hover:bg-[var(--danger-soft)]/80',
        variant === 'amber' && 'border border-[var(--warning-border)] bg-[var(--warning-soft)] text-[var(--warning)] hover:bg-[var(--warning-soft)]/80',
        className,
      )}
    >
      {children}
    </button>
  );
}

export function Input({
  className = '',
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cx(
        'h-8 w-full rounded-[var(--radius-control)] border border-[var(--border-default)] bg-white px-2.5 text-xs text-[var(--text-default)] outline-none transition-colors duration-150',
        'placeholder:text-[var(--text-subtle)]',
        'hover:border-[var(--border-strong)] focus:border-[var(--brand)] focus:ring-2 focus:ring-[var(--brand)]/8',
        className,
      )}
    />
  );
}

export function Select({
  className = '',
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={cx(
        'h-8 rounded-[var(--radius-control)] border border-[var(--border-default)] bg-white px-2 text-xs text-[var(--text-default)] outline-none transition-colors duration-150 hover:border-[var(--border-strong)] focus:border-[var(--brand)] focus:ring-2 focus:ring-[var(--brand)]/8',
        className,
      )}
    />
  );
}

const severityConfig: Record<Severity, { bg: string; text: string; dot: string; label: string }> = {
  CRITICAL: { bg: 'bg-[var(--danger-soft)]', text: 'text-[var(--danger)]', dot: 'bg-[var(--danger)]', label: 'CRIT' },
  HIGH: { bg: 'bg-[var(--warning-soft)]', text: 'text-[var(--warning)]', dot: 'bg-[var(--warning)]', label: 'HIGH' },
  MEDIUM: { bg: 'bg-amber-50', text: 'text-amber-700', dot: 'bg-amber-500', label: 'MED' },
  LOW: { bg: 'bg-[var(--info-soft)]', text: 'text-[var(--info)]', dot: 'bg-[var(--info)]', label: 'LOW' },
  INFO: { bg: 'bg-gray-50', text: 'text-gray-500', dot: 'bg-gray-400', label: 'INFO' },
};

export function SeverityBadge({ severity, compact }: { severity: Severity; compact?: boolean }) {
  const cfg = severityConfig[severity];
  return (
    <span className={cx('inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-semibold text-[10px]', cfg.bg, cfg.text)}>
      <span className={cx('h-1.5 w-1.5 rounded-full shrink-0', cfg.dot)} />
      {compact ? cfg.label : severity}
    </span>
  );
}

export function DotSeverity({ severity }: { severity: Severity }) {
  const cfg = severityConfig[severity];
  return <span className={cx('h-1.5 w-1.5 rounded-full shrink-0', cfg.dot)} title={severity} />;
}

const statusStyle = (status: string) => {
  const n = status.toLowerCase();
  const ok = n.includes('complete') || n.includes('connected') || n.includes('verified') || n.includes('healthy') || n === 'pass' || n === 'live' || n === 'resolved' || n === 'fix_verified';
  const active = n.includes('running') || n.includes('active') || n.includes('queued') || n.includes('progress') || n.includes('starting') || n.includes('pending') || n === 'open' || n === 'in_progress';
  const err = n.includes('cancel') || n.includes('error') || n.includes('failed') || n.includes('critical') || n.includes('blocked') || n === 'false_positive' || n === 'issue_still_present';
  const warn = n.includes('attention') || n.includes('degraded') || n.includes('warning') || n.includes('na') || n.includes('expired') || n.includes('revoked');
  if (ok) return 'bg-[var(--success-soft)] text-[var(--success)]';
  if (active) return 'bg-[var(--brand-soft)] text-[var(--brand)]';
  if (err) return 'bg-[var(--danger-soft)] text-[var(--danger)]';
  if (warn) return 'bg-[var(--warning-soft)] text-[var(--warning)]';
  return 'text-[var(--text-muted)] bg-[var(--surface-tertiary)]';
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cx('inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider', statusStyle(status))}>
      {status.replace(/_/g, ' ')}
    </span>
  );
}

export function ModeBadge({ mode }: { mode: 'defend' | 'pentest' | 'multi_agent' }) {
  const labels: Record<string, { text: string; className: string }> = {
    defend: { text: 'Defend', className: 'bg-[var(--info-soft)] text-[var(--info)]' },
    pentest: { text: 'Pentest', className: 'bg-[var(--warning-soft)] text-[var(--warning)]' },
    multi_agent: { text: 'Multi-Agent', className: 'bg-[var(--info-soft)] text-[var(--info)]' },
  };
  const label = labels[mode] ?? labels.pentest;
  return (
    <span
      className={cx(
        'inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider',
        label.className,
      )}
    >
      {label.text}
    </span>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  accent = false,
}: {
  label: string;
  value: ReactNode;
  detail?: string;
  accent?: boolean;
}) {
  return (
    <div className={cx('rounded-[var(--radius-panel)] border bg-[var(--surface-primary)] px-3.5 py-2.5 shadow-[var(--shadow-card)]', accent ? 'border-l-[3px] border-l-[var(--warning)] border-[var(--border-light)]' : 'border-[var(--border-light)]')}>
      <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="mt-1 text-lg font-bold font-mono tracking-tight text-[var(--text-strong)]">{value}</div>
      {detail ? <div className="mt-0.5 text-[10px] text-[var(--text-muted)] leading-tight">{detail}</div> : null}
    </div>
  );
}

export function ProgressBar({ value, className = '' }: { value: number; className?: string }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div className={cx('h-1.5 overflow-hidden rounded-full bg-[var(--surface-tertiary)]', className)}>
      <motion.div
        className="h-full rounded-full bg-[var(--brand)]"
        initial={false}
        animate={{ width: `${clamped}%` }}
        transition={{ duration: 0.4, ease: 'easeOut' }}
      />
    </div>
  );
}

const applicabilityColor = (a: AgentApplicability) => {
  switch (a) {
    case 'RUNNING': return 'text-[var(--brand)] animate-spin';
    case 'QUEUED': return 'text-[var(--warning)]';
    case 'COMPLETED': return 'text-[var(--success)]';
    case 'FAILED': return 'text-[var(--danger)]';
    case 'WAITING': return 'text-[var(--warning)]';
    case 'NOT_APPLICABLE': return 'text-[var(--text-subtle)]';
    default: return 'text-[var(--text-muted)]';
  }
};

export function AgentCard({ agent, onClick }: { agent: AgentStateDetail; onClick?: () => void }) {
  const c = applicabilityColor(agent.applicability);
  const showProgress = agent.applicability === 'RUNNING' || agent.applicability === 'QUEUED' || agent.applicability === 'COMPLETED';
  const isNa = agent.applicability === 'NOT_APPLICABLE';
  return (
    <div
      onClick={onClick}
      className={cx(
        'rounded-[var(--radius-panel)] border px-3 py-2 transition-all duration-150',
        agent.applicability === 'RUNNING' ? 'border-[var(--brand)]/35 bg-[var(--brand-soft)]/40' :
        isNa ? 'border-[var(--border-light)] opacity-55' :
        agent.applicability === 'FAILED' ? 'border-[var(--danger-border)] bg-[var(--danger-soft)]/20' :
        'border-[var(--border-light)] hover:border-[var(--border-default)]',
        onClick && 'cursor-pointer active:scale-[0.99] active:translate-y-[0.5px]',
      )}
    >
      <div className="flex items-center gap-2">
        <span className={cx('h-1.5 w-1.5 rounded-full shrink-0', c.split(' ').find(s => s.startsWith('text-') && s.includes('['))?.replace('text-', 'bg-') || 'bg-slate-300')} />
        <span className="min-w-0 flex-1 truncate text-xs font-semibold text-[var(--text-strong)]">{agent.name}</span>
        <AgentStatePill state={agent.applicability} />
      </div>
      {!isNa ? (
        <div className="mt-1.5 space-y-1">
          <div className="text-[10px] text-[var(--text-muted)] leading-tight">{agent.responsibility}</div>
          {agent.detail ? <div className="text-[10px] text-[var(--text-default)] leading-tight">{agent.detail}</div> : null}
          {agent.current_module ? (
            <div className="text-[10px] text-[var(--text-default)]">
              <span className="text-[var(--text-muted)]">Module:</span>{' '}
              <span className="font-semibold text-[var(--brand)]">{agent.current_module.replace(/_/g, ' ')}</span>
            </div>
          ) : null}
          {showProgress && agent.progress > 0 ? (
            <div className="flex items-center gap-1.5 mt-1">
              <ProgressBar value={agent.progress} className="flex-1" />
              <span className="text-[9px] font-mono text-[var(--text-muted)]">{agent.progress}%</span>
            </div>
          ) : null}
        </div>
      ) : (
        <div className="mt-1 text-[10px] text-[var(--text-muted)]">{agent.detail || 'Not applicable'}</div>
      )}
    </div>
  );
}

function AgentStatePill({ state }: { state: string }) {
  const map: Record<string, { bg: string; text: string }> = {
    RUNNING: { bg: 'bg-[var(--brand-soft)]', text: 'text-[var(--brand)]' },
    QUEUED: { bg: 'bg-[var(--warning-soft)]', text: 'text-[var(--warning)]' },
    WAITING: { bg: 'bg-[var(--warning-soft)]', text: 'text-[var(--warning)]' },
    COMPLETED: { bg: 'bg-[var(--success-soft)]', text: 'text-[var(--success)]' },
    FAILED: { bg: 'bg-[var(--danger-soft)]', text: 'text-[var(--danger)]' },
    NOT_APPLICABLE: { bg: 'bg-[var(--surface-tertiary)]', text: 'text-[var(--text-subtle)]' },
    IDLE: { bg: '', text: 'text-[var(--text-muted)]' },
  };
  const s = map[state] || { bg: '', text: 'text-[var(--text-muted)]' };
  return (
    <span className={cx('inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium', s.bg, s.text)}>
      {state === 'NOT_APPLICABLE' ? 'N/A' : state}
    </span>
  );
}

export function DataTable({
  columns,
  rows,
  onRowClick,
}: {
  columns: Array<{ key: string; label: string; width?: string; align?: 'left' | 'center' | 'right' }>;
  rows: Array<{ id: string | number; cells: Record<string, ReactNode> }>;
  onRowClick?: (id: string | number) => void;
}) {
  const template = columns.map((c) => c.width || 'minmax(0,1fr)').join(' ');
  return (
    <div className="overflow-x-auto">
      <div className="min-w-[500px]">
        <div
          className="grid gap-3 border-b border-[var(--border-light)] bg-[var(--surface-secondary)] px-4 py-2.5 text-[11px] font-semibold text-[var(--text-muted)] tracking-wide"
          style={{ gridTemplateColumns: template }}
        >
          {columns.map((col) => (
            <span key={col.key} className={cx(col.align === 'right' ? 'text-right' : col.align === 'center' ? 'text-center' : '', 'truncate')}>
              {col.label}
            </span>
          ))}
        </div>
        <div className="divide-y divide-[var(--border-light)]">
          {rows.map((row) => (
            <div
              key={row.id}
              onClick={() => onRowClick?.(row.id)}
              className={cx(
                'grid gap-3 px-4 py-2.5 transition-colors',
                onRowClick ? 'cursor-pointer hover:bg-[var(--surface-hover)]' : '',
              )}
              style={{ gridTemplateColumns: template }}
            >
              {columns.map((col) => (
                <div
                  key={col.key}
                  className={cx(
                    'truncate text-xs',
                    col.align === 'right' ? 'text-right' : col.align === 'center' ? 'text-center' : '',
                  )}
                >
                  {row.cells[col.key]}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  compact,
}: {
  icon?: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={cx(
      'flex flex-col items-center justify-center rounded-[var(--radius-panel)] border border-dashed border-[var(--border-default)] bg-[var(--surface-secondary)]/20 text-center',
      compact ? 'px-4 py-5' : 'px-6 py-8',
    )}>
      {icon || <ShieldCheck className="mb-2 h-5 w-5 text-[var(--text-subtle)]" />}
      <h3 className="text-xs font-semibold text-[var(--text-strong)]">{title}</h3>
      <p className="mt-1 max-w-sm text-[10px] text-[var(--text-muted)] leading-normal">{description}</p>
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  title,
  description,
  detail,
  action,
}: {
  title: string;
  description: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <div className="rounded-[var(--radius-panel)] border border-[var(--danger-border)] bg-[var(--danger-soft)]/30 p-3">
      <div className="flex items-start gap-2.5">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--danger)]" />
        <div className="min-w-0 flex-1">
          <h3 className="text-xs font-semibold text-[var(--danger)]">{title}</h3>
          <p className="mt-0.5 text-xs text-[var(--text-default)]">{description}</p>
          {detail ? (
            <details className="mt-1.5">
              <summary className="cursor-pointer text-[10px] text-[var(--text-muted)] font-semibold hover:text-[var(--text-default)] select-none">Details</summary>
              <pre className="mt-1.5 whitespace-pre-wrap rounded bg-[var(--surface-tertiary)] p-2 font-mono text-[9px] text-[var(--text-muted)] leading-tight border border-[var(--border-light)]">{detail}</pre>
            </details>
          ) : null}
          {action ? <div className="mt-2.5">{action}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function LoadingSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2.5">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-9 animate-pulse rounded-lg bg-[var(--surface-tertiary)]" />
      ))}
    </div>
  );
}

export function PanelSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3 rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)] p-5">
      <div className="h-4 w-1/3 animate-pulse rounded bg-[var(--surface-tertiary)]" />
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-8 animate-pulse rounded bg-[var(--surface-tertiary)]" />
      ))}
    </div>
  );
}

export function Drawer({
  title,
  open,
  onClose,
  children,
}: {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <AnimatePresence>
      {open ? (
        <>
          <motion.div
            className="fixed inset-0 z-40 bg-slate-900/20 backdrop-blur-[2px]"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            aria-hidden
          />
          <motion.aside
            role="dialog"
            aria-modal="true"
            aria-label={title}
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 350, damping: 35 }}
            className="fixed right-0 top-0 z-50 h-full w-full max-w-md overflow-y-auto border-l border-[var(--border-light)] bg-[var(--surface-primary)] shadow-[var(--shadow-drawer)]"
          >
            <div className="flex items-center justify-between border-b border-[var(--border-light)] px-4 py-2.5 bg-[var(--surface-secondary)]/50">
              <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--text-strong)]">{title}</h2>
              <button
                onClick={onClose}
                className="rounded-[var(--radius-control)] p-1 text-[var(--text-subtle)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]"
                aria-label="Close drawer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-4">{children}</div>
          </motion.aside>
        </>
      ) : null}
    </AnimatePresence>
  );
}

export function InfoCallout({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-[var(--info-soft)] bg-[var(--info-soft)]/30 p-3.5 text-xs">
      <div className="mb-1 flex items-center gap-1.5 font-semibold text-[var(--info)]">
        <Info className="h-3.5 w-3.5" />
        {title}
      </div>
      <div className="text-[var(--text-default)]">{children}</div>
    </div>
  );
}

export function RemediationChecklist({ items }: { items: string[] }) {
  const normalized = items.length ? items : ['Review the evidence.', 'Apply the recommended fix.', 'Deploy changes.', 'Rerun the relevant VulScan check.'];
  return (
    <ol className="space-y-1.5">
      {normalized.map((item, index) => (
        <li key={`${item}-${index}`} className="flex gap-2.5 rounded p-2 text-xs text-[var(--text-default)]">
          <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-[var(--brand-soft)] text-[10px] font-semibold text-[var(--brand)]">{index + 1}</span>
          <span className="leading-5">{item}</span>
        </li>
      ))}
    </ol>
  );
}

export function ActivityTimeline({ events }: { events: Array<{ id: string; timestamp: string; title: string; detail?: string; agent?: string; tone?: string }> }) {
  if (!events.length) return <EmptyState title="No activity" description="Activity appears when events are recorded." compact />;
  return (
    <div className="space-y-1.5">
      {events.slice(-60).map((event) => (
        <div
          key={event.id}
          className="flex gap-3 px-3 py-2 rounded-lg hover:bg-[var(--surface-hover)] transition-colors"
        >
          <span className="shrink-0 font-mono text-[10px] text-[var(--text-subtle)] mt-0.5">{event.timestamp}</span>
          <div className="min-w-0 flex-1">
            <div className="text-xs font-medium text-[var(--text-strong)]">{event.title}</div>
            {event.detail ? <div className="mt-0.5 text-[11px] text-[var(--text-muted)] leading-relaxed">{event.detail}</div> : null}
            {event.agent ? <div className="mt-1 text-[10px] text-[var(--text-subtle)]">{event.agent}</div> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

export function AgentRow({ agent, onClick }: { agent: { name: string; status: string }; onClick?: () => void }) {
  const isActive = agent.status === 'active' || agent.status === 'running';
  const isComplete = agent.status === 'complete' || agent.status === 'completed';
  const isError = agent.status === 'error' || agent.status === 'failed';
  return (
    <button
      onClick={onClick}
      className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-xs transition-colors hover:bg-[var(--surface-hover)]"
    >
      <span className={cx('h-2 w-2 rounded-full shrink-0', isActive ? 'bg-[var(--brand)]' : isComplete ? 'bg-[var(--success)]' : isError ? 'bg-[var(--danger)]' : 'bg-[var(--text-subtle)]')} />
      <span className="min-w-0 flex-1 truncate text-[var(--text-default)]">{agent.name}</span>
      <StatusBadge status={agent.status} />
    </button>
  );
}

export const EVENT_STYLES: Record<string, { color: string; icon: any }> = {
  JOB_STARTED: { color: 'text-[var(--brand)]', icon: Loader2 },
  SURFACE_DISCOVERED: { color: 'text-[var(--info)]', icon: ShieldCheck },
  MODULE_STARTED: { color: 'text-[var(--warning)]', icon: Loader2 },
  TEST_PREPARED: { color: 'text-[var(--text-default)]', icon: Circle },
  TEST_REQUEST_SENT: { color: 'text-[var(--text-default)]', icon: Circle },
  RESPONSE_RECEIVED: { color: 'text-[var(--success)]', icon: CheckCircle2 },
  SECURITY_CONTROL_EVALUATED: { color: 'text-[var(--brand)]', icon: ShieldCheck },
  FINDING_DETECTED: { color: 'text-[var(--danger)]', icon: AlertTriangle },
  CONTROL_BLOCKED_TEST: { color: 'text-[var(--success)]', icon: CheckCircle2 },
  RETEST_STARTED: { color: 'text-[var(--warning)]', icon: Loader2 },
  FIX_VERIFIED: { color: 'text-[var(--success)]', icon: CheckCircle2 },
  MODULE_COMPLETED: { color: 'text-[var(--success)]', icon: CheckCircle2 },
  MODULE_FAILED: { color: 'text-[var(--danger)]', icon: AlertTriangle },
  JOB_COMPLETED: { color: 'text-[var(--success)]', icon: CheckCircle2 },
};

export function getEventStyle(eventType: string) {
  return EVENT_STYLES[eventType] || { color: 'text-[var(--text-default)]', icon: Circle };
}
