import { Gauge, TerminalSquare } from 'lucide-react';
import type { ComplexityResult } from '../../types';
import { cx } from '../../components/ui/Primitives';

const BAND_STYLES: Record<string, string> = {
  simple: 'bg-[var(--success-subtle)] text-[var(--success)] border-[var(--success)]/40',
  medium: 'bg-[var(--info-subtle)] text-[var(--info)] border-[var(--info)]/40',
  complex: 'bg-[var(--warning-subtle)] text-[var(--warning)] border-[var(--warning)]/40',
  critical: 'bg-[var(--danger-soft)] text-[var(--danger)] border-[var(--danger)]/40',
};

function BandBadge({ band, label }: { band: string; label: string }) {
  const style = BAND_STYLES[band] ?? BAND_STYLES.complex;
  return (
    <span className={cx('rounded-md border px-2 py-1 text-[10px] font-bold uppercase tracking-wide', style)}>
      {label}
    </span>
  );
}

function Row({ label, value, points }: { label: string; value: string; points?: number }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded px-2.5 py-1.5 text-xs">
      <span className="text-[var(--text-muted)]">{label}</span>
      <span className="flex items-center gap-2">
        <span className="max-w-[180px] truncate text-right font-mono text-[10px] text-[var(--text-secondary)]">
          {value}
        </span>
        {points !== undefined ? (
          <span className="w-7 text-right text-[10px] font-semibold text-[var(--text-primary)]">+{points}</span>
        ) : null}
      </span>
    </div>
  );
}

export default function ComplexityCard({ complexity }: { complexity: ComplexityResult }) {
  const b = complexity.breakdown;
  const wafLabel = b.waf
    ? 'WAF detected (hardened)'
    : `${b.security_headers.present.length}/${b.security_headers.present.length + b.security_headers.missing.length} security headers`;
  return (
    <div className="rounded-xl border border-[var(--border-default)] p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-primary)]">
          <Gauge className="h-3.5 w-3.5 text-[var(--accent)]" />
          Target Complexity
        </div>
        <BandBadge band={complexity.band} label={complexity.band_label} />
      </div>
      <div className="mb-3 flex items-end gap-3">
        <div className="text-4xl font-bold text-[var(--text-primary)]">{complexity.score}</div>
        <div className="mb-1 text-[10px] text-[var(--text-muted)]">/ 100 complexity index</div>
      </div>
      <div className="space-y-0.5">
        <Row
          label="Ports"
          value={
            b.ports.web_ports.length
              ? `${b.ports.web_ports.concat(b.ports.extra_web_ports).join(', ')}${b.ports.database_ports.length ? ` · DB ${b.ports.database_ports.join(', ')}` : ''}`
              : 'none detected'
          }
          points={b.ports.points}
        />
        <Row
          label="Technology"
          value={b.tech_stack.detected.length ? b.tech_stack.detected.slice(0, 4).join(', ') : 'none detected'}
          points={b.tech_stack.points}
        />
        <Row
          label="Authentication"
          value={b.authentication.mechanisms.length ? b.authentication.mechanisms.join(', ') : 'none detected'}
          points={b.authentication.points}
        />
        <Row
          label="API surface"
          value={
            b.api_surface.endpoints
              ? `${b.api_surface.endpoints} endpoint${b.api_surface.endpoints !== 1 ? 's' : ''}${b.api_surface.graphql ? ' · GraphQL' : ''}${b.api_surface.openapi ? ' · OpenAPI' : ''}`
              : 'none detected'
          }
          points={b.api_surface.points}
        />
        <Row label="WAF / headers" value={wafLabel} points={b.security_headers.points} />
        <Row
          label="Scale"
          value={`${b.scale.endpoints} paths${b.scale.subdomains ? ` · ${b.scale.subdomains} subdomains` : ''}`}
          points={b.scale.points}
        />
      </div>
      <div className="mt-3 flex items-start gap-2 rounded-md bg-[var(--bg-inset)] px-2.5 py-2 text-[10px] leading-relaxed text-[var(--text-muted)]">
        <TerminalSquare className="mt-0.5 h-3 w-3 shrink-0 text-[var(--accent)]" />
        <span>
          Higher complexity drives deeper module selection and a higher request rate during the scan.
        </span>
      </div>
    </div>
  );
}

export function ComplexitySkeleton() {
  return (
    <div className="rounded-xl border border-[var(--border-default)] p-3">
      <div className="mb-3 flex items-center justify-between">
        <div className="h-3 w-32 animate-pulse rounded bg-[var(--bg-hover)]" />
        <div className="h-5 w-24 animate-pulse rounded bg-[var(--bg-hover)]" />
      </div>
      <div className="mb-3 h-10 w-20 animate-pulse rounded bg-[var(--bg-hover)]" />
      <div className="space-y-1.5">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-4 animate-pulse rounded bg-[var(--bg-hover)]" />
        ))}
      </div>
    </div>
  );
}
