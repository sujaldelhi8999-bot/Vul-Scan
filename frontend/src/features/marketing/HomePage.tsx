import { Link } from 'react-router-dom';
import { ArrowRight, CheckCircle2, GitBranch, Shield, Sparkles, Workflow } from 'lucide-react';

import { cx } from '../../components/ui/Primitives';
import { useAuth } from '../../context/AuthContext';
import UniversalNavbar from '../../components/layout/UniversalNavbar';

const features = [
  { title: 'Fast asset scanning', description: 'Find exposed services, weak headers, and common web risks before attackers do.', icon: Shield },
  { title: 'AI explanations', description: 'Turn findings into plain-language risk summaries and next steps.', icon: Sparkles },
  { title: 'Developer workflow', description: 'Connect GitHub, export reports, and keep scan history in one workspace.', icon: GitBranch },
];

const workspaceItems = ['Assets', 'Scans', 'Findings', 'AI remediation', 'Reports', 'Audit logs'];

export default function HomePage() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-[var(--app-canvas)] text-[var(--text-default)]">
      <UniversalNavbar />

      <main>
        <section className="mx-auto grid max-w-6xl gap-8 px-5 py-14 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:py-20">
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-[var(--border-light)] bg-white px-3 py-1 text-[11px] font-semibold text-[var(--brand)]">
              <Workflow className="h-3.5 w-3.5" /> Security workspace for builders
            </div>
            <h1 className="max-w-2xl text-4xl font-semibold leading-tight tracking-[-0.04em] text-[var(--text-strong)] sm:text-5xl">
              Scan, explain, and fix security issues from one focused workspace.
            </h1>
            <p className="mt-5 max-w-xl text-base leading-7 text-[var(--text-muted)]">
              VulScan helps developers and small teams run vulnerability scans, understand findings, and ship safer software without a heavy security stack.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Link to={user ? '/dashboard' : '/register'} className="inline-flex items-center gap-2 rounded-[var(--radius-control)] bg-[var(--brand)] px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-[var(--brand-hover)]">
                {user ? 'Open dashboard' : 'Start free'} <ArrowRight className="h-4 w-4" />
              </Link>
              <Link to="/pricing" className="inline-flex items-center gap-2 rounded-[var(--radius-control)] border border-[var(--border-default)] bg-white px-4 py-2.5 text-sm font-semibold text-[var(--text-default)] hover:bg-[var(--surface-hover)]">
                View pricing
              </Link>
            </div>
          </div>

          <div className="rounded-[var(--radius-panel)] border border-[var(--border-light)] bg-white p-3.5 shadow-[var(--shadow-float)]">
            <div className="rounded-[var(--radius-panel)] bg-[var(--surface-secondary)] p-3.5">
              <div className="mb-3 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-[var(--text-strong)]">Workspace</div>
                  <div className="text-[10px] text-[var(--text-muted)]">Everything security in one place</div>
                </div>
                <span className="rounded bg-[var(--success-soft)] px-1.5 py-0.5 text-[9px] font-semibold text-[var(--success)] uppercase tracking-wider">Online</span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {workspaceItems.map((item, index) => (
                  <div key={item} className={cx('rounded-[var(--radius-control)] border border-[var(--border-light)] bg-white p-2.5', index === 2 && 'sm:col-span-2')}>
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-strong)]">
                      <CheckCircle2 className="h-3.5 w-3.5 text-[var(--brand)]" /> {item}
                    </div>
                    <div className="mt-2 h-1.5 rounded-full bg-[var(--surface-tertiary)]">
                      <div className="h-full rounded-full bg-[var(--brand)]" style={{ width: `${55 + index * 7}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="mx-auto grid max-w-6xl gap-4 px-5 pb-16 md:grid-cols-3">
          {features.map((feature) => {
            const Icon = feature.icon;
            return (
              <div key={feature.title} className="rounded-[var(--radius-panel)] border border-[var(--border-light)] bg-white p-4 shadow-[var(--shadow-card)]">
                <div className="mb-3 flex h-8 w-8 items-center justify-center rounded-[var(--radius-control)] bg-[var(--brand-soft)]">
                  <Icon className="h-3.5 w-3.5 text-[var(--brand)]" />
                </div>
                <h2 className="text-xs font-semibold text-[var(--text-strong)]">{feature.title}</h2>
                <p className="mt-1.5 text-xs leading-relaxed text-[var(--text-muted)]">{feature.description}</p>
              </div>
            );
          })}
        </section>
      </main>
    </div>
  );
}
