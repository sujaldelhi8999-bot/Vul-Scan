import { Link } from 'react-router-dom';
import { Check, ShieldCheck } from 'lucide-react';

import { cx } from '../../components/ui/Primitives';
import { useAuth } from '../../context/AuthContext';
import UniversalNavbar from '../../components/layout/UniversalNavbar';

const tiers = [
  {
    id: 'FREE',
    name: 'Free',
    price: '₹0',
    purpose: 'Acquisition & Basic Security Testing',
    description: 'For trying VulScan and scanning personal or open projects.',
    features: ['Limited assets', 'Limited scans/month', 'Basic vulnerability findings', 'Basic AI explanations', 'Community support'],
  },
  {
    id: 'PRO',
    name: 'Developer / Pro',
    price: '₹999-₹2,499',
    suffix: '/month',
    purpose: 'Individual developers, freelancers, and small teams',
    description: 'More scans, deeper analysis, DoS testing, and workflow integrations.',
    featured: true,
    features: ['More scans', 'Deeper security analysis', 'Scan history & audit logs', 'AI remediation engine', 'Scheduled scanning', 'Exportable reports', 'GitHub & CI/CD integration', 'Authorized Testing & Private Scope'],
  },
  {
    id: 'ENTERPRISE',
    name: 'Enterprise',
    price: 'Custom',
    purpose: 'Teams that need control, compliance, and support',
    description: 'Private security workflows with dedicated policies and SLAs.',
    features: ['SSO', 'Private deployment', 'Custom scan policies', 'Compliance reporting', 'Audit logs', 'API access', 'SLAs', 'Dedicated support', 'Custom integrations'],
  },
];

export default function PricingPage() {
  const { user } = useAuth();

  const isProOrAdmin = user?.role === 'admin' || user?.subscriptionTier === 'PRO' || user?.subscriptionTier === 'ENTERPRISE';
  const isFreeUser = user && !isProOrAdmin;

  return (
    <div className="min-h-screen bg-[var(--app-canvas)] text-[var(--text-default)]">
      <UniversalNavbar />

      <main className="mx-auto max-w-6xl px-5 py-12 lg:py-16">
        <div className="mx-auto max-w-2xl text-center">
          <div className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-[var(--brand)]">Pricing & Tiers</div>
          <h1 className="text-4xl font-semibold tracking-[-0.04em] text-[var(--text-strong)] sm:text-5xl">Pick the workspace that fits your security workflow.</h1>
          <p className="mt-4 text-base leading-7 text-[var(--text-muted)]">Start free, upgrade when full-scope security testing, DoS testing, AI remediation, and integrations become part of your release process.</p>
        </div>

        <div className="mt-12 grid gap-6 lg:grid-cols-3">
          {tiers.map((tier) => {
            const isCurrentPlan =
              (tier.id === 'PRO' && isProOrAdmin) ||
              (tier.id === 'FREE' && isFreeUser);

            return (
              <section
                key={tier.name}
                className={cx(
                  'relative flex flex-col justify-between rounded-2xl border bg-[var(--surface-primary)] p-6 shadow-[var(--shadow-card)] transition-all',
                  isCurrentPlan
                    ? 'border-[var(--brand)] ring-2 ring-[var(--brand)]/20 shadow-[var(--shadow-float)]'
                    : tier.featured
                    ? 'border-[var(--brand-soft)]'
                    : 'border-[var(--border-light)]'
                )}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <div className="text-base font-bold text-[var(--text-strong)]">
                      {tier.id === 'PRO' ? 'Developer / Pro' : tier.name}
                    </div>
                    {isCurrentPlan ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-100 dark:bg-emerald-950/60 px-3 py-1 text-[11px] font-bold text-emerald-700 dark:text-emerald-300">
                        <ShieldCheck className="h-3.5 w-3.5" />
                        Current plan
                      </span>
                    ) : tier.featured ? (
                      <span className="rounded-full bg-[var(--brand-soft)] px-2.5 py-1 text-[10px] font-bold text-[var(--brand)]">
                        Recommended
                      </span>
                    ) : null}
                  </div>

                  <div className="mt-4 flex items-end gap-1">
                    <span className="text-3xl font-bold tracking-tight text-[var(--text-strong)]">{tier.price}</span>
                    {tier.suffix ? <span className="pb-1 text-xs text-[var(--text-muted)]">{tier.suffix}</span> : null}
                  </div>
                  <p className="mt-3 text-xs leading-5 text-[var(--text-muted)] min-h-[40px]">{tier.description}</p>
                  <div className="mt-3 rounded-lg bg-[var(--surface-secondary)] px-3 py-2 text-[11px] font-medium text-[var(--text-muted)]">
                    <span className="font-semibold text-[var(--text-strong)]">Ideal for:</span> {tier.purpose}
                  </div>

                  <ul className="mt-6 space-y-2.5">
                    {tier.features.map((feature) => (
                      <li key={feature} className="flex gap-2 text-xs text-[var(--text-default)]">
                        <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--success)]" />
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="mt-8">
                  {isCurrentPlan ? (
                    <button
                      disabled
                      className="w-full rounded-[var(--radius-control)] bg-[var(--surface-secondary)] border border-[var(--border-default)] px-4 py-2.5 text-xs font-semibold text-[var(--text-muted)] cursor-default text-center"
                    >
                      Active Plan
                    </button>
                  ) : tier.id === 'PRO' && isFreeUser ? (
                    <Link
                      to="/register"
                      className="inline-flex w-full items-center justify-center rounded-[var(--radius-control)] bg-[var(--brand)] px-4 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-[var(--brand-hover)] transition-colors"
                    >
                      Upgrade to Developer / Pro
                    </Link>
                  ) : tier.id === 'ENTERPRISE' ? (
                    <a
                      href="mailto:sales@vulscan.io"
                      className="inline-flex w-full items-center justify-center rounded-[var(--radius-control)] border border-[var(--border-default)] px-4 py-2.5 text-xs font-semibold text-[var(--text-default)] hover:bg-[var(--surface-hover)] transition-colors"
                    >
                      Contact Sales
                    </a>
                  ) : !user ? (
                    <Link
                      to="/register"
                      className={cx(
                        'inline-flex w-full items-center justify-center rounded-[var(--radius-control)] px-4 py-2.5 text-xs font-semibold transition-colors',
                        tier.featured
                          ? 'bg-[var(--brand)] text-white hover:bg-[var(--brand-hover)]'
                          : 'border border-[var(--border-default)] text-[var(--text-default)] hover:bg-[var(--surface-hover)]'
                      )}
                    >
                      Start Free
                    </Link>
                  ) : (
                    <Link
                      to="/dashboard"
                      className="inline-flex w-full items-center justify-center rounded-[var(--radius-control)] border border-[var(--border-default)] px-4 py-2.5 text-xs font-semibold text-[var(--text-default)] hover:bg-[var(--surface-hover)] transition-colors"
                    >
                      Go to Dashboard
                    </Link>
                  )}
                </div>
              </section>
            );
          })}
        </div>
      </main>
    </div>
  );
}
