import { LogOut, Mail, ShieldCheck, User as UserIcon } from 'lucide-react';

import { Button, Page, PageHeader, Panel, SectionHeader } from '../../components/ui/Primitives';
import { useAuth } from '../../context/AuthContext';
import { displayRole, hasElevatedAccess } from '../../utils/access';

export default function ProfilePage() {
  const { user, logoutUser } = useAuth();

  if (!user) {
    return (
      <Page>
        <PageHeader title="Profile" description="Sign in to view your account details." />
      </Page>
    );
  }

  const displayName = user.name || user.username || 'User';
  const initial = displayName.charAt(0).toUpperCase();
  const elevated = hasElevatedAccess(user);

  const rows: Array<[string, string]> = [
    ['Username', user.username],
    ['Email', user.email || '—'],
    ['Role', displayRole(user)],
  ];

  return (
    <Page>
      <PageHeader
        title="Profile"
        description="Your account details and session information."
        action={
          <Button variant="danger" onClick={() => void logoutUser()}>
            <LogOut className="h-3.5 w-3.5" />Logout
          </Button>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel>
          <SectionHeader title="Account" />
          <div className="flex flex-col items-center gap-3 rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-6 text-center">
            <span className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--brand)] text-2xl font-bold text-white">
              {initial}
            </span>
            <div>
              <div className="text-sm font-semibold text-[var(--text-strong)]">{displayName}</div>
              <div className="mt-0.5 flex items-center justify-center gap-1.5 text-[11px] text-[var(--text-muted)]">
                {elevated ? (
                  <>
                    <ShieldCheck className="h-3.5 w-3.5 text-[var(--brand)]" />
                    <span className="font-semibold text-[var(--brand)]">{displayRole(user)}</span>
                  </>
                ) : (
                  <>
                    <UserIcon className="h-3.5 w-3.5" />
                    <span>{displayRole(user)}</span>
                  </>
                )}
              </div>
            </div>
          </div>
        </Panel>

        <div className="lg:col-span-2">
          <Panel>
            <SectionHeader title="Details" />
            <div className="divide-y divide-[var(--border-light)]">
              {rows.map(([label, value]) => (
                <div key={label} className="flex items-center justify-between gap-3 py-2.5">
                  <span className="text-xs text-[var(--text-muted)]">{label}</span>
                  <span className="flex items-center gap-1.5 text-xs font-medium text-[var(--text-strong)]">
                    {label === 'Email' ? <Mail className="h-3 w-3 text-[var(--text-subtle)]" /> : null}
                    {value}
                  </span>
                </div>
              ))}
              <div className="flex items-center justify-between gap-3 py-2.5">
                <span className="text-xs text-[var(--text-muted)]">Sign-in method</span>
                <span className="text-xs font-medium text-[var(--text-strong)]">
                  {user.email ? 'Google / GitHub (Supabase)' : 'Local admin credentials'}
                </span>
              </div>
            </div>
            <p className="mt-4 text-[11px] leading-relaxed text-[var(--text-subtle)]">
              Password changes and provider unlinking are managed directly by your identity provider (Supabase).
            </p>
          </Panel>

          <Panel>
            <SectionHeader title="Session" />
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="text-xs font-semibold text-[var(--text-strong)]">End current session</div>
                <p className="text-[11px] text-[var(--text-subtle)]">
                  Signs you out of VulScan and clears your locally stored credentials.
                </p>
              </div>
              <Button variant="danger" onClick={() => void logoutUser()}>
                <LogOut className="h-3.5 w-3.5" />Logout
              </Button>
            </div>
          </Panel>
        </div>
      </div>
    </Page>
  );
}
