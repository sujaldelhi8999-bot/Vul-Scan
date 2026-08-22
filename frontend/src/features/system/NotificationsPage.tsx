import { useMemo } from 'react';
import { EmptyState, Page, PageHeader, Panel } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { deriveNotifications, relativeTime } from '../../utils/derived';

export default function NotificationsPage() {
  const { findings, logs } = usePhantomData();
  const notices = useMemo(() => deriveNotifications(findings, logs), [findings, logs]);

  const toneStyles: Record<string, string> = {
    red: 'border-l-[var(--danger)]',
    amber: 'border-l-[var(--warning)]',
    purple: 'border-l-[var(--brand)]',
    green: 'border-l-[var(--success)]',
  };

  return (
    <Page>
      <PageHeader title="Notifications" description={`${notices.length} events derived from backend activity.`} />
      {notices.length ? (
        <div className="grid gap-2 sm:grid-cols-2">
          {notices.map((notice) => (
            <Panel key={notice.id}>
              <div className="p-3.5 border-l-[3px]" style={{ borderLeftColor: `var(--${notice.tone === 'red' ? 'danger' : notice.tone === 'amber' ? 'warning' : notice.tone === 'green' ? 'success' : 'brand'})` }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{notice.type}</span>
                  <span className="text-[10px] text-[var(--text-muted)]">{relativeTime(notice.timestamp)}</span>
                </div>
                <div className="mt-1.5 text-xs font-medium text-[var(--text-strong)]">{notice.title}</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)] leading-relaxed">{notice.detail}</div>
              </div>
            </Panel>
          ))}
        </div>
      ) : (
        <EmptyState title="No notifications" description="Notifications appear from findings and audit events." />
      )}
    </Page>
  );
}
