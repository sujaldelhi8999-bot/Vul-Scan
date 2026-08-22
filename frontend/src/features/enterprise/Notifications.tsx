import { useCallback, useEffect, useState } from 'react';
import { Bell, Check, ExternalLink, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';

import { Button, EmptyState, Panel, PanelSkeleton, StatusBadge } from '../../components/ui/Primitives';
import apiClient, { apiErrorMessage } from '../../services/api';

interface NotificationItem {
  id: number;
  type: string;
  title: string;
  body: string | null;
  link: string | null;
  read: number;
  created_at: string;
}

interface NotificationResponse {
  items: NotificationItem[];
  unread_count: number;
}

export default function Notifications() {
  const navigate = useNavigate();
  const [data, setData] = useState<NotificationResponse>({ items: [], unread_count: 0 });
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get<NotificationResponse>('/api/enterprise/notifications');
      setData(res.data);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to load notifications'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const markRead = async (id: number) => {
    try {
      await apiClient.post(`/api/enterprise/notifications/${id}/read`);
      setData((current) => ({
        ...current,
        unread_count: Math.max(0, current.unread_count - (current.items.find((item) => item.id === id)?.read ? 0 : 1)),
        items: current.items.map((item) => item.id === id ? { ...item, read: 1 } : item),
      }));
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to mark notification read'));
    }
  };

  const markAllRead = async () => {
    try {
      await apiClient.post('/api/enterprise/notifications/read-all');
      setData((current) => ({ unread_count: 0, items: current.items.map((item) => ({ ...item, read: 1 })) }));
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Failed to mark notifications read'));
    }
  };

  const follow = (item: NotificationItem) => {
    if (!item.link) return;
    if (item.link.startsWith('http://') || item.link.startsWith('https://')) {
      window.open(item.link, '_blank', 'noopener,noreferrer');
    } else {
      navigate(item.link);
    }
  };

  if (loading) {
    return <Panel><PanelSkeleton rows={5} /></Panel>;
  }

  return (
    <Panel>
      <div className="flex items-center justify-between gap-3 p-3.5">
        <div>
          <h3 className="flex items-center gap-2 text-xs font-semibold text-[var(--text-strong)]">
            <Bell className="h-4 w-4 text-[var(--text-subtle)]" />
            Notifications {data.unread_count ? `(${data.unread_count} unread)` : ''}
          </h3>
          <p className="mt-1 text-[11px] text-[var(--text-muted)]">Approval decisions and enterprise activity addressed to you.</p>
        </div>
        <div className="flex gap-1.5">
          <Button variant="ghost" onClick={() => void load()} aria-label="Refresh notifications">
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
          {data.unread_count > 0 ? <Button variant="secondary" onClick={() => void markAllRead()}><Check className="h-3.5 w-3.5" /> Mark all read</Button> : null}
        </div>
      </div>

      {data.items.length === 0 ? (
        <div className="border-t border-[var(--border-light)] p-2">
          <EmptyState title="No notifications" description="New approval activity will appear here." compact />
        </div>
      ) : (
        <div className="divide-y divide-[var(--border-light)] border-t border-[var(--border-light)]">
          {data.items.map((item) => (
            <div key={item.id} className={`flex items-start gap-3 px-3.5 py-3 ${item.read ? '' : 'bg-[var(--brand-soft)]/30'}`}>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-semibold text-[var(--text-strong)]">{item.title}</span>
                  <StatusBadge status={item.type} />
                  {!item.read ? <span className="rounded-full bg-[var(--brand)] px-1.5 py-0.5 text-[9px] font-bold text-white">NEW</span> : null}
                </div>
                {item.body ? <p className="mt-1 text-[11px] leading-relaxed text-[var(--text-muted)]">{item.body}</p> : null}
                <div className="mt-1 text-[10px] text-[var(--text-subtle)]">{new Date(item.created_at).toLocaleString()}</div>
              </div>
              <div className="flex shrink-0 items-center gap-1.5">
                {item.link ? <Button variant="ghost" onClick={() => { void markRead(item.id); follow(item); }}><ExternalLink className="h-3.5 w-3.5" /> Open</Button> : null}
                {!item.read ? <Button variant="secondary" onClick={() => void markRead(item.id)}>Mark read</Button> : null}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
