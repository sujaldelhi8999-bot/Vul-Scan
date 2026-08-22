import { useCallback, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardCopy,
  Eye,
  EyeOff,
  Filter,
  Loader2,
  Pause,
  Play,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { Button, EmptyState, getEventStyle, StatusBadge } from '../../components/ui/Primitives';
import { getJobEvents } from '../../services/api';
import type { JobEvent } from '../../types';

const POLL_INTERVAL = 1500;

const STATUS_COLORS: Record<string, string> = {
  RUNNING: 'text-[var(--accent-hover)]',
  COMPLETED: 'text-[var(--success)]',
  FAILED: 'text-[var(--error)]',
  CANCELLED: 'text-[var(--text-muted)]',
  SENT: 'text-[var(--text-secondary)]',
  BLOCKED: 'text-[var(--success)]',
  VERIFIED: 'text-[var(--success)]',
  CRITICAL: 'text-[var(--error)]',
  HIGH: 'text-[var(--high)]',
  MEDIUM: 'text-[var(--medium)]',
  LOW: 'text-[var(--low)]',
  INFO: 'text-[var(--info)]',
  ERROR: 'text-[var(--error)]',
};

function formatTime(ts: string) {
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function getStatusClass(status: string | null) {
  if (!status) return 'text-[var(--text-muted)]';
  return STATUS_COLORS[status] || 'text-[var(--text-muted)]';
}

export default function LiveActivityConsole({
  jobId,
  isRunning,
  onSelectEvent,
  onEventsChange,
}: {
  jobId: string | null;
  isRunning: boolean;
  onSelectEvent?: (event: JobEvent) => void;
  onEventsChange?: (events: JobEvent[]) => void;
}) {
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [latestSequence, setLatestSequence] = useState(0);
  const latestSequenceRef = useRef(0);
  const [paused, setPaused] = useState(false);
  const [bufferedEvents, setBufferedEvents] = useState<JobEvent[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [moduleFilter, setModuleFilter] = useState<string | null>(null);
  const [eventTypeFilter, setEventTypeFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const autoScrollRef = useRef(true);

  const uniqueModules = [...new Set(events.filter((e) => e.module).map((e) => e.module as string))];
  const uniqueEventTypes = [...new Set(events.map((e) => e.event_type))];
  const uniqueStatuses = [...new Set(events.filter((e) => e.status).map((e) => e.status as string))];
  const hasFilters = moduleFilter || eventTypeFilter || statusFilter || searchQuery;

  const filteredEvents = events.filter((event) => {
    if (moduleFilter && event.module !== moduleFilter) return false;
    if (eventTypeFilter && event.event_type !== eventTypeFilter) return false;
    if (statusFilter && event.status !== statusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const msg = (event.message || '').toLowerCase();
      const mod = (event.module || '').toLowerCase();
      if (!msg.includes(q) && !mod.includes(q)) return false;
    }
    return true;
  });

  const stopPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const fetchEvents = useCallback(
    async (id: string, afterSeq: number) => {
      if (!id) return;
      try {
        const response = await getJobEvents(id, afterSeq);
        if (response.events.length > 0) {
          const newEvents = response.events.filter((e) => e.sequence_number > afterSeq);
          if (newEvents.length > 0) {
            if (paused) {
              setBufferedEvents((prev) => [...prev, ...newEvents]);
            } else {
              setEvents((prev) => {
                const existingIds = new Set(prev.map((e) => e.sequence_number));
                const unique = newEvents.filter((e) => !existingIds.has(e.sequence_number));
                return [...prev, ...unique];
              });
            }
            setLatestSequence(response.latest_sequence);
            latestSequenceRef.current = response.latest_sequence;
          }
        }
      } catch {
        /* silent retry */
      }
    },
    [paused],
  );

  const startPolling = useCallback(
    (id: string) => {
      stopPolling();
      void fetchEvents(id, 0);
      pollingRef.current = setInterval(() => void fetchEvents(id, latestSequenceRef.current), POLL_INTERVAL);
    },
    [fetchEvents, stopPolling],
  );

  useEffect(() => {
    if (jobId && isRunning) {
      setEvents([]);
      setLatestSequence(0);
      latestSequenceRef.current = 0;
      setBufferedEvents([]);
      setPaused(false);
      setModuleFilter(null);
      setEventTypeFilter(null);
      setStatusFilter(null);
      setSearchQuery('');
      startPolling(jobId);
    } else if (jobId && !isRunning) {
      void fetchEvents(jobId, 0);
      stopPolling();
    } else {
      setEvents([]);
      setLatestSequence(0);
      latestSequenceRef.current = 0;
      stopPolling();
    }
    return () => stopPolling();
  }, [jobId, isRunning]);

  useEffect(() => {
    onEventsChange?.(events);
  }, [events]);

  useEffect(() => {
    if (autoScrollRef.current && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filteredEvents.length]);

  const handleResume = () => {
    setPaused(false);
    if (bufferedEvents.length > 0) {
      setEvents((prev) => {
        const existingIds = new Set(prev.map((e) => e.sequence_number));
        const unique = bufferedEvents.filter((e) => !existingIds.has(e.sequence_number));
        return [...prev, ...unique];
      });
      setBufferedEvents([]);
    }
  };

  const copyEvent = (event: JobEvent) => {
    const text = `[${event.timestamp}] ${event.event_type} | ${event.module ? event.module + ' | ' : ''}${event.message || ''} | ${event.status || ''}`;
    navigator.clipboard.writeText(text).then(() => toast.success('Copied')).catch(() => toast.error('Copy failed'));
  };

  const clearFilters = () => {
    setModuleFilter(null);
    setEventTypeFilter(null);
    setStatusFilter(null);
    setSearchQuery('');
  };

  const getDetail = (event: JobEvent) => {
    if (!event.metadata || Object.keys(event.metadata).length === 0) return null;
    return event.metadata;
  };

  return (
    <div className="flex flex-col gap-2">
      {/* Controls bar */}
      <div className="flex flex-wrap items-center gap-1.5">
        <Button
          variant="ghost"
          className="px-2 py-1 text-[10px]"
          onClick={() => (paused ? handleResume() : setPaused(true))}
          disabled={!isRunning}
        >
          {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
          {paused ? 'Resume' : 'Pause'}
        </Button>
        {paused ? (
          <span className="flex items-center gap-1 rounded bg-[var(--warning-subtle)] px-2 py-0.5 text-[10px] text-[var(--warning)]">
            <EyeOff className="h-3 w-3" /> {bufferedEvents.length} buffered
          </span>
        ) : isRunning ? (
          <span className="flex items-center gap-1 rounded bg-[var(--success-subtle)] px-2 py-0.5 text-[10px] text-[var(--success)]">
            <Eye className="h-3 w-3" /> Live
          </span>
        ) : null}
        {hasFilters ? (
          <Button variant="ghost" className="px-2 py-1 text-[10px]" onClick={clearFilters}>
            <X className="h-3 w-3" /> Clear
          </Button>
        ) : null}
        <div className="relative ml-auto">
          <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search…"
            className="h-7 w-32 rounded border border-[var(--border-default)] bg-[var(--bg-inset)] pl-7 pr-2 text-[10px] text-[var(--text-primary)] outline-none focus:border-[var(--border-active)]"
          />
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-1.5">
        <select
          value={moduleFilter || ''}
          onChange={(e) => setModuleFilter(e.target.value || null)}
          className="h-6 rounded border border-[var(--border-default)] bg-[var(--bg-inset)] px-1.5 text-[10px] text-[var(--text-secondary)] outline-none"
        >
          <option value="">All modules</option>
          {uniqueModules.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <select
          value={eventTypeFilter || ''}
          onChange={(e) => setEventTypeFilter(e.target.value || null)}
          className="h-6 rounded border border-[var(--border-default)] bg-[var(--bg-inset)] px-1.5 text-[10px] text-[var(--text-secondary)] outline-none"
        >
          <option value="">All events</option>
          {uniqueEventTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={statusFilter || ''}
          onChange={(e) => setStatusFilter(e.target.value || null)}
          className="h-6 rounded border border-[var(--border-default)] bg-[var(--bg-inset)] px-1.5 text-[10px] text-[var(--text-secondary)] outline-none"
        >
          <option value="">All statuses</option>
          {uniqueStatuses.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {/* Event list */}
      <div
        ref={scrollRef}
        className="max-h-[400px] min-h-[150px] overflow-y-auto rounded-lg border border-[var(--border-default)] bg-[var(--bg-surface)] p-1 shadow-[var(--shadow-xs)] scrollbar-compact"
        onWheel={() => {
          autoScrollRef.current = false;
        }}
        onScroll={() => {
          if (scrollRef.current) {
            const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
            autoScrollRef.current = scrollHeight - scrollTop - clientHeight < 50;
          }
        }}
      >
        {filteredEvents.length === 0 ? (
          <div className="flex items-center justify-center py-8">
            <div className="text-center">
              {isRunning ? <Loader2 className="mx-auto mb-2 h-5 w-5 animate-spin text-[var(--text-muted)]" /> : null}
              <div className="text-xs text-[var(--text-muted)]">
                {isRunning ? 'Waiting for events…' : 'No events recorded.'}
              </div>
            </div>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {filteredEvents.map((event) => {
              const style = getEventStyle(event.event_type);
              const Icon = style.icon;
              const detail = getDetail(event);
              const isExpanded = expandedId === event.sequence_number;
              return (
                <motion.div
                  key={event.sequence_number}
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.1 }}
                  className="group"
                >
                  <div
                    className="flex cursor-pointer items-start gap-2 rounded px-2 py-1.5 transition hover:bg-[var(--bg-hover)]"
                    onClick={() => {
                      if (detail) setExpandedId(isExpanded ? null : event.sequence_number);
                      onSelectEvent?.(event);
                    }}
                  >
                    <Icon className={`mt-0.5 h-3 w-3 shrink-0 ${style.color}`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5 text-[10px]">
                        <span className="shrink-0 font-mono text-[var(--text-disabled)]">{formatTime(event.timestamp)}</span>
                        <span className={`rounded bg-[var(--bg-surface-soft)] px-1 py-0.5 font-medium ${style.color}`}>
                          {event.event_type.replace(/_/g, ' ')}
                        </span>
                        {event.module ? (
                          <span className="truncate text-[var(--text-muted)]">{event.module}</span>
                        ) : null}
                        {event.status ? (
                          <span className={getStatusClass(event.status)}>{event.status}</span>
                        ) : null}
                      </div>
                      {event.message ? (
                        <div className="mt-0.5 text-[11px] text-[var(--text-secondary)] leading-4">{event.message}</div>
                      ) : null}
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); copyEvent(event); }}
                      className="shrink-0 rounded p-0.5 text-[var(--text-disabled)] opacity-0 transition group-hover:opacity-100 hover:text-[var(--text-secondary)]"
                      title="Copy"
                    >
                      <ClipboardCopy className="h-3 w-3" />
                    </button>
                  </div>
                  {isExpanded && detail ? (
                    <div className="mx-3 mb-1 overflow-hidden rounded border border-[var(--border-default)] bg-[var(--bg-inset)] p-2">
                      <pre className="whitespace-pre-wrap break-all font-mono text-[10px] text-[var(--text-muted)]">
                        {JSON.stringify(detail, null, 2)}
                      </pre>
                    </div>
                  ) : null}
                </motion.div>
              );
            })}
          </AnimatePresence>
        )}
        {isRunning && filteredEvents.length > 0 ? (
          <div className="flex justify-center py-1.5">
            <Loader2 className="h-3 w-3 animate-spin text-[var(--text-muted)]" />
          </div>
        ) : null}
      </div>
    </div>
  );
}
