import { useEffect, useState } from 'react';

import { createAuthenticatedWebSocket, expireSession, getAgentStatuses, getLogs, getScan, refreshSessionToken } from '../services/api';
import type { AgentStatus, AuditLog, ConnectionState, Finding, ScanStatus, TimelineEvent } from '../types';

interface ScanTelemetry {
  connectionState: ConnectionState;
  scanStatus: ScanStatus | null;
  progress: number | null;
  requestCount: number | null;
  findings: Finding[];
  logs: AuditLog[];
  agents: AgentStatus[];
  events: TimelineEvent[];
  error: string | null;
}

const terminalStatuses: ScanStatus[] = ['cancelled', 'complete', 'error'];
const scanStatuses: ScanStatus[] = ['queued', 'running', 'cancelling', 'cancelled', 'complete', 'error'];

function numericProgress(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, Math.min(100, value));
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.max(0, Math.min(100, parsed));
  }
  return null;
}

function normalizeScanStatus(value: unknown): ScanStatus | null {
  if (typeof value !== 'string') return null;
  const normalized = value.toLowerCase();
  if (normalized === 'completed') return 'complete';
  if (normalized === 'failed') return 'error';
  return scanStatuses.includes(normalized as ScanStatus) ? normalized as ScanStatus : null;
}

function timestamp(value?: string): string {
  const date = value ? new Date(value) : new Date();
  return Number.isNaN(date.getTime())
    ? new Date().toLocaleTimeString('en-GB', { hour12: false })
    : date.toLocaleTimeString('en-GB', { hour12: false });
}

function toneFor(action: string): TimelineEvent['tone'] {
  if (/error|failed|cancel/i.test(action)) return 'red';
  if (/complete|delivered|destroyed/i.test(action)) return 'green';
  if (/cve|intelligence/i.test(action)) return 'blue';
  if (/warning|alert/i.test(action)) return 'amber';
  return 'purple';
}

function logsToEvents(logs: AuditLog[]): TimelineEvent[] {
  return logs.map((log) => ({
    id: `log-${log.id}`,
    timestamp: timestamp(log.timestamp),
    title: log.action.replace(/_/g, ' '),
    detail: log.details,
    agent: log.agent_name,
    tone: toneFor(log.action)
  }));
}

export function useScanTelemetry(scanId: number | null): ScanTelemetry {
  const [connectionState, setConnectionState] = useState<ConnectionState>('idle');
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [requestCount, setRequestCount] = useState<number | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setConnectionState(scanId ? 'connecting' : 'idle');
    setScanStatus(null);
    setProgress(null);
    setRequestCount(null);
    setFindings([]);
    setLogs([]);
    setEvents([]);
    setError(null);

    if (!scanId) return undefined;

    let socket: WebSocket | null = null;
    let active = true;
    let reconnectTimer: number | undefined;
    let connectTimer: number | undefined;
    let pollTimer: number | undefined;
    let pollInFlight = false;
    let reconnectAttempts = 0;
    const MAX_RECONNECT_ATTEMPTS = 4;
    const CONNECT_TIMEOUT_MS = 5000;
    const POLL_INTERVAL_MS = 2000;
    let sequence = 0;
    let latestStatus: ScanStatus | null = null;
    const seenEvents = new Set<string>();

    const appendEvent = (event: Omit<TimelineEvent, 'id'> & { id?: string }) => {
      const id = event.id ?? `event-${scanId}-${Date.now()}-${sequence++}`;
      if (seenEvents.has(id)) return;
      seenEvents.add(id);
      setEvents((current) => [...current, { ...event, id }].slice(-240));
    };

    const applyLogs = (nextLogs: AuditLog[]) => {
      setLogs(nextLogs);
      for (const event of logsToEvents(nextLogs)) appendEvent(event);
    };

    const applyFinding = (finding: Finding) => {
      setFindings((current) => {
        const id = Number(finding.id);
        if (!Number.isFinite(id)) return [...current, finding];
        const existingIndex = current.findIndex((item) => Number(item.id) === id);
        if (existingIndex === -1) return [...current, finding];
        const next = [...current];
        next[existingIndex] = finding;
        return next;
      });
    };

    const stopPolling = () => {
      if (pollTimer) {
        window.clearInterval(pollTimer);
        pollTimer = undefined;
      }
    };

    const refreshFallback = async () => {
      try {
        const [scan, nextLogs, nextAgents] = await Promise.all([getScan(scanId), getLogs(scanId), getAgentStatuses(scanId)]);
        latestStatus = scan.status;
        setScanStatus(scan.status);
        setProgress((current) => Math.max(current ?? 0, scan.progress));
        setRequestCount(scan.request_count);
        setFindings(scan.findings);
        applyLogs(nextLogs);
        setAgents(nextAgents);
        if (terminalStatuses.includes(scan.status)) stopPolling();
      } catch (fallbackError) {
        const is404 = typeof fallbackError === 'object' && fallbackError !== null && 'response' in fallbackError &&
          (fallbackError as { response?: { status?: number } }).response?.status === 404;
        if (is404) {
          setScanStatus('error' as ScanStatus);
          setError('Scan no longer exists');
        } else {
          setError(fallbackError instanceof Error ? fallbackError.message : 'Unable to refresh scan telemetry.');
        }
      }
    };

    const handleFrame = (raw: string) => {
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        setError('Malformed realtime frame received.');
        return;
      }

      const payload = typeof frame.payload === 'object' && frame.payload !== null ? (frame.payload as Record<string, unknown>) : frame;
      const eventName = String(frame.event ?? frame.type ?? 'telemetry');
      if (eventName === 'scan_complete') {
        latestStatus = 'complete';
        setScanStatus('complete');
        setProgress(100);
        stopPolling();
      }
      if (typeof payload.error === 'string') {
        setError(payload.error);
        appendEvent({ timestamp: timestamp(), title: 'Realtime error', detail: payload.error, tone: 'red', agent: 'System' });
      }
      const nextStatus = normalizeScanStatus(payload.status);
      if (nextStatus) {
        latestStatus = nextStatus;
        setScanStatus(nextStatus);
        if (terminalStatuses.includes(nextStatus)) stopPolling();
      }
      const nextProgress = numericProgress(payload.progress ?? payload.payload_progress);
      if (nextProgress !== null) setProgress((current) => Math.max(current ?? 0, nextProgress));
      if (typeof payload.request_count === 'number') setRequestCount(payload.request_count);
      if (Array.isArray(payload.findings)) {
        setFindings(payload.findings as Finding[]);
      } else if (typeof payload.finding === 'object' && payload.finding !== null) {
        applyFinding(payload.finding as Finding);
      }
      if (Array.isArray(payload.logs)) applyLogs(payload.logs as AuditLog[]);

      if (eventName !== 'snapshot' && eventName !== 'heartbeat') {
        const title = eventName.replace(/_/g, ' ');
        appendEvent({
          timestamp: timestamp(),
          title,
          detail: typeof payload.message === 'string'
            ? payload.message
            : typeof payload.phase === 'string'
              ? payload.phase.replace(/_/g, ' ')
              : typeof payload.details === 'string'
                ? payload.details
                : typeof payload.result === 'string'
                  ? payload.result
                  : undefined,
          agent: typeof payload.agent_name === 'string' ? payload.agent_name : typeof payload.agent === 'string' ? payload.agent : 'System',
          tone: toneFor(`${eventName} ${String(payload.status ?? '')}`)
        });
      }

      if (eventName === 'snapshot' || eventName === 'scan_complete' || eventName === 'scan_failed' || eventName === 'scan_cancelled') {
        void getAgentStatuses(scanId).then(setAgents).catch(() => undefined);
        if (eventName !== 'snapshot') void refreshFallback();
      }
    };

    const connect = async () => {
      if (!active) return;
      if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        setConnectionState('error');
        setError('Realtime connection unavailable. Data updates via polling.');
        return;
      }
      // Never dial with an expired token — refresh first (single-flight).
      const refreshed = await refreshSessionToken();
      if (!active) return;
      if (!refreshed) {
        expireSession();
        return;
      }
      setConnectionState('connecting');
      try {
        socket = await createAuthenticatedWebSocket(`/ws/scan/${scanId}`, 'scan', scanId);
      } catch {
        setConnectionState('error');
        setError('Realtime connection unavailable. Data updates via polling.');
        reconnectAttempts += 1;
        reconnectTimer = window.setTimeout(() => void connect(), Math.min(1000 * 2 ** reconnectAttempts, 8000));
        return;
      }

      // Timeout: if connection doesn't open within CONNECT_TIMEOUT_MS, treat as failed
      connectTimer = window.setTimeout(() => {
        if (socket && socket.readyState === WebSocket.CONNECTING) {
          socket.close();
          setConnectionState('error');
          setError('WebSocket connection timed out');
          reconnectAttempts += 1;
          reconnectTimer = window.setTimeout(() => void connect(), Math.min(1000 * 2 ** reconnectAttempts, 8000));
        }
      }, CONNECT_TIMEOUT_MS);

      socket.onopen = () => {
        if (connectTimer) { clearTimeout(connectTimer); connectTimer = undefined; }
        reconnectAttempts = 0;
        setConnectionState('open');
        appendEvent({ timestamp: timestamp(), title: 'Realtime connected', detail: `Scan ${scanId}`, tone: 'green', agent: 'System' });
      };
      socket.onmessage = (event: MessageEvent<string>) => handleFrame(event.data);
      socket.onerror = () => setConnectionState('error');
      socket.onclose = (event: CloseEvent) => {
        if (connectTimer) { clearTimeout(connectTimer); connectTimer = undefined; }
        if (!active) return;
        setConnectionState('closed');
        // 4000/4001 = access token expired — refresh and reconnect with the fresh token.
        if (event.code === 4000 || event.code === 4001) {
          void refreshSessionToken().then((refreshed) => {
            if (!active) return;
            if (!refreshed) {
              setConnectionState('error');
              setError('Authentication failed. Please log in again.');
              expireSession();
              return;
            }
            if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
              reconnectAttempts += 1;
              reconnectTimer = window.setTimeout(() => void connect(), 1000);
            }
          });
          return;
        }
        // Code 1008 = policy violation (invalid credential) — session is dead.
        if (event.code === 1008) {
          setConnectionState('error');
          setError('Authentication failed. Please log in again.');
          expireSession();
          return;
        }
        // 4044 = scan no longer exists.
        if (event.code === 4044) {
          setConnectionState('error');
          setError('Scan no longer exists');
          return;
        }
        if (latestStatus && terminalStatuses.includes(latestStatus)) return;
        void refreshFallback();
        if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
          reconnectAttempts += 1;
          reconnectTimer = window.setTimeout(() => void connect(), Math.min(1000 * 2 ** reconnectAttempts, 8000));
        }
      };
    };

    const startPolling = () => {
      stopPolling();
      pollTimer = window.setInterval(() => {
        if (!active || (latestStatus && terminalStatuses.includes(latestStatus)) || pollInFlight) return;
        pollInFlight = true;
        void refreshFallback().finally(() => { pollInFlight = false; });
      }, POLL_INTERVAL_MS);
    };

    void refreshFallback();
    void connect();
    startPolling();

    return () => {
      active = false;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      if (connectTimer) window.clearTimeout(connectTimer);
      stopPolling();
      socket?.close();
    };
  }, [scanId]);

  return { connectionState, scanStatus, progress, requestCount, findings, logs, agents, events, error };
}
