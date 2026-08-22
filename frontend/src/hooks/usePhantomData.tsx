import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';

import {
  expireSession,
  getAgentStatuses,
  getExecutionStatus,
  getFindings,
  getHealth,
  getLogs,
  getScanArtifacts,
  getScanHistory,
  getSelfAuditStatus,
  getWebSocketUrl,
  refreshSessionToken
} from '../services/api';
import type {
  AgentStatus,
  AuditLog,
  ConnectionState,
  ExecutionLifecycle,
  ExecutionStatusResponse,
  Finding,
  HealthResponse,
  ScanArtifactsResponse,
  ScanHistoryItem,
  SelfAuditStatusResponse
} from '../types';

const EXECUTION_POLL_INTERVAL = 5000;
const COMPLETED_STATUSES = new Set(['complete', 'completed']);
const TERMINAL_EXECUTION: ExecutionLifecycle[] = ['COMPLETED', 'FAILED', 'CANCELLED'];
const ACTIVE_EXECUTION: ExecutionLifecycle[] = ['QUEUED', 'STARTING', 'RUNNING', 'PAUSED'];

interface PhantomDataContextValue {
  health: HealthResponse | null;
  scans: ScanHistoryItem[];
  findings: Finding[];
  logs: AuditLog[];
  agents: AgentStatus[];
  selfAudit: SelfAuditStatusResponse | null;
  artifactsByScanId: Record<number, ScanArtifactsResponse>;
  loading: boolean;
  refreshing: boolean;
  error: string | null;
  realtimeState: ConnectionState;
  realtimeHealthy: boolean;
  refresh: () => Promise<void>;
  executionStatus: ExecutionStatusResponse | null;
  executionActive: boolean;
}

const PhantomDataContext = createContext<PhantomDataContextValue | null>(null);

function isHealthResponse(value: unknown): value is HealthResponse {
  return typeof value === 'object' && value !== null && 'database' in value && 'scheduler' in value;
}

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  let timer: number | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<null>((resolve) => {
        timer = window.setTimeout(() => resolve(null), ms);
      }),
    ]);
  } finally {
    if (timer) window.clearTimeout(timer);
  }
}

export function PhantomDataProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [selfAudit, setSelfAudit] = useState<SelfAuditStatusResponse | null>(null);
  const [artifactsByScanId, setArtifactsByScanId] = useState<Record<number, ScanArtifactsResponse>>({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [realtimeState, setRealtimeState] = useState<ConnectionState>('idle');
  const [executionStatus, setExecutionStatus] = useState<ExecutionStatusResponse | null>(null);
  const refreshInFlight = useRef(false);
  const execPollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [hasToken, setHasToken] = useState(() => !!localStorage.getItem('phantom_token'));

  useEffect(() => {
    const check = () => setHasToken(!!localStorage.getItem('phantom_token'));
    window.addEventListener('storage', check);
    const id = window.setInterval(check, 2000);
    return () => { window.removeEventListener('storage', check); window.clearInterval(id); };
  }, []);

  const refresh = async () => {
    if (!hasToken) {
      setLoading(false);
      return;
    }
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    try {
      const requests = Promise.allSettled([
        getHealth(),
        getScanHistory(),
        getFindings(),
        getLogs(),
        getAgentStatuses(),
        getSelfAuditStatus()
      ]);

      const results = await withTimeout(requests, 8000);

      if (results) {
        const [healthResult, scansResult, findingsResult, logsResult, agentsResult, selfAuditResult] = results;

        if (healthResult.status === 'fulfilled') setHealth(healthResult.value);
        if (scansResult.status === 'fulfilled') setScans(scansResult.value);
        if (findingsResult.status === 'fulfilled') setFindings(findingsResult.value);
        if (logsResult.status === 'fulfilled') setLogs(logsResult.value);
        if (agentsResult.status === 'fulfilled') setAgents(agentsResult.value);
        if (selfAuditResult.status === 'fulfilled') setSelfAudit(selfAuditResult.value);

        const failures = [healthResult, scansResult, findingsResult, logsResult, agentsResult, selfAuditResult].filter(
          (result) => result.status === 'rejected'
        );
        setError(failures.length ? 'Some VulScan backend data could not be refreshed.' : null);

        const artifactScans = scansResult.status === 'fulfilled'
          ? scansResult.value.filter((scan) => COMPLETED_STATUSES.has(scan.status)).slice(0, 8)
          : scans.filter((scan) => COMPLETED_STATUSES.has(scan.status)).slice(0, 8);
        const artifactResults = await withTimeout(
          Promise.allSettled(artifactScans.map((scan) => getScanArtifacts(scan.id))),
          5000
        );
        if (artifactResults) {
          const nextArtifacts: Record<number, ScanArtifactsResponse> = {};
          for (const result of artifactResults) {
            if (result.status === 'fulfilled') {
              nextArtifacts[result.value.scan_id] = result.value;
            }
          }
          setArtifactsByScanId((current) => ({ ...current, ...nextArtifacts }));
        }
      } else {
        setError('Backend data refresh timed out. Check that the API is reachable.');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
      refreshInFlight.current = false;
    }
  };

  useEffect(() => {
    if (!hasToken) return;
    void refresh();
    const id = window.setInterval(() => void refresh(), 15000);
    return () => window.clearInterval(id);
  }, [hasToken]);

  useEffect(() => {
    if (!hasToken) return;
    let socket: WebSocket | null = null;
    let reconnect: number | undefined;
    let connectTimeout: number | undefined;
    let active = true;
    let reconnectAttempts = 0;
    let refreshCycles = 0;
    const MAX_RECONNECT_ATTEMPTS = 6;
    const MAX_REFRESH_CYCLES = 2;
    const CONNECT_TIMEOUT_MS = 5000;

    const connect = async () => {
      if (!active) return;
      if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        setRealtimeState('error');
        return;
      }
      // Never dial with an expired token — refresh first (single-flight).
      const refreshed = await refreshSessionToken();
      if (!active) return;
      if (!refreshed) {
        expireSession();
        return;
      }
      setRealtimeState('connecting');
      try {
        socket = new WebSocket(getWebSocketUrl('/ws/status'));
      } catch {
        setRealtimeState('error');
        reconnectAttempts += 1;
        reconnect = window.setTimeout(() => void connect(), Math.min(5000 * reconnectAttempts, 30000));
        return;
      }

      // Timeout: if connection doesn't open within CONNECT_TIMEOUT_MS, treat as error
      connectTimeout = window.setTimeout(() => {
        if (socket && socket.readyState === WebSocket.CONNECTING) {
          socket.close();
          setRealtimeState('error');
          reconnectAttempts += 1;
          reconnect = window.setTimeout(() => void connect(), Math.min(5000 * reconnectAttempts, 30000));
        }
      }, CONNECT_TIMEOUT_MS);

      socket.onopen = () => {
        if (connectTimeout) { clearTimeout(connectTimeout); connectTimeout = undefined; }
        reconnectAttempts = 0;
        setRealtimeState('open');
      };
      socket.onerror = () => {
        setRealtimeState('error');
      };
      socket.onmessage = (event: MessageEvent<string>) => {
        try {
          const parsed = JSON.parse(event.data) as Record<string, unknown>;
          const payload = typeof parsed.payload === 'object' && parsed.payload !== null ? parsed.payload : parsed;
          if (isHealthResponse(payload)) setHealth(payload);
        } catch {
          // Ignore malformed frames
        }
      };
      socket.onclose = (event: CloseEvent) => {
        if (connectTimeout) { clearTimeout(connectTimeout); connectTimeout = undefined; }
        if (!active) return;
        // 4000/4001 = access token expired — refresh and reconnect with the fresh token.
        if (event.code === 4000 || event.code === 4001) {
          refreshCycles += 1;
          if (refreshCycles > MAX_REFRESH_CYCLES) {
            setRealtimeState('error');
            expireSession();
            return;
          }
          void refreshSessionToken().then((refreshed) => {
            if (!active) return;
            if (!refreshed) {
              setRealtimeState('error');
              expireSession();
              return;
            }
            reconnectAttempts += 1;
            reconnect = window.setTimeout(() => void connect(), 1000);
          });
          return;
        }
        // Code 1008 = policy violation (invalid credential) — session is dead.
        if (event.code === 1008) {
          setRealtimeState('error');
          expireSession();
          return;
        }
        setRealtimeState('closed');
        reconnectAttempts += 1;
        reconnect = window.setTimeout(() => void connect(), Math.min(5000 * reconnectAttempts, 30000));
      };
    };

    void connect();
    return () => {
      active = false;
      if (reconnect) window.clearTimeout(reconnect);
      if (connectTimeout) window.clearTimeout(connectTimeout);
      socket?.close();
    };
  }, []);

  const realtimeHealthy = realtimeState === 'open' && health?.status === 'ok';

  const execActive = executionStatus ? ACTIVE_EXECUTION.includes(executionStatus.lifecycle) : false;

  const fetchExecutionStatus = async () => {
    // Never dial without a credential — prevents guaranteed-401 requests
    // (e.g. visibilitychange firing while logged out).
    if (!localStorage.getItem('phantom_token')) return;
    try {
      const result = await getExecutionStatus();
      if (result) {
        setExecutionStatus(result);
        if (TERMINAL_EXECUTION.includes(result.lifecycle)) {
          if (execPollingRef.current) {
            clearInterval(execPollingRef.current);
            execPollingRef.current = null;
          }
        }
      }
    } catch {
      // silent
    }
  };

  useEffect(() => {
    if (!hasToken) return;
    const startPolling = () => {
      if (execPollingRef.current) {
        clearInterval(execPollingRef.current);
        execPollingRef.current = null;
      }
      execPollingRef.current = setInterval(() => void fetchExecutionStatus(), EXECUTION_POLL_INTERVAL);
    };

    fetchExecutionStatus().then(() => {
      if (execActive && !execPollingRef.current) {
        startPolling();
      }
    });

    return () => {
      if (execPollingRef.current) {
        clearInterval(execPollingRef.current);
        execPollingRef.current = null;
      }
    };
  }, [execActive]);

  useEffect(() => {
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        void fetchExecutionStatus();
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, []);

  // When refresh is called, also refetch execution status
  const origRefresh = refresh;
  const superRefresh = async () => {
    await origRefresh();
    await fetchExecutionStatus();
  };

  return (
    <PhantomDataContext.Provider
      value={{
        health,
        scans,
        findings,
        logs,
        agents,
        selfAudit,
        artifactsByScanId,
        loading,
        refreshing,
        error,
        realtimeState,
        realtimeHealthy,
        refresh: superRefresh,
        executionStatus,
        executionActive: execActive,
      }}
    >
      {children}
    </PhantomDataContext.Provider>
  );
}

export function usePhantomData() {
  const context = useContext(PhantomDataContext);
  if (!context) throw new Error('usePhantomData must be used inside PhantomDataProvider');
  return context;
}
