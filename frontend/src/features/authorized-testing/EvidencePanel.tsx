import { useCallback, useEffect, useRef, useState } from 'react';
import { getJobEvidence } from '../../services/api';
import { cx } from '../../components/ui/Primitives';

interface EvidenceRecord {
  id: number;
  request_id: string;
  job_id: string;
  module: string;
  surface: string;
  method: string;
  request_url: string;
  safe_test_marker: string;
  request_timestamp: string;
  response_status: number | null;
  response_time_ms: number | null;
  response_observed: boolean;
  detection_result: string;
  evidence_summary: string;
  finding_id: number | null;
  error: string | null;
}

function resultColor(result: string) {
  switch (result) {
    case 'VULNERABLE': return 'text-[var(--error)]';
    case 'PROTECTED': return 'text-[var(--success)]';
    case 'INCONCLUSIVE': return 'text-[var(--warning)]';
    case 'ERROR': return 'text-[var(--error)]';
    default: return 'text-[var(--text-muted)]';
  }
}

export default function EvidencePanel({ jobId, isRunning }: { jobId: string | null; isRunning: boolean }) {
  const [records, setRecords] = useState<EvidenceRecord[]>([]);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchEvidence = useCallback(async () => {
    if (!jobId) return;
    try {
      const data = await getJobEvidence(jobId);
      setRecords(data);
    } catch {
      /* ignore */
    }
  }, [jobId]);

  useEffect(() => {
    if (isRunning) {
      void fetchEvidence();
      pollingRef.current = setInterval(() => void fetchEvidence(), 3000);
    } else if (jobId) {
      void fetchEvidence();
    }
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [jobId, isRunning, fetchEvidence]);

  if (!jobId) return null;

  const requestCount = records.length;
  const responseCount = records.filter(r => r.response_observed).length;
  const timeoutCount = records.filter(r => r.error && r.error.toLowerCase().includes('timeout')).length;

  return (
    <div className="mt-4">
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
        Request Evidence ({requestCount} requests, {responseCount} responses
        {timeoutCount > 0 ? `, ${timeoutCount} timeouts` : ''})
      </h4>
      <div className="max-h-[320px] space-y-1 overflow-y-auto rounded-lg border border-[var(--border-light)] bg-[var(--surface-secondary)] p-2 font-mono text-[10px]">
        {records.length === 0 ? (
          <div className="px-2 py-3 text-center text-[var(--text-muted)]">
            Waiting for request evidence...
          </div>
        ) : (
          [...records].reverse().map((rec) => (
            <div
              key={rec.id}
              className="rounded-md bg-white px-2.5 py-1.5 shadow-sm"
            >
              <div className="flex items-center gap-2">
                <span className={cx('shrink-0 rounded px-1 py-0.5 font-semibold', resultColor(rec.detection_result))}>
                  {rec.detection_result}
                </span>
                <span className="shrink-0 text-[var(--text-muted)]">{rec.method}</span>
                <span className="min-w-0 flex-1 truncate text-[var(--text-strong)]" title={rec.request_url}>
                  {rec.surface || rec.request_url}
                </span>
                <span className="shrink-0 text-[var(--text-muted)]">{rec.module}</span>
              </div>
              <div className="mt-0.5 flex items-center gap-3 text-[9px] text-[var(--text-muted)]">
                <span>ID: {rec.request_id}</span>
                {rec.response_status !== null && <span>Status: {rec.response_status}</span>}
                {rec.response_time_ms !== null && <span>{rec.response_time_ms}ms</span>}
                {rec.finding_id !== null && (
                  <span className="text-[var(--info)]">Finding #{rec.finding_id}</span>
                )}
                {rec.error && <span className="text-[var(--error)]">Error: {rec.error.slice(0, 60)}</span>}
                {rec.safe_test_marker && <span>Marker: {rec.safe_test_marker}</span>}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}