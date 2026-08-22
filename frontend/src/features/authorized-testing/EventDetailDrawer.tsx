import type { JobEvent } from '../../types';
import { Drawer, StatusBadge } from '../../components/ui/Primitives';

export default function EventDetailDrawer({
  event,
  open,
  onClose,
}: {
  event: JobEvent | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!event) return null;

  const metadata = event.metadata || {};
  const reqMethod = metadata.method as string | undefined;
  const reqRoute = metadata.route as string | undefined;
  const reqHeaders = metadata.safe_headers as Record<string, string> | undefined;
  const reqBodyShape = metadata.body_shape as string | undefined;
  const reqContentType = metadata.content_type as string | undefined;
  const respStatusCode = metadata.status_code as number | undefined;
  const respHeaders = metadata.response_headers as Record<string, string> | undefined;
  const respSummary = metadata.response_summary as string | undefined;
  const respDuration = metadata.duration_ms as number | undefined;
  const findingSeverity = metadata.severity as string | undefined;
  const findingConfidence = metadata.confidence as string | undefined;
  const findingEndpoint = metadata.endpoint as string | undefined;
  const isRequestResponse = event.event_type === 'TEST_REQUEST_SENT' || event.event_type === 'RESPONSE_RECEIVED';

  return (
    <Drawer title={`Event: ${event.event_type.replace(/_/g, ' ')}`} open={open} onClose={onClose}>
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          <div className="rounded-lg bg-[var(--bg-surface-soft)] p-2.5">
            <div className="text-[10px] text-[var(--text-muted)]">Type</div>
            <div className="mt-0.5 text-xs text-[var(--text-primary)]">{event.event_type}</div>
          </div>
          <div className="rounded-lg bg-[var(--bg-surface-soft)] p-2.5">
            <div className="text-[10px] text-[var(--text-muted)]">Time</div>
            <div className="mt-0.5 text-xs text-[var(--text-primary)]">
              {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '--'}
            </div>
          </div>
          <div className="rounded-lg bg-[var(--bg-surface-soft)] p-2.5">
            <div className="text-[10px] text-[var(--text-muted)]">Module</div>
            <div className="mt-0.5 text-xs text-[var(--text-primary)]">{event.module || '--'}</div>
          </div>
          <div className="rounded-lg bg-[var(--bg-surface-soft)] p-2.5">
            <div className="text-[10px] text-[var(--text-muted)]">Status</div>
            <div className="mt-0.5">{event.status ? <StatusBadge status={event.status} /> : '--'}</div>
          </div>
        </div>

        {event.message ? (
          <div className="rounded-lg bg-[var(--bg-surface-soft)] p-3">
            <div className="mb-0.5 text-[10px] text-[var(--text-muted)]">Message</div>
            <div className="text-xs text-[var(--text-secondary)]">{event.message}</div>
          </div>
        ) : null}

        {isRequestResponse ? (
          <>
            <div className="rounded-lg border border-[var(--warning-subtle)] bg-[var(--warning-subtle)] p-3">
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--warning)]">Request</div>
              <div className="space-y-1 text-[11px]">
                <div><span className="text-[var(--text-muted)]">Method:</span> <span className="font-mono text-[var(--text-secondary)]">{reqMethod || '--'}</span></div>
                <div><span className="text-[var(--text-muted)]">Route:</span> <span className="font-mono text-[var(--text-secondary)]">{reqRoute || '--'}</span></div>
                {reqContentType ? <div><span className="text-[var(--text-muted)]">Content-Type:</span> <span className="font-mono text-[var(--text-secondary)]">{reqContentType}</span></div> : null}
                {reqBodyShape ? <div><span className="text-[var(--text-muted)]">Body:</span> <span className="font-mono text-[var(--text-secondary)]">{reqBodyShape}</span></div> : null}
                {reqHeaders ? (
                  <div>
                    <div className="mb-0.5 mt-1 text-[10px] text-[var(--text-muted)]">Headers:</div>
                    <pre className="overflow-x-auto rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-muted)]">{JSON.stringify(reqHeaders, null, 2)}</pre>
                  </div>
                ) : null}
              </div>
            </div>
            <div className="rounded-lg border border-[var(--success-subtle)] bg-[var(--success-subtle)] p-3">
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--success)]">Response</div>
              <div className="space-y-1 text-[11px]">
                {respStatusCode ? <div><span className="text-[var(--text-muted)]">Status:</span> <span className="font-mono text-[var(--text-secondary)]">{respStatusCode}</span></div> : null}
                {respDuration ? <div><span className="text-[var(--text-muted)]">Duration:</span> <span className="font-mono text-[var(--text-secondary)]">{respDuration}ms</span></div> : null}
                {respHeaders ? (
                  <div>
                    <div className="mb-0.5 mt-1 text-[10px] text-[var(--text-muted)]">Security Headers:</div>
                    <pre className="overflow-x-auto rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-muted)]">{JSON.stringify(respHeaders, null, 2)}</pre>
                  </div>
                ) : null}
                {respSummary ? (
                  <div>
                    <div className="mb-0.5 mt-1 text-[10px] text-[var(--text-muted)]">Body:</div>
                    <pre className="max-h-24 overflow-y-auto rounded bg-[var(--bg-inset)] p-2 font-mono text-[10px] text-[var(--text-muted)]">{respSummary.slice(0, 500)}</pre>
                  </div>
                ) : null}
              </div>
            </div>
          </>
        ) : event.event_type === 'FINDING_DETECTED' ? (
          <div className="rounded-lg border border-[var(--error-subtle)] bg-[var(--error-subtle)] p-3">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--error)]">Finding</div>
            <div className="space-y-1 text-[11px]">
              {findingSeverity ? <div><span className="text-[var(--text-muted)]">Severity:</span> <span className="text-[var(--text-secondary)]">{findingSeverity}</span></div> : null}
              {findingConfidence ? <div><span className="text-[var(--text-muted)]">Confidence:</span> <span className="text-[var(--text-secondary)]">{findingConfidence}</span></div> : null}
              {findingEndpoint ? <div><span className="text-[var(--text-muted)]">Endpoint:</span> <span className="text-[var(--text-secondary)]">{findingEndpoint}</span></div> : null}
            </div>
          </div>
        ) : null}

        {Object.keys(metadata).length > 0 && !isRequestResponse && event.event_type !== 'FINDING_DETECTED' ? (
          <div>
            <div className="mb-1 text-[10px] font-semibold text-[var(--text-muted)]">Metadata</div>
            <pre className="overflow-x-auto rounded-lg bg-[var(--bg-inset)] p-3 font-mono text-[10px] text-[var(--text-muted)]">{JSON.stringify(metadata, null, 2)}</pre>
          </div>
        ) : null}

        <div className="grid grid-cols-2 gap-2 rounded-lg bg-[var(--bg-surface-soft)] p-2.5 text-[10px] text-[var(--text-muted)]">
          <div>
            <span className="block text-[var(--text-disabled)]">Sequence</span>
            <span className="font-mono text-[var(--text-secondary)]">#{event.sequence_number}</span>
          </div>
          <div>
            <span className="block text-[var(--text-disabled)]">Job ID</span>
            <span className="font-mono text-[var(--text-secondary)]">{event.job_id.slice(0, 12)}…</span>
          </div>
        </div>
      </div>
    </Drawer>
  );
}
