import type { AgentStatus, AuditLog, Finding, ScanArtifactsResponse, ScanHistoryItem, ScanResponse, Severity } from '../types';

export const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function unresolved(findings: Finding[]): Finding[] {
  return findings.filter(
    (finding) =>
      finding.remediation_status !== 'RESOLVED' &&
      finding.verification_status !== 'FIX_VERIFIED' &&
      (finding.risk_status ?? 'ACTIVE') === 'ACTIVE'
  );
}

export function formatDateTime(value?: string | null): string {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

export function relativeTime(value?: string | null): string {
  if (!value) return 'Never';
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) return value;
  const seconds = Math.round((time - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const ranges: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['year', 31536000],
    ['month', 2592000],
    ['week', 604800],
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60]
  ];
  for (const [unit, amount] of ranges) {
    if (Math.abs(seconds) >= amount) return formatter.format(Math.round(seconds / amount), unit);
  }
  return formatter.format(seconds, 'second');
}

export function countBySeverity(findings: Finding[]) {
  const activeFindings = unresolved(findings);
  return severityOrder.reduce<Record<Severity, number>>((acc, severity) => {
    acc[severity] = activeFindings.filter((finding) => finding.severity === severity).length;
    return acc;
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
}

export function securityScore(findings: Finding[]): number {
  const counts = countBySeverity(findings);
  const penalty = counts.CRITICAL * 24 + counts.HIGH * 14 + counts.MEDIUM * 7 + counts.LOW * 2;
  return Math.max(0, Math.min(100, 100 - penalty));
}

export function latestCompletedScan(scans: ScanHistoryItem[]): ScanHistoryItem | undefined {
  return scans.find((scan) => scan.status === 'complete') ?? scans[0];
}

export function targetName(targetUrl: string): string {
  try {
    const url = new URL(targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`);
    return url.host || targetUrl;
  } catch {
    return targetUrl;
  }
}

export function deriveAssets(scans: ScanHistoryItem[], findings: Finding[]) {
  const byTarget = new Map<string, { target_url: string; scans: ScanHistoryItem[]; findings: Finding[] }>();
  for (const scan of scans) {
    const key = targetName(scan.target_url);
    const current = byTarget.get(key) ?? { target_url: scan.target_url, scans: [], findings: [] };
    current.scans.push(scan);
    byTarget.set(key, current);
  }
  for (const finding of findings) {
    const key = targetName(finding.target || finding.endpoint || 'unknown');
    const current = byTarget.get(key) ?? { target_url: finding.target || key, scans: [], findings: [] };
    current.findings.push(finding);
    byTarget.set(key, current);
  }
  return [...byTarget.entries()].map(([name, asset]) => {
    const latest = asset.scans[0];
    const score = securityScore(asset.findings);
    return {
      name,
      target_url: asset.target_url,
      score,
      findings: asset.findings,
      scans: asset.scans,
      last_scan: latest?.created_at ?? null,
      status: score >= 80 ? 'Healthy' : score >= 50 ? 'Attention Required' : 'Critical'
    };
  });
}

export function deriveTechnologies(artifactsByScanId: Record<number, ScanArtifactsResponse>) {
  const technologies = new Map<string, { name: string; scans: number[]; source: string }>();
  for (const artifact of Object.values(artifactsByScanId)) {
    const stack = artifact.scanner_output?.tech_stack;
    if (!stack || typeof stack !== 'object') continue;
    const record = stack as Record<string, unknown>;
    const values = [record.server, record.x_powered_by, ...(Array.isArray(record.technologies) ? record.technologies : [])];
    for (const value of values) {
      if (typeof value !== 'string' || !value.trim()) continue;
      const key = value.trim().toLowerCase();
      const current = technologies.get(key) ?? { name: value.trim(), scans: [], source: 'Scanner Agent' };
      if (!current.scans.includes(artifact.scan_id)) current.scans.push(artifact.scan_id);
      technologies.set(key, current);
    }
  }
  return [...technologies.values()];
}

export function deriveNotifications(findings: Finding[], logs: AuditLog[]) {
  const findingNotices = findings
    .filter((finding) => finding.severity === 'CRITICAL' || finding.severity === 'HIGH')
    .slice(-10)
    .map((finding) => ({
      id: `finding-${finding.id}`,
      type: 'Finding',
      title: `${finding.severity === 'CRITICAL' ? 'Critical' : 'High-priority'} finding detected`,
      detail: finding.title,
      timestamp: finding.timestamp,
      tone: finding.severity === 'CRITICAL' ? 'red' : 'amber'
    }));
  const logNotices = logs
    .filter((log) => /complete|error|failed|cancel|alert|verification|delivered|skipped/i.test(`${log.action} ${log.details}`))
    .slice(-20)
    .map((log) => ({
      id: `log-${log.id}`,
      type: log.agent_name.includes('Self Audit') ? 'Self Audit' : log.agent_name.includes('Agent') ? 'Agent' : 'System',
      title: log.action.replace(/_/g, ' '),
      detail: log.details,
      timestamp: log.timestamp,
      tone: /error|failed|cancel/i.test(log.action) ? 'red' : /alert|warning/i.test(log.action) ? 'amber' : 'purple'
    }));
  return [...findingNotices, ...logNotices].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export function agentSummary(agents: AgentStatus[]) {
  return {
    active: agents.filter((agent) => agent.status === 'active').length,
    waiting: agents.filter((agent) => agent.status === 'idle').length,
    completed: agents.filter((agent) => agent.status === 'complete').length,
    failed: agents.filter((agent) => agent.status === 'error').length
  };
}

export function scanDuration(scan: ScanHistoryItem | ScanResponse): string {
  const start = new Date(scan.created_at).getTime();
  const end = scan.completed_at ? new Date(scan.completed_at).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end)) return 'Not available';
  const seconds = Math.max(0, Math.round((end - start) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes}m ${remaining}s`;
}

export function previousScanForTarget(scans: ScanHistoryItem[], current: ScanResponse): ScanHistoryItem | undefined {
  return scans.find((scan) => scan.id !== current.scan_id && targetName(scan.target_url) === targetName(current.target_url));
}
