import { isValidElement, useState, type ReactNode } from 'react';
import {
  AlertTriangle,
  ExternalLink,
  Globe,
  Lock,
  Search,
  Shield,
  Zap,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { useAuth } from '../../context/AuthContext';
import apiClient, { apiErrorMessage } from '../../services/api';
import { hasElevatedAccess } from '../../utils/access';
import {
  Button,
  EmptyState,
  ErrorState,
  InfoCallout,
  Input,
  Page,
  PageHeader,
  Panel,
  SeverityBadge,
} from '../../components/ui/Primitives';

interface SensitiveFiles {
  '.git/': number | null;
  '.env': number | null;
  'config.php': number | null;
  'wp-config.php': number | null;
  'backup.sql': number | null;
  'dump.sql': number | null;
  'admin/': number | null;
  'phpinfo.php': number | null;
  '.htaccess': number | null;
  [key: string]: number | null;
}

interface Finding {
  id: number;
  title: string;
  description: string;
  category: string;
  severity: string;
  confidence: string;
  target: string;
  endpoint: string;
  evidence: string;
  impact: string;
  parameter: string | null;
  module: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  recommended_fix: string | null;
  confidence_score?: number | null;
  confidence_label?: string | null;
  risk_status?: string | null;
  reproduction_command?: string | null;
  request_response_diff?: string | null;
  affected_urls?: string[];
}

interface IntelligenceData {
  target: {
    url: string;
    hostname: string | null;
    ip: string | null;
    timestamp: string | null;
  };
  recon: {
    dns: {
      a_records: string[];
      aaaa_records: string[];
      mx_records: string[];
      txt_records: string[];
      cname_records: string[];
      ns_records: string[];
      soa_records: string[];
      ptr_records: string[];
      srv_records: string[];
      caa_records: string[];
      zone_transfer: string | null;
      wildcard: boolean | null;
      dnssec: boolean | null;
    };
    ports: {
      open: number[];
      closed: number[];
      filtered: number[];
      details: {
        number: number;
        protocol?: string;
        state?: string;
        service?: string;
        banner?: string;
        tls?: boolean;
        version?: string;
        http_version?: string;
        server?: string;
        x_powered_by?: string;
      }[];
    };
    technologies: {
      frameworks: string[];
      servers: string[];
      waf: string | null;
      cdn: string | null;
      detailed: { name: string; category?: string; version?: string; confidence?: number; evidence?: string[] }[];
      waf_evidence: string[];
    };
    headers: Record<string, string>;
    tls: {
      version: string | null;
      cipher: string | null;
      expiry: string | null;
      valid: boolean | null;
      protocols: Record<string, boolean>;
      ciphers: string[];
      vulnerabilities: string[];
      port: number | null;
    };
  };
  exposed: {
    robots_txt: string | null;
    sitemap: string[];
    emails: string[];
    internal_ips: string[];
    comments: string[];
    sensitive_files: SensitiveFiles;
    js_source_maps: string[];
    phones: string[];
    social_profiles: { network: string; url: string }[];
    discovered_files: { path: string; url?: string; status_code?: number }[];
  };
  entry_points: {
    url_parameters: string[];
    post_fields: string[];
    headers: string[];
    cookies: string[];
    json_body: string[];
    websockets: string[];
    graphql_endpoints: string[];
    api_endpoints: string[];
    file_uploads: string[];
  };
  findings: {
    critical: Finding[];
    high: Finding[];
    medium: Finding[];
    low: Finding[];
    info: Finding[];
  };
  risk_score: {
    score: number;
    level: string;
    color: string;
  };
  exploitation_roadmap: {
    summary: string | null;
    steps: string[];
    recommended_chain: string[];
  };
  ai_analysis: {
    attack_vector_summary: string | null;
    most_dangerous_entry: string | null;
    recommended_next_steps: string[];
  };
}

const riskColors: Record<string, { text: string; bg: string; border: string; bar: string }> = {
  red:    { text: 'text-red-700 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/20', border: 'border-red-500', bar: 'bg-red-500' },
  orange: { text: 'text-orange-700 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-900/20', border: 'border-orange-500', bar: 'bg-orange-500' },
  yellow: { text: 'text-yellow-700 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-900/20', border: 'border-yellow-500', bar: 'bg-yellow-500' },
  blue:   { text: 'text-blue-700 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-900/20', border: 'border-blue-500', bar: 'bg-blue-500' },
  green:  { text: 'text-green-700 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-900/20', border: 'border-green-500', bar: 'bg-green-500' },
  gray:   { text: 'text-gray-600 dark:text-gray-400', bg: 'bg-gray-50 dark:bg-gray-900/20', border: 'border-gray-500', bar: 'bg-gray-400' },
};

const sevBadge: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  INFO: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
};

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (['string', 'number', 'bigint'].includes(typeof value)) return String(value);
  if (Array.isArray(value)) return value.map(formatValue).filter(Boolean).join(', ');
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (typeof record.url === 'string') {
      const scheme = typeof record.https === 'boolean' ? ` (${record.https ? 'HTTPS' : 'HTTP'})` : '';
      return `${record.url}${scheme}`;
    }
    if (typeof record.name === 'string') return record.name;
    if (typeof record.path === 'string') return record.path;
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function valueKey(value: unknown, index: number): string {
  return `${formatValue(value) || 'item'}-${index}`;
}

function renderSafe(value: unknown): ReactNode {
  if (isValidElement(value)) return value;
  if (Array.isArray(value)) {
    return value.map((item, index) => (isValidElement(item) ? item : <span key={valueKey(item, index)}>{formatValue(item)}</span>));
  }
  const text = formatValue(value);
  return text || null;
}

function Value({ label, children }: { label: string; children: ReactNode }) {
  const rendered = renderSafe(children);
  return (
    <div className="flex items-start gap-2 py-1">
      <span className="shrink-0 font-medium text-[var(--text-muted)] min-w-[100px]">{label}:</span>
      <span className="text-[var(--text-default)]">{rendered || <span className="italic text-[var(--text-subtle)]">None</span>}</span>
    </div>
  );
}

function Tag({ children, color = 'default' }: { children: ReactNode; color?: string }) {
  const colors: Record<string, string> = {
    red: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    amber: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    green: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    purple: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
    blue: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    default: 'bg-[var(--surface-tertiary)] text-[var(--text-muted)]',
  };
  return (
    <span className={`inline-block rounded-md px-2 py-0.5 text-[10px] font-medium ${colors[color] || colors.default}`}>
      {renderSafe(children)}
    </span>
  );
}

export default function AttackIntelligence() {
  const { user } = useAuth();
  const [target, setTarget] = useState('');
  const [depth, setDepth] = useState('standard');
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchIntelligence = async () => {
    if (!target.trim()) return;
    setLoading(true);
    setError('');
    setData(null);
    try {
      const response = await apiClient.get<IntelligenceData>('/api/admin/intelligence/', {
        params: { target: target.trim(), port_scan_depth: depth },
      });
      setData(response.data);
      toast.success('Intelligence dossier ready');
    } catch (err) {
      const msg = apiErrorMessage(err, 'Failed to fetch intelligence');
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  if (!hasElevatedAccess(user)) {
    return (
      <Page>
        <PageHeader title="Attack Intelligence" description="Admin-only feature" />
        <Panel>
          <div className="flex items-center gap-3 p-6">
            <Lock className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-sm font-semibold text-red-600 dark:text-red-400">Admin access required</p>
              <p className="text-xs text-[var(--text-muted)]">Log in as admin or enterprise owner to access Attack Intelligence.</p>
            </div>
          </div>
        </Panel>
      </Page>
    );
  }

  const totalFindings = data
    ? Object.values(data.findings).reduce((sum, arr) => sum + arr.length, 0)
    : 0;

  const activeSeverities = data
    ? Object.keys(data.findings).filter((k) => data.findings[k as keyof typeof data.findings].length > 0)
    : [];
  const impactfulFindings = data
    ? (['critical', 'high', 'medium', 'low', 'info'] as const).flatMap((sev) => data.findings[sev]).slice(0, 6)
    : [];

  return (
    <Page>
      <PageHeader
        title="Attack Intelligence"
        description="Complete dossier of recon, entry points, vulnerabilities, and exploitation roadmap."
      />

      <div className="space-y-5">
        {/* Input */}
        <Panel>
          <div className="p-4">
            <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">Target URL</label>
            <div className="flex gap-2">
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://example.com"
                className="flex-1 font-mono"
                onKeyDown={(e) => { if (e.key === 'Enter') fetchIntelligence(); }}
              />
              <select
                value={depth}
                onChange={(e) => setDepth(e.target.value)}
                className="rounded-md border border-[var(--border-light)] bg-[var(--surface-primary)] px-3 py-1.5 text-xs text-[var(--text-default)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]"
              >
                <option value="fast">Fast (21 ports)</option>
                <option value="standard">Standard (3 tiers)</option>
                <option value="full">Full (1-1024)</option>
              </select>
              <Button onClick={fetchIntelligence} disabled={loading || !target.trim()}>
                {loading ? 'Analyzing...' : <><Search className="h-3.5 w-3.5" /> Analyze</>}
              </Button>
            </div>
          </div>
        </Panel>

        {error ? <ErrorState title="Intelligence failed" description={error} /> : null}

        {loading ? (
          <Panel>
            <div className="flex items-center justify-center p-8">
              <div className="flex items-center gap-3 text-sm text-[var(--text-muted)]">
                <div className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--brand)] border-t-transparent" />
                Aggregating intelligence data...
              </div>
            </div>
          </Panel>
        ) : null}

        {data ? (
          <>
            {/* Risk Score Hero */}
            <div className={`border-2 rounded-xl p-5 ${riskColors[data.risk_score.color]?.bg ?? 'bg-gray-50'} ${riskColors[data.risk_score.color]?.border ?? 'border-gray-500'}`}>
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold text-[var(--text-strong)]">Risk Score</h2>
                  <p className={`text-sm ${riskColors[data.risk_score.color]?.text ?? 'text-gray-600'}`}>
                    {formatValue(data.risk_score.level)} Risk Level
                  </p>
                </div>
                <div className="flex items-center gap-5">
                  <span className={`text-4xl font-bold ${riskColors[data.risk_score.color]?.text ?? ''}`}>
                    {formatValue(data.risk_score.score)}%
                  </span>
                  <div className="text-xs text-[var(--text-muted)]">
                    <div className="font-semibold text-[var(--text-strong)]">{totalFindings} real findings</div>
                    <div>{activeSeverities.length} severity levels</div>
                  </div>
                </div>
              </div>
              <div className="mt-3 w-full bg-white/40 dark:bg-black/20 rounded-full h-2.5 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-1000 ${riskColors[data.risk_score.color]?.bar ?? 'bg-gray-400'}`}
                  style={{ width: `${Math.max(2, data.risk_score.score)}%` }}
                />
              </div>
            </div>

            {impactfulFindings.length ? (
              <Panel>
                <div className="flex items-center gap-2 border-b border-[var(--border-light)] px-4 py-3">
                  <Shield className="h-4 w-4 text-[var(--brand)]" />
                  <h3 className="text-sm font-semibold text-[var(--text-strong)]">Most Impactful Findings</h3>
                </div>
                <div className="grid gap-2 p-4 md:grid-cols-2">
                  {impactfulFindings.map((finding) => (
                    <div key={`impact-${finding.id}`} className="rounded-lg border border-[var(--border-light)] bg-[var(--surface-tertiary)] p-3 text-xs">
                      <div className="mb-2 flex flex-wrap items-center gap-1.5">
                        <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${sevBadge[finding.severity] || sevBadge.INFO}`}>{formatValue(finding.severity)}</span>
                        <Tag color={finding.confidence_label === 'HIGH' || finding.confidence === 'HIGH' ? 'green' : 'amber'}>{finding.confidence_label || finding.confidence}</Tag>
                      </div>
                      <div className="font-semibold text-[var(--text-strong)]">{formatValue(finding.title)}</div>
                      <div className="mt-1 break-all font-mono text-[var(--text-muted)]">{formatValue(finding.endpoint)}</div>
                      {finding.affected_urls?.length ? <div className="mt-1 text-[var(--text-subtle)]">Affected URLs: {finding.affected_urls.slice(0, 3).map(formatValue).join(', ')}{finding.affected_urls.length > 3 ? ` and ${finding.affected_urls.length - 3} more` : ''}</div> : null}
                    </div>
                  ))}
                </div>
              </Panel>
            ) : null}

            {/* AI Analysis Banner */}
            {(data.ai_analysis.attack_vector_summary || data.ai_analysis.most_dangerous_entry) ? (
              <InfoCallout
                title="AI Analysis"
              >
                {data.ai_analysis.attack_vector_summary ? (
                  <p className="text-sm text-[var(--text-default)]">{formatValue(data.ai_analysis.attack_vector_summary)}</p>
                ) : null}
                {data.ai_analysis.most_dangerous_entry ? (
                  <p className="text-sm mt-2">
                    <span className="font-semibold text-[var(--text-strong)]">Most Dangerous Entry:</span>{' '}
                    <span className="text-[var(--text-default)]">{formatValue(data.ai_analysis.most_dangerous_entry)}</span>
                  </p>
                ) : null}
                {data.ai_analysis.recommended_next_steps?.length ? (
                  <div className="mt-3 text-sm">
                    <span className="font-semibold text-[var(--text-strong)]">Next Steps:</span>
                    <ul className="list-disc list-inside mt-1 space-y-1 text-[var(--text-default)]">
                      {data.ai_analysis.recommended_next_steps.map((step, i) => (
                        <li key={i}>{formatValue(step)}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </InfoCallout>
            ) : null}

            {/* Target Profile */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: 'URL', value: data.target.url, mono: true },
                { label: 'Hostname', value: data.target.hostname, mono: true },
                { label: 'IP Address', value: data.target.ip, mono: true },
                { label: 'Entry Points', value: String(
                  data.entry_points.url_parameters.length +
                  data.entry_points.api_endpoints.length +
                  data.entry_points.post_fields.length
                ), mono: false },
              ].map((item) => (
                <Panel key={item.label}>
                  <div className="p-3">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-subtle)]">{item.label}</div>
                    <div className={`mt-1 text-sm truncate ${item.mono ? 'font-mono' : ''} text-[var(--text-strong)]`}>
                      {formatValue(item.value) || 'Unknown'}
                    </div>
                  </div>
                </Panel>
              ))}
            </div>

            {/* Reconnaissance */}
            <Panel>
              <div className="flex items-center gap-2 border-b border-[var(--border-light)] px-4 py-3">
                <Globe className="h-4 w-4 text-[var(--brand)]" />
                <h3 className="text-sm font-semibold text-[var(--text-strong)]">Reconnaissance</h3>
              </div>
              <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                <div className="sm:col-span-2">
                  <div className="font-medium text-[var(--text-muted)] mb-1">Open Ports ({data.recon.ports.open?.length || 0})</div>
                  {data.recon.ports.details?.length ? (
                    <div className="space-y-1.5">
                      {data.recon.ports.details.map((p) => (
                        <div key={p.number} className="border border-[var(--border-light)] rounded-md px-3 py-2">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono font-semibold text-[var(--text-strong)]">{formatValue(p.number)}</span>
                            <span className="text-[var(--text-muted)]">{formatValue(p.protocol) || 'tcp'}</span>
                            <Tag color="green">{p.service || 'unknown'}</Tag>
                            {p.tls ? <Tag color="purple">TLS</Tag> : null}
                            {p.version ? <Tag color="blue">v{formatValue(p.version)}</Tag> : null}
                            {p.server ? <Tag color="amber">{p.server}</Tag> : null}
                          </div>
                          {p.banner ? <div className="mt-1 truncate text-[10px] text-[var(--text-subtle)] font-mono">{formatValue(p.banner)}</div> : null}
                          {p.x_powered_by ? <div className="text-[10px] text-[var(--text-subtle)]">X-Powered-By: {formatValue(p.x_powered_by)}</div> : null}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="font-mono text-[var(--text-default)]">
                      {data.recon.ports.open?.length ? data.recon.ports.open.map(formatValue).join(', ') : 'None'}
                    </div>
                  )}
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">Frameworks</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.recon.technologies.frameworks?.length ? data.recon.technologies.frameworks.map(formatValue).join(', ') : 'Unknown'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">Servers</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.recon.technologies.servers?.length ? data.recon.technologies.servers.map(formatValue).join(', ') : 'Unknown'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">WAF</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {formatValue(data.recon.technologies.waf) || 'None detected'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">CDN</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {formatValue(data.recon.technologies.cdn) || 'None detected'}
                  </div>
                </div>
                {data.recon.dns.a_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">A Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.a_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.aaaa_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">AAAA Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.aaaa_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.mx_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">MX Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.mx_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.txt_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TXT Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.txt_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.cname_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">CNAME Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.cname_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.ns_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">NS Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.ns_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.soa_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">SOA Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.soa_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.ptr_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">PTR Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.ptr_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.srv_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">SRV Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.srv_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.caa_records?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">CAA Records</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.caa_records.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.dns.wildcard !== null ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">Wildcard DNS</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.wildcard ? 'Enabled' : 'Disabled'}</div>
                  </div>
                ) : null}
                {data.recon.dns.dnssec !== null ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">DNSSEC</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.dns.dnssec ? 'Enabled' : 'Disabled'}</div>
                  </div>
                ) : null}
                {data.recon.dns.zone_transfer ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">Zone Transfer</div>
                    <div className="font-mono text-[var(--text-default)]">{formatValue(data.recon.dns.zone_transfer)}</div>
                  </div>
                ) : null}
                {data.recon.technologies.detailed?.length ? (
                  <div className="sm:col-span-3">
                    <div className="font-medium text-[var(--text-muted)] mb-1">Detected Technologies</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {data.recon.technologies.detailed.map((t, i) => (
                        <div key={i} className="flex items-center gap-2 border border-[var(--border-light)] rounded-md px-2 py-1">
                          <span className="font-mono text-[var(--text-strong)]">{formatValue(t.name)}{t.version ? ` ${formatValue(t.version)}` : ''}</span>
                          {t.category ? <Tag color="blue">{t.category}</Tag> : null}
                          {t.confidence !== undefined ? (
                            <span className="ml-auto text-[10px] text-[var(--text-subtle)]">{formatValue(t.confidence)}%</span>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
                {data.recon.technologies.waf_evidence?.length ? (
                  <div className="sm:col-span-3">
                    <div className="font-medium text-[var(--text-muted)] mb-1">WAF Evidence</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.technologies.waf_evidence.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.tls.version ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TLS Version</div>
                    <div className="font-mono text-[var(--text-default)]">{formatValue(data.recon.tls.version)}</div>
                  </div>
                ) : null}
                {data.recon.tls.cipher ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TLS Cipher</div>
                    <div className="font-mono text-[var(--text-default)]">{formatValue(data.recon.tls.cipher)}</div>
                  </div>
                ) : null}
                {data.recon.tls.expiry ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TLS Expiry</div>
                    <div className="font-mono text-[var(--text-default)]">{formatValue(data.recon.tls.expiry)}</div>
                  </div>
                ) : null}
                {data.recon.tls.valid !== null ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TLS Valid</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.tls.valid ? 'Yes' : 'No'}</div>
                  </div>
                ) : null}
                {Object.keys(data.recon.tls.protocols || {}).length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TLS Protocols</div>
                    <div className="font-mono text-[var(--text-default)] space-y-0.5">
                      {Object.entries(data.recon.tls.protocols).map(([proto, enabled]) => (
                        <div key={proto}>
                          <span className={enabled ? 'text-red-500' : 'text-[var(--text-subtle)]'}>{proto}</span>
                          <span className="text-[var(--text-muted)]">: {enabled ? 'supported' : 'disabled'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
                {data.recon.tls.ciphers?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TLS Ciphers</div>
                    <div className="font-mono text-[var(--text-default)]">{data.recon.tls.ciphers.map(formatValue).join(', ')}</div>
                  </div>
                ) : null}
                {data.recon.tls.vulnerabilities?.length ? (
                  <div>
                    <div className="font-medium text-[var(--text-muted)] mb-1">TLS Vulnerabilities</div>
                    <div className="font-mono text-red-500">{data.recon.tls.vulnerabilities.map(formatValue).join('; ')}</div>
                  </div>
                ) : null}
                {Object.keys(data.recon.headers).length > 0 ? (
                  <div className="sm:col-span-3">
                    <div className="font-medium text-[var(--text-muted)] mb-1">HTTP Headers</div>
                    <div className="font-mono text-[var(--text-default)] space-y-0.5">
                      {Object.entries(data.recon.headers).map(([k, v]) => (
                        <div key={k}><span className="text-[var(--text-muted)]">{k}:</span> {formatValue(v)}</div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </Panel>

            {/* Exposed Assets */}
            <Panel>
              <div className="flex items-center gap-2 border-b border-[var(--border-light)] px-4 py-3">
                <Shield className="h-4 w-4 text-[var(--brand)]" />
                <h3 className="text-sm font-semibold text-[var(--text-strong)]">Exposed Assets</h3>
              </div>
              <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                <Value label="robots.txt">{data.exposed.robots_txt ? 'Found' : 'Not found'}</Value>
                <Value label="Emails">
                  {data.exposed.emails?.length
                    ? data.exposed.emails.map((e, i) => <div key={valueKey(e, i)} className="text-red-500">{formatValue(e)}</div>)
                    : 'None'}
                </Value>
                <Value label="Sensitive Files">
                  {Object.entries(data.exposed.sensitive_files || {}).filter(([_, v]) => v).length
                    ? Object.entries(data.exposed.sensitive_files).filter(([_, v]) => v).map(([file, status]) => (
                        <div key={file} className="flex items-center gap-2 text-red-500">
                          <AlertTriangle className="h-3 w-3" />
                          <span>{file}</span>
                          <Tag color="red">HTTP {status}</Tag>
                        </div>
                      ))
                    : 'None found'}
                </Value>
                <Value label="Internal IPs">
                  {data.exposed.internal_ips?.length ? data.exposed.internal_ips.map(formatValue).join(', ') : 'None'}
                </Value>
                <Value label="Phone Numbers">
                  {data.exposed.phones?.length ? data.exposed.phones.map((p, i) => <div key={valueKey(p, i)} className="font-mono">{formatValue(p)}</div>) : 'None'}
                </Value>
                <Value label="Social Profiles">
                  {data.exposed.social_profiles?.length
                    ? data.exposed.social_profiles.map((s, i) => (
                        <div key={i}>
                          <span className="font-medium">{formatValue(s.network)}:</span>{' '}
                          <a href={formatValue(s.url)} target="_blank" rel="noreferrer" className="text-[var(--brand)] underline truncate">{formatValue(s.url)}</a>
                        </div>
                      ))
                    : 'None'}
                </Value>
                <Value label="Discovered Files">
                  {data.exposed.discovered_files?.length
                    ? data.exposed.discovered_files.slice(0, 10).map((f, i) => (
                        <div key={i} className="flex items-center gap-2">
                          <span className="truncate font-mono">{formatValue(f.path)}</span>
                          {f.status_code ? <Tag color={f.status_code < 400 ? 'red' : 'default'}>{f.status_code}</Tag> : null}
                        </div>
                      ))
                    : 'None'}
                  {data.exposed.discovered_files?.length > 10 ? (
                    <div className="text-[var(--text-subtle)]">... and {data.exposed.discovered_files.length - 10} more</div>
                  ) : null}
                </Value>
                <Value label="HTML Comments">
                  {data.exposed.comments?.length ? data.exposed.comments.slice(0, 5).map((c, i) => <div key={valueKey(c, i)} className="truncate font-mono">{formatValue(c)}</div>) : 'None'}
                  {data.exposed.comments?.length > 5 ? <div className="text-[var(--text-subtle)]">... and {data.exposed.comments.length - 5} more</div> : null}
                </Value>
                <Value label="JS Source Maps">
                  {data.exposed.js_source_maps?.length ? data.exposed.js_source_maps.map((m, i) => <div key={valueKey(m, i)} className="truncate font-mono">{formatValue(m)}</div>) : 'None'}
                </Value>
                <Value label="Sitemap URLs">
                  {data.exposed.sitemap?.length ? data.exposed.sitemap.slice(0, 5).map((s, i) => <div key={valueKey(s, i)} className="truncate font-mono">{formatValue(s)}</div>) : 'None'}
                  {data.exposed.sitemap?.length > 5 ? <div className="text-[var(--text-subtle)]">... and {data.exposed.sitemap.length - 5} more</div> : null}
                </Value>
              </div>
            </Panel>

            {/* Entry Points */}
            <Panel>
              <div className="flex items-center gap-2 border-b border-[var(--border-light)] px-4 py-3">
                <Search className="h-4 w-4 text-[var(--brand)]" />
                <h3 className="text-sm font-semibold text-[var(--text-strong)]">Entry Points</h3>
              </div>
              <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">URL Parameters</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.url_parameters?.length
                      ? data.entry_points.url_parameters.map((p, i) => <div key={valueKey(p, i)}>?{formatValue(p)}=</div>)
                      : 'None'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">POST Fields</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.post_fields?.length
                      ? data.entry_points.post_fields.map((p, i) => <div key={valueKey(p, i)}>{formatValue(p)}:</div>)
                      : 'None'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">API Endpoints</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.api_endpoints?.length
                      ? data.entry_points.api_endpoints.map((p, i) => <div key={valueKey(p, i)}>{formatValue(p)}</div>)
                      : 'None'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">Cookies</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.cookies?.length
                      ? data.entry_points.cookies.map((c, i) => <div key={valueKey(c, i)}>{formatValue(c)}</div>)
                      : 'None'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">GraphQL Endpoints</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.graphql_endpoints?.length
                      ? data.entry_points.graphql_endpoints.map((g, i) => <div key={valueKey(g, i)}>{formatValue(g)}</div>)
                      : 'None'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">JSON Body Fields</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.json_body?.length
                      ? data.entry_points.json_body.map((j, i) => <div key={valueKey(j, i)}>{formatValue(j)}</div>)
                      : 'None'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">File Uploads</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.file_uploads?.length
                      ? data.entry_points.file_uploads.map((f, i) => <div key={valueKey(f, i)}>{formatValue(f)}</div>)
                      : 'None'}
                  </div>
                </div>
                <div>
                  <div className="font-medium text-[var(--text-muted)] mb-1">WebSockets</div>
                  <div className="font-mono text-[var(--text-default)]">
                    {data.entry_points.websockets?.length
                      ? data.entry_points.websockets.map((w, i) => <div key={valueKey(w, i)}>{formatValue(w)}</div>)
                      : 'None'}
                  </div>
                </div>
              </div>
            </Panel>

            {/* Findings */}
            <Panel>
              <div className="flex items-center justify-between border-b border-[var(--border-light)] px-4 py-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-[var(--brand)]" />
                  <h3 className="text-sm font-semibold text-[var(--text-strong)]">Real Findings by Severity</h3>
                </div>
                {totalFindings > 0 ? (
                  <span className="text-xs text-[var(--text-muted)]">{totalFindings} total</span>
                ) : null}
              </div>
              <div className="p-4">
                {activeSeverities.length === 0 ? (
                  <div className="text-center py-8 text-[var(--text-muted)]">
                    <div className="text-3xl mb-2">&#10003;</div>
                    <p>No findings for this target.</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                      const items = data.findings[sev];
                      if (!items.length) return null;
                      return (
                        <div key={sev}>
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase ${sevBadge[sev.toUpperCase()] || sevBadge.INFO}`}>
                              {sev} ({items.length})
                            </span>
                          </div>
                          <div className="space-y-1.5 ml-1">
                            {items.slice(0, 5).map((f) => (
                              <div key={f.id} className="rounded-lg bg-[var(--surface-tertiary)] px-3 py-2 text-xs">
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    <div className="font-medium text-[var(--text-strong)]">{formatValue(f.title)}</div>
                                    <Tag color={f.confidence_label === 'HIGH' || f.confidence === 'HIGH' ? 'green' : 'amber'}>{f.confidence_label || f.confidence}</Tag>
                                  </div>
                                {f.endpoint ? (
                                  <div className="text-[var(--text-muted)] font-mono">{formatValue(f.endpoint)}</div>
                                ) : null}
                                {f.description ? (
                                  <div className="text-[var(--text-muted)] mt-0.5 truncate">{formatValue(f.description).substring(0, 200)}</div>
                                ) : null}
                                 {f.parameter ? (
                                    <div className="text-[var(--text-muted)] mt-0.5">Parameter: ?{formatValue(f.parameter)}=</div>
                                 ) : null}
                                {f.affected_urls?.length ? (
                                  <div className="text-[var(--text-muted)] mt-0.5">Grouped URLs: {f.affected_urls.slice(0, 3).map(formatValue).join(', ')}{f.affected_urls.length > 3 ? ` and ${f.affected_urls.length - 3} more` : ''}</div>
                                ) : null}
                              </div>
                            ))}
                            {items.length > 5 ? (
                              <div className="text-xs text-[var(--text-subtle)] pl-2">... and {items.length - 5} more</div>
                            ) : null}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </Panel>

            {/* Exploitation Roadmap */}
            <Panel>
              <div className="flex items-center gap-2 border-b border-[var(--border-light)] px-4 py-3">
                <Zap className="h-4 w-4 text-[var(--brand)]" />
                <h3 className="text-sm font-semibold text-[var(--text-strong)]">Exploitation Roadmap</h3>
              </div>
              <div className="p-4">
                {data.exploitation_roadmap.summary ? (
                  <p className="text-xs text-[var(--text-muted)] mb-3">{formatValue(data.exploitation_roadmap.summary)}</p>
                ) : null}
                {data.exploitation_roadmap.steps?.length ? (
                  <ol className="list-inside list-decimal space-y-2">
                    {data.exploitation_roadmap.steps.map((step, i) => (
                      <li key={i} className="rounded-lg bg-[var(--surface-tertiary)] p-2.5 text-xs leading-relaxed text-[var(--text-default)]">
                        {formatValue(step)}
                      </li>
                    ))}
                  </ol>
                ) : (
                  <div className="text-[var(--text-muted)] text-xs">No exploitation path identified.</div>
                )}
              </div>
            </Panel>

            {/* Footer */}
            <div className="flex items-center gap-2 rounded-lg bg-[var(--surface-secondary)] px-4 py-3 text-[10px] text-[var(--text-subtle)]">
              <ExternalLink className="h-3 w-3" />
              Intelligence dossier compiled from scan artifacts and findings.
            </div>
          </>
        ) : loading ? null : (
          <Panel>
            <EmptyState
              icon={<Search className="h-6 w-6 text-[var(--text-subtle)]" />}
              title="Enter a target"
              description="Enter a target URL above to generate a complete attack intelligence dossier."
            />
          </Panel>
        )}
      </div>
    </Page>
  );
}
