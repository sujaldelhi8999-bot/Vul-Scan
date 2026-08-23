import { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { apiErrorMessage, getDosHistory, getDosStatus, startDos, stopDos } from '../../services/api';
import { hasElevatedAccess } from '../../utils/access';

interface DoSJob {
  job_id: string;
  target_url: string;
  intensity: string;
  duration: number;
  status: string;
  requests_sent: number;
  responses_received: number;
  errors: number;
  started_at: string;
  stopped_at: string | null;
  baseline_latency?: number;
  peak_latency?: number;
  avg_latency_during?: number;
  recovery_latency?: number;
  impact_score?: number;
  effective?: boolean;
  website_status?: string;
  health_score?: number;
  p95_latency?: number;
  p99_latency?: number;
  jitter_ms?: number;
  error_rate?: number;
  throughput_mbps?: number;
  total_requests?: number;
  status_2xx?: number;
  status_3xx?: number;
  status_4xx?: number;
  status_5xx?: number;
  total_data_mb?: number;
  avg_dns_ms?: number;
  avg_tcp_ms?: number;
  avg_tls_ms?: number;
  avg_ttfb_ms?: number;
  packet_loss?: number;
  recovery_ratio?: number;
  recovered?: boolean;
  attack_mode?: string;
  endpoint?: string;
  target_class?: string;
  workers?: number;
}

interface LiveStats {
  requests_sent: number;
  responses_received: number;
  errors: number;
  avg_latency: number;
  error_rate: number;
  jitter: number;
}

interface AttackMode {
  description: string;
  default_rps: number;
  max_rps_lab: number;
  max_rps_external: number;
}

const ATTACK_MODES: Record<string, AttackMode> = {
  get_flood: { description: 'High-rate GET requests', default_rps: 100, max_rps_lab: 50000, max_rps_external: 200 },
  post_flood: { description: 'POST with random payloads', default_rps: 100, max_rps_lab: 30000, max_rps_external: 150 },
  slowloris: { description: 'Keep-alive connections (exhausts server pool)', default_rps: 50, max_rps_lab: 20000, max_rps_external: 100 },
  connection_exhaust: { description: 'Rapid connect/close (exhausts TCP)', default_rps: 200, max_rps_lab: 200000, max_rps_external: 300 },
  amplification: { description: 'Request large resources (bandwidth)', default_rps: 100, max_rps_lab: 50000, max_rps_external: 200 },
};

const MODE_ICONS: Record<string, string> = {
  get_flood: 'GET', post_flood: 'POST', slowloris: 'SLO',
  connection_exhaust: 'CON', amplification: 'AMP',
};

const ENDPOINTS = [
  { value: '/', label: 'Homepage (/)' },
  { value: '/search?q=test', label: 'Search (/search?q=)' },
  { value: '/api', label: 'API (/api)' },
  { value: '/graphql', label: 'GraphQL (/graphql)' },
  { value: '/admin', label: 'Admin (/admin)' },
  { value: '/login', label: 'Login (/login)' },
];

const fmt = (value: number | undefined | null, digits = 0): string => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return 'N/A';
  return Number(value).toFixed(digits);
};

const healthColor = (score: number | undefined) => {
  const s = Number(score ?? 100);
  if (s > 80) return { text: 'text-green-600', bg: '#22c55e' };
  if (s > 50) return { text: 'text-orange-500', bg: '#f97316' };
  return { text: 'text-red-600', bg: '#ef4444' };
};

const statusInfo = (status: string | undefined) => {
  const base = (status || 'unknown').split('_')[0];
  const map: Record<string, { label: string; icon: string }> = {
    critical: { label: 'Critical — Website severely impacted', icon: '🔴' },
    significant: { label: 'Significant — Website slowed down', icon: '🟠' },
    moderate: { label: 'Moderate — Some impact detected', icon: '🟡' },
    minor: { label: 'Minor — Barely noticeable', icon: '🟢' },
    stable: { label: 'Stable — No significant impact', icon: '✅' },
    unknown: { label: 'Unknown', icon: '❓' },
  };
  const info = map[base] || map.unknown;
  const recoverySuffix = status?.includes('_failed_recovery')
    ? ' (failed to recover)'
    : status?.includes('_slow_recovery')
      ? ' (slow recovery)'
      : '';
  return { ...info, label: info.label + recoverySuffix };
};

function classifyTarget(url: string): string {
  const lower = url.toLowerCase();
  if (lower.includes('localhost') || lower.includes('127.0.0.1') || lower.includes('::1')) return 'loopback';
  if (lower.includes('phantombank')) return 'lab';
  return 'external';
}

export default function DoSPanel() {
  const { user } = useAuth();
  const [target, setTarget] = useState('');
  const [intensity, setIntensity] = useState('low');
  const [duration, setDuration] = useState(30);
  const [mode, setMode] = useState('get_flood');
  const [endpoint, setEndpoint] = useState('/');
  const [useCustomEndpoint, setUseCustomEndpoint] = useState(false);
  const [customEndpoint, setCustomEndpoint] = useState('');
  const [overrideCap, setOverrideCap] = useState(false);
  const [running, setRunning] = useState(false);
  const [currentJob, setCurrentJob] = useState<DoSJob | null>(null);
  const [history, setHistory] = useState<DoSJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [stats, setStats] = useState<LiveStats>({ requests_sent: 0, responses_received: 0, errors: 0, avg_latency: 0, error_rate: 0, jitter: 0 });

  if (!hasElevatedAccess(user)) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center p-8 border-2 border-red-500 rounded-lg">
          <h2 className="text-2xl font-bold text-red-600">Admin Access Required</h2>
          <p className="text-gray-600 mt-2">Please log in as admin or enterprise owner to access DoS testing.</p>
        </div>
      </div>
    );
  }

  const targetClass = classifyTarget(target);
  const modeConfig = ATTACK_MODES[mode] || ATTACK_MODES.get_flood;
  const maxRps = targetClass === 'external' && !overrideCap
    ? modeConfig.max_rps_external
    : modeConfig.max_rps_lab;

  const fetchHistory = async () => {
    try {
      const data = await getDosHistory();
      setHistory(data);
    } catch {
      // ignore
    }
  };

  useEffect(() => { fetchHistory(); }, []);

  useEffect(() => {
    if (!running || !currentJob) return;
    const interval = setInterval(async () => {
      try {
        const data = await getDosStatus(currentJob.job_id);
        setStats({
          requests_sent: data.stats?.requests_sent || data.requests_sent || 0,
          responses_received: data.stats?.responses_received || data.responses_received || 0,
          errors: data.stats?.errors || data.errors || 0,
          avg_latency: data.during?.latency_mean || data.avg_latency_during || 0,
          error_rate: data.during?.error_rate || data.error_rate || 0,
          jitter: data.during?.jitter_ms || data.jitter_ms || 0,
        });
        if (data.status !== 'running' && data.running !== true) {
          setRunning(false);
          setCurrentJob(data);
          await fetchHistory();
        }
      } catch {
        // ignore
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [running, currentJob]);

  const handleStart = async () => {
    if (!target) { setError('Please enter a target URL'); return; }
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const finalEndpoint = useCustomEndpoint ? customEndpoint : (endpoint !== '/' ? endpoint : null);
      const data = await startDos(target, intensity, duration, mode, finalEndpoint, overrideCap);
      if (data.warning) { setNotice(data.warning); }
      setCurrentJob(data);
      setRunning(true);
      setStats({ requests_sent: 0, responses_received: 0, errors: 0, avg_latency: 0, error_rate: 0, jitter: 0 });
      await fetchHistory();
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to start DoS attack'));
    } finally { setLoading(false); }
  };

  const handleStop = async () => {
    if (!currentJob) return;
    try {
      await stopDos(currentJob.job_id);
      setError('');
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to stop attack'));
    }
  };

  const intensityColor = (level: string) => {
    const map: Record<string, string> = { low: 'bg-green-500', medium: 'bg-yellow-500', high: 'bg-orange-500', critical: 'bg-red-600', nuclear: 'bg-red-900' };
    return map[level] || 'bg-gray-500';
  };

  const statusBadge = (status: string) => {
    const map: Record<string, string> = { running: 'text-green-500', completed: 'text-blue-500', stopped: 'text-yellow-500', error: 'text-red-500' };
    return <span className={`${map[status] || 'text-gray-500'}`}>{'\u25CF'} {status}</span>;
  };

  const showReport = !running && currentJob && (currentJob.status === 'completed' || currentJob.status === 'stopped' || currentJob.status === 'error');

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">DoS Testing</h1>
        <p className="text-gray-600 mt-1">Simulate Denial of Service attacks on authorized targets for educational purposes.</p>
        <div className="mt-2 p-3 bg-red-50 border border-red-300 rounded-lg text-sm text-red-700">
          WARNING: Only use on your own websites, PhantomBank Lab, or localhost. Unauthorized DoS attacks are illegal.
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-500 text-red-700 p-4 rounded-lg mb-6">{error}</div>
      )}

      {/* Attack Controls */}
      <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
        <h2 className="text-xl font-bold mb-4">Attack Configuration</h2>

        {/* Row 1: Target + Mode */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com or localhost:8000"
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={running}
            />
            {target && (
              <div className="mt-1 text-xs">
                <span className={`px-2 py-0.5 rounded ${
                  targetClass === 'lab' ? 'bg-green-100 text-green-700' :
                  targetClass === 'loopback' ? 'bg-blue-100 text-blue-700' :
                  'bg-yellow-100 text-yellow-700'
                }`}>
                  {targetClass === 'lab' ? 'Lab Target - No caps' :
                   targetClass === 'loopback' ? 'Loopback - No caps' :
                   `External - Max ${maxRps} req/s`}
                </span>
              </div>
            )}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Attack Mode</label>
            <div className="grid grid-cols-5 gap-1">
              {Object.entries(ATTACK_MODES).map(([key, cfg]) => (
                <button
                  key={key}
                  onClick={() => setMode(key)}
                  disabled={running}
                  className={`px-2 py-2 text-xs font-medium rounded-lg border transition-colors ${
                    mode === key
                      ? 'bg-red-600 text-white border-red-600'
                      : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                  }`}
                  title={cfg.description}
                >
                  <div className="font-bold">{MODE_ICONS[key]}</div>
                  <div className="text-[10px] mt-0.5 leading-tight">{key.split('_').map(w => w[0]).join('')}</div>
                </button>
              ))}
            </div>
            <div className="mt-1 text-xs text-gray-500">{modeConfig.description}</div>
          </div>
        </div>

        {/* Row 2: Intensity + Duration + Endpoint */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Intensity (RPS)</label>
            <select
              value={intensity}
              onChange={(e) => setIntensity(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={running}
            >
              <option value="low">Low (2 req/s) - Safe</option>
              <option value="medium">Medium (10 req/s)</option>
              <option value="high">High (50 req/s)</option>
              <option value="critical">Critical (100 req/s) - Lab</option>
              <option value="nuclear">Nuclear (10,000 req/s) - LAB ONLY</option>
            </select>
            <div className="mt-1 text-xs text-gray-500">
              Cap: {maxRps} req/s for {targetClass} targets
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Duration (seconds)</label>
            <input
              type="number"
              value={duration}
              onChange={(e) => setDuration(Math.min(300, Math.max(5, parseInt(e.target.value) || 30)))}
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={running}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target Endpoint</label>
            <select
              value={useCustomEndpoint ? 'custom' : endpoint}
              onChange={(e) => {
                if (e.target.value === 'custom') {
                  setUseCustomEndpoint(true);
                } else {
                  setUseCustomEndpoint(false);
                  setEndpoint(e.target.value);
                }
              }}
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={running}
            >
              {ENDPOINTS.map((ep) => (
                <option key={ep.value} value={ep.value}>{ep.label}</option>
              ))}
              <option value="custom">Custom endpoint...</option>
            </select>
            {useCustomEndpoint && (
              <input
                type="text"
                value={customEndpoint}
                onChange={(e) => setCustomEndpoint(e.target.value)}
                placeholder="/custom/endpoint"
                className="w-full mt-2 px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                disabled={running}
              />
            )}
          </div>
        </div>

        {/* Override Cap for Authorized Targets */}
        {targetClass === 'external' && (
          <div className="p-3 bg-yellow-50 border border-yellow-300 rounded-lg mb-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={overrideCap}
                onChange={(e) => setOverrideCap(e.target.checked)}
                disabled={running}
                className="w-4 h-4 text-yellow-600 rounded"
              />
              <span className="text-sm font-medium text-yellow-800">
                Override intensity cap for this authorized target
              </span>
            </label>
            <p className="text-xs text-yellow-700 mt-1 ml-6">
              This allows lab-level intensity on external targets. Only use on systems you own and have authorization to test.
            </p>
          </div>
        )}

        {intensity === 'nuclear' && (
          <div className="p-3 bg-red-100 border border-red-500 text-red-700 rounded-lg mb-4">
            WARNING: High intensity can overwhelm targets. Auto-downgraded for non-lab targets without override.
          </div>
        )}

        {notice && (
          <div className="p-3 bg-yellow-50 border border-yellow-500 text-yellow-800 rounded-lg mb-4">{notice}</div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-3">
          {!running ? (
            <button
              onClick={handleStart}
              disabled={loading || !target}
              className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50"
            >
              {loading ? 'Starting...' : `Launch ${MODE_ICONS[mode]} Attack`}
            </button>
          ) : (
            <button
              onClick={handleStop}
              className="px-6 py-2 bg-yellow-600 hover:bg-yellow-700 text-white font-semibold rounded-lg transition-colors"
            >
              Emergency Stop
            </button>
          )}
          <button
            onClick={() => setTarget('http://localhost:8000/lab/phantombank')}
            className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg transition-colors"
            disabled={running}
          >
            Target Lab
          </button>
        </div>

        {/* Running Status */}
        {running && currentJob && (
          <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-bold">Attack Running</span>
                <span className="ml-2 text-sm text-gray-600">
                  {(currentJob.attack_mode || mode)} mode | {currentJob.intensity} intensity | {currentJob.workers || 'N/A'} workers
                </span>
              </div>
              {statusBadge('running')}
            </div>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mt-3 text-sm">
              <div><span className="text-gray-500">Requests Sent</span><div className="font-bold text-lg">{stats.requests_sent}</div></div>
              <div><span className="text-gray-500">Responses</span><div className="font-bold text-lg text-green-600">{stats.responses_received}</div></div>
              <div><span className="text-gray-500">Errors</span><div className="font-bold text-lg text-red-600">{stats.errors}</div></div>
              <div><span className="text-gray-500">Avg Latency</span><div className="font-bold text-lg">{fmt(stats.avg_latency)} ms</div></div>
              <div><span className="text-gray-500">Error Rate</span><div className="font-bold text-lg">{fmt(stats.error_rate, 1)}%</div></div>
              <div><span className="text-gray-500">Jitter</span><div className="font-bold text-lg">{fmt(stats.jitter)} ms</div></div>
            </div>
          </div>
        )}
      </div>

      {showReport && currentJob && (
        <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
          <h3 className="text-xl font-bold mb-4">📊 Attack Accuracy Report</h3>

          <div className="flex items-center gap-6 mb-6 p-4 bg-gray-50 rounded-lg">
            <div className={`text-5xl font-bold ${healthColor(currentJob.health_score).text}`}>
              {fmt(currentJob.health_score)}%
            </div>
            <div>
              <div className="text-lg font-semibold">Website Health Score</div>
              <div className="text-sm text-gray-600">
                {statusInfo(currentJob.website_status).icon} {statusInfo(currentJob.website_status).label}
              </div>
            </div>
            <div className="ml-auto text-sm text-gray-500">
              Impact Score: {fmt(currentJob.impact_score)}%
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-blue-50 p-3 rounded border border-blue-200">
              <div className="text-xs text-gray-600">Baseline Latency (Mean)</div>
              <div className="font-bold text-lg">{fmt(currentJob.baseline_latency)} ms</div>
              <div className="text-xs text-gray-500">Normal response time</div>
            </div>
            <div className="bg-red-50 p-3 rounded border border-red-200">
              <div className="text-xs text-gray-600">Peak Latency</div>
              <div className="font-bold text-lg text-red-600">{fmt(currentJob.peak_latency)} ms</div>
              <div className="text-xs text-red-500">
                {currentJob.baseline_latency ? `↑ ${Math.round((Number(currentJob.peak_latency) / Number(currentJob.baseline_latency)) * 100 - 100)}% increase` : ''}
              </div>
            </div>
            <div className="bg-orange-50 p-3 rounded border border-orange-200">
              <div className="text-xs text-gray-600">P95 / P99 Latency</div>
              <div className="font-bold text-lg">{fmt(currentJob.p95_latency)} / {fmt(currentJob.p99_latency)} ms</div>
              <div className="text-xs text-gray-500">Tail latency percentiles</div>
            </div>
            <div className="bg-green-50 p-3 rounded border border-green-200">
              <div className="text-xs text-gray-600">Recovery Latency</div>
              <div className="font-bold text-lg text-green-600">{fmt(currentJob.recovery_latency)} ms</div>
              <div className="text-xs text-gray-500">
                {currentJob.recovery_latency && currentJob.baseline_latency
                  ? (Number(currentJob.recovery_latency) / Number(currentJob.baseline_latency) < 1.2 ? '✅ Fully recovered' : '⚠️ Slow recovery')
                  : ''}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Error Rate / Packet Loss</div>
              <div className="font-bold">{fmt(currentJob.error_rate, 1)}% / {fmt(currentJob.packet_loss, 1)}%</div>
              <div className="text-xs text-gray-400">5xx: {currentJob.status_5xx || 0} &middot; 4xx: {currentJob.status_4xx || 0} &middot; 3xx: {currentJob.status_3xx || 0} &middot; 2xx: {currentJob.status_2xx || 0}</div>
            </div>
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Jitter (Latency Variability)</div>
              <div className="font-bold">{fmt(currentJob.jitter_ms)} ms</div>
              <div className="text-xs text-gray-400">{Number(currentJob.jitter_ms || 0) > 100 ? '⚠️ High instability' : '✅ Stable'}</div>
            </div>
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Throughput</div>
              <div className="font-bold">{fmt(currentJob.throughput_mbps, 2)} MB/s</div>
              <div className="text-xs text-gray-400">Total: {fmt(currentJob.total_data_mb, 2)} MB</div>
            </div>
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Transaction Phases (avg)</div>
              <div className="font-bold">{fmt(currentJob.avg_ttfb_ms)} ms TTFB</div>
              <div className="text-xs text-gray-400">DNS {fmt(currentJob.avg_dns_ms)} &middot; TCP {fmt(currentJob.avg_tcp_ms)} &middot; TLS {fmt(currentJob.avg_tls_ms)} ms</div>
            </div>
          </div>

          <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
            <div
              className="h-full transition-all duration-1000"
              style={{ width: `${Number(currentJob.health_score ?? 100)}%`, background: healthColor(currentJob.health_score).bg }}
            />
          </div>

          <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-start gap-2">
              <span className="text-xl">{currentJob.effective ? '⚠️' : '✅'}</span>
              <div>
                <strong>Attack Effectiveness: </strong>
                {currentJob.effective ? (
                  `Attack caused significant impact. Website health dropped from 100% to ${fmt(currentJob.health_score)}%. `
                ) : (
                  'No significant impact detected. The website handled the traffic normally. '
                )}
                {currentJob.recovered
                  ? 'The website recovered successfully.'
                  : `Recovery issue: post-attack latency is ${fmt((Number(currentJob.recovery_ratio) - 1) * 100, 0)}% above baseline.`}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="text-xl font-bold">Attack History</h2>
          <button onClick={fetchHistory} className="text-sm text-blue-600 hover:text-blue-800">Refresh</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Mode</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Intensity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Requests</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Errors</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Impact</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Health</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {history.length === 0 ? (
                <tr><td colSpan={9} className="px-4 py-8 text-center text-gray-500">No DoS attacks in history</td></tr>
              ) : (
                history.map((job) => (
                  <tr key={job.job_id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm truncate max-w-xs">{job.target_url}</td>
                    <td className="px-4 py-3 text-sm">
                      <span className="px-2 py-1 rounded text-xs bg-gray-100 text-gray-700 font-mono">
                        {MODE_ICONS[job.attack_mode || ''] || job.attack_mode || 'GET'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className={`px-2 py-1 rounded-full text-white text-xs ${intensityColor(job.intensity)}`}>{job.intensity}</span>
                    </td>
                    <td className="px-4 py-3 text-sm">{statusBadge(job.status)}</td>
                    <td className="px-4 py-3 text-sm">{job.requests_sent || 0}</td>
                    <td className="px-4 py-3 text-sm text-red-600">{job.errors || 0}</td>
                    <td className="px-4 py-3 text-sm">
                      {job.impact_score !== undefined && job.impact_score !== null && job.status !== 'running' ? (
                        <span className={Number(job.impact_score) >= 50 ? 'text-red-600 font-medium' : Number(job.impact_score) >= 25 ? 'text-orange-500' : 'text-gray-600'}>
                          {fmt(job.impact_score)}% {job.website_status ? statusInfo(job.website_status).icon : ''}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {job.health_score !== undefined && job.health_score !== null && job.status !== 'running' ? (
                        <span className={healthColor(job.health_score).text}>{fmt(job.health_score)}%</span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">{job.started_at ? new Date(job.started_at).toLocaleTimeString() : '-'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
