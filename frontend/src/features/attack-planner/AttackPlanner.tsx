import { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import apiClient, { apiErrorMessage } from '../../services/api';
import { hasElevatedAccess } from '../../utils/access';
import SecurityPriorityCard, { SecurityRecommendation } from './AttackPlanCard';

interface SecurityPrioritiesResponse {
  target: string;
  technologies: string[];
  total_recommendations: number;
  recommendations: SecurityRecommendation[];
  context: {
    has_user_input: boolean;
    has_api_endpoints: boolean;
    has_graphql: boolean;
    has_authentication: boolean;
    has_file_upload: boolean;
    has_hsts: boolean;
    has_tls: boolean;
    has_secret_findings: boolean;
    missing_browser_headers: string[];
  };
}

export default function SecurityPriorities() {
  const { user } = useAuth();
  const [target, setTarget] = useState('');
  const [result, setResult] = useState<SecurityPrioritiesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!hasElevatedAccess(user)) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center p-8 border-2 border-red-500 rounded-lg">
          <h2 className="text-2xl font-bold text-red-600">Elevated Access Required</h2>
          <p className="text-gray-600 mt-2">Please use an authorized admin or enterprise owner account.</p>
        </div>
      </div>
    );
  }

  const handleScan = async () => {
    if (!target) { setError('Please enter a target URL'); return; }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const url = target.startsWith('http') ? target : 'https://' + target;
      const resp = await apiClient.get<SecurityPrioritiesResponse>('/api/security-priorities', { params: { target: url } });
      setResult(resp.data);
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to generate security priorities'));
    } finally {
      setLoading(false);
    }
  };

  const techList = result?.technologies ?? [];

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Security Priorities</h1>
        <p className="text-gray-600 mt-1">Generate context-aware, evidence-backed recommendations for an authorized target.</p>
        <div className="mt-2 p-3 bg-orange-50 border border-orange-300 rounded-lg text-sm text-orange-700">
          WARNING: Only use on your own systems or systems you have explicit authorization to assess.
        </div>
      </div>

      {error && <div className="bg-red-50 border border-red-500 text-red-700 p-4 rounded-lg mb-6">{error}</div>}

      <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
        <h2 className="text-xl font-bold mb-4">Target Analysis</h2>
        <div className="flex gap-3">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !loading && handleScan()}
            placeholder="https://example.com or localhost:8000"
            className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={loading}
          />
          <button
            onClick={handleScan}
            disabled={loading || !target}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50"
          >
            {loading ? 'Analyzing...' : 'Generate Priorities'}
          </button>
        </div>
      </div>

      {loading && (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mb-3"></div>
          <p className="text-gray-600">Detecting target context and prioritizing recommendations...</p>
        </div>
      )}

      {result && !loading && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-white border border-gray-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-gray-900">{result.total_recommendations}</div>
              <div className="text-xs text-gray-500 mt-1">Recommendations</div>
            </div>
            <div className="bg-white border border-blue-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-blue-600">{result.context.missing_browser_headers.length}</div>
              <div className="text-xs text-gray-500 mt-1">Missing Headers</div>
            </div>
            <div className="bg-white border border-green-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-green-600">{result.context.has_hsts ? 'Yes' : 'No'}</div>
              <div className="text-xs text-gray-500 mt-1">HSTS Present</div>
            </div>
            <div className="bg-white border border-purple-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-purple-600">{techList.length}</div>
              <div className="text-xs text-gray-500 mt-1">Technologies</div>
            </div>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 mb-6">
            <h2 className="text-lg font-bold mb-2 text-blue-900">Context-Aware Filtering</h2>
            <p className="text-sm text-blue-800">
              Recommendations are tailored to the target's detected features. Only applicable issues are shown.
            </p>
            <div className="mt-3 grid grid-cols-2 md:grid-cols-5 gap-3 text-xs text-blue-900">
              <div><span className="font-semibold">User Input:</span> {result.context.has_user_input ? 'Yes' : 'No'}</div>
              <div><span className="font-semibold">APIs:</span> {result.context.has_api_endpoints ? 'Yes' : 'No'}</div>
              <div><span className="font-semibold">GraphQL:</span> {result.context.has_graphql ? 'Yes' : 'No'}</div>
              <div><span className="font-semibold">Auth:</span> {result.context.has_authentication ? 'Yes' : 'No'}</div>
              <div><span className="font-semibold">Uploads:</span> {result.context.has_file_upload ? 'Yes' : 'No'}</div>
              <div><span className="font-semibold">TLS OK:</span> {result.context.has_tls ? 'Yes' : 'No'}</div>
              <div><span className="font-semibold">Secrets:</span> {result.context.has_secret_findings ? 'Yes' : 'No'}</div>
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
            <h2 className="text-xl font-bold mb-3">Detected Technology Stack</h2>
            {techList.length === 0 ? (
              <p className="text-gray-500 text-sm">No specific technologies detected.</p>
            ) : (
              <div className="flex flex-wrap gap-1">
                {techList.map((item) => (
                  <span key={item} className="text-xs px-2 py-1 rounded bg-blue-50 text-blue-700 border border-blue-200">
                    {item}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="mb-6">
            <h2 className="text-xl font-bold mb-3">Recommendations ({result.recommendations.length})</h2>
            <div className="space-y-2">
              {result.recommendations.map((recommendation) => (
                <SecurityPriorityCard key={recommendation.id} recommendation={recommendation} />
              ))}
              {result.recommendations.length === 0 && (
                <p className="text-gray-500 text-sm py-4">No evidence-backed recommendations for the detected target context.</p>
              )}
            </div>
          </div>
        </>
      )}

      {!result && !loading && (
        <div className="text-center py-16 text-gray-400">
          <div className="text-5xl mb-4">PRIORITIES</div>
          <p className="text-lg">Enter a target URL above and click "Generate Priorities"</p>
          <p className="text-sm mt-2">The engine will show only recommendations supported by detected context.</p>
        </div>
      )}
    </div>
  );
}
