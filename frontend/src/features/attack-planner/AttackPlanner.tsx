import { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import apiClient, { apiErrorMessage } from '../../services/api';
import AttackPlanCard, { AttackStep } from './AttackPlanCard';

interface AttackPlan {
  target: string;
  tech_stack: Record<string, string[]>;
  attack_steps: AttackStep[];
  summary: {
    total_steps: number;
    phase_distribution: Record<string, number>;
    likelihood_distribution: Record<string, number>;
    impact_distribution: Record<string, number>;
    critical_attacks: number;
    high_attacks: number;
    applicable_modules: string[];
    tech_stack_summary: Record<string, string[]>;
  };
  recommended_chain: string[];
}

const PHASE_ORDER = [
  'Reconnaissance', 'Initial Access', 'Privilege Escalation',
  'Lateral Movement', 'Persistence', 'Exfiltration',
];

export default function AttackPlanner() {
  const { user } = useAuth();
  const [target, setTarget] = useState('');
  const [plan, setPlan] = useState<AttackPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activePhase, setActivePhase] = useState<string>('all');

  if (!user || (user.role !== 'admin' && !user.enterpriseId)) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center p-8 border-2 border-red-500 rounded-lg">
          <h2 className="text-2xl font-bold text-red-600">Admin Access Required</h2>
          <p className="text-gray-600 mt-2">Please log in as admin to access the Attack Planner.</p>
        </div>
      </div>
    );
  }

  const handleScan = async () => {
    if (!target) { setError('Please enter a target URL'); return; }
    setLoading(true);
    setError('');
    setPlan(null);
    try {
      const url = target.startsWith('http') ? target : 'https://' + target;
      const resp = await apiClient.post<AttackPlan>('/api/attack-planner/quick', { target_url: url });
      setPlan(resp.data);
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to generate attack plan'));
    } finally {
      setLoading(false);
    }
  };

  const filteredSteps = plan
    ? activePhase === 'all'
      ? plan.attack_steps
      : plan.attack_steps.filter((s) => s.phase === activePhase)
    : [];

  const techList = plan
    ? Object.entries(plan.tech_stack).filter(([, v]) => v.length > 0).flatMap(([, v]) => v)
    : [];

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Attack Planner</h1>
        <p className="text-gray-600 mt-1">Analyze a target and generate a prioritized attack plan with realistic commands.</p>
        <div className="mt-2 p-3 bg-orange-50 border border-orange-300 rounded-lg text-sm text-orange-700">
          WARNING: Only use on your own systems or systems you have explicit authorization to test.
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
            {loading ? 'Analyzing...' : 'Generate Plan'}
          </button>
        </div>
      </div>

      {loading && (
        <div className="text-center py-12">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mb-3"></div>
          <p className="text-gray-600">Detecting technologies and generating attack plan...</p>
        </div>
      )}

      {plan && !loading && (
        <>
          <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
            <h2 className="text-xl font-bold mb-3">Detected Technology Stack</h2>
            {techList.length === 0 ? (
              <p className="text-gray-500 text-sm">No specific technologies detected.</p>
            ) : (
              <div className="space-y-2">
                {Object.entries(plan.tech_stack).filter(([, v]) => v.length > 0).map(([category, items]) => (
                  <div key={category} className="flex items-start gap-2">
                    <span className="text-xs font-semibold text-gray-500 uppercase w-32 flex-shrink-0 pt-0.5">
                      {category.replace('_', ' ')}
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {items.map((item) => (
                        <span key={item} className="text-xs px-2 py-1 rounded bg-blue-50 text-blue-700 border border-blue-200">
                          {item}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-white border border-gray-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-gray-900">{plan.summary.total_steps}</div>
              <div className="text-xs text-gray-500 mt-1">Total Attack Steps</div>
            </div>
            <div className="bg-white border border-red-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-red-600">{plan.summary.critical_attacks}</div>
              <div className="text-xs text-gray-500 mt-1">Critical Impact</div>
            </div>
            <div className="bg-white border border-orange-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-orange-600">{plan.summary.high_attacks}</div>
              <div className="text-xs text-gray-500 mt-1">High Impact</div>
            </div>
            <div className="bg-white border border-purple-200 rounded-xl p-4 text-center">
              <div className="text-3xl font-bold text-purple-600">{plan.summary.applicable_modules.length}</div>
              <div className="text-xs text-gray-500 mt-1">Modules to Run</div>
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
            <h2 className="text-xl font-bold mb-3">Attack Phases</h2>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setActivePhase('all')}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
                  activePhase === 'all' ? 'bg-gray-900 text-white border-gray-900' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                }`}
              >
                All ({plan.summary.total_steps})
              </button>
              {PHASE_ORDER.map((phase) => {
                const count = plan.summary.phase_distribution[phase] || 0;
                if (count === 0) return null;
                return (
                  <button
                    key={phase}
                    onClick={() => setActivePhase(phase)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
                      activePhase === phase ? 'bg-gray-900 text-white border-gray-900' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    {phase} ({count})
                  </button>
                );
              })}
            </div>
          </div>

          {plan.recommended_chain.length > 0 && (
            <div className="bg-gradient-to-r from-red-50 to-orange-50 border border-red-200 rounded-xl p-6 mb-6">
              <h2 className="text-xl font-bold mb-3 text-red-800">Recommended Attack Chain</h2>
              <p className="text-sm text-red-700 mb-3">Highest-priority attacks ranked by likelihood and impact:</p>
              <ol className="space-y-1.5">
                {plan.recommended_chain.map((attack, i) => (
                  <li key={i} className="flex items-center gap-2 text-sm">
                    <span className="text-xs font-bold text-red-600 w-6">{i + 1}.</span>
                    <span className="text-gray-800">{attack}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {plan.summary.applicable_modules.length > 0 && (
            <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
              <h2 className="text-xl font-bold mb-3">Recommended Brutal Mode Modules</h2>
              <div className="flex flex-wrap gap-2">
                {plan.summary.applicable_modules.map((mod) => (
                  <span key={mod} className="text-sm px-3 py-1.5 rounded-lg bg-purple-100 text-purple-700 border border-purple-200 font-medium">
                    {mod}
                  </span>
                ))}
              </div>
              <p className="text-xs text-gray-500 mt-3">These modules can be run in Brutal Mode to exploit the identified vulnerabilities.</p>
            </div>
          )}

          <div className="mb-6">
            <h2 className="text-xl font-bold mb-3">Attack Steps ({filteredSteps.length})</h2>
            <div className="space-y-2">
              {filteredSteps.map((step) => (
                <AttackPlanCard key={step.id} step={step} />
              ))}
              {filteredSteps.length === 0 && <p className="text-gray-500 text-sm py-4">No attacks in this phase.</p>}
            </div>
          </div>
        </>
      )}

      {!plan && !loading && (
        <div className="text-center py-16 text-gray-400">
          <div className="text-5xl mb-4">PLAN</div>
          <p className="text-lg">Enter a target URL above and click "Generate Plan"</p>
          <p className="text-sm mt-2">The planner will detect technologies and suggest attacks.</p>
        </div>
      )}
    </div>
  );
}


