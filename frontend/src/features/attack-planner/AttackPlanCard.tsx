import { useState } from 'react';

export interface AttackStep {
  id: number;
  phase: string;
  attack: string;
  description: string;
  likelihood: string;
  impact: string;
  ease: string;
  commands: string[];
  modules: string[];
  prerequisites: string[];
  mitigations: string[];
}

const LIKELIHOOD_COLORS: Record<string, string> = {
  VERY_HIGH: 'bg-red-100 text-red-800 border-red-300',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 border-blue-300',
  VERY_LOW: 'bg-gray-100 text-gray-600 border-gray-300',
};

const IMPACT_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-red-500 text-white',
  MEDIUM: 'bg-orange-500 text-white',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-gray-500 text-white',
};

const PHASE_ICONS: Record<string, string> = {
  Reconnaissance: 'RECON',
  'Initial Access': 'ACCESS',
  'Privilege Escalation': 'PRIVESC',
  'Lateral Movement': 'LATMOV',
  Persistence: 'PERSIST',
  Exfiltration: 'EXFIL',
};

export default function AttackPlanCard({ step }: { step: AttackStep }) {
  const [expanded, setExpanded] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<number | null>(null);

  const copyCommand = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(idx);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const riskScore = (() => {
    const lScore: Record<string, number> = { VERY_HIGH: 5, HIGH: 4, MEDIUM: 3, LOW: 2, VERY_LOW: 1 };
    const iScore: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    return (lScore[step.likelihood] || 0) + (iScore[step.impact] || 0);
  })();

  return (
    <div
      className={`border rounded-lg transition-all ${
        riskScore >= 8
          ? 'border-red-300 bg-red-50/30'
          : riskScore >= 5
          ? 'border-orange-200 bg-orange-50/20'
          : 'border-gray-200 bg-white'
      }`}
    >
      <div
        className="px-4 py-3 cursor-pointer flex items-start gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex-shrink-0 mt-0.5">
          <span className="text-xs font-mono font-bold text-gray-400">#{step.id}</span>
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">
              {PHASE_ICONS[step.phase] || step.phase.slice(0, 6).toUpperCase()}
            </span>
            <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${LIKELIHOOD_COLORS[step.likelihood] || ''}`}>
              {step.likelihood.replace('_', ' ')}
            </span>
            <span className={`text-xs font-medium px-2 py-0.5 rounded ${IMPACT_COLORS[step.impact] || ''}`}>
              {step.impact}
            </span>
          </div>
          <h3 className="text-sm font-semibold text-gray-900 mt-1">{step.attack}</h3>
          <p className="text-xs text-gray-600 mt-0.5 line-clamp-2">{step.description}</p>
        </div>

        <div className="flex-shrink-0 text-gray-400 text-xs">
          {expanded ? 'COLLAPSE' : 'EXPAND'}
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-100">
          {/* Commands */}
          {step.commands.length > 0 && (
            <div className="mt-3">
              <div className="text-xs font-semibold text-gray-700 mb-1">Commands</div>
              <div className="space-y-1">
                {step.commands.map((cmd, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <code className="flex-1 text-xs bg-gray-900 text-green-400 px-3 py-1.5 rounded font-mono overflow-x-auto">
                      {cmd}
                    </code>
                    <button
                      onClick={(e) => { e.stopPropagation(); copyCommand(cmd, idx); }}
                      className="text-xs text-gray-500 hover:text-gray-700 px-2 py-1"
                    >
                      {copiedCmd === idx ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Modules */}
          {step.modules.length > 0 && (
            <div className="mt-3">
              <div className="text-xs font-semibold text-gray-700 mb-1">Brutal Mode Modules</div>
              <div className="flex flex-wrap gap-1">
                {step.modules.map((mod) => (
                  <span key={mod} className="text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-700 border border-purple-200">
                    {mod}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Prerequisites */}
          {step.prerequisites.length > 0 && (
            <div className="mt-3">
              <div className="text-xs font-semibold text-gray-700 mb-1">Prerequisites</div>
              <ul className="text-xs text-gray-600 list-disc list-inside">
                {step.prerequisites.map((p, i) => (
                  <li key={i}>{p}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Mitigations */}
          {step.mitigations.length > 0 && (
            <div className="mt-3">
              <div className="text-xs font-semibold text-green-700 mb-1">Mitigations</div>
              <ul className="text-xs text-green-600 list-disc list-inside">
                {step.mitigations.map((m, i) => (
                  <li key={i}>{m}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
