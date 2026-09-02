export interface SecurityRecommendation {
  id: string;
  name: string;
  priority: number;
  severity: string;
  description: string;
  evidence: string[];
  requirements: string[];
  vulnerability_type: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  HIGH: 'bg-red-600 text-white',
  MEDIUM: 'bg-orange-500 text-white',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-gray-500 text-white',
};

export default function SecurityPriorityCard({ recommendation }: { recommendation: SecurityRecommendation }) {
  return (
    <div className="border border-gray-200 bg-white rounded-lg px-4 py-3">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-sm font-bold text-blue-700">
          {recommendation.priority}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-xs font-semibold px-2 py-0.5 rounded ${SEVERITY_COLORS[recommendation.severity] || SEVERITY_COLORS.INFO}`}>
              {recommendation.severity}
            </span>
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {recommendation.vulnerability_type.replace('_', ' ')}
            </span>
          </div>
          <h3 className="mt-1 text-sm font-semibold text-gray-900">{recommendation.name}</h3>
          <p className="mt-0.5 text-xs text-gray-600">{recommendation.description}</p>

          {recommendation.evidence.length > 0 && (
            <div className="mt-3 rounded-lg border border-blue-200 bg-blue-50 px-3 py-2">
              <div className="text-xs font-semibold text-blue-900">Evidence</div>
              <ul className="mt-1 list-disc list-inside text-xs text-blue-800">
                {recommendation.evidence.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          {recommendation.requirements.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1">
              {recommendation.requirements.map((requirement) => (
                <span key={requirement} className="text-xs px-2 py-0.5 rounded bg-gray-100 text-gray-700 border border-gray-200">
                  {requirement.replace('_', ' ')}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
