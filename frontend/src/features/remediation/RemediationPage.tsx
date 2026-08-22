import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { ChevronDown, ChevronRight, Loader2, ShieldCheck } from 'lucide-react';

import { Button, EmptyState, Page, PageHeader, Panel, SectionHeader, SeverityBadge, StatusBadge, cx } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { apiErrorMessage, applyFindingPatch, updateFindingRemediation, verifyFindingFix } from '../../services/api';
import { relativeTime, targetName } from '../../utils/derived';
import type { Finding } from '../../types';
import { clearEnterpriseApproval, getEnterpriseApproval } from '../enterprise/approvalHandoff';

const queueDefinitions = [
  { label: 'Immediate', match: (f: Finding) => isActionable(f) && f.remediation_status !== 'IN_PROGRESS' && ['CRITICAL', 'HIGH'].includes(f.severity) },
  { label: 'In Progress', match: (f: Finding) => isActionable(f) && f.remediation_status === 'IN_PROGRESS' },
  { label: 'Planned', match: (f: Finding) => isActionable(f) && f.remediation_status !== 'IN_PROGRESS' && ['MEDIUM', 'LOW', 'INFO'].includes(f.severity) },
  { label: 'Resolved', match: (f: Finding) => isResolved(f) },
  { label: 'Excluded', match: (f: Finding) => isExcluded(f) },
];

function isResolved(f: Finding) { return f.remediation_status === 'RESOLVED' || f.verification_status === 'FIX_VERIFIED'; }
function isExcluded(f: Finding) { return !isResolved(f) && (f.risk_status ?? 'ACTIVE') !== 'ACTIVE'; }
function isActionable(f: Finding) { return !isResolved(f) && !isExcluded(f); }

export default function RemediationPage() {
  const { findings, refresh } = usePhantomData();
  const [action, setAction] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [approval, setApproval] = useState(() => getEnterpriseApproval(['code_fix', 'remediation', 'github_push']));
  const grouped = useMemo(() => queueDefinitions.map((g) => ({ ...g, items: findings.filter(g.match) })), [findings]);

  const markInProgress = async (finding: Finding) => {
    setAction(`progress-${finding.id}`);
    try {
      await updateFindingRemediation(finding.id, 'IN_PROGRESS');
      toast.success('Marked in progress');
      await refresh();
    } catch (err) { toast.error(apiErrorMessage(err, 'Unable to update.')); }
    finally { setAction(null); }
  };

  const verifyFix = async (finding: Finding) => {
    setAction(`verify-${finding.id}`);
    try {
      const result = await verifyFindingFix(finding.id);
      toast.success(result.status === 'FIX_VERIFIED' ? 'Fix verified' : 'Issue still present');
      await refresh();
    } catch (err) { toast.error(apiErrorMessage(err, 'Unable to verify.')); }
    finally { setAction(null); }
  };

  const applyApprovedPatch = async (finding: Finding) => {
    if (!approval) return;
    const patch = typeof approval.details.patch === 'string' ? approval.details.patch : '';
    const filePath = typeof approval.details.file_path === 'string' ? approval.details.file_path : '';
    if (!patch || !filePath || Number(approval.details.finding_id) !== finding.id) {
      toast.error('The approval does not contain a matching code patch');
      return;
    }
    setAction(`patch-${finding.id}`);
    try {
      await applyFindingPatch(finding.id, {
        approval_request_id: approval.id,
        patch,
        file_path: filePath,
        target_root: typeof approval.details.target_root === 'string' ? approval.details.target_root : undefined,
        verify_after: false,
      });
      clearEnterpriseApproval();
      setApproval(null);
      toast.success('Approved patch applied to the attached source workspace');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to apply approved patch.'));
    } finally {
      setAction(null);
    }
  };

  return (
    <Page>
      <PageHeader title="Remediation" description="Prioritize and verify fixes from security evidence." />
      {grouped.map((group) => (
        <Panel key={group.label}>
          <SectionHeader title={group.label} description={`${group.items.length} finding${group.items.length === 1 ? '' : 's'}`} />
          {group.items.length ? (
            <div className="divide-y divide-[var(--border-light)]">
              {group.items.map((finding) => (
                <div key={finding.id}>
                  <div className="grid gap-2.5 px-4 py-2.5 sm:grid-cols-[90px_1.3fr_1fr_130px_160px] items-center">
                    <SeverityBadge severity={finding.severity} />
                    <div className="min-w-0">
                      <button
                        onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        className="flex items-center gap-1 truncate text-xs font-medium text-[var(--text-strong)] hover:text-[var(--brand)] text-left"
                      >
                        {expandedId === finding.id ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />}
                        {finding.title}
                      </button>
                      <div className="mt-0.5 text-[10px] text-[var(--text-muted)]">Updated {relativeTime(finding.timestamp)}</div>
                    </div>
                    <span className="truncate font-mono text-xs text-[var(--text-muted)]">{targetName(finding.target)}</span>
                    <div className="flex flex-wrap gap-1">
                      <StatusBadge status={finding.remediation_status ?? 'OPEN'} />
                      {finding.verification_status && finding.verification_status !== 'NOT_VERIFIED' ? <StatusBadge status={finding.verification_status} /> : null}
                    </div>
                    <div className="flex gap-1.5">
                      <Button onClick={() => void markInProgress(finding)} disabled={!isActionable(finding) || action === `progress-${finding.id}`} variant="secondary">
                        {action === `progress-${finding.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                        In Progress
                      </Button>
                      <Button variant="amber" onClick={() => void verifyFix(finding)} disabled={!isActionable(finding) || action === `verify-${finding.id}`}>
                        {action === `verify-${finding.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                        Verify
                      </Button>
                      {approval?.details.change_type === 'code_patch' && Number(approval.details.finding_id) === finding.id ? (
                        <Button variant="primary" onClick={() => void applyApprovedPatch(finding)} disabled={action === `patch-${finding.id}`}>
                          {action === `patch-${finding.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                          Apply Approved Patch
                        </Button>
                      ) : null}
                    </div>
                  </div>
                  {expandedId === finding.id && (finding.description || finding.recommendation || finding.fix) ? (
                    <div className="border-t border-[var(--border-light)] bg-[var(--surface-secondary)] px-4 py-3 space-y-2">
                      {finding.description ? (
                        <div>
                          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Description</div>
                          <p className="mt-0.5 text-xs text-[var(--text-default)]">{finding.description}</p>
                        </div>
                      ) : null}
                      {finding.recommendation || finding.fix ? (
                        <div>
                          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Recommended Fix</div>
                          <p className="mt-0.5 text-xs text-[var(--text-default)]">{finding.recommendation || finding.fix}</p>
                        </div>
                      ) : null}
                      {finding.endpoint ? <div className="font-mono text-[11px] text-[var(--brand)]">{finding.endpoint}</div> : null}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4"><EmptyState title="No findings" description="No findings in this queue." compact /></div>
          )}
        </Panel>
      ))}
    </Page>
  );
}
