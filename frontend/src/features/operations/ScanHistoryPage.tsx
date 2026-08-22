import { Link } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { Button, DataTable, EmptyState, ModeBadge, Page, PageHeader, Panel, StatusBadge } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { countBySeverity, formatDateTime, scanDuration, targetName } from '../../utils/derived';

export default function ScanHistoryPage() {
  const navigate = useNavigate();
  const { scans, findings } = usePhantomData();
  const columns = [
    { key: 'target', label: 'Target' },
    { key: 'mode', label: 'Mode', width: '80px' },
    { key: 'started', label: 'Started', width: '130px' },
    { key: 'duration', label: 'Duration', width: '90px' },
    { key: 'findings', label: 'Findings', width: '100px' },
    { key: 'status', label: 'Status', width: '100px' },
  ];
  const rows = scans.map((scan) => {
    const scanFindings = findings.filter((f) => f.scan_id === scan.id);
    const counts = countBySeverity(scanFindings);
    return {
      id: scan.id,
      cells: {
        target: <span className="truncate font-mono text-xs text-[var(--text-strong)]">{targetName(scan.target_url)}</span>,
        mode: <ModeBadge mode={scan.mode} />,
        started: <span className="text-xs text-[var(--text-muted)]">{formatDateTime(scan.created_at)}</span>,
        duration: <span className="text-xs text-[var(--text-muted)]">{scanDuration(scan)}</span>,
        findings: (
          <span className="text-xs text-[var(--text-default)]">
            {scanFindings.length}
            {counts.CRITICAL > 0 || counts.HIGH > 0 ? (
              <span className="ml-1 text-[10px] text-[var(--danger)]">
                ({counts.CRITICAL > 0 ? `C:${counts.CRITICAL}` : ''}{counts.CRITICAL > 0 && counts.HIGH > 0 ? ' ' : ''}{counts.HIGH > 0 ? `H:${counts.HIGH}` : ''})
              </span>
            ) : null}
          </span>
        ),
        status: <StatusBadge status={scan.status} />,
      },
    };
  });

  return (
    <Page>
      <PageHeader title="Scan History" description={`${scans.length} past assessments.`} />
      <Panel>
        {scans.length ? (
          <DataTable columns={columns} rows={rows} onRowClick={(id) => navigate(`/report/${id}`)} />
        ) : (
          <div className="p-5">
            <EmptyState title="No scans yet" description="Run your first assessment to populate scan history." action={<Link to="/scan"><Button variant="primary">Start Scan</Button></Link>} />
          </div>
        )}
      </Panel>
    </Page>
  );
}
