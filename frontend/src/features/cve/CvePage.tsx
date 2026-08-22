import { useMemo, useState } from 'react';
import type { Finding } from '../../types';
import { DataTable, Drawer, EmptyState, Page, PageHeader, Panel, SectionHeader, SeverityBadge, StatusBadge } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { deriveTechnologies, targetName } from '../../utils/derived';

export default function CvePage() {
  const { findings, artifactsByScanId } = usePhantomData();
  const [selected, setSelected] = useState<Finding | null>(null);
  const technologies = useMemo(() => deriveTechnologies(artifactsByScanId), [artifactsByScanId]);
  const cves = findings.filter((f) => f.cve_id);

  const columns = [
    { key: 'severity', label: 'Severity', width: '75px' },
    { key: 'cve', label: 'CVE ID', width: '130px' },
    { key: 'technology', label: 'Technology' },
    { key: 'source', label: 'Source', width: '100px' },
    { key: 'status', label: 'Status', width: '80px' },
  ];

  const rows = cves.map((finding) => ({
    id: finding.id,
    cells: {
      severity: <SeverityBadge severity={finding.severity} compact />,
      cve: <span className="font-mono text-xs text-[var(--brand)]">{finding.cve_id}</span>,
      technology: <span className="truncate text-xs text-[var(--text-strong)]">{finding.title.replace(/^Known vulnerability in /, '')}</span>,
      source: <span className="text-xs text-[var(--text-muted)]">{finding.agent || 'Scanner'}</span>,
      status: <StatusBadge status="Open" />,
    },
  }));

  return (
    <Page>
      <PageHeader title="CVE Intelligence" description="Correlate detected technologies with known vulnerabilities." />

      <Panel>
        <SectionHeader title="Technologies" description="Detected by Scanner Agent artifacts." />
        {technologies.length ? (
          <div className="p-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {technologies.map((tech) => (
              <div key={tech.name} className="rounded-lg bg-[var(--surface-secondary)] p-3">
                <div className="font-mono text-sm text-[var(--text-strong)]">{tech.name}</div>
                <div className="mt-1 text-xs text-[var(--text-muted)]">Seen in {tech.scans.length} scan{tech.scans.length === 1 ? '' : 's'}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-4"><EmptyState title="No technologies" description="Run a scan to populate technology data." /></div>
        )}
      </Panel>

      <Panel>
        <SectionHeader title="Relevant CVEs" description={`${cves.length} matched vulnerabilities.`} />
        {cves.length ? (
          <DataTable columns={columns} rows={rows} onRowClick={(id) => { const f = cves.find((fv) => fv.id === id); if (f) setSelected(f); }} />
        ) : (
          <div className="p-4"><EmptyState title="No CVE findings" description="No CVE matches for current scan history." /></div>
        )}
      </Panel>

      <Drawer title={selected?.cve_id ?? 'CVE Details'} open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-1.5">
              <SeverityBadge severity={selected.severity} />
              <StatusBadge status={selected.confidence} />
            </div>
            <div className="grid grid-cols-2 gap-2">
              {[
                ['CVE ID', selected.cve_id],
                ['CVSS', selected.cvss_score?.toString() ?? 'N/A'],
                ['Affected', selected.title],
                ['Source', selected.agent],
                ['Asset', targetName(selected.target)],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg bg-[var(--surface-secondary)] p-2.5">
                  <div className="text-[10px] font-semibold text-[var(--text-muted)]">{label}</div>
                  <div className="mt-1 text-xs text-[var(--text-strong)]">{value}</div>
                </div>
              ))}
            </div>
            {selected.description || selected.evidence ? (
              <div>
                <h3 className="mb-1 text-xs font-semibold text-[var(--text-strong)]">Description</h3>
                <p className="line-clamp-6 text-xs leading-relaxed text-[var(--text-default)]">{selected.description || selected.evidence}</p>
              </div>
            ) : null}
            {selected.recommendation || selected.fix ? (
              <div>
                <h3 className="mb-1 text-xs font-semibold text-[var(--text-strong)]">Recommendation</h3>
                <p className="text-xs leading-relaxed text-[var(--text-default)]">{selected.recommendation || selected.fix}</p>
              </div>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </Page>
  );
}
