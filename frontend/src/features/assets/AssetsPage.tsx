import { useMemo, useState } from 'react';
import { Drawer, EmptyState, Page, PageHeader, Panel, SectionHeader, SeverityBadge, StatusBadge } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { deriveAssets, formatDateTime, relativeTime } from '../../utils/derived';

type Asset = ReturnType<typeof deriveAssets>[number];

export default function AssetsPage() {
  const { scans, findings, artifactsByScanId } = usePhantomData();
  const assets = useMemo(() => deriveAssets(scans, findings), [scans, findings]);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [tab, setTab] = useState('Overview');
  const technologies = useMemo(() => {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const artifact of Object.values(artifactsByScanId)) {
      const stack = artifact.scanner_output?.tech_stack;
      if (!stack || typeof stack !== 'object') continue;
      const record = stack as Record<string, unknown>;
      const values = [record.server, record.x_powered_by, ...(Array.isArray(record.technologies) ? record.technologies : [])];
      for (const v of values) {
        if (typeof v === 'string' && v.trim() && !seen.has(v.trim())) { seen.add(v.trim()); result.push(v.trim()); }
      }
    }
    return result;
  }, [artifactsByScanId]);

  const tabs = ['Overview', 'Findings', 'Technologies', 'Endpoints', 'Scans'];

  return (
    <Page>
      <PageHeader title="Assets" description={`${assets.length} monitored targets from scan history.`} />
      {assets.length ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {assets.map((asset) => (
            <button
              key={asset.name}
              onClick={() => { setSelected(asset); setTab('Overview'); }}
              className="rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)] p-4 text-left transition-all hover:border-[var(--brand)] hover:shadow-[var(--shadow-card)]"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-[var(--text-strong)]">{asset.name}</div>
                  <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">Last scan {relativeTime(asset.last_scan)}</div>
                </div>
                <StatusBadge status={asset.status} />
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2">
                <div className="rounded-lg bg-[var(--surface-secondary)] px-2 py-1.5 text-center">
                  <div className="text-[10px] text-[var(--text-muted)]">Score</div>
                  <div className="text-sm font-semibold text-[var(--text-strong)]">{asset.score}</div>
                </div>
                <div className="rounded-lg bg-[var(--surface-secondary)] px-2 py-1.5 text-center">
                  <div className="text-[10px] text-[var(--text-muted)]">Findings</div>
                  <div className="text-sm font-semibold text-[var(--text-strong)]">{asset.findings.length}</div>
                </div>
                <div className="rounded-lg bg-[var(--surface-secondary)] px-2 py-1.5 text-center">
                  <div className="text-[10px] text-[var(--text-muted)]">Scans</div>
                  <div className="text-sm font-semibold text-[var(--text-strong)]">{asset.scans.length}</div>
                </div>
              </div>
            </button>
          ))}
        </div>
      ) : (
        <EmptyState title="No assets" description="Assets appear after scans and findings are available." />
      )}

      <Drawer title={selected?.name ?? 'Asset'} open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected ? (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-1.5">
              {tabs.map((item) => (
                <button key={item} onClick={() => setTab(item)} className={`rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors ${tab === item ? 'bg-[var(--brand-soft)] text-[var(--brand)]' : 'text-[var(--text-muted)] hover:bg-[var(--surface-hover)]'}`}>
                  {item}
                </button>
              ))}
            </div>

            {tab === 'Overview' ? (
              <div className="space-y-2">
                <div className="rounded-xl bg-[var(--surface-secondary)] p-3">
                  <div className="text-[10px] text-[var(--text-muted)]">Target</div>
                  <div className="mt-0.5 break-all font-mono text-xs text-[var(--text-strong)]">{selected.target_url}</div>
                </div>
                <div className="rounded-xl bg-[var(--surface-secondary)] p-3">
                  <div className="text-[10px] text-[var(--text-muted)]">Last Scan</div>
                  <div className="mt-0.5 text-xs text-[var(--text-strong)]">{formatDateTime(selected.last_scan)}</div>
                </div>
                <div className="rounded-xl bg-[var(--surface-secondary)] p-3">
                  <div className="text-[10px] text-[var(--text-muted)]">Status</div>
                  <div className="mt-1"><StatusBadge status={selected.status} /></div>
                </div>
              </div>
            ) : null}

            {tab === 'Findings' ? (
              selected.findings.length ? (
                <div className="space-y-1.5">
                  {selected.findings.map((finding) => (
                    <div key={finding.id} className="rounded-xl bg-[var(--surface-secondary)] p-2.5">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={finding.severity} compact />
                        <span className="text-xs font-medium text-[var(--text-strong)]">{finding.title}</span>
                      </div>
                      <div className="mt-1 text-[11px] text-[var(--text-muted)]">{finding.category}</div>
                    </div>
                  ))}
                </div>
              ) : (<EmptyState title="No findings" description="No findings associated with this asset." compact />)
            ) : null}

            {tab === 'Technologies' ? (
              technologies.length ? (
                <div className="space-y-1">
                  {technologies.map((tech) => (
                    <div key={tech} className="rounded-lg bg-[var(--surface-secondary)] px-3 py-2 font-mono text-xs text-[var(--text-strong)]">{tech}</div>
                  ))}
                </div>
              ) : (<EmptyState title="No technologies" description="Technology data from scanner artifacts." compact />)
            ) : null}

            {tab === 'Endpoints' ? (
              <div className="space-y-1">
                {Array.from(new Set(selected.findings.map((f) => f.endpoint).filter(Boolean))).map((ep) => (
                  <div key={ep} className="rounded-lg bg-[var(--surface-secondary)] px-3 py-2 font-mono text-xs text-[var(--text-default)]">{ep}</div>
                ))}
              </div>
            ) : null}

            {tab === 'Scans' ? (
              <div className="space-y-1.5">
                {selected.scans.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between rounded-xl bg-[var(--surface-secondary)] px-3 py-2.5">
                    <div>
                      <div className="text-xs text-[var(--text-strong)]">Scan {scan.id}</div>
                      <div className="text-[10px] text-[var(--text-muted)]">{formatDateTime(scan.created_at)}</div>
                    </div>
                    <StatusBadge status={scan.status} />
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </Page>
  );
}
