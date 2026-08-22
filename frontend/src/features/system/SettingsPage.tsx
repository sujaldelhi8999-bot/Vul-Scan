import { Page, PageHeader, Panel, SectionHeader, StatusBadge } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';

const env = [
  'VITE_API_BASE_URL', 'VITE_WS_BASE_URL', 'DATABASE_URL',
  'ACTIVE_TARGET_ALLOWLIST', 'MAX_SCAN_DURATION', 'MAX_REQUESTS_PER_SECOND',
  'MAX_TOTAL_REQUESTS', 'MAX_CONCURRENT_SCANS', 'MAX_REDIRECT_DEPTH',
  'MAX_RESPONSE_SIZE', 'BROWSER_PAGE_LIMIT', 'NVD_API_KEY',
  'OPENROUTER_API_KEY', 'OPENROUTER_MODEL', 'PHANTOMSCAN_WEBHOOK_URL',
];

const settingsGroups = [
  {
    title: 'Service',
    items: [
      { label: 'API Status', value: 'Connected', status: 'Connected' },
      { label: 'Database', value: 'Healthy', status: 'Healthy' },
      { label: 'WebSocket', value: 'Active', status: 'Connected' },
    ],
  },
  {
    title: 'Scan Defaults',
    items: [
      { label: 'Max Duration', value: '30 minutes' },
      { label: 'Max Requests/s', value: '50' },
      { label: 'Max Total Requests', value: '5000' },
      { label: 'Concurrent Scans', value: '3' },
      { label: 'Redirect Depth', value: '5' },
      { label: 'Max Response Size', value: '2 MB' },
    ],
  },
  {
    title: 'Browser',
    items: [{ label: 'Page Limit', value: '10' }],
  },
  {
    title: 'Integration Keys',
    sensitive: true,
    items: [
      { label: 'NVD API Key', value: '********' },
      { label: 'OpenRouter API Key', value: '********' },
      { label: 'Webhook URL', value: 'Not configured' },
    ],
  },
];

export default function SettingsPage() {
  const { health } = usePhantomData();

  const serviceItems = [
    { label: 'API', status: health ? 'Connected' : 'Unavailable' },
    { label: 'Database', status: health?.database ?? 'unavailable' },
    { label: 'WebSocket', status: health ? 'Connected' : 'Unavailable' },
  ];

  return (
    <Page>
      <PageHeader title="Settings" description="Read-only runtime configuration reference." />

      <Panel>
        <SectionHeader title="Service Status" />
        <div className="p-4 grid gap-2 sm:grid-cols-3">
          {serviceItems.map((item) => (
            <div key={item.label} className="rounded-lg bg-[var(--surface-secondary)] p-3">
              <div className="text-xs text-[var(--text-muted)]">{item.label}</div>
              <div className="mt-2"><StatusBadge status={item.status} /></div>
            </div>
          ))}
        </div>
      </Panel>

      {settingsGroups.map((group) => (
        <Panel key={group.title}>
          <SectionHeader title={group.title} description={group.sensitive ? 'Values masked for security' : undefined} />
          <div className="p-4 space-y-1">
            {group.items.map((item) => (
              <div key={item.label} className="flex items-center justify-between rounded-lg bg-[var(--surface-secondary)] px-3 py-2.5">
                <span className="text-xs text-[var(--text-default)]">{item.label}</span>
                <span className="text-xs font-mono text-[var(--text-muted)]">{item.value}</span>
              </div>
            ))}
          </div>
        </Panel>
      ))}

      <Panel>
        <SectionHeader title="Environment Variables" description="Known configuration names consumed by backend and frontend." />
        <div className="p-4 grid gap-1.5 sm:grid-cols-2">
          {env.map((name) => {
            const isKey = name.includes('KEY') || name.includes('SECRET');
            return (
              <div key={name} className="rounded-lg bg-[var(--surface-secondary)] px-3 py-2.5">
                <div className="font-mono text-xs text-[var(--text-strong)]">{name}</div>
                {isKey ? <div className="mt-0.5 text-[10px] text-[var(--warning)]">Sensitive &mdash; masked</div> : null}
              </div>
            );
          })}
        </div>
      </Panel>
    </Page>
  );
}
