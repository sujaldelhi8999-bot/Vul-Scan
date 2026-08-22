import { useCallback, useEffect, useState } from 'react';
import { ExternalLink, GitBranch, Loader2, Plug, RefreshCw, Unplug, XCircle } from 'lucide-react';
import toast from 'react-hot-toast';

import { Button, EmptyState, Page, PageHeader, Panel, SectionHeader, StatusBadge } from '../../components/ui/Primitives';
import {
  apiErrorMessage,
  connectGitHub,
  disconnectGitHub,
  getGitHubStatus,
  listGitHubInstallations,
  listGitHubRepos,
} from '../../services/api';
import type { GitHubInstallation, GitHubRepo, GitHubStatusResponse } from '../../types';
import { formatDateTime } from '../../utils/derived';

export default function GitHubConnectPage() {
  const [status, setStatus] = useState<GitHubStatusResponse | null>(null);
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [installations, setInstallations] = useState<GitHubInstallation[]>([]);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [statusResult, repoResult, installationResult] = await Promise.allSettled([
        getGitHubStatus(),
        listGitHubRepos(),
        listGitHubInstallations(),
      ]);
      if (statusResult.status === 'fulfilled') setStatus(statusResult.value);
      if (repoResult.status === 'fulfilled') {
        setRepos(repoResult.value.repos);
        if (!repoResult.value.connected) setStatus({ connected: false });
      }
      if (installationResult.status === 'fulfilled') setInstallations(installationResult.value);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not load GitHub connection status.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleConnect = async () => {
    setConnecting(true);
    try {
      const result = await connectGitHub();
      window.location.href = result.authorize_url;
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not start GitHub OAuth flow.'));
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    setDisconnecting(true);
    try {
      await disconnectGitHub();
      toast.success('GitHub disconnected');
      setStatus({ connected: false });
      setRepos([]);
      setInstallations([]);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not disconnect GitHub.'));
    } finally {
      setDisconnecting(false);
    }
  };

  return (
    <Page>
      <PageHeader
        title="GitHub Integration"
        description="Connect your GitHub account to scan repositories, watch PRs, and automate security testing."
        action={
          status?.connected ? (
            <Button variant="secondary" onClick={handleDisconnect} disabled={disconnecting}>
              {disconnecting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unplug className="h-3.5 w-3.5" />}Disconnect
            </Button>
          ) : (
            <Button onClick={handleConnect} disabled={connecting}>
              {connecting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plug className="h-3.5 w-3.5" />}Connect GitHub
            </Button>
          )
        }
      />

      {loading ? (
        <Panel>
          <div className="flex items-center justify-center gap-2 p-8 text-xs text-[var(--text-muted)]">
            <Loader2 className="h-4 w-4 animate-spin text-[var(--brand)]" />Loading GitHub integration...
          </div>
        </Panel>
      ) : (
        <div className="space-y-4">
          {/* Status panel */}
          <Panel>
            <SectionHeader title="Connection" />
            {status?.connected ? (
              <div className="flex flex-wrap items-center gap-3 rounded-xl border border-green-500/30 bg-green-500/10 p-3.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-full bg-green-500/20">
                  <GitBranch className="h-5 w-5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-[var(--text-strong)]">Connected as @{status.login}</div>
                  <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                    {status.connected_at ? `Connected ${formatDateTime(status.connected_at)}` : 'Connected'}
                  </div>
                </div>
                <StatusBadge status="Connected" />
                <Button
                  variant="secondary"
                  className="ml-auto !px-2.5"
                  onClick={() => { void load(); }}
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                </Button>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3 rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-8 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--surface-tertiary)]">
                  <GitBranch className="h-6 w-6 text-[var(--text-subtle)]" />
                </div>
                <p className="max-w-md text-xs leading-relaxed text-[var(--text-muted)]">
                  Connect your GitHub account to enable repo scanning, PR webhook auto-scans, and Code Scanning result uploads.
                  You will be redirected to GitHub to authorize VulScan.
                </p>
                <Button onClick={handleConnect} disabled={connecting}>
                  {connecting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plug className="h-3.5 w-3.5" />}Connect GitHub
                </Button>
              </div>
            )}
          </Panel>

          {/* Repositories */}
          <Panel>
            <div className="flex items-center justify-between">
              <SectionHeader title="Repositories" />
              <span className="text-[11px] text-[var(--text-muted)]">{repos.length} accessible</span>
            </div>
            {repos.length ? (
              <div className="divide-y divide-[var(--border-light)]">
                {repos.slice(0, 25).map((repo) => (
                  <div key={repo.id} className="flex items-center gap-3 py-2.5">
                    <GitBranch className="h-4 w-4 shrink-0 text-[var(--text-subtle)]" />
                    <div className="min-w-0 flex-1">
                      <a
                        href={repo.html_url}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1.5 truncate text-xs font-medium text-[var(--brand)] hover:underline"
                      >
                        {repo.full_name}
                        <ExternalLink className="h-3 w-3 shrink-0" />
                      </a>
                      <div className="mt-0.5 truncate text-[11px] text-[var(--text-muted)]">
                        {repo.language || 'Unknown language'} · default branch: {repo.default_branch} ·{' '}
                        {repo.private ? 'Private' : 'Public'}
                      </div>
                    </div>
                    <span className="shrink-0 rounded bg-[var(--surface-tertiary)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">
                      {repo.topics.slice(0, 3).join(', ') || 'No topics'}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={status?.connected ? <XCircle className="h-6 w-6 text-[var(--text-subtle)]" /> : <GitBranch className="h-6 w-6 text-[var(--text-subtle)]" />}
                title={status?.connected ? 'No repositories found' : 'Connect to see repositories'}
                description={status?.connected ? 'Your account has no accessible repositories.' : 'Repositories will appear here after connecting.'}
              />
            )}
          </Panel>

          {/* Installations */}
          <Panel>
            <SectionHeader title="App Installations" />
            {installations.length ? (
              <div className="divide-y divide-[var(--border-light)]">
                {installations.map((installation) => (
                  <div key={installation.id} className="flex items-center gap-3 py-2.5">
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--surface-tertiary)]">
                      <GitBranch className="h-4 w-4 text-[var(--text-subtle)]" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-xs font-medium text-[var(--text-strong)]">
                        {String(installation.account?.login ?? `Installation ${installation.id}`)}
                      </div>
                      <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                        {installation.repository_selection} · events: {installation.events.join(', ') || 'none'}
                      </div>
                    </div>
                    <StatusBadge status="Active" />
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={<GitBranch className="h-6 w-6 text-[var(--text-subtle)]" />}
                title="No installations"
                description="Install the VulScan GitHub App on your repositories to enable webhook auto-scans."
              />
            )}
          </Panel>
        </div>
      )}
    </Page>
  );
}
