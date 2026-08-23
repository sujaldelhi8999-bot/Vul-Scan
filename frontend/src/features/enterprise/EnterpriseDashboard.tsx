import { useState } from 'react';
import { Building2 } from 'lucide-react';

import { useAuth } from '../../context/AuthContext';
import { Page, PageHeader } from '../../components/ui/Primitives';
import EmployeeManagement from './EmployeeManagement';
import ApprovalWorkflow from './ApprovalWorkflow';
import AuditLogs from './AuditLogs';
import MyRequests from './MyRequests';
import EnterpriseSettings from './EnterpriseSettings';
import { isEnterpriseOwner } from '../../utils/access';

type Tab = 'requests' | 'employees' | 'approvals' | 'audit' | 'settings';

const USER_TABS: Array<{ id: Tab; label: string }> = [
  { id: 'requests', label: 'My Requests' },
];

const OWNER_TABS: Array<{ id: Tab; label: string }> = [
  { id: 'approvals', label: 'Approvals' },
  { id: 'audit', label: 'Audit Logs' },
  { id: 'employees', label: 'Employees' },
  { id: 'settings', label: 'Settings' },
];

export default function EnterpriseDashboard() {
  const { user } = useAuth();
  const [tab, setTab] = useState<Tab>('requests');

  if (!user) {
    return (
      <Page>
        <PageHeader title="Enterprise Workspace" description="Sign in to manage requests and notifications." />
        <div className="rounded-xl border border-[var(--danger-soft)] bg-[var(--danger-soft)]/30 p-6 text-sm text-[var(--danger)]">
          Authentication required.
        </div>
      </Page>
    );
  }

  const isOwner = isEnterpriseOwner(user);
  const tabs = isOwner ? [...USER_TABS, ...OWNER_TABS] : USER_TABS;

  return (
    <Page>
        <PageHeader
        title="Enterprise Workspace"
        description={isOwner ? 'Manage employees, organization settings, and remediation approvals.' : 'Track your enterprise approval requests and status.'}
        action={<Building2 className="h-4 w-4 text-[var(--text-subtle)]" />}
      />

      <div className="mb-4 flex gap-1 border-b border-[var(--border-light)]">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-2 text-xs font-semibold transition-colors ${
              tab === t.id
                ? 'border-b-2 border-[var(--brand)] text-[var(--brand)]'
                : 'text-[var(--text-muted)] hover:text-[var(--text-default)]'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

        {tab === 'requests' && <MyRequests />}
        {tab === 'employees' && isOwner && <EmployeeManagement />}
        {tab === 'approvals' && isOwner && <ApprovalWorkflow />}
        {tab === 'audit' && isOwner && <AuditLogs />}
        {tab === 'settings' && isOwner && <EnterpriseSettings />}
    </Page>
  );
}
