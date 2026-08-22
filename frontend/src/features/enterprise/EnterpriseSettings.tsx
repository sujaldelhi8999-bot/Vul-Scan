import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';

import apiClient, { apiErrorMessage } from '../../services/api';
import { Button, Input, Panel, PanelSkeleton } from '../../components/ui/Primitives';

interface EnterpriseSettingsData {
  name: string;
  allowed_email_domains: string[];
}

export default function EnterpriseSettings() {
  const [settings, setSettings] = useState<EnterpriseSettingsData | null>(null);
  const [name, setName] = useState('');
  const [domains, setDomains] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void apiClient.get<EnterpriseSettingsData>('/api/enterprise/settings')
      .then(({ data }) => {
        setSettings(data);
        setName(data.name);
        setDomains(data.allowed_email_domains.join(', '));
      })
      .catch((error) => toast.error(apiErrorMessage(error, 'Failed to load enterprise settings')));
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const { data } = await apiClient.put<EnterpriseSettingsData>('/api/enterprise/settings', {
        name: name.trim(),
        allowed_email_domains: domains.split(',').map((value) => value.trim()).filter(Boolean),
      });
      setSettings(data);
      toast.success('Enterprise settings updated');
    } catch (error) {
      toast.error(apiErrorMessage(error, 'Failed to update enterprise settings'));
    } finally {
      setSaving(false);
    }
  };

  if (!settings) return <Panel><PanelSkeleton rows={3} /></Panel>;

  return (
    <Panel>
      <div className="space-y-3 p-3.5">
        <div>
          <h3 className="text-xs font-semibold text-[var(--text-strong)]">Enterprise Settings</h3>
          <p className="mt-1 text-[11px] text-[var(--text-muted)]">
            Domains restrict employee provisioning only. Membership remains the authorization boundary.
          </p>
        </div>
        <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Enterprise name" aria-label="Enterprise name" />
        <Input value={domains} onChange={(event) => setDomains(event.target.value)} placeholder="Allowed domains, comma separated (optional)" aria-label="Allowed email domains" />
        <div className="flex justify-end">
          <Button variant="primary" onClick={() => void save()} disabled={saving}>{saving ? 'Saving...' : 'Save Settings'}</Button>
        </div>
      </div>
    </Panel>
  );
}
