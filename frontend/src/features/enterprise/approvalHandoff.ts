export interface EnterpriseApprovalHandoff {
  id: number;
  request_type: string;
  target_url: string | null;
  details: Record<string, unknown>;
}

const STORAGE_KEY = 'vulscan:enterprise-approval';

export function storeEnterpriseApproval(value: EnterpriseApprovalHandoff) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(value));
}

export function getEnterpriseApproval(types: string[]): EnterpriseApprovalHandoff | null {
  const raw = sessionStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as EnterpriseApprovalHandoff;
    return Number.isInteger(value.id) && types.includes(value.request_type) ? value : null;
  } catch {
    sessionStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

export function clearEnterpriseApproval() {
  sessionStorage.removeItem(STORAGE_KEY);
}
