type AccessUser = {
  role?: string | null;
  subscriptionTier?: string | null;
  enterpriseId?: string | null;
  enterpriseRole?: string | null;
  canManageMembers?: boolean | null;
};

export function isEnterpriseOwner(user?: AccessUser | null): boolean {
  return Boolean(user?.enterpriseId && (user.enterpriseRole === 'owner' || user.canManageMembers));
}

export function hasElevatedAccess(user?: AccessUser | null): boolean {
  return (user?.role === 'admin' && !user.enterpriseId) || isEnterpriseOwner(user);
}

export function displayRole(user?: AccessUser | null): string {
  if (!user) return 'User';
  if (isEnterpriseOwner(user)) return 'Enterprise Owner';
  if (user.enterpriseId) return 'Enterprise Employee';
  if (user.role === 'admin') return 'Admin';
  if (user.subscriptionTier === 'ENTERPRISE') return 'Enterprise';
  if (user.subscriptionTier === 'PRO') return 'Pro / Plus';
  return 'Free';
}
