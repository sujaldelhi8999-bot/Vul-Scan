import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Loader2 } from 'lucide-react';
import { hasPlatformAdminAccess } from '../../utils/access';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredTier?: 'FREE' | 'PRO' | 'ENTERPRISE';
  requireEnterprise?: boolean;
  requireAdmin?: boolean;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requiredTier = 'FREE',
  requireEnterprise = false,
  requireAdmin = false,
}) => {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[var(--app-canvas)]">
        <Loader2 className="h-8 w-8 animate-spin text-[var(--brand)]" />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  const tierOrder = { FREE: 0, PRO: 1, ENTERPRISE: 2 } as const;
  const platformAdmin = user.role === 'admin' && !user.enterpriseId;
  const enterpriseMember = Boolean(user.enterpriseId);
  const tierSatisfiedByMembership = requiredTier === 'ENTERPRISE' && enterpriseMember;
  if (tierOrder[user.subscriptionTier] < tierOrder[requiredTier] && !platformAdmin && !tierSatisfiedByMembership) {
    return <Navigate to="/pricing" replace state={{ from: location, message: 'Upgrade to Pro / Plus required' }} />;
  }

  if (requireEnterprise && !user.enterpriseId) {
    return <Navigate to="/dashboard" replace state={{ from: location, message: 'Enterprise membership required' }} />;
  }

  if (requireAdmin && !hasPlatformAdminAccess(user)) {
    return <Navigate to="/dashboard" replace state={{ from: location, message: 'Platform admin privileges required' }} />;
  }

  return <>{children}</>;
};
