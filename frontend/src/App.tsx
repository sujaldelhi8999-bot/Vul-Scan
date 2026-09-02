import { Navigate, Route, Routes } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { type ReactNode } from 'react';

import AppShell from './components/layout/AppShell';
import { PhantomDataProvider } from './hooks/usePhantomData';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import HomePage from './features/marketing/HomePage';
import PricingPage from './features/marketing/PricingPage';
import DashboardPage from './features/dashboard/DashboardPage';
import LiveScanPage from './features/scans/LiveScanPage';
import FindingsPage from './features/findings/FindingsPage';
import AttackPaths from './features/attack_paths/AttackPaths';
import AssetsPage from './features/assets/AssetsPage';
import CvePage from './features/cve/CvePage';
import RemediationPage from './features/remediation/RemediationPage';
import AgentsPage from './features/operations/AgentsPage';
import ScanHistoryPage from './features/operations/ScanHistoryPage';
import AuditLogsPage from './features/operations/AuditLogsPage';
import SelfAuditPage from './features/system/SelfAuditPage';
import NotificationsPage from './features/system/NotificationsPage';
import SystemHealthPage from './features/system/SystemHealthPage';
import SettingsPage from './features/system/SettingsPage';
import AttackIntelligence from './features/private/AttackIntelligence';
import CodeAnalysis from './features/private/CodeAnalysis';
import BrutalMode from './features/brutal/BrutalMode';
import AuthorizedTestingPage from './features/authorized-testing/AuthorizedTestingPage';
import ScanQualityPage from './features/learning/ScanQualityPage';
import DoSPanel from './features/private/DoSPanel';
import ReportPage from './features/reports/ReportPage';
import SecurityPriorities from './features/attack-planner/AttackPlanner';
import GitHubConnectPage from './features/github/GitHubConnectPage';
import MultiSourceScanPage from './features/multi-source/MultiSourceScanPage';
import MultiSourceDetailPage from './features/multi-source/MultiSourceDetailPage';
import AuthCallbackPage from './features/auth/AuthCallbackPage';
import ProfilePage from './features/auth/ProfilePage';
import LoginPage from './features/auth/LoginPage';
import RegisterPage from './features/auth/RegisterPage';
import EnterpriseDashboard from './features/enterprise/EnterpriseDashboard';

export default function App() {
  const isAuthCallback =
    window.location.pathname === '/auth/callback' ||
    window.location.hash.startsWith('#/auth/callback') ||
    window.location.hash.includes('access_token=');
  const workspace = (children: ReactNode, requiredTier?: 'FREE' | 'PRO' | 'ENTERPRISE', requireEnterprise = false, requireAdmin = false) => (
    <ProtectedRoute requiredTier={requiredTier} requireEnterprise={requireEnterprise} requireAdmin={requireAdmin}>
      <AppShell>{children}</AppShell>
    </ProtectedRoute>
  );

  if (isAuthCallback) {
    return (
      <AuthProvider>
        <AuthCallbackPage />
      </AuthProvider>
    );
  }

  return (
    <AuthProvider>
        <PhantomDataProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/" element={<HomePage />} />
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/auth/callback" element={<AuthCallbackPage />} />

          {/* Protected workspace routes - FREE tier */}
          <Route path="/dashboard" element={workspace(<DashboardPage />)} />
          <Route path="/scan" element={workspace(<LiveScanPage />)} />
          <Route path="/findings" element={workspace(<FindingsPage />)} />
          <Route path="/attack-paths" element={workspace(<AttackPaths />)} />
          <Route path="/assets" element={workspace(<AssetsPage />)} />
          <Route path="/cve" element={workspace(<CvePage />)} />
          <Route path="/remediation" element={workspace(<RemediationPage />)} />
          <Route path="/agents" element={workspace(<AgentsPage />)} />
          <Route path="/history" element={workspace(<ScanHistoryPage />)} />
          <Route path="/audit-logs" element={workspace(<AuditLogsPage />)} />
          <Route path="/self-audit" element={workspace(<SelfAuditPage />)} />
          <Route path="/notifications" element={workspace(<NotificationsPage />)} />
          <Route path="/system-health" element={workspace(<SystemHealthPage />)} />
          <Route path="/settings" element={workspace(<SettingsPage />)} />
          <Route path="/intelligence" element={workspace(<AttackIntelligence />)} />
          <Route path="/security-priorities" element={workspace(<SecurityPriorities />)} />
          <Route path="/attack-planner" element={<Navigate to="/security-priorities" replace />} />
          <Route path="/code-analysis" element={workspace(<CodeAnalysis />)} />
          <Route path="/brutal" element={workspace(<BrutalMode />)} />
          <Route path="/quality" element={workspace(<ScanQualityPage />)} />
          <Route path="/github" element={workspace(<GitHubConnectPage />)} />
          <Route path="/github/callback" element={<GitHubConnectPage />} />
          <Route path="/profile" element={workspace(<ProfilePage />)} />
          <Route path="/enterprise" element={workspace(<EnterpriseDashboard />, 'ENTERPRISE', true)} />
          <Route path="/multi-source" element={workspace(<MultiSourceScanPage />)} />
          <Route path="/multi-source/:scan_id" element={workspace(<MultiSourceDetailPage />)} />
          <Route path="/report/:scan_id" element={workspace(<ReportPage />)} />

          {/* Protected workspace routes - PRO tier only */}
          <Route path="/authorized-testing" element={workspace(<AuthorizedTestingPage />, 'PRO')} />
          <Route path="/private/dos" element={workspace(<DoSPanel />, 'PRO')} />

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
        </PhantomDataProvider>
        <Toaster
          position="bottom-right"
          toastOptions={{
            duration: 3500,
            style: {
              background: 'var(--surface-primary)',
              color: 'var(--text-strong)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-control)',
              fontFamily: 'Inter, sans-serif',
              fontSize: '13px',
              boxShadow: 'var(--shadow-float)',
            },
          }}
        />
    </AuthProvider>
  );
}
