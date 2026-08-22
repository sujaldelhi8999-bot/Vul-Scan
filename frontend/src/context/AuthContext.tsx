import React, { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { getStoredUser, login, loginWithSupabase, logout, getUserProfile, register, refreshToken as refreshTokenApi, getStoredRefreshToken, clearSession, type LoginResponse, type UserRole } from '../services/auth';
import { signInWithProvider, signOutOfSupabase, supabaseConfigured } from '../services/supabase';
import { isTokenExpired, tokenExpiresWithin } from '../utils/jwt';
import type { Provider } from '@supabase/supabase-js';
import type { UserProfile } from '../services/auth';

const REFRESH_WINDOW_MS = 5 * 60 * 1000;
const REFRESH_CHECK_INTERVAL_MS = 60 * 1000;

let refreshInFlight: Promise<boolean> | null = null;

// Helper to add timeout to promises
const withTimeout = async <T,>(promise: Promise<T>, ms: number): Promise<T | null> => {
  let timer: number | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<null>((resolve) => {
        timer = window.setTimeout(() => resolve(null), ms);
      }),
    ]);
  } finally {
    if (timer) window.clearTimeout(timer);
  }
};

export interface PhantomUser {
  id: string;
  username: string;
  email: string | null;
  name: string;
  role: UserRole;
  subscriptionTier: 'FREE' | 'PRO' | 'ENTERPRISE';
  subscriptionStatus: 'active' | 'canceled' | 'past_due';
  enterpriseId?: string | null;
  enterpriseName?: string | null;
  enterpriseRole?: string | null;
  maxSeverity?: string | null;
  canRequestAudit?: boolean;
  canRequestFix?: boolean;
  canApprove?: boolean;
  canManageMembers?: boolean;
  allowedEmailDomains?: string[];
}

interface AuthContextType {
  user: PhantomUser | null;
  loginUser: (email: string, password: string) => Promise<void>;
  registerUser: (email: string, password: string, name?: string) => Promise<void>;
  loginWithProvider: (provider: Provider) => Promise<void>;
  exchangeSupabaseLogin: (accessToken: string) => Promise<void>;
  logoutUser: () => Promise<void>;
  isLoading: boolean;
  supabaseConfigured: boolean;
  refreshUser: () => Promise<void>;
  refreshToken: () => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<PhantomUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

const fetchUserProfile = useCallback(async (token: string) => {
    try {
      // Add timeout to prevent hanging requests
      const profileResponse = await withTimeout<UserProfile>(getUserProfile(token), 8000);
      if (profileResponse) {
        const profile = profileResponse;
        setUser({
          id: profile.id,
          username: profile.email,
          email: profile.email,
          name: profile.name || profile.email,
          role: profile.role as UserRole,
          subscriptionTier: profile.subscription_tier as 'FREE' | 'PRO' | 'ENTERPRISE',
          subscriptionStatus: profile.subscription_status as 'active' | 'canceled' | 'past_due',
          enterpriseId: profile.enterprise_id,
          enterpriseName: profile.enterprise_name,
          enterpriseRole: profile.enterprise_role,
          maxSeverity: profile.max_severity,
          canRequestAudit: profile.can_request_audit,
          canRequestFix: profile.can_request_fix,
          canApprove: profile.can_approve,
          canManageMembers: profile.can_manage_members,
          allowedEmailDomains: profile.allowed_email_domains,
        });
      } else {
        // Timeout occurred
        console.warn('getUserProfile request timed out');
        // Fall back to stored user on timeout
        const stored = getStoredUser();
        if (stored) {
          setUser({
            id: stored.username,
            username: stored.username || 'admin',
            email: stored.email ?? null,
            name: stored.name || stored.username || 'Admin',
            role: stored.role as UserRole,
             subscriptionTier: (stored.subscriptionTier || 'FREE') as 'FREE' | 'PRO' | 'ENTERPRISE',
            subscriptionStatus: (stored.subscriptionStatus || 'active') as 'active' | 'canceled' | 'past_due',
            enterpriseId: stored.enterpriseId,
            enterpriseName: stored.enterpriseName,
            enterpriseRole: stored.enterpriseRole,
            maxSeverity: stored.maxSeverity,
            canRequestAudit: stored.canRequestAudit,
            canRequestFix: stored.canRequestFix,
            canApprove: stored.canApprove,
            canManageMembers: stored.canManageMembers,
            allowedEmailDomains: stored.allowedEmailDomains,
          });
        } else {
          setUser(null);
        }
      }
    } catch (error) {
      console.error('Failed to fetch user profile:', error);
      // On 401 (invalid/expired token), clear the session entirely
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        logout();
        setUser(null);
      } else {
        // For other errors (network, etc.), fall back to stored user
        const stored = getStoredUser();
        if (stored) {
          setUser({
            id: stored.username,
            username: stored.username || 'admin',
            email: stored.email ?? null,
            name: stored.name || stored.username || 'Admin',
            role: stored.role as UserRole,
             subscriptionTier: (stored.subscriptionTier || 'FREE') as 'FREE' | 'PRO' | 'ENTERPRISE',
            subscriptionStatus: (stored.subscriptionStatus || 'active') as 'active' | 'canceled' | 'past_due',
            enterpriseId: stored.enterpriseId,
            enterpriseName: stored.enterpriseName,
            enterpriseRole: stored.enterpriseRole,
            maxSeverity: stored.maxSeverity,
            canRequestAudit: stored.canRequestAudit,
            canRequestFix: stored.canRequestFix,
            canApprove: stored.canApprove,
            canManageMembers: stored.canManageMembers,
            allowedEmailDomains: stored.allowedEmailDomains,
          });
        } else {
          setUser(null);
        }
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    const stored = getStoredUser();
    if (stored) {
      const token = stored.token;
      if (token) {
        if (isTokenExpired(token)) {
          void refreshToken().then((refreshed) => {
            if (refreshed) {
              const fresh = localStorage.getItem('phantom_token');
              if (fresh) void fetchUserProfile(fresh);
            } else {
              setIsLoading(false);
            }
          });
        } else {
          void fetchUserProfile(token);
        }
      } else {
        setUser({
          id: stored.username,
          username: stored.username || 'admin',
          role: stored.role as UserRole,
          name: stored.name || stored.username || 'Admin',
          email: stored.email ?? null,
           subscriptionTier: (stored.subscriptionTier || 'FREE') as 'FREE' | 'PRO' | 'ENTERPRISE',
          subscriptionStatus: (stored.subscriptionStatus || 'active') as 'active' | 'canceled' | 'past_due',
          enterpriseId: stored.enterpriseId,
          enterpriseName: stored.enterpriseName,
          enterpriseRole: stored.enterpriseRole,
          maxSeverity: stored.maxSeverity,
          canRequestAudit: stored.canRequestAudit,
          canRequestFix: stored.canRequestFix,
          canApprove: stored.canApprove,
          canManageMembers: stored.canManageMembers,
          allowedEmailDomains: stored.allowedEmailDomains,
        });
        setIsLoading(false);
      }
    } else {
      setIsLoading(false);
    }
  }, []);

  const applySession = (response: LoginResponse) => {
    const name = response.name || response.username;
    localStorage.setItem('phantom_token', response.token);
    if (response.refresh_token) {
      localStorage.setItem('phantom_refresh_token', response.refresh_token);
    }
    localStorage.setItem('phantom_user_role', response.role);
    localStorage.setItem('phantom_username', response.username);
    localStorage.setItem('phantom_user_name', name);
    localStorage.setItem('phantom_user_email', response.email ?? '');
    localStorage.setItem('phantom_subscription_tier', response.subscription_tier || 'FREE');
    localStorage.setItem('phantom_subscription_status', response.subscription_status || 'active');
    localStorage.setItem('phantom_enterprise_id', response.enterprise_id || '');
    localStorage.setItem('phantom_enterprise_name', response.enterprise_name || '');
    localStorage.setItem('phantom_enterprise_role', response.enterprise_role || '');
    localStorage.setItem('phantom_max_severity', response.max_severity || '');
    localStorage.setItem('phantom_can_request_audit', String(Boolean(response.can_request_audit)));
    localStorage.setItem('phantom_can_request_fix', String(Boolean(response.can_request_fix)));
    localStorage.setItem('phantom_can_approve', String(Boolean(response.can_approve)));
    localStorage.setItem('phantom_can_manage_members', String(Boolean(response.can_manage_members)));
    localStorage.setItem('phantom_allowed_email_domains', JSON.stringify(response.allowed_email_domains || []));
    setUser({ 
      id: response.username, 
      username: response.username, 
      role: response.role, 
      name, 
      email: response.email ?? null,
      subscriptionTier: (response.subscription_tier || 'FREE') as 'FREE' | 'PRO' | 'ENTERPRISE',
      subscriptionStatus: (response.subscription_status || 'active') as 'active' | 'canceled' | 'past_due',
      enterpriseId: response.enterprise_id,
      enterpriseName: response.enterprise_name,
      enterpriseRole: response.enterprise_role,
      maxSeverity: response.max_severity,
      canRequestAudit: response.can_request_audit,
      canRequestFix: response.can_request_fix,
      canApprove: response.can_approve,
      canManageMembers: response.can_manage_members,
      allowedEmailDomains: response.allowed_email_domains,
    });
  };

  /**
   * Silently rotate the access token before it expires. Returns false when
   * the refresh token is missing/invalid, in which case the session is
   * cleared and the user is sent back to the login page.
   */
  const refreshToken = useCallback(async (): Promise<boolean> => {
    const refreshValue = getStoredRefreshToken();
    if (!refreshValue) {
      clearSession();
      setUser(null);
      return false;
    }
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = (async () => {
      try {
        // Add timeout to prevent hanging requests
        const response = await withTimeout<LoginResponse>(refreshTokenApi(refreshValue), 8000);
        if (response) {
          applySession(response);
          return true;
        } else {
          // Timeout occurred
          console.warn('refreshTokenApi request timed out');
          clearSession();
          setUser(null);
          navigate('/login');
          return false;
        }
      } catch (error) {
        console.warn('Session refresh failed:', error);
        clearSession();
        setUser(null);
        navigate('/login');
        return false;
      } finally {
        refreshInFlight = null;
      }
    })();
    return refreshInFlight;
  }, [navigate]);

  useEffect(() => {
    // Proactively refresh before the access token expires so sessions
    // survive across long browser sessions without a re-login.
    const tick = () => {
      const token = localStorage.getItem('phantom_token');
      if (!token) return;
      if (tokenExpiresWithin(token, REFRESH_WINDOW_MS)) {
        void refreshToken();
      }
    };
    tick();
    const id = window.setInterval(tick, REFRESH_CHECK_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, []);

  const loginUser = useCallback(async (email: string, password: string) => {
    const response = await login(email, password);
    applySession(response);
  }, []);

  const registerUser = useCallback(async (email: string, password: string, name?: string) => {
    const response = await register(email, password, name);
    applySession(response);
  }, []);

  const loginWithProvider = useCallback(async (provider: Provider) => {
    await signInWithProvider(provider);
  }, []);

  const exchangeSupabaseLogin = useCallback(async (accessToken: string) => {
    const response = await loginWithSupabase(accessToken);
    applySession(response);
  }, []);

  const logoutUser = useCallback(async () => {
    logout();
    await signOutOfSupabase();
    setUser(null);
    navigate('/');
  }, [navigate]);

  const refreshUser = useCallback(async () => {
    const token = localStorage.getItem('phantom_token');
    if (token) {
      await fetchUserProfile(token);
    }
  }, [fetchUserProfile]);

  return (
    <AuthContext.Provider
      value={{ user, loginUser, registerUser, loginWithProvider, exchangeSupabaseLogin, logoutUser, isLoading, supabaseConfigured, refreshUser, refreshToken }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
