import axios from 'axios';

const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000')
  .replace(/\/api\/?$/, '')
  .replace(/\/$/, '');

export type UserRole = 'admin' | 'manager' | 'employee' | 'user';

export interface LoginResponse {
  token: string;
  role: UserRole;
  username: string;
  name?: string | null;
  email?: string | null;
  subscription_tier?: string;
  subscription_status?: string;
  enterprise_id?: string | null;
  enterprise_name?: string | null;
  enterprise_role?: string | null;
  max_severity?: string | null;
  can_request_audit?: boolean;
  can_request_fix?: boolean;
  can_approve?: boolean;
  can_manage_members?: boolean;
  allowed_email_domains?: string[];
  refresh_token?: string | null;
  expires_at?: string | null;
}

interface AuthApiResponse {
  token: string;
  user: UserProfile;
  refresh_token?: string | null;
  expires_at?: string | null;
}

export interface UserProfile {
  id: string;
  email: string;
  name: string | null;
  role: string;
  subscription_tier: string;
  subscription_status: string;
  created_at: string;
  enterprise_id?: string | null;
  enterprise_name?: string | null;
  enterprise_role?: string | null;
  max_severity?: string | null;
  can_request_audit?: boolean;
  can_request_fix?: boolean;
  can_approve?: boolean;
  can_manage_members?: boolean;
  allowed_email_domains?: string[];
}

const normalizeAuthResponse = (data: AuthApiResponse): LoginResponse => ({
  token: data.token,
  role: data.user.role as UserRole,
  username: data.user.email,
  name: data.user.name,
  email: data.user.email,
  subscription_tier: data.user.subscription_tier,
  subscription_status: data.user.subscription_status,
  enterprise_id: data.user.enterprise_id ?? null,
  enterprise_name: data.user.enterprise_name ?? null,
  enterprise_role: data.user.enterprise_role ?? null,
  max_severity: data.user.max_severity ?? null,
  can_request_audit: Boolean(data.user.can_request_audit),
  can_request_fix: Boolean(data.user.can_request_fix),
  can_approve: Boolean(data.user.can_approve),
  can_manage_members: Boolean(data.user.can_manage_members),
  allowed_email_domains: data.user.allowed_email_domains ?? [],
  refresh_token: data.refresh_token ?? null,
  expires_at: data.expires_at ?? null,
});

const AUTH_PATH = '/api/auth';

export const login = async (email: string, password: string): Promise<LoginResponse> => {
  const response = await axios.post<AuthApiResponse>(`${API_BASE}${AUTH_PATH}/login`, {
    email,
    password,
  });
  return normalizeAuthResponse(response.data);
};

export const register = async (email: string, password: string, name?: string): Promise<LoginResponse> => {
  const response = await axios.post<AuthApiResponse>(`${API_BASE}${AUTH_PATH}/register`, {
    email,
    password,
    name: name || undefined,
  });
  return normalizeAuthResponse(response.data);
};

export const loginWithSupabase = async (accessToken: string): Promise<LoginResponse> => {
  const response = await axios.post<AuthApiResponse>(`${API_BASE}${AUTH_PATH}/supabase`, {
    access_token: accessToken,
  });
  return normalizeAuthResponse(response.data);
};

export const refreshToken = async (refreshTokenValue: string): Promise<LoginResponse> => {
  const response = await axios.post<AuthApiResponse>(`${API_BASE}${AUTH_PATH}/refresh`, {
    refresh_token: refreshTokenValue,
  });
  return normalizeAuthResponse(response.data);
};

export const getUserProfile = async (token: string): Promise<UserProfile> => {
  const response = await axios.get(`${API_BASE}${AUTH_PATH}/me`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data;
};

export const clearSession = () => {
  localStorage.removeItem('phantom_token');
  localStorage.removeItem('phantom_refresh_token');
  localStorage.removeItem('phantom_user_role');
  localStorage.removeItem('phantom_username');
  localStorage.removeItem('phantom_user_name');
  localStorage.removeItem('phantom_user_email');
  localStorage.removeItem('phantom_subscription_tier');
  localStorage.removeItem('phantom_subscription_status');
  localStorage.removeItem('phantom_enterprise_id');
  localStorage.removeItem('phantom_enterprise_name');
  localStorage.removeItem('phantom_enterprise_role');
  localStorage.removeItem('phantom_max_severity');
  localStorage.removeItem('phantom_can_request_audit');
  localStorage.removeItem('phantom_can_request_fix');
  localStorage.removeItem('phantom_can_approve');
  localStorage.removeItem('phantom_can_manage_members');
  localStorage.removeItem('phantom_allowed_email_domains');
};

export const logout = () => {
  clearSession();
};

export const getStoredRefreshToken = (): string | null => {
  return localStorage.getItem('phantom_refresh_token');
};

export const getStoredUser = () => {
  const token = localStorage.getItem('phantom_token');
  const role = localStorage.getItem('phantom_user_role');
  const username = localStorage.getItem('phantom_username');
  const name = localStorage.getItem('phantom_user_name');
  const email = localStorage.getItem('phantom_user_email');
  const subscriptionTier = localStorage.getItem('phantom_subscription_tier');
  const subscriptionStatus = localStorage.getItem('phantom_subscription_status');
  const enterpriseId = localStorage.getItem('phantom_enterprise_id');
  const enterpriseName = localStorage.getItem('phantom_enterprise_name');
  const enterpriseRole = localStorage.getItem('phantom_enterprise_role');
  const maxSeverity = localStorage.getItem('phantom_max_severity');
  const canRequestAudit = localStorage.getItem('phantom_can_request_audit') === 'true';
  const canRequestFix = localStorage.getItem('phantom_can_request_fix') === 'true';
  const canApprove = localStorage.getItem('phantom_can_approve') === 'true';
  const canManageMembers = localStorage.getItem('phantom_can_manage_members') === 'true';
  let allowedEmailDomains: string[] = [];
  try {
    allowedEmailDomains = JSON.parse(localStorage.getItem('phantom_allowed_email_domains') || '[]');
  } catch {
    allowedEmailDomains = [];
  }
  if (token && role) {
    return { token, role: role as UserRole, username: username || '', name, email, subscriptionTier, subscriptionStatus, enterpriseId, enterpriseName, enterpriseRole, maxSeverity, canRequestAudit, canRequestFix, canApprove, canManageMembers, allowedEmailDomains };
  }
  return null;
};
