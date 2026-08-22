import React, { useState } from 'react';
import { GitBranch, Globe, Loader2, Lock, Mail, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { apiErrorMessage } from '../services/api';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [ssoProvider, setSsoProvider] = useState<'google' | 'github' | null>(null);
  const { loginUser, loginWithProvider, supabaseConfigured } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await loginUser(email, password);
      onClose();
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Login failed. Try again.'));
    } finally {
      setLoading(false);
    }
  };

  const handleSso = async (provider: 'google' | 'github') => {
    setError('');
    setSsoProvider(provider);
    try {
      await loginWithProvider(provider);
    } catch (err: any) {
      setError(apiErrorMessage(err, `Could not start ${provider} login.`));
      setSsoProvider(null);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-slate-900/20 backdrop-blur-[2.5px] flex items-center justify-center z-50 p-4">
      <div className="bg-[var(--surface-primary)] rounded-[var(--radius-panel)] p-6 max-w-sm w-full border border-[var(--border-light)] shadow-[var(--shadow-float)]">
        <div className="text-center mb-5">
          <div className="flex justify-center mb-2.5">
            <div className="flex h-9 w-9 items-center justify-center overflow-hidden rounded-[var(--radius-control)]">
              <img src="/favicon.png" alt="VulScan logo" className="h-full w-full object-contain" />
            </div>
          </div>
          <h2 className="text-base font-bold text-[var(--text-strong)]">
            Sign In to VulScan
          </h2>
          <p className="text-[10px] text-[var(--text-muted)] mt-0.5">Enter your credentials to access your security workspace</p>
        </div>

        {supabaseConfigured && (
          <>
            <div className="space-y-2 mb-4">
              <button
                type="button"
                onClick={() => void handleSso('google')}
                disabled={ssoProvider !== null}
                className="w-full flex items-center justify-center gap-2 border border-[var(--border-light)] rounded-[var(--radius-control)] px-4 py-1.5 text-xs font-semibold text-[var(--text-strong)] hover:bg-[var(--surface-hover)] transition-colors disabled:opacity-50 active:scale-[0.98] active:translate-y-[0.5px]"
              >
                {ssoProvider === 'google' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Globe className="h-3.5 w-3.5 text-[var(--brand)]" />}
                Continue with Google
              </button>
            </div>

            <div className="flex items-center gap-2.5 mb-4">
              <div className="flex-1 border-t border-[var(--border-light)]" />
              <span className="text-[10px] text-[var(--text-muted)] font-semibold uppercase tracking-wider">or with email</span>
              <div className="flex-1 border-t border-[var(--border-light)]" />
            </div>
          </>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-[var(--text-strong)] mb-1">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[var(--text-muted)]" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs border border-[var(--border-default)] rounded-[var(--radius-control)] bg-white text-[var(--text-strong)] placeholder-[var(--text-subtle)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]/8 focus:border-[var(--brand)] transition-all"
                placeholder="you@example.com"
                required
                autoComplete="email"
              />
            </div>
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-[var(--text-strong)] mb-1">Password</label>
            <div className="relative">
              <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[var(--text-muted)]" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs border border-[var(--border-default)] rounded-[var(--radius-control)] bg-white text-[var(--text-strong)] placeholder-[var(--text-subtle)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]/8 focus:border-[var(--brand)] transition-all"
                placeholder="Enter password"
                required
                autoComplete="current-password"
              />
            </div>
          </div>
          {error && (
            <div className="p-2 rounded-[var(--radius-control)] bg-[var(--danger-soft)] border border-[var(--danger-border)] text-[10px] font-semibold text-[var(--danger)] text-center">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[var(--brand)] hover:bg-[var(--brand-hover)] text-white font-semibold py-1.75 px-4 rounded-[var(--radius-control)] text-xs transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 active:scale-[0.98] active:translate-y-[0.5px]"
          >
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        <button
          onClick={onClose}
          className="mt-2.5 text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)] hover:text-[var(--text-strong)] w-full text-center py-1 transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
};

export default LoginModal;
