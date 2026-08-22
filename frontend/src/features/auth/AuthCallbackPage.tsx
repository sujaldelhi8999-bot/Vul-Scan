import { useEffect, useRef, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../../context/AuthContext';
import { exchangeSupabaseSession, supabaseConfigured } from '../../services/supabase';
import { Button, Page } from '../../components/ui/Primitives';

export default function AuthCallbackPage() {
  const navigate = useNavigate();
  const { exchangeSupabaseLogin } = useAuth();
  const [error, setError] = useState('');
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    let cancelled = false;
    const complete = async () => {
      if (!supabaseConfigured) {
        setError('Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.');
        return;
      }
      try {
        const accessToken = await exchangeSupabaseSession();
        if (cancelled) return;
        if (!accessToken) {
          setError('No Supabase session found. Please try logging in again.');
          return;
        }
        await exchangeSupabaseLogin(accessToken);
        if (cancelled) return;
        navigate('/dashboard', { replace: true });
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Login failed. Please try again.');
      }
    };
    void complete();
    return () => {
      cancelled = true;
    };
  }, [exchangeSupabaseLogin, navigate]);

  return (
    <Page>
      <div className="flex flex-col items-center justify-center gap-4 p-12 text-center">
        {error ? (
          <>
            <div className="text-sm font-semibold text-[var(--danger)]">Login failed</div>
            <p className="max-w-md text-xs text-[var(--text-muted)]">{error}</p>
            <div className="flex gap-2">
              <Button onClick={() => navigate('/login', { replace: true })}>Back to login</Button>
              <Button variant="secondary" onClick={() => navigate('/', { replace: true })}>Home</Button>
            </div>
          </>
        ) : (
          <>
            <Loader2 className="h-6 w-6 animate-spin text-[var(--brand)]" />
            <div className="text-sm font-semibold text-[var(--text-strong)]">Completing sign-in...</div>
            <p className="text-xs text-[var(--text-muted)]">Exchanging the Supabase session with VulScan.</p>
          </>
        )}
      </div>
    </Page>
  );
}
