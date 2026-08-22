import { createClient, type SupabaseClient, type Provider } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabase: SupabaseClient | null =
  supabaseUrl && supabaseAnonKey ? createClient(supabaseUrl, supabaseAnonKey) : null;

export const supabaseConfigured = supabase !== null;

export async function signInWithProvider(provider: Provider): Promise<void> {
  if (!supabase) {
    throw new Error('Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.');
  }
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider,
    options: {
      redirectTo: `${window.location.origin}/auth/callback`,
      queryParams: {
        prompt: 'select_account',
        access_type: 'offline',
      },
    },
  });
  if (error) throw new Error(error.message);
  if (!data.url) throw new Error('Could not start the provider login. Please try again.');
  window.location.href = data.url;
}

export async function exchangeSupabaseSession(): Promise<string | null> {
  if (!supabase) return null;

  // 1. Check if session is already present
  const { data: existing, error: sessionError } = await supabase.auth.getSession();
  if (sessionError) throw sessionError;
  if (existing.session?.access_token) return existing.session.access_token;

  // 2. Handle PKCE code in query params (?code=...)
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  if (code) {
    const { data: exchanged, error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) throw error;
    window.history.replaceState({}, document.title, window.location.pathname);
    if (exchanged.session?.access_token) return exchanged.session.access_token;
    const { data: afterData } = await supabase.auth.getSession();
    if (afterData.session?.access_token) return afterData.session.access_token;
  }

  // 3. Handle Hash params (#access_token=... or #error=...) from implicit flow
  if (window.location.hash) {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const errorDescription = hashParams.get('error_description') || hashParams.get('error');
    if (errorDescription) {
      throw new Error(errorDescription);
    }
    const hashAccessToken = hashParams.get('access_token');
    const hashRefreshToken = hashParams.get('refresh_token');
    if (hashAccessToken) {
      if (hashRefreshToken) {
        const { data: setSessionData, error: setSessionError } = await supabase.auth.setSession({
          access_token: hashAccessToken,
          refresh_token: hashRefreshToken,
        });
        if (!setSessionError && setSessionData.session?.access_token) {
          window.history.replaceState({}, document.title, window.location.pathname);
          return setSessionData.session.access_token;
        }
      }
      window.history.replaceState({}, document.title, window.location.pathname);
      return hashAccessToken;
    }
  }

  // 4. Wait for onAuthStateChange in case Supabase client processes it asynchronously
  return new Promise<string | null>((resolve) => {
    let resolved = false;
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        subscription.unsubscribe();
        resolve(null);
      }
    }, 4000);

    const { data: { subscription } } = supabase!.auth.onAuthStateChange((event, session) => {
      if (!resolved && session?.access_token) {
        resolved = true;
        clearTimeout(timer);
        subscription.unsubscribe();
        resolve(session.access_token);
      }
    });
  });
}

export async function signOutOfSupabase(): Promise<void> {
  if (!supabase) return;
  await supabase.auth.signOut();
}
