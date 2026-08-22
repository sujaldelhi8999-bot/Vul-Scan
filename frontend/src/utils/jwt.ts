/**
 * JWT helpers — decode the payload without verifying the signature
 * (verification happens server-side) and surface the expiry time so the
 * client can proactively refresh or detect stale sessions.
 */

export interface JwtPayload {
  sub?: string;
  role?: string;
  typ?: string;
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

function base64UrlDecode(input: string): string {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function getJwtPayload(token: string | null | undefined): JwtPayload | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(parts[1])) as JwtPayload;
    return payload && typeof payload === 'object' ? payload : null;
  } catch {
    return null;
  }
}

export function getTokenExpiry(token: string | null | undefined): number | null {
  const payload = getJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return null;
  return payload.exp * 1000;
}

export function isTokenExpired(token: string | null | undefined, skewMs = 60_000): boolean {
  const expiryMs = getTokenExpiry(token);
  if (expiryMs === null) return true;
  return expiryMs - skewMs <= Date.now();
}

export function tokenExpiresWithin(
  token: string | null | undefined,
  withinMs: number,
  skewMs = 60_000
): boolean {
  const expiryMs = getTokenExpiry(token);
  if (expiryMs === null) return true;
  return expiryMs - skewMs <= Date.now() + withinMs;
}