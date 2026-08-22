import { useEffect, useRef, useState } from 'react';
import { ChevronDown, LayoutDashboard, LogOut, Settings } from 'lucide-react';
import { Link } from 'react-router-dom';

import { useAuth } from '../../context/AuthContext';
import { cx } from '../ui/Primitives';

export default function UserMenu() {
  const { user, logoutUser } = useAuth();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event: PointerEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  if (!user) return null;

  const displayName = user.name || user.username || user.email || 'User';
  const emailDisplay = user.email || user.username || '';
  const initial = (displayName.charAt(0) || 'U').toUpperCase();

  return (
    <div className="relative ml-2" ref={containerRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-[var(--radius-control)] border border-[var(--border-light)] bg-white py-1 px-2.5 text-xs shadow-sm hover:bg-[var(--surface-hover)] transition-all active:scale-[0.98]"
        aria-label="User menu"
        aria-expanded={open}
      >
        {/* Avatar (first letter) */}
        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-gradient-to-br from-[var(--brand)] to-blue-500 text-[10px] font-bold text-white uppercase">
          {initial}
        </span>

        {/* Role / Plan Badge inside pill */}
        {user.role === 'admin' || user.enterpriseId ? (
          <span className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold bg-purple-50 border border-purple-200 text-purple-700">
            {user.enterpriseId ? 'Enterprise Admin' : 'Admin'}
          </span>
        ) : user.subscriptionTier === 'PRO' ? (
          <span className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold bg-amber-50 border border-amber-200 text-amber-700">
            ⚡ Pro
          </span>
        ) : (
          <span className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-semibold bg-slate-50 border border-slate-200 text-slate-600">
            Free
          </span>
        )}

        <span className="font-semibold text-[var(--text-default)] max-w-[130px] truncate sm:inline">
          {emailDisplay}
        </span>
        <ChevronDown className={cx('h-3.5 w-3.5 text-[var(--text-subtle)] transition-transform', open && 'rotate-180')} />
      </button>

      {open ? (
        <div className="absolute right-0 top-10 z-50 w-56 overflow-hidden rounded-[var(--radius-panel)] border border-[var(--border-light)] bg-white p-1.5 shadow-[var(--shadow-float)] animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="border-b border-[var(--border-light)] px-2.5 py-2 mb-1">
            <div className="flex items-center gap-2">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[var(--brand)] to-blue-500 text-xs font-bold text-white uppercase">
                {initial}
              </span>
              <div className="min-w-0">
                <div className="truncate text-xs font-bold text-[var(--text-strong)]">{displayName}</div>
                <div className="mt-0.5 truncate text-[10px] text-[var(--text-muted)]">{emailDisplay}</div>
              </div>
            </div>
          </div>

          <div className="space-y-0.5">
            <Link
              to="/dashboard"
              onClick={() => setOpen(false)}
              className="flex w-full items-center gap-2 rounded-[var(--radius-control)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-default)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-strong)] transition-colors"
            >
              <LayoutDashboard className="h-3.5 w-3.5 text-[var(--brand)]" />
              Dashboard
            </Link>

            <Link
              to="/profile"
              onClick={() => setOpen(false)}
              className="flex w-full items-center gap-2 rounded-[var(--radius-control)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-default)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-strong)] transition-colors"
            >
              <Settings className="h-3.5 w-3.5 text-[var(--text-muted)]" />
              Profile Settings
            </Link>

            <button
              type="button"
              onClick={() => {
                setOpen(false);
                void logoutUser();
              }}
              className="flex w-full items-center gap-2 rounded-[var(--radius-control)] px-2.5 py-1.5 text-xs font-medium text-red-600 hover:bg-red-50 transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
