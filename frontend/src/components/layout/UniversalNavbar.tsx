import React from 'react';
import { Link, NavLink } from 'react-router-dom';
import { LayoutDashboard } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import UserMenu from './UserMenu';

export const UniversalNavbar: React.FC = () => {
  const { user } = useAuth();

  return (
    <header className="sticky top-0 z-40 border-b border-[var(--border-light)] bg-white/90 backdrop-blur-md transition-colors shadow-xs">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 sm:px-6 py-2.5">
        {/* Brand Logo - Clicking takes user Home */}
        <Link to="/" className="flex items-center gap-2.5 group">
          <span className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-xl shadow-sm group-hover:scale-105 transition-transform">
            <img src="/favicon.png" alt="VulScan logo" className="h-full w-full object-contain" />
          </span>
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight text-[var(--text-strong)] leading-none">VulScan</span>
            <span className="text-[10px] font-medium text-[var(--text-muted)] mt-0.5">Security Workspace</span>
          </div>
        </Link>

        {/* Navigation Links */}
        <nav className="flex items-center gap-1 sm:gap-2">
          <NavLink
            to="/pricing"
            className={({ isActive }) =>
              `px-3 py-1.5 rounded-full text-xs font-semibold transition-colors ${
                isActive
                  ? 'bg-slate-100 text-[var(--brand)]'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-strong)] hover:bg-[var(--surface-hover)]'
              }`
            }
          >
            Pricing
          </NavLink>

          {user && (
            <NavLink
              to="/dashboard"
              className={({ isActive }) =>
                `px-3.5 py-1.5 rounded-full text-xs font-semibold transition-all flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-[var(--brand)] text-white shadow-sm'
                    : 'bg-blue-50 text-[var(--brand)] hover:bg-[var(--brand)] hover:text-white'
                }`
              }
            >
              <LayoutDashboard className="h-3.5 w-3.5" />
              <span>Dashboard</span>
            </NavLink>
          )}
        </nav>

        {/* Status Pill & User Profile Menu */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-1.5 rounded-full border border-[var(--border-light)] bg-[var(--surface-secondary)] px-2.5 py-1 text-xs text-[var(--text-subtle)]">
            <span className="h-2 w-2 rounded-full bg-[var(--success)]" />
            <span className="text-[11px] font-medium text-[var(--text-muted)]">Online</span>
          </div>

          {user ? (
            <UserMenu />
          ) : (
            <div className="flex items-center gap-2">
              <Link
                to="/login"
                className="rounded-full px-3.5 py-1.5 text-xs font-semibold text-[var(--text-muted)] hover:text-[var(--text-strong)] hover:bg-[var(--surface-hover)] transition-colors"
              >
                Sign In
              </Link>
              <Link
                to="/register"
                className="rounded-full bg-[var(--brand)] px-4 py-1.5 text-xs font-semibold text-white shadow-sm hover:bg-[var(--brand-hover)] transition-colors"
              >
                Get Started
              </Link>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default UniversalNavbar;
