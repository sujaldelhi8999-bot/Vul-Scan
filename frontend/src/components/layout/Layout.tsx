import { type ReactNode } from 'react';
import { useAuth } from '../../context/AuthContext';
import Navbar from './Navbar';

export default function Layout({ children }: { children: ReactNode }) {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100">
      <header className="sticky top-0 z-30 border-b border-gray-200 dark:border-gray-800 bg-white/90 dark:bg-gray-900/90 backdrop-blur-sm">
        <div className="flex items-center justify-between px-6 py-3 max-w-7xl mx-auto">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-lg">
              <img src="/favicon.png" alt="VulScan logo" className="h-full w-full object-contain" />
            </div>
            <span className="font-bold text-base text-gray-900 dark:text-white">VulScan</span>
            <span className="hidden sm:inline text-xs text-gray-400">Security Operations Platform</span>
          </div>
          <div className="flex items-center gap-4">
            {user ? (
              <>
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {user.username}
                </span>
                <button
                  onClick={() => { localStorage.clear(); window.location.reload(); }}
                  className="text-sm text-gray-400 hover:text-red-500 transition-colors"
                >
                  Logout
                </button>
              </>
            ) : null}
          </div>
        </div>
      </header>

      <Navbar />

      <main className="max-w-7xl mx-auto px-6 py-6">
        {children}
      </main>

      <footer className="border-t border-gray-200 dark:border-gray-800 mt-12 py-6 text-center text-xs text-gray-400">
        VulScan — Security Operations Platform
      </footer>
    </div>
  );
}
