import { NavLink } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { displayRole, hasElevatedAccess } from '../../utils/access';

const baseClass = 'px-4 py-2 text-sm font-medium rounded-lg transition-colors';
const activeClass = 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300';
const inactiveClass = 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800';

export default function Navbar() {
  const { user } = useAuth();
  const elevated = hasElevatedAccess(user);

  return (
    <nav className="border-b border-gray-200 dark:border-gray-800 bg-white/50 dark:bg-gray-950/50 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center gap-1 px-6 py-2">
        <NavLink to="/dashboard" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          Dashboard
        </NavLink>
        <NavLink to="/scan" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          Defend Scan
        </NavLink>
        <NavLink to="/findings" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          Findings
        </NavLink>
        <NavLink to="/assets" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          Assets
        </NavLink>
        <NavLink to="/history" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          Reports
        </NavLink>
        <NavLink to="/agents" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          Agents
        </NavLink>
        <NavLink to="/authorized-testing" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          Authorized Testing
        </NavLink>

        {elevated && (
          <NavLink to="/intelligence" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
            Attack Intelligence
          </NavLink>
        )}

        {elevated && (
          <NavLink to="/quality" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
            Scan Quality
          </NavLink>
        )}

        <NavLink to="/system-health" className={({ isActive }) => `${baseClass} ${isActive ? activeClass : inactiveClass}`}>
          System
        </NavLink>

        <div className="ml-auto flex items-center gap-3 text-xs text-gray-400">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-green-500" />
            Online
          </span>
          <span>{displayRole(user)}</span>
        </div>
      </div>
    </nav>
  );
}
