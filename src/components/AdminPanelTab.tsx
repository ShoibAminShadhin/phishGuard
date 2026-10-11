import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  UserProfile,
  adminFetchAllUsers,
  adminFetchRecentScans,
  adminUpdateUserStatus,
  adminUpdateUserRole,
  isAuthorizedAdminEmail,
  ADMIN_EMAILS,
} from '../services/firebase';
import {
  ShieldAlert,
  ShieldCheck,
  Users,
  Activity,
  Lock,
  Search,
  Filter,
  RefreshCw,
  UserCheck,
  UserX,
  Download,
  AlertTriangle,
  ArrowRight,
  Database,
  Key,
} from 'lucide-react';

export const AdminPanelTab: React.FC = () => {
  const { currentUser, userProfile, isAdmin, login } = useAuth();

  // Admin Login State when not authenticated as admin
  const [adminEmailInput, setAdminEmailInput] = useState('shoibaminshadhin@gmail.com');
  const [adminPasswordInput, setAdminPasswordInput] = useState('AdminPass123!');
  const [authError, setAuthError] = useState<string | null>(null);
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  // Admin Data State
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [loadingData, setLoadingData] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<'ALL' | 'admin' | 'user'>('ALL');
  const [activeSubTab, setActiveSubTab] = useState<'users' | 'scans'>('users');

  const isCurrentAdmin =
    isAdmin || (currentUser && isAuthorizedAdminEmail(currentUser.email));

  const loadAdminData = async () => {
    setLoadingData(true);
    try {
      const [userList, scanList] = await Promise.all([
        adminFetchAllUsers(),
        adminFetchRecentScans(100),
      ]);
      setUsers(userList);
      setScans(scanList);
    } catch (err: any) {
      console.error('Error fetching admin data:', err);
    } finally {
      setLoadingData(false);
    }
  };

  useEffect(() => {
    if (isCurrentAdmin) {
      loadAdminData();
    }
  }, [isCurrentAdmin]);

  const handleAdminLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    // Strict Admin Email validation
    if (!isAuthorizedAdminEmail(adminEmailInput)) {
      setAuthError(
        `Access Denied: "${adminEmailInput}" is not an authorized administrator email. Only designated admin emails can access this console.`
      );
      return;
    }

    setIsAuthenticating(true);
    try {
      await login(adminEmailInput, adminPasswordInput);
      await loadAdminData();
    } catch (err: any) {
      console.error('Admin login failed:', err);
      // If user doesn't exist yet, we can create or advise
      setAuthError(
        err.message || 'Authentication failed. Please verify admin password.'
      );
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handleToggleStatus = async (user: UserProfile) => {
    const nextStatus = user.status === 'active' ? 'suspended' : 'active';
    try {
      await adminUpdateUserStatus(user.uid, nextStatus);
      setUsers((prev) =>
        prev.map((u) => (u.uid === user.uid ? { ...u, status: nextStatus } : u))
      );
    } catch (err: any) {
      alert('Failed to update status: ' + err.message);
    }
  };

  const handleToggleRole = async (user: UserProfile) => {
    const nextRole = user.role === 'admin' ? 'user' : 'admin';
    try {
      await adminUpdateUserRole(user.uid, nextRole);
      setUsers((prev) =>
        prev.map((u) => (u.uid === user.uid ? { ...u, role: nextRole } : u))
      );
    } catch (err: any) {
      alert('Failed to update role: ' + err.message);
    }
  };

  const exportUsersCsv = () => {
    const headers = ['UID', 'Email', 'DisplayName', 'Role', 'Status', 'TotalScans', 'Created', 'LastLogin'];
    const rows = users.map((u) => [
      u.uid,
      `"${u.email}"`,
      `"${u.displayName}"`,
      u.role,
      u.status,
      u.totalScans,
      u.createdAt,
      u.lastLoginAt,
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `phishguard-users-directory-${Date.now()}.csv`;
    link.click();
  };

  const filteredUsers = users.filter((u) => {
    if (roleFilter !== 'ALL' && u.role !== roleFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        u.email.toLowerCase().includes(q) ||
        (u.displayName && u.displayName.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const totalUsersCount = users.length;
  const activeUsersCount = users.filter((u) => u.status === 'active').length;
  const totalScansLogged = scans.length;
  const maliciousScansCount = scans.filter((s) => s.riskLevel === 'MALICIOUS_PHISHING').length;

  // 1. IF NOT LOGGED IN AS ADMIN: RENDER THE RESTRICTED ADMIN LOGIN GATE
  if (!isCurrentAdmin) {
    return (
      <div className="max-w-md mx-auto py-8">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 relative overflow-hidden space-y-6">
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-rose-500 via-amber-500 to-indigo-500" />

          <div className="text-center space-y-2">
            <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 mx-auto flex items-center justify-center">
              <Lock className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white tracking-tight">
              Restricted Administrative Terminal
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              This console is locked. As mandated by security policy, you can <strong>only login using an authorized admin email</strong>.
            </p>
          </div>

          <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-400 space-y-1">
            <span className="text-[11px] font-mono uppercase text-slate-500 block">
              Authorized Administrator Identity:
            </span>
            <div className="font-mono text-cyan-300 font-semibold break-all">
              shoibaminshadhin@gmail.com
            </div>
            <div className="text-[10px] text-slate-500">
              Non-admin email addresses will be rejected automatically.
            </div>
          </div>

          <form onSubmit={handleAdminLoginSubmit} className="space-y-4">
            {authError && (
              <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <span>{authError}</span>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Admin Email
              </label>
              <input
                type="email"
                required
                value={adminEmailInput}
                onChange={(e) => setAdminEmailInput(e.target.value)}
                placeholder="shoibaminshadhin@gmail.com"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Admin Password
              </label>
              <input
                type="password"
                required
                value={adminPasswordInput}
                onChange={(e) => setAdminPasswordInput(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              disabled={isAuthenticating}
              className="w-full py-2.5 bg-gradient-to-r from-rose-600 to-indigo-600 hover:from-rose-500 hover:to-indigo-500 text-white text-xs font-semibold rounded-xl shadow-md transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {isAuthenticating ? (
                <span>Validating Admin Credentials...</span>
              ) : (
                <>
                  <Key className="w-3.5 h-3.5" />
                  <span>Verify & Unlock Admin Panel</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // 2. AUTHENTICATED ADMIN CONSOLE
  return (
    <div className="space-y-6">
      {/* Top Banner & Global Stats */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-tight">
                  PhishGuard Central Command
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/60 font-bold">
                  ADMIN TERMINAL
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Logged in as <strong className="text-slate-200 font-mono">{currentUser?.email}</strong>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={loadAdminData}
              disabled={loadingData}
              className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 font-medium flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingData ? 'animate-spin' : ''}`} />
              <span>Refresh Telemetry</span>
            </button>

            <button
              onClick={exportUsersCsv}
              className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-cyan-300 font-medium flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Global KPI Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">
              Registered Users
            </span>
            <span className="text-xl font-bold font-mono text-white block mt-0.5">
              {totalUsersCount}
            </span>
          </div>

          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">
              Active Accounts
            </span>
            <span className="text-xl font-bold font-mono text-emerald-400 block mt-0.5">
              {activeUsersCount}
            </span>
          </div>

          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">
              Audit Scans Recorded
            </span>
            <span className="text-xl font-bold font-mono text-cyan-400 block mt-0.5">
              {totalScansLogged}
            </span>
          </div>

          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">
              Phishing Caught
            </span>
            <span className="text-xl font-bold font-mono text-rose-400 block mt-0.5">
              {maliciousScansCount}
            </span>
          </div>
        </div>
      </div>

      {/* Main Admin Content */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
        {/* Sub-tab Navigation (User Directory vs Audit Log) */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveSubTab('users')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeSubTab === 'users'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              User Directory ({users.length})
            </button>
            <button
              onClick={() => setActiveSubTab('scans')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeSubTab === 'scans'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Global Audit Log ({scans.length})
            </button>
          </div>

          {activeSubTab === 'users' && (
            <div className="flex items-center gap-2">
              <div className="relative w-48 sm:w-60">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by email or name..."
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value as any)}
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2 py-1.5 focus:outline-none"
              >
                <option value="ALL">All Roles</option>
                <option value="admin">Admins</option>
                <option value="user">Users</option>
              </select>
            </div>
          )}
        </div>

        {/* Tab 1: User Directory */}
        {activeSubTab === 'users' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800/80 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-2.5 px-3">User Email / Identity</th>
                  <th className="py-2.5 px-3">Role</th>
                  <th className="py-2.5 px-3">Scan Allowance</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Registered</th>
                  <th className="py-2.5 px-3">Last Active</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {filteredUsers.map((u) => {
                  const isUserAdmin = u.role === 'admin';
                  const isActive = u.status === 'active';

                  return (
                    <tr key={u.uid} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3">
                        <div className="font-medium text-slate-200">{u.displayName || 'Security Analyst'}</div>
                        <div className="font-mono text-slate-400 text-[11px]">{u.email}</div>
                      </td>

                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`font-mono text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                            isUserAdmin
                              ? 'bg-rose-950 text-rose-300 border border-rose-800/60'
                              : 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                          }`}
                        >
                          {u.role}
                        </span>
                      </td>

                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <div className="font-mono text-emerald-400 font-semibold">Unlimited</div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {u.totalScans} executed
                        </div>
                      </td>

                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                            isActive
                              ? 'bg-emerald-950/80 text-emerald-300'
                              : 'bg-rose-950/80 text-rose-300'
                          }`}
                        >
                          {u.status}
                        </span>
                      </td>

                      <td className="py-2.5 px-3 whitespace-nowrap text-slate-400 text-[11px] font-mono">
                        {new Date(u.createdAt).toLocaleDateString()}
                      </td>

                      <td className="py-2.5 px-3 whitespace-nowrap text-slate-400 text-[11px] font-mono">
                        {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleTimeString() : 'N/A'}
                      </td>

                      <td className="py-2.5 px-3 text-right whitespace-nowrap space-x-1.5">
                        <button
                          onClick={() => handleToggleStatus(u)}
                          className={`px-2 py-1 rounded text-[11px] transition-colors border ${
                            isActive
                              ? 'bg-slate-950 hover:bg-rose-950 border-slate-800 hover:border-rose-800 text-rose-300'
                              : 'bg-slate-950 hover:bg-emerald-950 border-slate-800 hover:border-emerald-800 text-emerald-300'
                          }`}
                        >
                          {isActive ? 'Suspend' : 'Reactivate'}
                        </button>

                        <button
                          onClick={() => handleToggleRole(u)}
                          className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-[11px] text-slate-300 transition-colors"
                        >
                          {isUserAdmin ? 'Set User' : 'Set Admin'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {filteredUsers.length === 0 && (
              <div className="py-12 text-center text-xs text-slate-500">
                No user records matched your criteria.
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Global Audit Log */}
        {activeSubTab === 'scans' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800/80 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Risk %</th>
                  <th className="py-2.5 px-3">Defanged URL</th>
                  <th className="py-2.5 px-3">User Attribution</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {scans.map((s, idx) => (
                  <tr key={s.id || idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-3 whitespace-nowrap font-mono text-[11px] font-bold">
                      <span
                        className={
                          s.riskLevel === 'MALICIOUS_PHISHING'
                            ? 'text-rose-400'
                            : s.riskLevel === 'SUSPICIOUS'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }
                      >
                        {s.verdict || s.riskLevel}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono font-semibold">
                      {s.probability ? `${s.probability}%` : 'N/A'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300 max-w-sm truncate">
                      {s.defangedUrl || s.url}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-cyan-300 text-[11px]">
                      {s.userEmail || s.userId || 'Guest'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                      {s.timestamp ? new Date(s.timestamp).toLocaleString() : 'Recent'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {scans.length === 0 && (
              <div className="py-12 text-center text-xs text-slate-500">
                No scan logs stored yet.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
