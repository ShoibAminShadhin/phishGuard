import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  History,
  Database,
  Layers,
  Sliders,
  User,
  LogOut,
  LogIn,
  Lock,
  Sparkles,
} from 'lucide-react';
import { SensitivityMode } from '../utils/mlClassifier';
import { useAuth } from '../context/AuthContext';

interface HeaderProps {
  activeTab: 'single' | 'batch' | 'playground' | 'library' | 'admin';
  setActiveTab: (tab: 'single' | 'batch' | 'playground' | 'library' | 'admin') => void;
  sensitivity: SensitivityMode;
  setSensitivity: (mode: SensitivityMode) => void;
  historyCount: number;
  onOpenHistory: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  sensitivity,
  setSensitivity,
  historyCount,
  onOpenHistory,
}) => {
  const {
    currentUser,
    userProfile,
    isAdmin,
    guestScansRemaining,
    guestScansUsed,
    isUnlimited,
    openAuthModal,
    logout,
  } = useAuth();

  return (
    <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-2">
          {/* Logo & Platform Name */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyan-500 to-indigo-600 p-0.5 shadow-lg shadow-cyan-950/50 flex items-center justify-center cursor-pointer" onClick={() => setActiveTab('single')}>
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base sm:text-lg tracking-tight text-white cursor-pointer" onClick={() => setActiveTab('single')}>
                  PhishGuard
                </span>
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/50 text-cyan-300 font-mono hidden sm:inline-block">
                  ML ENGINE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden md:block">
                Predictive URL Threat & Homoglyph Classifier
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800 overflow-x-auto">
            <button
              onClick={() => setActiveTab('single')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                activeTab === 'single'
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Live Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('batch')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                activeTab === 'batch'
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Batch Analyzer</span>
            </button>

            <button
              onClick={() => setActiveTab('playground')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                activeTab === 'playground'
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Model & XAI</span>
              <span className="sm:hidden">Model</span>
            </button>

            <button
              onClick={() => setActiveTab('library')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap ${
                activeTab === 'library'
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Dataset Samples</span>
              <span className="sm:hidden">Samples</span>
            </button>

            {/* Admin Panel Tab Button */}
            <button
              onClick={() => setActiveTab('admin')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap ${
                activeTab === 'admin'
                  ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60 shadow-sm'
                  : 'text-slate-400 hover:text-rose-300 hover:bg-slate-800/50'
              }`}
            >
              <Lock className="w-3.5 h-3.5 text-rose-400" />
              <span>Admin Console</span>
              {isAdmin && (
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
              )}
            </button>
          </nav>

          {/* User Auth / Scan Limit Status Section */}
          <div className="flex items-center gap-2 shrink-0">
            {/* Scan Allowance Display */}
            {isUnlimited ? (
              <div className="hidden lg:flex items-center gap-1 text-[11px] font-mono text-emerald-300 bg-emerald-950/40 border border-emerald-800/50 px-2.5 py-1 rounded-lg">
                <Sparkles className="w-3 h-3 text-emerald-400" />
                <span>Unlimited Scans</span>
              </div>
            ) : (
              <div
                onClick={() => openAuthModal('register')}
                className="hidden lg:flex items-center gap-1.5 text-[11px] font-mono text-amber-300 bg-amber-950/40 border border-amber-800/50 px-2.5 py-1 rounded-lg cursor-pointer hover:bg-amber-950/60 transition-colors"
                title="Guest scan limit. Register to unlock unlimited scans."
              >
                <span>Guest: <strong>{guestScansRemaining}/10</strong> left</span>
                <span className="text-[10px] text-amber-400/80 font-sans underline ml-1">Unlock</span>
              </div>
            )}

            {/* History Button */}
            <button
              onClick={onOpenHistory}
              className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors"
              title="View Scan History"
            >
              <History className="w-3.5 h-3.5 text-slate-400" />
              {historyCount > 0 && (
                <span className="w-4 h-4 text-[10px] font-mono rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center justify-center">
                  {historyCount}
                </span>
              )}
            </button>

            {/* User Profile / Login Button */}
            {currentUser ? (
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 px-2.5 py-1 rounded-lg text-xs">
                  <div className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center font-bold text-[10px]">
                    {userProfile?.displayName ? userProfile.displayName.charAt(0).toUpperCase() : 'U'}
                  </div>
                  <span className="text-slate-200 font-medium hidden md:inline truncate max-w-[100px]">
                    {userProfile?.displayName || currentUser.email?.split('@')[0]}
                  </span>
                  {isAdmin && (
                    <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800 uppercase font-bold">
                      Admin
                    </span>
                  )}
                </div>

                <button
                  onClick={logout}
                  className="p-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-400 hover:text-rose-300 transition-colors"
                  title="Sign Out"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => openAuthModal('login')}
                  className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors"
                >
                  <LogIn className="w-3.5 h-3.5 text-slate-400" />
                  <span>Sign In</span>
                </button>

                <button
                  onClick={() => openAuthModal('register')}
                  className="hidden sm:flex items-center gap-1 px-3 py-1.5 text-xs font-semibold text-white bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 rounded-lg shadow-sm transition-all"
                >
                  <span>Register Free</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
