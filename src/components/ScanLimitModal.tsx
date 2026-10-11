import React from 'react';
import { useAuth } from '../context/AuthContext';
import { ShieldAlert, Sparkles, X, ArrowRight, UserPlus, LogIn } from 'lucide-react';

export const ScanLimitModal: React.FC = () => {
  const { isLimitModalOpen, closeLimitModal, openAuthModal, guestScansUsed } = useAuth();

  if (!isLimitModalOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden relative">
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-500 via-rose-500 to-indigo-500" />

        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight">
                Guest Scan Limit Reached
              </h3>
              <p className="text-[11px] text-slate-400">
                10 of 10 free evaluation scans exhausted
              </p>
            </div>
          </div>

          <button
            onClick={closeLimitModal}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 font-medium">Guest Quota Allocation:</span>
              <span className="font-mono text-amber-400 font-bold">{guestScansUsed} / 10 Scans Used</span>
            </div>
            <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden">
              <div className="bg-amber-500 h-full w-full rounded-full" />
            </div>
            <p className="text-xs text-slate-400 leading-relaxed pt-1">
              Without an account, you receive <strong>10 complimentary evaluations</strong>. Create a free account to unlock <strong>Unlimited Scans</strong>, deep AI threat intelligence, and batch processing.
            </p>
          </div>

          <div className="space-y-2 pt-2">
            <button
              onClick={() => {
                closeLimitModal();
                openAuthModal('register');
              }}
              className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-semibold rounded-xl shadow-md transition-all flex items-center justify-center gap-2 cursor-pointer"
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Create Free Account (Unlimited Scans)</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>

            <button
              onClick={() => {
                closeLimitModal();
                openAuthModal('login');
              }}
              className="w-full py-2 px-4 bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-semibold rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer"
            >
              <LogIn className="w-3.5 h-3.5 text-slate-400" />
              <span>Already Have An Account? Sign In</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
