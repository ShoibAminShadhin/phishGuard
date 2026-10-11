import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { X, Lock, Mail, User, ShieldCheck, AlertCircle, ArrowRight, Sparkles } from 'lucide-react';

interface AuthModalProps {
  forcedAdminOnly?: boolean;
}

export const AuthModal: React.FC<AuthModalProps> = ({ forcedAdminOnly = false }) => {
  const { isAuthModalOpen, closeAuthModal, authModalMode, login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>(forcedAdminOnly ? 'login' : authModalMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!isAuthModalOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        if (!password || password.length < 6) {
          throw new Error('Password must be at least 6 characters');
        }
        await register(email, password, displayName);
      }
      closeAuthModal();
    } catch (err: any) {
      console.error('Authentication error:', err);
      let msg = err.message || 'Authentication failed. Please verify credentials.';
      if (msg.includes('auth/invalid-credential') || msg.includes('auth/wrong-password')) {
        msg = 'Invalid email or password.';
      } else if (msg.includes('auth/email-already-in-use')) {
        msg = 'This email is already registered. Please sign in instead.';
      } else if (msg.includes('auth/weak-password')) {
        msg = 'Password should be at least 6 characters.';
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleDemoFill = (demoEmail: string, demoPass: string, name?: string) => {
    setEmail(demoEmail);
    setPassword(demoPass);
    if (name) setDisplayName(name);
    setError(null);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden relative">
        {/* Glow accent */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-indigo-500 to-rose-500" />

        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white tracking-tight">
                {forcedAdminOnly
                  ? 'Administrator Terminal Access'
                  : mode === 'login'
                  ? 'Account Sign In'
                  : 'Register Security Account'}
              </h3>
              <p className="text-[11px] text-slate-400">
                {forcedAdminOnly
                  ? 'Authorized administrator credentials required'
                  : mode === 'login'
                  ? 'Sign in for unlimited scans and persistent history'
                  : 'Unlock unlimited scans and full telemetry access'}
              </p>
            </div>
          </div>

          <button
            onClick={closeAuthModal}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Benefits notice */}
        {!forcedAdminOnly && (
          <div className="px-5 py-2.5 bg-cyan-950/20 border-b border-cyan-900/30 text-[11px] text-cyan-300 flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>
              <strong>Registered accounts</strong> receive <strong>unlimited scans</strong> (guests are restricted to 10 scans).
            </span>
          </div>
        )}

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {mode === 'register' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Analyst Name or Call-Sign
              </label>
              <div className="relative">
                <User className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. Alex Rivera"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Email Address
            </label>
            <div className="relative">
              <Mail className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={forcedAdminOnly ? 'shoibaminshadhin@gmail.com' : 'analyst@organization.com'}
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Password
            </label>
            <div className="relative">
              <Lock className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-semibold rounded-xl shadow-md transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            {loading ? (
              <span>Authenticating...</span>
            ) : (
              <>
                <span>{mode === 'login' ? 'Authenticate & Enter' : 'Create Account & Unlock Unlimited'}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>

          {/* Quick Demo Credentials */}
          <div className="pt-3 border-t border-slate-800/80">
            <div className="text-[11px] text-slate-400 mb-2 flex items-center justify-between">
              <span>Quick Test Credentials:</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <button
                type="button"
                onClick={() => handleDemoFill('shoibaminshadhin@gmail.com', 'AdminPass123!', 'Shoib (Admin)')}
                className="p-2 bg-slate-950 hover:bg-slate-800/80 border border-slate-800 rounded-lg text-left transition-colors"
              >
                <span className="font-semibold text-rose-300 block text-[11px]">Admin Account</span>
                <span className="text-[10px] text-slate-400 font-mono block truncate">shoibaminshadhin@gmail.com</span>
              </button>

              <button
                type="button"
                onClick={() => handleDemoFill('analyst@phishguard.ai', 'AnalystPass123!', 'SOC Analyst')}
                className="p-2 bg-slate-950 hover:bg-slate-800/80 border border-slate-800 rounded-lg text-left transition-colors"
              >
                <span className="font-semibold text-cyan-300 block text-[11px]">Standard User</span>
                <span className="text-[10px] text-slate-400 font-mono block truncate">analyst@phishguard.ai</span>
              </button>
            </div>
          </div>

          {/* Toggle between Login and Register */}
          {!forcedAdminOnly && (
            <div className="pt-2 text-center text-xs text-slate-400">
              {mode === 'login' ? (
                <>
                  Don't have an account?{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setMode('register');
                      setError(null);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors"
                  >
                    Register free for unlimited scans
                  </button>
                </>
              ) : (
                <>
                  Already registered?{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setMode('login');
                      setError(null);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors"
                  >
                    Sign in to your account
                  </button>
                </>
              )}
            </div>
          )}
        </form>
      </div>
    </div>
  );
};
