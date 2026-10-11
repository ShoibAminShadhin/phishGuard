import React from 'react';
import { ThreatIntelligenceResult, MLScoreResult, URLFeatures } from '../types/phishing';
import { Sparkles, ShieldCheck, ShieldAlert, AlertTriangle, Crosshair, CheckCircle2, RefreshCw, Terminal, ExternalLink } from 'lucide-react';

interface ThreatIntelligencePanelProps {
  threatIntel?: ThreatIntelligenceResult | null;
  loading: boolean;
  error?: string | null;
  onRunAnalysis: () => void;
  mlScore: MLScoreResult;
  features: URLFeatures;
}

export const ThreatIntelligencePanel: React.FC<ThreatIntelligencePanelProps> = ({
  threatIntel,
  loading,
  error,
  onRunAnalysis,
  features,
}) => {
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl overflow-hidden relative">
      {/* Background subtle cyber glow */}
      <div className="absolute top-0 right-0 -mr-16 -mt-16 w-64 h-64 bg-cyan-600/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Sparkles className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              Gemini Threat Intelligence
            </h3>
            <p className="text-xs text-slate-400">
              Deep contextual intent, brand impersonation & MITRE ATT&CK mapping
            </p>
          </div>
        </div>

        <div>
          <button
            onClick={onRunAnalysis}
            disabled={loading}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
              loading
                ? 'bg-slate-800 text-slate-400 cursor-not-allowed'
                : 'bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white shadow-md shadow-cyan-950/40 active:scale-95'
            }`}
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Synthesizing Threat Vector...</span>
              </>
            ) : threatIntel ? (
              <>
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Re-Run Deep Scan</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5 text-cyan-200" />
                <span>Run Deep AI Analysis</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Content State */}
      {loading ? (
        <div className="py-10 flex flex-col items-center justify-center text-center space-y-3">
          <div className="w-10 h-10 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin flex items-center justify-center" />
          <p className="text-sm font-medium text-slate-300">
            Evaluating Deceptive Infrastructure & Zero-Day Signatures
          </p>
          <p className="text-xs text-slate-500 max-w-md">
            Querying Gemini 3.8 Flash to cross-reference brand typosquatting, MITRE TTPs, and social engineering intent.
          </p>
        </div>
      ) : error ? (
        <div className="py-6 px-4 my-4 bg-rose-950/20 border border-rose-800/40 rounded-xl text-rose-300 text-xs flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold text-rose-200">Analysis Notice</p>
            <p className="mt-0.5 text-rose-300/90">{error}</p>
            <p className="mt-1 text-slate-400">
              The rule-based and ML classifier scores remain fully operational.
            </p>
          </div>
        </div>
      ) : threatIntel ? (
        <div className="mt-4 space-y-5">
          {/* Top Verdict & Attack Vector Row */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Verdict Box */}
            <div className={`p-3.5 rounded-xl border flex items-center gap-3 ${
              threatIntel.verdict === 'MALICIOUS'
                ? 'bg-rose-950/30 border-rose-800/60 text-rose-200'
                : threatIntel.verdict === 'SUSPICIOUS'
                ? 'bg-amber-950/30 border-amber-800/60 text-amber-200'
                : 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
            }`}>
              <div className="p-2 rounded-lg bg-slate-950/60 shrink-0">
                {threatIntel.verdict === 'MALICIOUS' ? (
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                ) : threatIntel.verdict === 'SUSPICIOUS' ? (
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                ) : (
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                )}
              </div>
              <div>
                <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
                  AI Verdict
                </span>
                <span className="text-sm font-bold tracking-tight">
                  {threatIntel.verdict === 'MALICIOUS'
                    ? 'Confirmed Threat'
                    : threatIntel.verdict === 'SUSPICIOUS'
                    ? 'High Suspicion'
                    : 'Benign Domain'}
                </span>
              </div>
            </div>

            {/* Target Brand Box */}
            <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-900 shrink-0">
                <Crosshair className="w-5 h-5 text-cyan-400" />
              </div>
              <div className="overflow-hidden">
                <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
                  Impersonated Target
                </span>
                <span className="text-sm font-medium text-slate-200 truncate block">
                  {threatIntel.targetBrand || features.targetedBrand || 'None (No brand targeted)'}
                </span>
              </div>
            </div>

            {/* Primary Attack Vector */}
            <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-900 shrink-0">
                <Terminal className="w-5 h-5 text-indigo-400" />
              </div>
              <div className="overflow-hidden">
                <span className="text-[11px] uppercase tracking-wider text-slate-400 font-mono block">
                  Attack Vector
                </span>
                <span className="text-sm font-medium text-slate-200 truncate block">
                  {threatIntel.attackVector}
                </span>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
            <span className="text-xs font-semibold text-slate-300 block mb-1">
              Executive Threat Assessment
            </span>
            <p className="text-xs text-slate-300 leading-relaxed">
              {threatIntel.summary}
            </p>
          </div>

          {/* Deceptive Signals & MITRE Techniques */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Deceptive Signals */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2.5">
                <span className="text-xs font-semibold text-slate-300">
                  Deceptive Signals Detected
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  {threatIntel.deceptiveSignals?.length || 0} indicators
                </span>
              </div>
              <ul className="space-y-1.5">
                {threatIntel.deceptiveSignals?.map((sig, i) => (
                  <li key={i} className="text-xs text-slate-300 flex items-start gap-2">
                    <span className="text-rose-400 font-bold shrink-0 mt-0.5">•</span>
                    <span>{sig}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* MITRE ATT&CK Techniques */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2.5">
                <span className="text-xs font-semibold text-slate-300">
                  MITRE ATT&CK Alignment
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  Adversary TTPs
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {threatIntel.mitreTechniques?.map((tech, i) => (
                  <span
                    key={i}
                    className="text-xs font-mono px-2 py-1 bg-slate-900 border border-slate-800 rounded-md text-cyan-300"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Recommended Actions for SOC / End User */}
          <div className="bg-cyan-950/20 border border-cyan-800/30 rounded-xl p-4">
            <span className="text-xs font-semibold text-cyan-200 block mb-2 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
              Recommended Security Actions
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {threatIntel.recommendedActions?.map((act, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-slate-300">
                  <span className="w-4 h-4 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-300 flex items-center justify-center text-[10px] shrink-0 mt-0.5 font-mono">
                    {i + 1}
                  </span>
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="py-6 px-4 my-2 text-center border border-dashed border-slate-800 rounded-xl">
          <p className="text-xs text-slate-400">
            ML feature extraction is active. Click <strong className="text-cyan-400">"Run Deep AI Analysis"</strong> to perform semantic intent inspection and MITRE ATT&CK mapping with Gemini 3.8 Flash.
          </p>
        </div>
      )}
    </div>
  );
};
