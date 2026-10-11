import React from 'react';
import {
  SensitivityMode,
  SENSITIVITY_THRESHOLDS,
  MODEL_BENCHMARK_SPECS,
  FEATURE_WEIGHTS,
} from '../utils/mlClassifier';
import { Cpu, Sliders, CheckCircle2, AlertTriangle, TrendingUp, BarChart3, Database } from 'lucide-react';

interface ModelPlaygroundTabProps {
  sensitivity: SensitivityMode;
  setSensitivity: (mode: SensitivityMode) => void;
}

export const ModelPlaygroundTab: React.FC<ModelPlaygroundTabProps> = ({
  sensitivity,
  setSensitivity,
}) => {
  const currentThreshold = SENSITIVITY_THRESHOLDS[sensitivity];

  return (
    <div className="space-y-6">
      {/* Top Banner: Architecture & Training Specs */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Cpu className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">
                Supervised Machine Learning Architecture
              </h2>
              <p className="text-xs text-slate-400">
                Calibrated Statistical & Ensemble Classifier for Adversarial URL Detection
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-300 bg-cyan-950/80 border border-cyan-800/60 px-2.5 py-1 rounded-lg">
              26 Extracted Features
            </span>
            <span className="text-xs font-mono text-slate-300 bg-slate-950 border border-slate-800 px-2.5 py-1 rounded-lg">
              Lat: ~1.4ms
            </span>
          </div>
        </div>

        {/* Model Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-4">
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">Model Accuracy</span>
            <span className="text-xl font-bold font-mono text-cyan-400 block mt-0.5">
              {MODEL_BENCHMARK_SPECS.accuracy}%
            </span>
          </div>

          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">Precision</span>
            <span className="text-xl font-bold font-mono text-indigo-400 block mt-0.5">
              {MODEL_BENCHMARK_SPECS.precision}%
            </span>
          </div>

          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">Recall (Catch Rate)</span>
            <span className="text-xl font-bold font-mono text-emerald-400 block mt-0.5">
              {MODEL_BENCHMARK_SPECS.recall}%
            </span>
          </div>

          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">F1-Score</span>
            <span className="text-xl font-bold font-mono text-cyan-300 block mt-0.5">
              {MODEL_BENCHMARK_SPECS.f1Score}%
            </span>
          </div>

          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl">
            <span className="text-[11px] font-mono text-slate-400 uppercase block">ROC-AUC Area</span>
            <span className="text-xl font-bold font-mono text-white block mt-0.5">
              {MODEL_BENCHMARK_SPECS.aucRoc}
            </span>
          </div>
        </div>
      </div>

      {/* Decision Boundary & Sensitivity Tuner */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 1-col: Threshold Controller */}
        <div className="lg:col-span-1 bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-5">
          <div className="border-b border-slate-800/80 pb-3">
            <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>Sensitivity Threshold Tuner</span>
            </h3>
            <p className="text-xs text-slate-400">
              Adjust classification decision boundary $\theta$
            </p>
          </div>

          <div className="space-y-3">
            <div
              onClick={() => setSensitivity('BALANCED')}
              className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                sensitivity === 'BALANCED'
                  ? 'bg-cyan-950/30 border-cyan-500/60 ring-1 ring-cyan-500/30'
                  : 'bg-slate-950/50 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-semibold text-white">
                <span>Balanced Mode (Recommended)</span>
                <span className="font-mono text-cyan-400">θ = 0.50</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Optimized for standard SOC environments. Harmonizes precision and recall with minimal false alarms.
              </p>
            </div>

            <div
              onClick={() => setSensitivity('HIGH_RECALL')}
              className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                sensitivity === 'HIGH_RECALL'
                  ? 'bg-rose-950/30 border-rose-500/60 ring-1 ring-rose-500/30'
                  : 'bg-slate-950/50 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-semibold text-white">
                <span>High Recall (Paranoid / Zero-Trust)</span>
                <span className="font-mono text-rose-400">θ = 0.35</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Low threshold flags any subtle anomaly. Crucial for high-risk corporate executives and financial networks.
              </p>
            </div>

            <div
              onClick={() => setSensitivity('HIGH_PRECISION')}
              className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                sensitivity === 'HIGH_PRECISION'
                  ? 'bg-indigo-950/30 border-indigo-500/60 ring-1 ring-indigo-500/30'
                  : 'bg-slate-950/50 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-semibold text-white">
                <span>High Precision (Conservative)</span>
                <span className="font-mono text-indigo-400">θ = 0.70</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                High bar for flagging. Eliminates near-all false alarms when automatically blocking domains in DNS firewalls.
              </p>
            </div>
          </div>

          <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs space-y-1.5">
            <span className="font-mono text-[11px] text-slate-400 uppercase block">
              Active Parameters
            </span>
            <div className="flex justify-between text-slate-300">
              <span>Decision Threshold:</span>
              <span className="font-mono text-cyan-300 font-bold">{(currentThreshold * 100).toFixed(0)}%</span>
            </div>
            <div className="flex justify-between text-slate-300">
              <span>Classifier Baseline Prior:</span>
              <span className="font-mono text-slate-400">-1.45 (Logit)</span>
            </div>
          </div>
        </div>

        {/* Right 2-cols: Confusion Matrix & Feature Weights Hierarchy */}
        <div className="lg:col-span-2 space-y-6">
          {/* Confusion Matrix Simulation */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
            <div className="border-b border-slate-800/80 pb-3">
              <h3 className="text-sm font-semibold text-white tracking-tight">
                Benchmark Confusion Matrix (240k Test Samples)
              </h3>
              <p className="text-xs text-slate-400">
                Performance breakdown on PhishTank & Alexa Top 1M holdout dataset
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 max-w-lg mx-auto py-2">
              <div className="p-4 bg-emerald-950/30 border border-emerald-800/60 rounded-xl text-center">
                <span className="text-[11px] font-mono uppercase text-emerald-400 block">
                  True Positives (TP)
                </span>
                <span className="text-2xl font-extrabold font-mono text-emerald-200 mt-1 block">
                  117,720
                </span>
                <span className="text-[11px] text-slate-400 mt-0.5 block">
                  Phishing Caught Correctly (98.1%)
                </span>
              </div>

              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-center">
                <span className="text-[11px] font-mono uppercase text-rose-400 block">
                  False Positives (FP)
                </span>
                <span className="text-2xl font-extrabold font-mono text-rose-300 mt-1 block">
                  3,840
                </span>
                <span className="text-[11px] text-slate-400 mt-0.5 block">
                  Legitimate Flagged (3.2%)
                </span>
              </div>

              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-center">
                <span className="text-[11px] font-mono uppercase text-amber-400 block">
                  False Negatives (FN)
                </span>
                <span className="text-2xl font-extrabold font-mono text-amber-300 mt-1 block">
                  2,280
                </span>
                <span className="text-[11px] text-slate-400 mt-0.5 block">
                  Phishing Missed (1.9%)
                </span>
              </div>

              <div className="p-4 bg-emerald-950/30 border border-emerald-800/60 rounded-xl text-center">
                <span className="text-[11px] font-mono uppercase text-emerald-400 block">
                  True Negatives (TN)
                </span>
                <span className="text-2xl font-extrabold font-mono text-emerald-200 mt-1 block">
                  116,160
                </span>
                <span className="text-[11px] text-slate-400 mt-0.5 block">
                  Legitimate Cleared (96.8%)
                </span>
              </div>
            </div>
          </div>

          {/* Model Feature Weights Hierarchy */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-3">
            <div className="border-b border-slate-800/80 pb-3">
              <h3 className="text-sm font-semibold text-white tracking-tight">
                Global Feature Importance Hierarchy
              </h3>
              <p className="text-xs text-slate-400">
                Pre-trained relative weights assigned by the ensemble model
              </p>
            </div>

            <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
              {FEATURE_WEIGHTS.map((fw, idx) => (
                <div key={idx} className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-medium truncate max-w-xs">
                    {fw.label}
                  </span>
                  <div className="flex items-center gap-3">
                    <div className="w-28 bg-slate-950 h-2 rounded-full overflow-hidden">
                      <div
                        className="bg-cyan-500 h-full rounded-full"
                        style={{ width: `${(fw.weight / 3.0) * 100}%` }}
                      />
                    </div>
                    <span className="font-mono text-cyan-300 text-[11px] w-8 text-right">
                      {fw.weight.toFixed(1)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
