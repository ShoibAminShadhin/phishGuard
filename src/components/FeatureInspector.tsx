import React, { useState } from 'react';
import { FeatureImpact } from '../types/phishing';
import { Search, AlertOctagon, ShieldCheck, HelpCircle, ArrowRight, Filter } from 'lucide-react';

interface FeatureInspectorProps {
  impacts: FeatureImpact[];
}

export const FeatureInspector: React.FC<FeatureInspectorProps> = ({ impacts }) => {
  const [filterType, setFilterType] = useState<'ALL' | 'RISK' | 'SAFE'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filtered = impacts.filter((item) => {
    if (filterType === 'RISK' && item.direction !== 'RISK') return false;
    if (filterType === 'SAFE' && item.direction !== 'SAFE') return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        item.label.toLowerCase().includes(q) ||
        item.explanation.toLowerCase().includes(q) ||
        String(item.value).toLowerCase().includes(q)
      );
    }
    return true;
  });

  const riskCount = impacts.filter((i) => i.direction === 'RISK').length;
  const safeCount = impacts.filter((i) => i.direction === 'SAFE').length;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
      {/* Title & Filter Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <span>Machine Learning Feature Explainability (XAI)</span>
            <span className="text-[11px] font-mono text-slate-400">
              {impacts.length} extracted features
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            SHAP-style directional weights illustrating each feature's contribution to the classification
          </p>
        </div>

        {/* Filter controls */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setFilterType('ALL')}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                filterType === 'ALL'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({impacts.length})
            </button>
            <button
              onClick={() => setFilterType('RISK')}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                filterType === 'RISK'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800/50'
                  : 'text-slate-400 hover:text-rose-300'
              }`}
            >
              Risk Drivers ({riskCount})
            </button>
            <button
              onClick={() => setFilterType('SAFE')}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                filterType === 'SAFE'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50'
                  : 'text-slate-400 hover:text-emerald-300'
              }`}
            >
              Protective ({safeCount})
            </button>
          </div>
        </div>
      </div>

      {/* Search Input */}
      <div className="my-3">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search feature parameters (e.g. entropy, typosquatting, TLD, length)..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800/90 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30"
          />
        </div>
      </div>

      {/* Feature Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800/80 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
              <th className="py-2.5 px-3">Feature Indicator</th>
              <th className="py-2.5 px-3">Extracted Value</th>
              <th className="py-2.5 px-3">Directional SHAP Impact</th>
              <th className="py-2.5 px-3">Cybersecurity Rationale</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {filtered.map((feat) => {
              const isRisk = feat.direction === 'RISK';
              const isSafe = feat.direction === 'SAFE';

              return (
                <tr
                  key={feat.featureName}
                  className="hover:bg-slate-800/30 transition-colors group"
                >
                  <td className="py-2.5 px-3 font-medium text-slate-200 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          isRisk
                            ? 'bg-rose-500 shadow-sm shadow-rose-500/50'
                            : isSafe
                            ? 'bg-emerald-500 shadow-sm shadow-emerald-500/50'
                            : 'bg-slate-600'
                        }`}
                      />
                      <span>{feat.label}</span>
                    </div>
                  </td>

                  <td className="py-2.5 px-3 font-mono text-slate-300 max-w-xs truncate">
                    {String(feat.value)}
                  </td>

                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <div className="w-20 bg-slate-950 rounded-full h-2 overflow-hidden flex items-center">
                        {isRisk ? (
                          <div
                            className="bg-rose-500 h-full rounded-full transition-all"
                            style={{
                              width: `${Math.min(100, Math.abs(feat.impactScore) * 35)}%`,
                            }}
                          />
                        ) : isSafe ? (
                          <div
                            className="bg-emerald-500 h-full rounded-full transition-all ml-auto"
                            style={{
                              width: `${Math.min(100, Math.abs(feat.impactScore) * 50)}%`,
                            }}
                          />
                        ) : (
                          <div className="bg-slate-700 h-full w-2 mx-auto rounded-full" />
                        )}
                      </div>
                      <span
                        className={`font-mono text-[11px] font-semibold ${
                          isRisk
                            ? 'text-rose-400'
                            : isSafe
                            ? 'text-emerald-400'
                            : 'text-slate-500'
                        }`}
                      >
                        {feat.impactScore > 0 ? `+${feat.impactScore}` : feat.impactScore}
                      </span>
                    </div>
                  </td>

                  <td className="py-2.5 px-3 text-slate-400 max-w-md leading-relaxed">
                    {feat.explanation}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="py-8 text-center text-xs text-slate-500">
            No features matched the query "{searchQuery}".
          </div>
        )}
      </div>
    </div>
  );
};
