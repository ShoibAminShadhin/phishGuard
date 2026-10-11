import React, { useState } from 'react';
import { SAMPLE_URLS } from '../utils/sampleData';
import { DatasetSample } from '../types/phishing';
import { Database, Search, ArrowRight, ShieldAlert, ShieldCheck } from 'lucide-react';

interface DatasetLibraryTabProps {
  onSelectSample: (sample: DatasetSample) => void;
}

export const DatasetLibraryTab: React.FC<DatasetLibraryTabProps> = ({ onSelectSample }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const categories = [
    'ALL',
    'Banking Spoof',
    'Cloud Credential Harvester',
    'Crypto Drainer',
    'Typosquatting',
    'IDN Homograph',
    'Legitimate Official',
  ];

  const filteredSamples = SAMPLE_URLS.filter((sample) => {
    if (selectedCategory !== 'ALL' && sample.category !== selectedCategory) {
      return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        sample.title.toLowerCase().includes(q) ||
        sample.description.toLowerCase().includes(q) ||
        sample.url.toLowerCase().includes(q) ||
        (sample.targetedBrand && sample.targetedBrand.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span>Phishing & Baseline Evaluation Samples</span>
            </h2>
            <p className="text-xs text-slate-400">
              Curated corpus of real-world attacks and legitimate references for testing detection accuracy
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">
              {filteredSamples.length} of {SAMPLE_URLS.length} cases
            </span>
          </div>
        </div>

        {/* Filter Tabs & Search */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mt-4">
          <div className="flex flex-wrap items-center gap-1.5">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                  selectedCategory === cat
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search test corpus..."
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>

      {/* Samples Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredSamples.map((sample) => {
          const isPhish = sample.actualLabel === 'PHISHING';

          return (
            <div
              key={sample.id}
              className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl hover:border-slate-700 transition-all flex flex-col justify-between space-y-4 group"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isPhish ? 'bg-rose-500 shadow-sm shadow-rose-500/50' : 'bg-emerald-500 shadow-sm shadow-emerald-500/50'
                      }`}
                    />
                    <h3 className="text-sm font-semibold text-white tracking-tight group-hover:text-cyan-300 transition-colors">
                      {sample.title}
                    </h3>
                  </div>

                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                      isPhish
                        ? 'bg-rose-950 text-rose-300 border border-rose-900/50'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-900/50'
                    }`}
                  >
                    {sample.actualLabel}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  {sample.description}
                </p>

                {sample.targetedBrand && (
                  <div className="text-[11px] text-slate-400">
                    Target Brand: <strong className="text-cyan-300 font-mono">{sample.targetedBrand}</strong>
                  </div>
                )}

                <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800/80 font-mono text-[11px] text-slate-300 truncate select-all">
                  {sample.url}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between">
                <span className="text-[11px] text-slate-500 font-medium">
                  {sample.category}
                </span>

                <button
                  onClick={() => onSelectSample(sample)}
                  className="px-3 py-1.5 bg-slate-950 hover:bg-cyan-950 border border-slate-800 hover:border-cyan-800/80 rounded-lg text-xs text-cyan-300 font-medium flex items-center gap-1.5 transition-all active:scale-95"
                >
                  <span>Evaluate in Live Scanner</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
