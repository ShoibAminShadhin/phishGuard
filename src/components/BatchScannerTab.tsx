import React, { useState } from 'react';
import { FullScanResult } from '../types/phishing';
import { SensitivityMode, classifyUrlFeatures } from '../utils/mlClassifier';
import { extractUrlFeatures } from '../utils/mlFeatureExtractor';
import { SAMPLE_URLS } from '../utils/sampleData';
import {
  Layers,
  Upload,
  Download,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Filter,
  CheckCircle2,
  Trash2,
} from 'lucide-react';

import { useAuth } from '../context/AuthContext';

interface BatchScannerTabProps {
  sensitivity: SensitivityMode;
  onInspectUrl: (scan: FullScanResult) => void;
}

export const BatchScannerTab: React.FC<BatchScannerTabProps> = ({
  sensitivity,
  onInspectUrl,
}) => {
  const { isUnlimited, guestScansRemaining, recordScanUsage, openAuthModal } = useAuth();
  const [inputText, setInputText] = useState('');
  const [results, setResults] = useState<FullScanResult[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'PHISHING' | 'SUSPICIOUS' | 'SAFE'>('ALL');

  const handleProcessBatch = async (textToProcess?: string) => {
    const raw = (textToProcess !== undefined ? textToProcess : inputText).trim();
    if (!raw) return;

    if (!isUnlimited && guestScansRemaining <= 0) {
      openAuthModal('register');
      return;
    }

    setIsProcessing(true);

    // Split by newlines, spaces, or commas
    const lines = raw
      .split(/[\r\n,]+/)
      .map((l) => l.trim())
      .filter((l) => l.length > 3);

    // Limit by remaining guest quota or 50 if unlimited
    const allowedCount = isUnlimited ? 50 : Math.min(50, guestScansRemaining);
    const trimmed = lines.slice(0, allowedCount);

    const batchResults: FullScanResult[] = [];
    for (const url of trimmed) {
      const features = extractUrlFeatures(url);
      const mlScore = classifyUrlFeatures(features, sensitivity);
      await recordScanUsage({
        url: features.url,
        defangedUrl: features.defangedUrl,
        verdict: mlScore.decision,
        probability: mlScore.percentage,
        riskLevel: mlScore.riskLevel,
      });
      batchResults.push({
        id: 'batch-' + Math.random().toString(36).substring(2, 9),
        timestamp: Date.now(),
        url: features.url,
        defangedUrl: features.defangedUrl,
        features,
        mlScore,
        threatIntel: null,
      });
    }

    setResults(batchResults);
    setIsProcessing(false);
  };

  const handleLoadDemoFeed = () => {
    const sampleBatch = SAMPLE_URLS.map((s) => s.url).join('\n');
    setInputText(sampleBatch);
    handleProcessBatch(sampleBatch);
  };

  const exportCsv = () => {
    if (results.length === 0) return;
    const headers = [
      'Original URL',
      'Defanged URL',
      'Verdict',
      'Probability (%)',
      'Risk Level',
      'Hostname',
      'TLD Risk',
      'Impersonated Brand',
      'Primary Risk Factor',
    ];

    const rows = results.map((r) => [
      `"${r.url.replace(/"/g, '""')}"`,
      `"${r.defangedUrl.replace(/"/g, '""')}"`,
      r.mlScore.decision,
      r.mlScore.percentage,
      r.mlScore.riskLevel,
      `"${r.features.hostname}"`,
      r.features.tldRiskLevel,
      `"${r.features.targetedBrand || 'None'}"`,
      `"${r.mlScore.keyRiskDrivers[0]?.label || 'None'}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `phishguard-batch-triage-${Date.now()}.csv`;
    link.click();
  };

  const filteredResults = results.filter((r) => {
    if (riskFilter === 'PHISHING') return r.mlScore.riskLevel === 'MALICIOUS_PHISHING';
    if (riskFilter === 'SUSPICIOUS') return r.mlScore.riskLevel === 'SUSPICIOUS';
    if (riskFilter === 'SAFE') return r.mlScore.riskLevel === 'SAFE' || r.mlScore.riskLevel === 'LOW_RISK';
    return true;
  });

  const total = results.length;
  const phishingCount = results.filter((r) => r.mlScore.riskLevel === 'MALICIOUS_PHISHING').length;
  const suspiciousCount = results.filter((r) => r.mlScore.riskLevel === 'SUSPICIOUS').length;
  const safeCount = results.filter((r) => r.mlScore.riskLevel === 'SAFE' || r.mlScore.riskLevel === 'LOW_RISK').length;

  return (
    <div className="space-y-6">
      {/* Batch Input Box */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Bulk URL Triage & Threat Stream Analyzer</span>
            </h2>
            <p className="text-xs text-slate-400">
              Paste email headers, proxy logs, or multi-line URLs (up to 50 URLs concurrently)
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleLoadDemoFeed}
              className="px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-cyan-300 font-medium transition-colors"
            >
              Load Incident Log Sample
            </button>
            {results.length > 0 && (
              <button
                onClick={() => {
                  setResults([]);
                  setInputText('');
                }}
                className="px-2.5 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
          </div>
        </div>

        <div className="space-y-3">
          <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            rows={5}
            placeholder={`https://chase-online-verify-auth.top/login\nhttps://github.com/torvalds/linux\nhttp://paypa1-account-resolution.com/signin\nhttps://en.wikipedia.org/wiki/Main_Page`}
            className="w-full p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
          />

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <span className="text-xs text-slate-500">
              Active sensitivity threshold: <strong className="text-slate-300">{sensitivity}</strong>
            </span>

            <button
              onClick={() => handleProcessBatch()}
              disabled={isProcessing || !inputText.trim()}
              className="px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 disabled:opacity-50 text-white text-xs font-semibold rounded-xl shadow-md transition-all flex items-center justify-center gap-2"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Execute Batch ML Evaluation</span>
            </button>
          </div>
        </div>
      </div>

      {/* Batch Results & Summary */}
      {results.length > 0 && (
        <div className="space-y-4">
          {/* Summary Metric Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
              <span className="text-[11px] font-mono uppercase text-slate-400 block">
                Total Evaluated
              </span>
              <span className="text-xl font-extrabold text-white font-mono mt-0.5 block">
                {total}
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-900/40">
              <span className="text-[11px] font-mono uppercase text-rose-400 block">
                Malicious Phishing
              </span>
              <span className="text-xl font-extrabold text-rose-300 font-mono mt-0.5 block">
                {phishingCount} ({Math.round((phishingCount / total) * 100)}%)
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-900/40">
              <span className="text-[11px] font-mono uppercase text-amber-400 block">
                Suspicious Domains
              </span>
              <span className="text-xl font-extrabold text-amber-300 font-mono mt-0.5 block">
                {suspiciousCount} ({Math.round((suspiciousCount / total) * 100)}%)
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-900/40">
              <span className="text-[11px] font-mono uppercase text-emerald-400 block">
                Cleared Benign
              </span>
              <span className="text-xl font-extrabold text-emerald-300 font-mono mt-0.5 block">
                {safeCount} ({Math.round((safeCount / total) * 100)}%)
              </span>
            </div>
          </div>

          {/* Table Container */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl">
            {/* Table Controls */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-slate-400 font-medium">Filter Verdict:</span>
                <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
                  <button
                    onClick={() => setRiskFilter('ALL')}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      riskFilter === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-400'
                    }`}
                  >
                    All ({total})
                  </button>
                  <button
                    onClick={() => setRiskFilter('PHISHING')}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      riskFilter === 'PHISHING' ? 'bg-rose-950 text-rose-300 border border-rose-800/50' : 'text-slate-400'
                    }`}
                  >
                    Phishing ({phishingCount})
                  </button>
                  <button
                    onClick={() => setRiskFilter('SUSPICIOUS')}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      riskFilter === 'SUSPICIOUS' ? 'bg-amber-950 text-amber-300 border border-amber-800/50' : 'text-slate-400'
                    }`}
                  >
                    Suspicious ({suspiciousCount})
                  </button>
                  <button
                    onClick={() => setRiskFilter('SAFE')}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      riskFilter === 'SAFE' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50' : 'text-slate-400'
                    }`}
                  >
                    Safe ({safeCount})
                  </button>
                </div>
              </div>

              <button
                onClick={exportCsv}
                className="px-3 py-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 font-medium flex items-center gap-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-slate-400" />
                <span>Export CSV Report</span>
              </button>
            </div>

            {/* Results Table */}
            <div className="overflow-x-auto mt-2">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800/80 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                    <th className="py-2.5 px-3">Verdict</th>
                    <th className="py-2.5 px-3">Probability</th>
                    <th className="py-2.5 px-3">Defanged URL</th>
                    <th className="py-2.5 px-3">Brand Target</th>
                    <th className="py-2.5 px-3">Primary Risk Factor</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {filteredResults.map((item) => {
                    const isPhish = item.mlScore.riskLevel === 'MALICIOUS_PHISHING';
                    const isSusp = item.mlScore.riskLevel === 'SUSPICIOUS';

                    return (
                      <tr
                        key={item.id}
                        className="hover:bg-slate-800/30 transition-colors"
                      >
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <span
                            className={`font-semibold font-mono text-[11px] px-2 py-0.5 rounded ${
                              isPhish
                                ? 'bg-rose-950 text-rose-300 border border-rose-800/60'
                                : isSusp
                                ? 'bg-amber-950 text-amber-300 border border-amber-800/60'
                                : 'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                            }`}
                          >
                            {item.mlScore.decision}
                          </span>
                        </td>

                        <td className="py-2.5 px-3 font-mono font-bold whitespace-nowrap">
                          <span
                            className={
                              isPhish
                                ? 'text-rose-400'
                                : isSusp
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }
                          >
                            {item.mlScore.percentage}%
                          </span>
                        </td>

                        <td className="py-2.5 px-3 font-mono text-slate-300 max-w-sm truncate">
                          {item.defangedUrl}
                        </td>

                        <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                          {item.features.targetedBrand ? (
                            <span className="text-cyan-300 font-medium">
                              {item.features.targetedBrand}
                            </span>
                          ) : (
                            <span className="text-slate-500">None</span>
                          )}
                        </td>

                        <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate">
                          {item.mlScore.keyRiskDrivers[0]?.label || 'Baseline structural criteria'}
                        </td>

                        <td className="py-2.5 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={() => onInspectUrl(item)}
                            className="px-2 py-1 bg-slate-950 hover:bg-cyan-950 border border-slate-800 hover:border-cyan-800 rounded text-cyan-300 text-[11px] transition-colors"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
