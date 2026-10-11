import React from 'react';
import { FullScanResult } from '../types/phishing';
import { X, History, Trash2, ArrowRight, Download, ShieldAlert, ShieldCheck } from 'lucide-react';

interface HistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  history: FullScanResult[];
  onSelectScan: (scan: FullScanResult) => void;
  onClearHistory: () => void;
}

export const HistoryDrawer: React.FC<HistoryDrawerProps> = ({
  isOpen,
  onClose,
  history,
  onSelectScan,
  onClearHistory,
}) => {
  if (!isOpen) return null;

  const exportAllHistory = () => {
    const blob = new Blob([JSON.stringify(history, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-scan-history-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end animate-in fade-in duration-200">
      <div className="w-full max-w-md bg-slate-950 border-l border-slate-800 h-full flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Scan Session History</h3>
            <span className="text-xs font-mono text-slate-400">({history.length})</span>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-900 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* History List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {history.length === 0 ? (
            <div className="py-16 text-center text-xs text-slate-500">
              No recent scans recorded in this session.
            </div>
          ) : (
            history.map((scan) => {
              const isPhish = scan.mlScore.riskLevel === 'MALICIOUS_PHISHING';
              const isSusp = scan.mlScore.riskLevel === 'SUSPICIOUS';

              return (
                <div
                  key={scan.id}
                  onClick={() => {
                    onSelectScan(scan);
                    onClose();
                  }}
                  className="p-3 bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl cursor-pointer transition-all space-y-1.5 group"
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        isPhish
                          ? 'bg-rose-950 text-rose-300 border border-rose-900/50'
                          : isSusp
                          ? 'bg-amber-950 text-amber-300 border border-amber-900/50'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-900/50'
                      }`}
                    >
                      {scan.mlScore.decision} ({scan.mlScore.percentage}%)
                    </span>

                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(scan.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="font-mono text-xs text-slate-300 truncate group-hover:text-cyan-300 transition-colors">
                    {scan.defangedUrl}
                  </div>

                  {scan.features.targetedBrand && (
                    <div className="text-[11px] text-slate-400">
                      Brand: <span className="text-cyan-400">{scan.features.targetedBrand}</span>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer actions */}
        {history.length > 0 && (
          <div className="p-4 border-t border-slate-800 flex items-center justify-between gap-2 bg-slate-950">
            <button
              onClick={exportAllHistory}
              className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 font-medium flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export JSON</span>
            </button>

            <button
              onClick={onClearHistory}
              className="px-3 py-1.5 bg-slate-900 hover:bg-rose-950/60 border border-slate-800 hover:border-rose-900/60 rounded-lg text-xs text-rose-300 font-medium flex items-center gap-1.5 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-400" />
              <span>Clear History</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
