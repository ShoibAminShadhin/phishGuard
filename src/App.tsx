import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Header } from './components/Header';
import { ScannerTab } from './components/ScannerTab';
import { BatchScannerTab } from './components/BatchScannerTab';
import { ModelPlaygroundTab } from './components/ModelPlaygroundTab';
import { DatasetLibraryTab } from './components/DatasetLibraryTab';
import { AdminPanelTab } from './components/AdminPanelTab';
import { HistoryDrawer } from './components/HistoryDrawer';
import { AuthModal } from './components/AuthModal';
import { ScanLimitModal } from './components/ScanLimitModal';
import { FullScanResult, DatasetSample } from './types/phishing';
import { SensitivityMode, classifyUrlFeatures } from './utils/mlClassifier';
import { extractUrlFeatures } from './utils/mlFeatureExtractor';

function AppContent() {
  const [activeTab, setActiveTab] = useState<'single' | 'batch' | 'playground' | 'library' | 'admin'>('single');
  const [sensitivity, setSensitivity] = useState<SensitivityMode>('BALANCED');
  const [currentScan, setCurrentScan] = useState<FullScanResult | null>(null);
  const [history, setHistory] = useState<FullScanResult[]>([]);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);

  // Load history from localStorage on initial render
  useEffect(() => {
    try {
      const stored = localStorage.getItem('phishguard_scan_history');
      if (stored) {
        setHistory(JSON.parse(stored));
      }
    } catch {
      // Ignore localStorage read errors
    }
  }, []);

  const handleSaveToHistory = (scan: FullScanResult) => {
    setHistory((prev) => {
      const filtered = prev.filter((item) => item.url !== scan.url);
      const updated = [scan, ...filtered].slice(0, 30);
      try {
        localStorage.setItem('phishguard_scan_history', JSON.stringify(updated));
      } catch {
        // Ignore quota errors
      }
      return updated;
    });
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('phishguard_scan_history');
    } catch {}
  };

  const handleSelectSample = (sample: DatasetSample) => {
    const features = extractUrlFeatures(sample.url);
    const mlScore = classifyUrlFeatures(features, sensitivity);
    const scan: FullScanResult = {
      id: 'scan-' + Date.now(),
      timestamp: Date.now(),
      url: features.url,
      defangedUrl: features.defangedUrl,
      features,
      mlScore,
      threatIntel: null,
    };
    setCurrentScan(scan);
    handleSaveToHistory(scan);
    setActiveTab('single');
  };

  const handleInspectBatchUrl = (scan: FullScanResult) => {
    setCurrentScan(scan);
    handleSaveToHistory(scan);
    setActiveTab('single');
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Cybersecurity Navigation */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        sensitivity={sensitivity}
        setSensitivity={setSensitivity}
        historyCount={history.length}
        onOpenHistory={() => setIsHistoryOpen(true)}
      />

      {/* Main Applet Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {activeTab === 'single' && (
          <ScannerTab
            currentScan={currentScan}
            setCurrentScan={setCurrentScan}
            sensitivity={sensitivity}
            onSaveToHistory={handleSaveToHistory}
          />
        )}

        {activeTab === 'batch' && (
          <BatchScannerTab
            sensitivity={sensitivity}
            onInspectUrl={handleInspectBatchUrl}
          />
        )}

        {activeTab === 'playground' && (
          <ModelPlaygroundTab
            sensitivity={sensitivity}
            setSensitivity={setSensitivity}
          />
        )}

        {activeTab === 'library' && (
          <DatasetLibraryTab onSelectSample={handleSelectSample} />
        )}

        {activeTab === 'admin' && (
          <AdminPanelTab />
        )}
      </main>

      {/* Modals & Slide-over Drawer */}
      <HistoryDrawer
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        history={history}
        onSelectScan={(scan) => setCurrentScan(scan)}
        onClearHistory={handleClearHistory}
      />

      <AuthModal />
      <ScanLimitModal />

      {/* Quiet Security Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span className="font-mono text-slate-400">PhishGuard ML v2.5</span>
            <span aria-hidden="true">·</span>
            <span>26-Feature Statistical Classifier & Gemini Neural Threat Model</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] text-slate-500">
            <span>Free Tier: 10 Scans · Registered: Unlimited</span>
            <span aria-hidden="true">·</span>
            <span>Zero-Trust Protocol</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
