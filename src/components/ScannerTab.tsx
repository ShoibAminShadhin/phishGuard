import React, { useState, useEffect } from 'react';
import {
  URLFeatures,
  MLScoreResult,
  ThreatIntelligenceResult,
  FullScanResult,
} from '../types/phishing';
import { SensitivityMode, classifyUrlFeatures } from '../utils/mlClassifier';
import { extractUrlFeatures, defangUrl } from '../utils/mlFeatureExtractor';
import { SAMPLE_URLS } from '../utils/sampleData';
import { ThreatIntelligencePanel } from './ThreatIntelligencePanel';
import { FeatureInspector } from './FeatureInspector';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  Check,
  Sparkles,
  Download,
  Share2,
  Lock,
  Unlock,
  Activity,
  Globe,
  Terminal,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';

import { useAuth } from '../context/AuthContext';

interface ScannerTabProps {
  currentScan: FullScanResult | null;
  setCurrentScan: (scan: FullScanResult) => void;
  sensitivity: SensitivityMode;
  onSaveToHistory: (scan: FullScanResult) => void;
}

export const ScannerTab: React.FC<ScannerTabProps> = ({
  currentScan,
  setCurrentScan,
  sensitivity,
  onSaveToHistory,
}) => {
  const {
    isUnlimited,
    guestScansRemaining,
    guestScansUsed,
    recordScanUsage,
    openAuthModal,
    currentUser,
  } = useAuth();

  const [inputUrl, setInputUrl] = useState('');
  const [copiedDefanged, setCopiedDefanged] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);
  const [threatLoading, setThreatLoading] = useState(false);
  const [threatError, setThreatError] = useState<string | null>(null);

  // Initialize with a high-profile sample if no current scan exists
  useEffect(() => {
    if (!currentScan) {
      handleScan(SAMPLE_URLS[0].url, true);
    }
  }, []);

  // When sensitivity changes, re-evaluate current scan if exists
  useEffect(() => {
    if (currentScan) {
      const updatedScore = classifyUrlFeatures(currentScan.features, sensitivity);
      setCurrentScan({
        ...currentScan,
        mlScore: updatedScore,
      });
    }
  }, [sensitivity]);

  const handleScan = async (targetUrl?: string, isInitialMount = false) => {
    const urlToProcess = (targetUrl !== undefined ? targetUrl : inputUrl).trim();
    if (!urlToProcess) return;

    const features = extractUrlFeatures(urlToProcess);
    const mlScore = classifyUrlFeatures(features, sensitivity);

    if (!isInitialMount) {
      const allowed = await recordScanUsage({
        url: features.url,
        defangedUrl: features.defangedUrl,
        verdict: mlScore.decision,
        probability: mlScore.percentage,
        riskLevel: mlScore.riskLevel,
      });
      if (!allowed) return;
    }

    const newScan: FullScanResult = {
      id: 'scan-' + Date.now(),
      timestamp: Date.now(),
      url: features.url,
      defangedUrl: features.defangedUrl,
      features,
      mlScore,
      threatIntel: null,
      threatIntelLoading: false,
    };

    setCurrentScan(newScan);
    onSaveToHistory(newScan);
    setInputUrl(urlToProcess);
  };

  const handleRunAiThreatScan = async () => {
    if (!currentScan) return;
    setThreatLoading(true);
    setThreatError(null);

    try {
      const response = await fetch('/api/analyze-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: currentScan.url,
          mlFeatures: {
            brandSpoofed: currentScan.features.brandImpersonationDetected,
            targetBrand: currentScan.features.targetedBrand,
            isIdnHomoglyph: currentScan.features.isIdnHomoglyph,
            isIpAddress: currentScan.features.isIpAddress,
            domainEntropy: currentScan.features.domainEntropy,
            tld: currentScan.features.tld,
            tldRisk: currentScan.features.tldRiskLevel,
            keywords: currentScan.features.matchedKeywords,
            subdomains: currentScan.features.numSubdomains,
            isHttps: currentScan.features.isHttps,
          },
          mlScore: currentScan.mlScore,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.details || data.error || 'Threat intelligence request failed');
      }

      if (data.available && data.analysis) {
        const threatIntel: ThreatIntelligenceResult = {
          ...data.analysis,
          timestamp: new Date().toISOString(),
        };

        const updatedScan: FullScanResult = {
          ...currentScan,
          threatIntel,
        };
        setCurrentScan(updatedScan);
        onSaveToHistory(updatedScan);
      } else if (data.message) {
        setThreatError(data.message);
      }
    } catch (err: any) {
      console.error('AI Threat Analysis Failed:', err);
      setThreatError(err.message || 'Unable to complete AI threat scan.');
    } finally {
      setThreatLoading(false);
    }
  };

  const copyDefangedUrl = () => {
    if (!currentScan) return;
    navigator.clipboard.writeText(currentScan.defangedUrl);
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const exportReportJson = () => {
    if (!currentScan) return;
    const blob = new Blob([JSON.stringify(currentScan, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copySocSummary = () => {
    if (!currentScan) return;
    const summary = `[PHISHGUARD ML INCIDENT REPORT]
Target URL (Defanged): ${currentScan.defangedUrl}
Verdict: ${currentScan.mlScore.decision}
Phishing Probability: ${currentScan.mlScore.percentage}% (${currentScan.mlScore.riskLevel})
Inference Latency: ${currentScan.mlScore.computationTimeMs}ms
Key Risk Factors: ${currentScan.mlScore.keyRiskDrivers.map(d => d.label).join(', ') || 'None'}
Host: ${currentScan.features.hostname}
TLD Risk: ${currentScan.features.tldRiskLevel}
Timestamp: ${new Date(currentScan.timestamp).toUTCString()}
${currentScan.threatIntel ? `AI Threat Vector: ${currentScan.threatIntel.attackVector}\nTarget Brand: ${currentScan.threatIntel.targetBrand || 'N/A'}` : ''}`;

    navigator.clipboard.writeText(summary);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const ml = currentScan?.mlScore;
  const features = currentScan?.features;

  return (
    <div className="space-y-6">
      {/* Scanner Input Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 sm:p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-indigo-500 to-rose-500" />

        <div className="flex flex-col space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                <span>Real-Time Phishing & Spoofing Detector</span>
              </h2>
              <p className="text-xs text-slate-400">
                Extracts 26 lexical, structural, and brand parameters for instantaneous ML inference
              </p>
            </div>

            {/* Quick Sample Selector */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0 text-xs text-slate-400">
              <span className="text-slate-500 text-[11px] uppercase tracking-wider font-mono">
                Try Sample:
              </span>
              <button
                onClick={() => handleScan(SAMPLE_URLS[0].url)}
                className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-300 text-[11px] whitespace-nowrap transition-colors"
              >
                M365 Phish
              </button>
              <button
                onClick={() => handleScan(SAMPLE_URLS[1].url)}
                className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-300 text-[11px] whitespace-nowrap transition-colors"
              >
                PayPal Typosquat
              </button>
              <button
                onClick={() => handleScan(SAMPLE_URLS[5].url)}
                className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-300 text-[11px] whitespace-nowrap transition-colors"
              >
                Apple Homoglyph
              </button>
              <button
                onClick={() => handleScan(SAMPLE_URLS[7].url)}
                className="px-2 py-1 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-300 text-[11px] whitespace-nowrap transition-colors"
              >
                Legitimate
              </button>
            </div>
          </div>

          {/* Quota Allowance Notification */}
          {!isUnlimited ? (
            <div className="p-2.5 rounded-xl bg-amber-950/20 border border-amber-900/40 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-amber-300">
                <Sparkles className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                <span>
                  Guest Mode: <strong>{guestScansUsed} of 10 free scans used</strong> ({guestScansRemaining} remaining).
                </span>
              </div>
              <button
                type="button"
                onClick={() => openAuthModal('register')}
                className="px-2.5 py-1 bg-amber-500 hover:bg-amber-400 text-slate-950 rounded-lg font-semibold text-[11px] whitespace-nowrap transition-colors self-start sm:self-auto cursor-pointer"
              >
                Register for Unlimited Scans
              </button>
            </div>
          ) : (
            <div className="p-2.5 rounded-xl bg-emerald-950/20 border border-emerald-900/40 text-xs flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-emerald-300">
                <Sparkles className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>
                  Active Account: <strong>{currentUser?.email}</strong> · <strong>Unlimited Scans Enabled</strong>
                </span>
              </div>
              <span className="font-mono text-[11px] text-emerald-400 font-semibold hidden sm:inline">
                Quota: ∞ Unlimited
              </span>
            </div>
          )}

          {/* Search Form */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScan();
            }}
            className="flex flex-col sm:flex-row gap-2"
          >
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Globe className="w-4 h-4 text-slate-500" />
              </div>
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                placeholder="Enter suspicious URL or IP (e.g. login.microsoftonline.security-account.xyz)..."
                className="w-full pl-10 pr-20 py-3 bg-slate-950 border border-slate-800 rounded-xl text-sm text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all shadow-inner"
              />
              {inputUrl && (
                <button
                  type="button"
                  onClick={() => setInputUrl('')}
                  className="absolute inset-y-0 right-3 flex items-center text-xs text-slate-500 hover:text-slate-300"
                >
                  Clear
                </button>
              )}
            </div>

            <button
              type="submit"
              className="px-6 py-3 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-sm font-semibold rounded-xl shadow-lg shadow-cyan-950/50 active:scale-95 transition-all flex items-center justify-center gap-2 shrink-0 cursor-pointer"
            >
              <Search className="w-4 h-4" />
              <span>Scan Target</span>
            </button>
          </form>

          {/* Defanged representation helper banner */}
          {features && (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-xs">
              <div className="flex items-center gap-2 overflow-hidden">
                <span className="font-mono text-slate-500 text-[11px] uppercase tracking-wider shrink-0">
                  Defanged:
                </span>
                <span className="font-mono text-cyan-300/90 truncate selection:bg-cyan-900">
                  {features.defangedUrl}
                </span>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  type="button"
                  onClick={copyDefangedUrl}
                  className="px-2 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded text-slate-300 text-[11px] font-mono flex items-center gap-1 transition-colors"
                >
                  {copiedDefanged ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3 text-slate-400" />
                      <span>Copy Defanged</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Main Results Grid */}
      {currentScan && ml && features && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column: Probability Gauge & Verdict */}
          <div className="lg:col-span-1 space-y-6">
            {/* Primary ML Verdict Card */}
            <div
              className={`rounded-2xl border p-6 shadow-xl transition-all relative overflow-hidden ${
                ml.riskLevel === 'MALICIOUS_PHISHING'
                  ? 'bg-rose-950/30 border-rose-800/60 shadow-rose-950/20'
                  : ml.riskLevel === 'SUSPICIOUS'
                  ? 'bg-amber-950/30 border-amber-800/60 shadow-amber-950/20'
                  : ml.riskLevel === 'LOW_RISK'
                  ? 'bg-blue-950/30 border-blue-800/60 shadow-blue-950/20'
                  : 'bg-emerald-950/30 border-emerald-800/60 shadow-emerald-950/20'
              }`}
            >
              {/* Verdict Header */}
              <div className="flex items-start justify-between gap-3 mb-6">
                <div className="flex items-center gap-3">
                  <div
                    className={`w-12 h-12 rounded-xl flex items-center justify-center p-2.5 ${
                      ml.riskLevel === 'MALICIOUS_PHISHING'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                        : ml.riskLevel === 'SUSPICIOUS'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        : ml.riskLevel === 'LOW_RISK'
                        ? 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    }`}
                  >
                    {ml.riskLevel === 'MALICIOUS_PHISHING' ? (
                      <ShieldAlert className="w-7 h-7" />
                    ) : ml.riskLevel === 'SUSPICIOUS' ? (
                      <AlertTriangle className="w-7 h-7" />
                    ) : (
                      <ShieldCheck className="w-7 h-7" />
                    )}
                  </div>
                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block">
                      ML Classifier Decision
                    </span>
                    <h3 className="text-lg font-extrabold tracking-tight text-white">
                      {ml.riskLevel === 'MALICIOUS_PHISHING'
                        ? 'MALICIOUS PHISHING'
                        : ml.riskLevel === 'SUSPICIOUS'
                        ? 'SUSPICIOUS URL'
                        : ml.riskLevel === 'LOW_RISK'
                        ? 'LOW RISK URL'
                        : 'CLEARED BENIGN'}
                    </h3>
                  </div>
                </div>
              </div>

              {/* Radial Probability Gauge Meter */}
              <div className="flex flex-col items-center justify-center py-2">
                <div className="relative w-44 h-44 flex items-center justify-center">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                    {/* Background circle track */}
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      className="stroke-slate-900 fill-none stroke-[9]"
                    />
                    {/* Probability arc */}
                    <circle
                      cx="50"
                      cy="50"
                      r="40"
                      className={`fill-none stroke-[9] transition-all duration-1000 ease-out ${
                        ml.riskLevel === 'MALICIOUS_PHISHING'
                          ? 'stroke-rose-500'
                          : ml.riskLevel === 'SUSPICIOUS'
                          ? 'stroke-amber-500'
                          : ml.riskLevel === 'LOW_RISK'
                          ? 'stroke-blue-500'
                          : 'stroke-emerald-500'
                      }`}
                      strokeDasharray="251.2"
                      strokeDashoffset={251.2 - (251.2 * ml.probability)}
                      strokeLinecap="round"
                    />
                  </svg>

                  {/* Centered Percentage Display */}
                  <div className="absolute flex flex-col items-center justify-center text-center">
                    <span className="text-3xl font-extrabold font-mono tracking-tight text-white">
                      {ml.percentage}%
                    </span>
                    <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                      Phishing Prob
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-xs text-slate-400 mt-2 font-mono">
                  <span>Confidence: <strong className="text-white">{ml.confidence}%</strong></span>
                  <span>·</span>
                  <span>Latency: <strong className="text-white">{ml.computationTimeMs}ms</strong></span>
                </div>
              </div>

              {/* Decision Threshold Info */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                <span>Threshold: <strong className="text-slate-300 font-mono">{(ml.classificationThreshold * 100).toFixed(0)}%</strong></span>
                <span>Mode: <strong className="text-cyan-400">{sensitivity}</strong></span>
              </div>
            </div>

            {/* Quick Diagnostic Checklist */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 shadow-xl space-y-3">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                Structural Diagnostics
              </h4>

              <div className="space-y-2 text-xs">
                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-950/60 border border-slate-800/60">
                  <span className="text-slate-400">Protocol Transport:</span>
                  <span className="font-mono flex items-center gap-1.5 text-slate-200">
                    {features.isHttps ? (
                      <>
                        <Lock className="w-3.5 h-3.5 text-emerald-400" />
                        <span>HTTPS</span>
                      </>
                    ) : (
                      <>
                        <Unlock className="w-3.5 h-3.5 text-rose-400" />
                        <span className="text-rose-400 font-semibold">Plaintext HTTP</span>
                      </>
                    )}
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-950/60 border border-slate-800/60">
                  <span className="text-slate-400">Domain Entropy:</span>
                  <span className={`font-mono ${features.domainEntropy > 3.8 ? 'text-rose-400 font-bold' : 'text-slate-300'}`}>
                    {features.domainEntropy} bits {features.domainEntropy > 3.8 ? '(High Randomness)' : ''}
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-950/60 border border-slate-800/60">
                  <span className="text-slate-400">TLD Risk Category:</span>
                  <span className={`font-mono px-1.5 py-0.5 rounded ${
                    features.tldRiskLevel === 'HIGH'
                      ? 'bg-rose-950 text-rose-300'
                      : features.tldRiskLevel === 'MEDIUM'
                      ? 'bg-amber-950 text-amber-300'
                      : 'text-slate-300'
                  }`}>
                    .{features.tld} ({features.tldRiskLevel})
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-950/60 border border-slate-800/60">
                  <span className="text-slate-400">Host Type:</span>
                  <span className="font-mono text-slate-200">
                    {features.isIpAddress ? (
                      <span className="text-rose-400 font-semibold">Direct IP Hostname</span>
                    ) : features.isIdnHomoglyph ? (
                      <span className="text-rose-400 font-semibold">Punycode / Homoglyph</span>
                    ) : (
                      'Standard Domain'
                    )}
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded-lg bg-slate-950/60 border border-slate-800/60">
                  <span className="text-slate-400">Total URL Length:</span>
                  <span className="font-mono text-slate-300">
                    {features.urlLength} characters
                  </span>
                </div>
              </div>

              {/* Action Buttons: Export & SOC Summary */}
              <div className="pt-2 flex items-center gap-2">
                <button
                  onClick={copySocSummary}
                  className="flex-1 py-2 px-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  {copiedReport ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Report Copied</span>
                    </>
                  ) : (
                    <>
                      <Share2 className="w-3.5 h-3.5 text-slate-400" />
                      <span>Copy SOC Brief</span>
                    </>
                  )}
                </button>

                <button
                  onClick={exportReportJson}
                  className="py-2 px-3 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-300 font-medium flex items-center justify-center gap-1.5 transition-colors"
                  title="Download JSON Report"
                >
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                  <span>JSON</span>
                </button>
              </div>
            </div>
          </div>

          {/* Right Columns (2 spans): Drivers & Threat Intel & Feature Breakdown */}
          <div className="lg:col-span-2 space-y-6">
            {/* Key Drivers Highlights (Zero-Pill Discipline: Clean Typography) */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
              <div className="border-b border-slate-800/80 pb-3">
                <h3 className="text-sm font-semibold text-white tracking-tight">
                  Primary Classification Influences
                </h3>
                <p className="text-xs text-slate-400">
                  Dominant factors identified by the model driving risk elevation vs safe baseline
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Risk Drivers */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-rose-400 flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-rose-500" />
                    Adverse Indicators (+Risk)
                  </span>
                  {ml.keyRiskDrivers.length > 0 ? (
                    <div className="space-y-2">
                      {ml.keyRiskDrivers.map((driver, i) => (
                        <div
                          key={i}
                          className="p-2.5 rounded-xl bg-rose-950/20 border border-rose-900/40 text-xs"
                        >
                          <div className="flex items-center justify-between text-rose-200 font-medium">
                            <span>{driver.label}</span>
                            <span className="font-mono text-rose-400 font-bold">
                              +{driver.impactScore}
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px] mt-1 leading-snug">
                            {driver.explanation}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 p-2.5 rounded-xl bg-slate-950/40 border border-slate-800/40">
                      No high-risk indicators triggered.
                    </p>
                  )}
                </div>

                {/* Protective Factors */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-500" />
                    Protective Factors (-Risk)
                  </span>
                  {ml.keyProtectiveDrivers.length > 0 ? (
                    <div className="space-y-2">
                      {ml.keyProtectiveDrivers.map((driver, i) => (
                        <div
                          key={i}
                          className="p-2.5 rounded-xl bg-emerald-950/20 border border-emerald-900/40 text-xs"
                        >
                          <div className="flex items-center justify-between text-emerald-200 font-medium">
                            <span>{driver.label}</span>
                            <span className="font-mono text-emerald-400 font-bold">
                              {driver.impactScore}
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px] mt-1 leading-snug">
                            {driver.explanation}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 p-2.5 rounded-xl bg-slate-950/40 border border-slate-800/40">
                      Baseline structural metrics.
                    </p>
                  )}
                </div>
              </div>
            </div>

            {/* AI Threat Intelligence Panel */}
            <ThreatIntelligencePanel
              threatIntel={currentScan.threatIntel}
              loading={threatLoading}
              error={threatError}
              onRunAnalysis={handleRunAiThreatScan}
              mlScore={ml}
              features={features}
            />

            {/* Feature Inspector */}
            <FeatureInspector impacts={ml.allFeatureImpacts} />
          </div>
        </div>
      )}
    </div>
  );
};
