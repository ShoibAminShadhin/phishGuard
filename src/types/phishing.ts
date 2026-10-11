export interface URLFeatures {
  url: string;
  rawUrl: string;
  defangedUrl: string;
  protocol: string;
  hostname: string;
  path: string;
  search: string;
  tld: string;
  
  // Numerical & Structural Features
  urlLength: number;
  domainLength: number;
  pathLength: number;
  numDots: number;
  numHyphens: number;
  numUnderscores: number;
  numAtSymbols: number;
  numDoubleSlashPath: number;
  numPercentSymbols: number;
  numSubdomains: number;
  subdomainDepth: number;
  hasPort: boolean;
  portNumber?: number;
  
  // Lexical & Statistical Features
  domainEntropy: number;
  pathEntropy: number;
  digitRatioDomain: number;
  digitRatioPath: number;
  vowelConsonantRatio: number;
  longestTokenLength: number;
  
  // Heuristic & Threat Signatures
  isIpAddress: boolean;
  hasSuspiciousTld: boolean;
  tldRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  sensitiveKeywordCount: number;
  matchedKeywords: string[];
  
  // Brand & Homoglyph Threat Flags
  isIdnHomoglyph: boolean;
  homoglyphDetails?: string;
  brandImpersonationDetected: boolean;
  targetedBrand?: string;
  typosquattingDistance?: number;
  
  // Evasion & Payload Indicators
  hasRedirectParams: boolean;
  matchedRedirectParams: string[];
  hasExecutableExt: boolean;
  matchedExtension?: string;
  isHttps: boolean;
}

export interface FeatureImpact {
  featureName: string;
  label: string;
  value: string | number | boolean;
  impactScore: number; // positive = pushes toward phishing, negative = pushes toward safe
  direction: 'RISK' | 'SAFE' | 'NEUTRAL';
  importance: number; // 0 to 1
  explanation: string;
}

export type RiskLevel = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'MALICIOUS_PHISHING';

export interface MLScoreResult {
  probability: number; // 0.0 to 1.0
  percentage: number; // 0 to 100
  riskLevel: RiskLevel;
  confidence: number; // 0 to 100
  classificationThreshold: number;
  decision: 'FLAGGED_PHISHING' | 'CLEARED_BENIGN';
  keyRiskDrivers: FeatureImpact[];
  keyProtectiveDrivers: FeatureImpact[];
  allFeatureImpacts: FeatureImpact[];
  computationTimeMs: number;
}

export interface ThreatIntelligenceResult {
  verdict: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  confidenceScore: number;
  targetBrand: string | null;
  attackVector: string;
  mitreTechniques: string[];
  summary: string;
  deceptiveSignals: string[];
  recommendedActions: string[];
  timestamp: string;
}

export interface FullScanResult {
  id: string;
  timestamp: number;
  url: string;
  defangedUrl: string;
  features: URLFeatures;
  mlScore: MLScoreResult;
  threatIntel?: ThreatIntelligenceResult | null;
  threatIntelLoading?: boolean;
  threatIntelError?: string | null;
}

export interface DatasetSample {
  id: string;
  title: string;
  url: string;
  actualLabel: 'PHISHING' | 'LEGITIMATE';
  category: 'Banking Spoof' | 'Cloud Credential Harvester' | 'Crypto Drainer' | 'Typosquatting' | 'IDN Homograph' | 'Legitimate Official' | 'Subdomain Abuse' | 'Shortened / Redirector';
  description: string;
  targetedBrand?: string;
}
