import { URLFeatures } from '../types/phishing';

// High-risk TLDs commonly abused in automated phishing kits
const HIGH_RISK_TLDS = new Set([
  'top', 'xyz', 'buzz', 'fit', 'work', 'icu', 'gq', 'tk', 'ml', 'cf',
  'rest', 'country', 'click', 'link', 'stream', 'download', 'racing',
  'accountant', 'date', 'faith', 'party', 'trade', 'bid', 'surf', 'tokyo'
]);

const MEDIUM_RISK_TLDS = new Set([
  'online', 'site', 'website', 'live', 'space', 'club', 'pro', 'vip', 'host', 'store'
]);

// High-value brand targets frequently impersonated in phishing attacks
export const HIGH_VALUE_BRANDS: Array<{ name: string; brand: string; officialDomains: string[] }> = [
  { name: 'paypal', brand: 'PayPal', officialDomains: ['paypal.com', 'paypal.me'] },
  { name: 'microsoft', brand: 'Microsoft / 365', officialDomains: ['microsoft.com', 'office.com', 'live.com', 'microsoftonline.com', 'outlook.com', 'sharepoint.com'] },
  { name: 'google', brand: 'Google / Workspace', officialDomains: ['google.com', 'accounts.google.com', 'drive.google.com', 'gmail.com'] },
  { name: 'apple', brand: 'Apple / iCloud', officialDomains: ['apple.com', 'icloud.com', 'appleid.apple.com'] },
  { name: 'netflix', brand: 'Netflix', officialDomains: ['netflix.com'] },
  { name: 'amazon', brand: 'Amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'] },
  { name: 'chase', brand: 'JPMorgan Chase', officialDomains: ['chase.com', 'jpmorganchase.com'] },
  { name: 'bankofamerica', brand: 'Bank of America', officialDomains: ['bankofamerica.com', 'bofa.com'] },
  { name: 'wellsfargo', brand: 'Wells Fargo', officialDomains: ['wellsfargo.com'] },
  { name: 'binance', brand: 'Binance', officialDomains: ['binance.com'] },
  { name: 'coinbase', brand: 'Coinbase', officialDomains: ['coinbase.com'] },
  { name: 'facebook', brand: 'Meta / Facebook', officialDomains: ['facebook.com', 'meta.com', 'fb.com'] },
  { name: 'instagram', brand: 'Instagram', officialDomains: ['instagram.com'] },
  { name: 'steam', brand: 'Valve / Steam', officialDomains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'stripe', brand: 'Stripe', officialDomains: ['stripe.com'] },
  { name: 'dhl', brand: 'DHL Express', officialDomains: ['dhl.com'] },
  { name: 'fedex', brand: 'FedEx', officialDomains: ['fedex.com'] },
  { name: 'usps', brand: 'USPS Postal', officialDomains: ['usps.com'] },
  { name: 'adobe', brand: 'Adobe Creative', officialDomains: ['adobe.com'] },
  { name: 'dropbox', brand: 'Dropbox', officialDomains: ['dropbox.com'] },
];

// Sensitive keywords associated with credential harvesting and urgent lures
const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'sign-in', 'logon', 'verify', 'verification', 'secure',
  'security', 'account', 'banking', 'update', 'wallet', 'token', 'password',
  'credential', 'auth', 'authenticate', 'recover', 'recovery', 'support',
  'billing', 'invoice', 'confirm', 'session', 'webscr', 'alert', 're-verify',
  'validate', 'unlock', 'suspended', 'appeal', 'portal'
];

// Open redirect parameter keywords
const REDIRECT_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_url',
  'url', 'next', 'target', 'dest', 'destination', 'goto', 'link', 'out', 'r'
];

// Potentially hazardous payload extensions
const EXECUTABLE_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.iso', '.dmg', '.apk', '.msi', '.ps1', '.jar', '.hta'
];

// Defang a URL for safe display and SOC reporting (prevents accidental click)
export function defangUrl(url: string): string {
  if (!url) return '';
  return url
    .replace(/^https:\/\//i, 'hxxps[://]')
    .replace(/^http:\/\//i, 'hxxp[://]')
    .replace(/\./g, '[.]');
}

// Refang a defanged URL back to standard format
export function refangUrl(url: string): string {
  if (!url) return '';
  return url
    .replace(/^hxxps\[:\/\/\]/i, 'https://')
    .replace(/^hxxp\[:\/\/\]/i, 'http://')
    .replace(/\[\.\]/g, '.');
}

// Shannon Entropy calculation for measuring randomness / DGA domains
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// Levenshtein edit distance between two strings
export function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  const aLen = a.length;
  const bLen = b.length;

  for (let i = 0; i <= bLen; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= aLen; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= bLen; i++) {
    for (let j = 1; j <= aLen; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          Math.min(
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          )
        );
      }
    }
  }
  return matrix[bLen][aLen];
}

// Check for IDN Homoglyph attack (Punycode xn-- or mixed Cyrillic/Latin chars)
function checkIdnHomoglyph(hostname: string): { isHomoglyph: boolean; details?: string } {
  if (hostname.includes('xn--')) {
    return {
      isHomoglyph: true,
      details: 'Punycode encoded international domain name (potential homograph attack)',
    };
  }

  // Look for non-ASCII or Cyrillic characters mixed with Latin
  const cyrillicRegex = /[\u0400-\u04FF]/;
  const latinRegex = /[a-zA-Z]/;
  if (cyrillicRegex.test(hostname)) {
    if (latinRegex.test(hostname)) {
      return {
        isHomoglyph: true,
        details: 'Mixed script detected: Cyrillic characters mixed with Latin characters (IDN Homograph attack)',
      };
    }
    return {
      isHomoglyph: true,
      details: 'Non-standard Unicode script in domain (Cyrillic)',
    };
  }

  return { isHomoglyph: false };
}

// Check for brand impersonation and typosquatting
function detectBrandSpoofing(hostname: string, fullUrl: string): {
  impersonationDetected: boolean;
  targetedBrand?: string;
  minDistance?: number;
} {
  const hostLower = hostname.toLowerCase();
  const urlLower = fullUrl.toLowerCase();
  
  // Extract main domain parts
  const parts = hostLower.split('.');
  const secondLevel = parts.length >= 2 ? parts[parts.length - 2] : hostLower;
  const registeredDomain = parts.length >= 2 ? `${parts[parts.length - 2]}.${parts[parts.length - 1]}` : hostLower;

  for (const item of HIGH_VALUE_BRANDS) {
    const isOfficial = item.officialDomains.some(official => hostLower === official || hostLower.endsWith('.' + official));
    if (isOfficial) {
      continue; // Legitimate official domain, not spoofing
    }

    // 1. Direct keyword impersonation in subdomain or path while root domain is different
    if (urlLower.includes(item.name)) {
      // Subdomain spoof: e.g. paypal.com.evil-domain.com or paypal-security.xyz
      if (hostLower.includes(item.name)) {
        return {
          impersonationDetected: true,
          targetedBrand: item.brand,
          minDistance: 0,
        };
      }
    }

    // 2. Typosquatting on the second-level domain name (Levenshtein distance <= 2)
    // e.g. paypa1, micros0ft, chsse, netflx
    const dist = levenshteinDistance(secondLevel, item.name);
    if (dist > 0 && dist <= 2 && Math.abs(secondLevel.length - item.name.length) <= 2) {
      return {
        impersonationDetected: true,
        targetedBrand: `${item.brand} (Typosquatted: "${secondLevel}" vs "${item.name}", edit distance: ${dist})`,
        minDistance: dist,
      };
    }
  }

  return { impersonationDetected: false };
}

// Core Machine Learning Feature Extractor
export function extractUrlFeatures(rawInput: string): URLFeatures {
  const cleanedInput = rawInput.trim();
  const refanged = refangUrl(cleanedInput);
  
  // Ensure valid URL scheme for parsing
  let normalizedUrl = refanged;
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    // If input starts with '//', prepend 'https:'
    if (normalizedUrl.startsWith('//')) {
      normalizedUrl = 'https:' + normalizedUrl;
    } else {
      normalizedUrl = 'https://' + normalizedUrl;
    }
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    // Fallback manual decomposition if standard URL constructor fails
    const slashIdx = normalizedUrl.indexOf('/', 8);
    const host = slashIdx !== -1 ? normalizedUrl.substring(8, slashIdx) : normalizedUrl.substring(8);
    const path = slashIdx !== -1 ? normalizedUrl.substring(slashIdx) : '/';
    parsed = {
      protocol: 'https:',
      hostname: host,
      pathname: path,
      search: '',
      href: normalizedUrl,
    } as any;
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname || '/';
  const search = parsed.search || '';
  const fullHref = parsed.href;

  // TLD extraction
  const hostParts = hostname.split('.');
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';

  // IP address detection (IPv4 regex & IPv6)
  const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
  const isIpv6 = /^\[?[a-f0-9:]+\]?$/i.test(hostname) && hostname.includes(':');
  const isIpAddress = isIpv4 || isIpv6;

  // TLD Risk level
  let tldRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  let hasSuspiciousTld = false;
  if (HIGH_RISK_TLDS.has(tld)) {
    tldRiskLevel = 'HIGH';
    hasSuspiciousTld = true;
  } else if (MEDIUM_RISK_TLDS.has(tld)) {
    tldRiskLevel = 'MEDIUM';
    hasSuspiciousTld = true;
  }

  // Numerical & punctuation counts
  const urlLength = fullHref.length;
  const domainLength = hostname.length;
  const pathLength = pathname.length;
  const numDots = (fullHref.match(/\./g) || []).length;
  const numHyphens = (fullHref.match(/-/g) || []).length;
  const numUnderscores = (fullHref.match(/_/g) || []).length;
  const numAtSymbols = (fullHref.match(/@/g) || []).length;
  const numDoubleSlashPath = (pathname.match(/\/\//g) || []).length;
  const numPercentSymbols = (fullHref.match(/%/g) || []).length;

  // Subdomain analysis
  // Standard domain: example.com has 2 parts (0 subdomains), sub.example.com has 3 parts (1 subdomain)
  const numSubdomains = Math.max(0, hostParts.length - 2);
  const subdomainDepth = hostParts.length;

  // Non-standard port check
  const hasPort = parsed.port !== '' && parsed.port !== '80' && parsed.port !== '443';
  const portNumber = parsed.port ? parseInt(parsed.port, 10) : undefined;

  // Lexical & Statistical features
  const domainEntropy = calculateShannonEntropy(hostname);
  const pathEntropy = calculateShannonEntropy(pathname);

  // Digit ratios
  const domainDigits = (hostname.match(/\d/g) || []).length;
  const digitRatioDomain = domainLength > 0 ? Number((domainDigits / domainLength).toFixed(3)) : 0;

  const pathDigits = (pathname.match(/\d/g) || []).length;
  const digitRatioPath = pathLength > 0 ? Number((pathDigits / pathLength).toFixed(3)) : 0;

  // Vowel to consonant ratio in domain (high or zero indicates machine generated string)
  const domainLetters = hostname.replace(/[^a-z]/g, '');
  const vowels = (domainLetters.match(/[aeiou]/g) || []).length;
  const consonants = domainLetters.length - vowels;
  const vowelConsonantRatio = consonants > 0 ? Number((vowels / consonants).toFixed(3)) : vowels > 0 ? 3 : 0;

  // Longest alphanumeric token length
  const tokens = fullHref.split(/[^a-zA-Z0-9]/).filter(Boolean);
  const longestTokenLength = tokens.reduce((max, t) => Math.max(max, t.length), 0);

  // Sensitive keywords presence
  const matchedKeywords: string[] = [];
  const lowerUrl = fullHref.toLowerCase();
  for (const kw of SENSITIVE_KEYWORDS) {
    if (lowerUrl.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  // IDN Homoglyph detection
  const homoglyphCheck = checkIdnHomoglyph(hostname);

  // Brand spoofing detection
  const brandSpoof = detectBrandSpoofing(hostname, fullHref);

  // Redirection parameters
  const matchedRedirectParams: string[] = [];
  for (const param of REDIRECT_PARAMS) {
    if (search.toLowerCase().includes(`${param}=`)) {
      matchedRedirectParams.push(param);
    }
  }
  const hasRedirectParams = matchedRedirectParams.length > 0;

  // Executable extension
  let hasExecutableExt = false;
  let matchedExtension: string | undefined;
  for (const ext of EXECUTABLE_EXTENSIONS) {
    if (pathname.toLowerCase().endsWith(ext) || pathname.toLowerCase().includes(ext + '?')) {
      hasExecutableExt = true;
      matchedExtension = ext;
      break;
    }
  }

  const isHttps = parsed.protocol === 'https:';

  return {
    url: fullHref,
    rawUrl: cleanedInput,
    defangedUrl: defangUrl(fullHref),
    protocol: parsed.protocol,
    hostname,
    path: pathname,
    search,
    tld,
    urlLength,
    domainLength,
    pathLength,
    numDots,
    numHyphens,
    numUnderscores,
    numAtSymbols,
    numDoubleSlashPath,
    numPercentSymbols,
    numSubdomains,
    subdomainDepth,
    hasPort,
    portNumber,
    domainEntropy,
    pathEntropy,
    digitRatioDomain,
    digitRatioPath,
    vowelConsonantRatio,
    longestTokenLength,
    isIpAddress,
    hasSuspiciousTld,
    tldRiskLevel,
    sensitiveKeywordCount: matchedKeywords.length,
    matchedKeywords,
    isIdnHomoglyph: homoglyphCheck.isHomoglyph,
    homoglyphDetails: homoglyphCheck.details,
    brandImpersonationDetected: brandSpoof.impersonationDetected,
    targetedBrand: brandSpoof.targetedBrand,
    typosquattingDistance: brandSpoof.minDistance,
    hasRedirectParams,
    matchedRedirectParams,
    hasExecutableExt,
    matchedExtension,
    isHttps,
  };
}
