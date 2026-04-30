/**
 * Phisherman – Scoring Engine
 * Balanced, explainable, low false-positive phishing detection.
 */

// ─── Trusted Domain Allowlist ─────────────────────────────────────────────────
export const TRUSTED_DOMAINS = new Set([
  // Finance
  "paypal.com","paypalobjects.com","chase.com","bankofamerica.com",
  "wellsfargo.com","citibank.com","americanexpress.com","discover.com",
  "capitalone.com","usbank.com","td.com","hsbc.com","barclays.co.uk",
  // Tech
  "google.com","gmail.com","youtube.com","googleapis.com","gstatic.com",
  "microsoft.com","live.com","outlook.com","office.com","azure.com",
  "apple.com","icloud.com","amazon.com","aws.amazon.com","cloudfront.net",
  "facebook.com","instagram.com","whatsapp.com","twitter.com","x.com",
  "linkedin.com","github.com","gitlab.com","stackoverflow.com",
  "dropbox.com","box.com","salesforce.com","slack.com","zoom.us",
  // Shopping
  "ebay.com","etsy.com","shopify.com","stripe.com","square.com",
  // News/Gov
  "wikipedia.org","reddit.com","bbc.com","nytimes.com","cnn.com",
  "gov.uk","irs.gov","ssa.gov","usa.gov",
]);

// ─── Suspicious TLDs ──────────────────────────────────────────────────────────
const SUSPICIOUS_TLDS = new Set([
  ".tk",".ml",".ga",".cf",".gq",".top",".xyz",".club",".online",
  ".site",".website",".store",".tech",".info",".work",".click",
  ".link",".live",".win",".loan",".review",".party",".trade",
]);

// ─── Keyword Patterns ─────────────────────────────────────────────────────────
const PHISHING_KEYWORDS = [
  "secure-login","verify-account","account-suspended","confirm-identity",
  "update-payment","urgent-action","login-required","banking-secure",
  "paypal-security","apple-id-verify","microsoft-alert","amazon-suspended",
];

const BRAND_IMPERSONATION = [
  "paypa1","paypa-l","g00gle","gooogle","micros0ft","app1e",
  "arnazon","arnaz0n","faceb00k","instagrarr","twltter",
  "linkedln","netfl1x","netfllx","roblox-free","fortnite-vbucks",
];

// ─── Entropy Calculation ──────────────────────────────────────────────────────
function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((acc, f) => {
    const p = f / len;
    return acc + p * Math.log2(p);
  }, 0);
}

// ─── Domain Helpers ───────────────────────────────────────────────────────────
function getRootDomain(hostname) {
  const parts = hostname.replace(/^www\./, "").split(".");
  // Handle cases like .co.uk or .gov.in
  if (parts.length >= 3 && parts[parts.length - 2].length <= 3 && [".co", ".com", ".org", ".gov", ".net"].some(s => hostname.endsWith(s + "." + parts[parts.length-1]))) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

// ─── String Similarity (Levenshtein) ──────────────────────────────────────────
function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function isTrustedDomain(hostname) {
  const root = getRootDomain(hostname);
  if (TRUSTED_DOMAINS.has(root)) return true;
  // Subdomains of trusted (e.g. mail.google.com)
  for (const trusted of TRUSTED_DOMAINS) {
    if (hostname.endsWith("." + trusted)) return true;
  }
  return false;
}

// ─── URL Feature Extraction ───────────────────────────────────────────────────
function analyzeURL(url) {
  const signals = [];
  let score = 0;

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { score: 80, signals: [{ key: "invalid_url", msg: "The page address is malformed or invalid", weight: 80 }] };
  }

  const { protocol, hostname, pathname, search, href } = parsed;

  // HTTPS check
  if (protocol !== "https:") {
    score += 20;
    signals.push({ key: "no_https", msg: "This site doesn't use a secure connection (HTTPS)", weight: 20 });
  }

  // IP address as hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    signals.push({ key: "ip_host", msg: "The site uses a raw IP address instead of a domain name", weight: 30 });
  }

  // Suspicious TLD — strong signal for free/disposable domains
  const tldMatch = SUSPICIOUS_TLDS.has("." + hostname.split(".").slice(-1)[0]);
  if (tldMatch) {
    score += 25;
    signals.push({ key: "sus_tld", msg: "This site uses a domain extension commonly associated with free or suspicious hosting", weight: 25 });
  }

  // Too many subdomains
  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 3) {
    score += 12;
    signals.push({ key: "deep_subdomain", msg: "The web address has an unusually deep structure (many subdomain levels)", weight: 12 });
  }

  // Brand impersonation in hostname — very strong signal
  for (const brand of BRAND_IMPERSONATION) {
    if (hostname.includes(brand)) {
      score += 45;
      signals.push({ key: "brand_spoof", msg: "The domain name appears to impersonate a well-known brand", weight: 45 });
      break;
    }
  }

  // Phishing keyword in URL — strong signal when in hostname
  const fullPath = (pathname + search).toLowerCase();
  let keywordHit = false;
  for (const kw of PHISHING_KEYWORDS) {
    if (hostname.includes(kw)) {
      // Keywords in the hostname itself are a stronger signal
      if (!keywordHit) {
        score += 30;
        signals.push({ key: "phish_keyword", msg: "The domain name contains phrases often used in fake security pages", weight: 30 });
        keywordHit = true;
      }
    } else if (fullPath.includes(kw)) {
      if (!keywordHit) {
        score += 15;
        signals.push({ key: "phish_keyword", msg: "The web address contains phrases often used in fake security pages", weight: 15 });
        keywordHit = true;
      }
    }
  }

  // Excessive hyphens in domain (2+ is suspicious)
  const domainPart = hostname.split(".")[0];
  if ((domainPart.match(/-/g) || []).length >= 2) {
    score += 12;
    signals.push({ key: "many_hyphens", msg: "The domain name contains an unusual number of hyphens", weight: 12 });
  }

  // Very long URL
  if (href.length > 150) {
    score += 8;
    signals.push({ key: "long_url", msg: "The web address is unusually long, which can be used to hide the true destination", weight: 8 });
  }

  // High entropy in subdomain (DGA detection)
  const subdomain = hostname.split(".").slice(0, -2).join(".");
  if (subdomain.length > 5 && shannonEntropy(subdomain) > 3.8) {
    score += 15;
    signals.push({ key: "high_entropy", msg: "The web address looks randomly generated, which is unusual for legitimate sites", weight: 15 });
  }

  // @-symbol trick
  if (href.includes("@")) {
    score += 25;
    signals.push({ key: "at_symbol", msg: "The URL contains an '@' symbol which can be used to disguise the true destination", weight: 25 });
  }

  // Double slashes mid-path
  if (pathname.includes("//")) {
    score += 8;
    signals.push({ key: "double_slash", msg: "The web address has an unusual format that may be misleading", weight: 8 });
  }

  // ─── Advanced Heuristics ───────────────────────────────────────────────────
  
  // 1. Fuzzy Brand Matching (Typosquatting)
  const currentRoot = getRootDomain(hostname).split(".")[0];
  if (!isTrustedDomain(hostname)) {
    for (const trusted of TRUSTED_DOMAINS) {
      const trustedRoot = trusted.split(".")[0];
      const distance = levenshteinDistance(currentRoot, trustedRoot);
      
      // If domain is very similar but not identical (1-2 edits)
      if (distance > 0 && distance <= 2 && trustedRoot.length > 4) {
        score += 45;
        signals.push({ 
          key: "fuzzy_match", 
          msg: `This domain looks suspiciously similar to "${trusted}", a common trick used in typosquatting`, 
          weight: 45 
        });
        break;
      }
    }
  }

  // 2. Homograph Attack Detection (Punycode/Lookalikes)
  if (hostname.includes("xn--")) {
    score += 40;
    signals.push({ 
      key: "punycode", 
      msg: "The domain uses international characters (punycode) to mimic a legitimate site", 
      weight: 40 
    });
  }
  
  // 3. Encoded Character Detection
  const encodedCount = (href.match(/%[0-9A-F]{2}/gi) || []).length;
  if (encodedCount > 5) {
    score += 15;
    signals.push({ 
      key: "excessive_encoding", 
      msg: "The URL uses excessive character encoding, which can be used to hide malicious code", 
      weight: 15 
    });
  }

  // Compound signal bonus: when multiple strong signals fire together,
  // confidence is very high and score should reflect that.
  const highConfidenceKeys = new Set(["brand_spoof", "fuzzy_match", "sus_tld", "no_https", "phish_keyword", "ip_host"]);
  const highConfidenceHits = signals.filter(s => highConfidenceKeys.has(s.key)).length;
  if (highConfidenceHits >= 3) {
    const bonus = 15;
    score += bonus;
    signals.push({ key: "compound_risk", msg: "Multiple strong phishing indicators detected simultaneously", weight: bonus });
  }

  return { score: Math.min(score, 100), signals };
}

// ─── Page Content Analysis ────────────────────────────────────────────────────
export function analyzeContent(pageData) {
  const signals = [];
  let score = 0;

  const { hasLoginForm, hasPasswordField, hasHiddenFields,
          externalFormAction, title, hasSSLMismatch,
          suspiciousScripts, iframeCount, hiddenElementCount } = pageData;

  // Login form with external action (critical signal)
  if (hasLoginForm && externalFormAction) {
    score += 30;
    signals.push({ key: "ext_form", msg: "Login form submits your data to a different website", weight: 30 });
  }

  // Password field without HTTPS already flagged → extra weight
  if (hasPasswordField && hasSSLMismatch) {
    score += 20;
    signals.push({ key: "pwd_no_ssl", msg: "Your password would be sent over an insecure connection", weight: 20 });
  }

  // Excessive hidden fields
  if (hiddenElementCount > 10) {
    score += 10;
    signals.push({ key: "hidden_fields", msg: "The page contains many hidden elements, which is unusual", weight: 10 });
  }

  // Suspicious scripts (obfuscated JS)
  if (suspiciousScripts > 0) {
    score += Math.min(suspiciousScripts * 8, 20);
    signals.push({ key: "obfuscated_js", msg: "The page contains code that is intentionally difficult to read, a common trick on fake sites", weight: Math.min(suspiciousScripts * 8, 20) });
  }

  // Too many iframes
  if (iframeCount > 3) {
    score += 8;
    signals.push({ key: "many_iframes", msg: "The page contains multiple hidden frames, which can be used to capture your data", weight: 8 });
  }

  // Mismatched/suspicious title
  if (title) {
    const lowerTitle = title.toLowerCase();
    const suspiciousTitlePhrases = ["verify your account","account suspended","urgent","confirm your","limited access","security alert"];
    for (const phrase of suspiciousTitlePhrases) {
      if (lowerTitle.includes(phrase)) {
        score += 12;
        signals.push({ key: "sus_title", msg: `The page title contains alarming language ("${phrase}") often used to create panic`, weight: 12 });
        break;
      }
    }
  }

  return { score: Math.min(score, 100), signals };
}

// ─── Combined Scoring ─────────────────────────────────────────────────────────
export function computeFinalScore({ urlScore, urlSignals, contentScore, contentSignals, isTrusted, isFrequentlyVisited, paranoiaLevel = 2 }) {
  // Merge all signals (deduplicated by key)
  const allSignals = [];
  const seen = new Set();
  for (const s of [...urlSignals, ...contentSignals]) {
    if (!seen.has(s.key)) { seen.add(s.key); allSignals.push(s); }
  }

  // Weighted combination — dynamic weighting based on signal availability
  // If content analysis returned signals, use balanced weights.
  // If only URL signals exist, URL analysis should dominate.
  let urlWeight, contentWeight;
  if (contentSignals.length > 0) {
    urlWeight = 0.55;
    contentWeight = 0.45;
  } else {
    // No content signals — URL is our only data, trust it more
    urlWeight = 0.85;
    contentWeight = 0.15;
  }

  let combined = (urlScore * urlWeight) + (contentScore * contentWeight);

  // Minimum floor: if URL alone shows overwhelming evidence, don't let
  // a missing content scan suppress it. This ensures brand impersonation +
  // suspicious TLD + no HTTPS will always flag as phishing.
  if (urlScore >= 70) {
    combined = Math.max(combined, urlScore * 0.85);
  }

  // Trust reduction
  if (isTrusted) combined *= 0.2;
  else if (isFrequentlyVisited) combined *= 0.7;

  // Cap
  combined = Math.min(Math.round(combined), 100);

  // Classification based on Paranoia (1=Lenient, 2=Balanced, 3=Paranoid)
  let riskLevel, color;
  
  let suspThresh = 40;
  let phishThresh = 70;
  
  if (paranoiaLevel === 1) { suspThresh = 50; phishThresh = 85; }
  else if (paranoiaLevel === 3) { suspThresh = 25; phishThresh = 50; }

  if (combined < suspThresh) { riskLevel = "Safe"; color = "safe"; }
  else if (combined < phishThresh) { riskLevel = "Suspicious"; color = "suspicious"; }
  else { riskLevel = "Phishing"; color = "danger"; }

  // Confidence
  const signalCount = allSignals.length;
  const maxWeight = allSignals.reduce((m, s) => Math.max(m, s.weight), 0);
  let confidence;
  if (signalCount >= 4 || maxWeight >= 30) confidence = "High";
  else if (signalCount >= 2 || maxWeight >= 15) confidence = "Medium";
  else confidence = "Low";

  // Top 3 reasons for display
  const topReasons = allSignals
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map(s => s.msg);

  const allReasons = allSignals
    .sort((a, b) => b.weight - a.weight)
    .map(s => s.msg);

  return { score: combined, riskLevel, color, confidence, topReasons, allReasons, isTrusted };
}

// ─── URL Analysis Entry ───────────────────────────────────────────────────────
export function analyzeURLFeatures(url) {
  return analyzeURL(url);
}
