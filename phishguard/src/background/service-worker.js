/**
 * Phisherman – Service Worker (Background)
 * Orchestrates analysis: URL scoring → content analysis → result caching → UI messaging.
 */

import { analyzeURLFeatures, analyzeContent, computeFinalScore, TRUSTED_DOMAINS } from "../utils/scorer.js";
import { domainCache, getVisitCount, incrementVisitCount } from "../utils/cache.js";
import { analyzeCookies, getCookieExplanations } from "../utils/cookie-intelligence.js";
import { computeCookieRiskScore, computeOverallSafety } from "../utils/cookie-risk-engine.js";

// ─── Tab State ────────────────────────────────────────────────────────────────
const tabResults = new Map(); // tabId → result

// ─── Helpers ──────────────────────────────────────────────────────────────────
function getRootDomain(hostname) {
  return hostname.replace(/^www\./, "").split(".").slice(-2).join(".");
}

function isTrustedDomain(hostname) {
  const root = getRootDomain(hostname);
  if (TRUSTED_DOMAINS.has(root)) return true;
  for (const trusted of TRUSTED_DOMAINS) {
    if (hostname.endsWith("." + trusted)) return true;
  }
  return false;
}

// ─── Core Analysis ────────────────────────────────────────────────────────────
async function analyzeTab(tab) {
  if (!tab?.url || !tab.url.startsWith("http")) return;

  let parsed;
  try { parsed = new URL(tab.url); } catch { return; }

  const domain = getRootDomain(parsed.hostname);

  // 1. Check cache
  const cached = await domainCache.get(domain);
  if (cached) {
    tabResults.set(tab.id, cached);
    notifyPopup(tab.id, cached);
    updateIcon(tab.id, cached.color);
    return;
  }

  // 2. STAGE 1: Immediate URL analysis
  const { score: urlScore, signals: urlSignals } = analyzeURLFeatures(tab.url);
  const trusted = isTrustedDomain(parsed.hostname);
  
  // Set preliminary result
  const prelimResult = {
    score: Math.round(urlScore * 0.55), // Preliminary weighted score
    riskLevel: urlScore > 60 ? "Phishing" : urlScore > 30 ? "Suspicious" : "Safe",
    color: urlScore > 60 ? "danger" : urlScore > 30 ? "suspicious" : "safe",
    confidence: "Low",
    topReasons: urlSignals.slice(0, 2).map(s => s.msg),
    url: tab.url,
    domain,
    loading: true, // Still loading content data
    analyzedAt: Date.now()
  };
  
  tabResults.set(tab.id, prelimResult);
  updateIcon(tab.id, prelimResult.color);
  notifyPopup(tab.id, prelimResult);

  // 3. STAGE 2: Delayed Content analysis (Wait for DOM)
  setTimeout(async () => {
    // Re-verify tab still exists and is on the same URL
    const currentTab = await chrome.tabs.get(tab.id).catch(() => null);
    if (!currentTab || currentTab.url !== tab.url) return;

    const visitCount = await getVisitCount(domain);
    const isFrequentlyVisited = visitCount >= 5;
    await incrementVisitCount(domain);

    let contentData = {
      hasLoginForm: false, hasPasswordField: false, hasHiddenFields: false,
      externalFormAction: false, title: "", hasSSLMismatch: false,
      suspiciousScripts: 0, iframeCount: 0, hiddenElementCount: 0
    };

    try {
      const [response] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: extractPageFeatures,
      });
      if (response?.result) contentData = response.result;
    } catch (e) {
      console.debug("[Phisherman] Content extraction failed:", e.message);
    }

    // Fetch settings
    const { phishermanSettings } = await chrome.storage.local.get("phishermanSettings");
    const settings = phishermanSettings || {};
    const safelist = settings.safelist || [];
    const blocklist = settings.blocklist || [];
    const paranoiaLevel = settings.paranoia || 2;

    // Manual list override check
    if (safelist.some(d => domain.includes(d) || parsed.hostname.includes(d))) {
      const result = { score: 0, riskLevel: "Safe", color: "safe", confidence: "High", topReasons: ["Domain is manually whitelisted by you"], url: tab.url, domain, loading: false, analyzedAt: Date.now() };
      await updateUIAndHistory(tab, domain, result);
      return;
    }
    if (blocklist.some(d => domain.includes(d) || parsed.hostname.includes(d))) {
      const result = { score: 100, riskLevel: "Phishing", color: "danger", confidence: "High", topReasons: ["Domain is manually blacklisted by you"], url: tab.url, domain, loading: false, analyzedAt: Date.now() };
      await updateUIAndHistory(tab, domain, result);
      return;
    }

    // ML Backend Integration (Optional)
    let mlScoreAdj = 0;
    let mlSignals = [];
    try {
      const mlResponse = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: tab.url })
      });
      
      if (mlResponse.ok) {
        const mlData = await mlResponse.json();
        if (mlData && typeof mlData.is_phishing !== "undefined") {
          if (mlData.is_phishing) {
            mlScoreAdj = 50;
            mlSignals.push({ key: "ml_phish", msg: "Machine Learning model detected phishing patterns 🛑", weight: 40 });
          } else {
            mlScoreAdj = -30;
            mlSignals.push({ key: "ml_safe", msg: "Machine Learning model verified this site as legitimate ✅", weight: 0 });
          }
        }
      }
    } catch (e) {
      // console.debug("[Phisherman] ML prediction skipped");
    }

    // 7. Compute final score
    let { score: contentScore, signals: contentSignals } = analyzeContent(contentData);
    
    contentScore = Math.max(0, Math.min(100, contentScore + mlScoreAdj));
    contentSignals = [...contentSignals, ...mlSignals];

    const result = computeFinalScore({
      urlScore, urlSignals, contentScore, contentSignals,
      isTrusted: trusted, isFrequentlyVisited, paranoiaLevel
    });

    // 8. STAGE 3: Cookie Intelligence (Background-only API)
    let cookieData = { total: 0, tracking: 0, analytics: 0, suspicious: 0, details: [] };
    let cookieRisk = { score: 0, riskLevel: "Low", color: "safe", trackingLevel: "Low Tracking" };
    let cookieExplanations = [];

    try {
      const cookies = await chrome.cookies.getAll({ domain: parsed.hostname });
      cookieData = analyzeCookies(cookies, domain);
      cookieRisk = computeCookieRiskScore(cookieData);
      cookieExplanations = getCookieExplanations(cookieData);
    } catch (e) {
      console.debug("[Phisherman] Cookie analysis failed:", e.message);
    }

    // 9. Final Fusion
    const overallSafety = computeOverallSafety(result.score, cookieRisk.score);

    result.url = tab.url;
    result.domain = domain;
    result.loading = false;
    result.analyzedAt = Date.now();
    
    // Attach cookie intelligence
    result.cookieIntelligence = {
      stats: cookieData,
      risk: cookieRisk,
      explanations: cookieExplanations,
      overallSafety
    };

    await updateUIAndHistory(tab, domain, result);
    
    // 10. Auto-Protection System
    const { phishermanAutoProtect } = await chrome.storage.local.get("phishermanAutoProtect");
    if (phishermanAutoProtect && cookieRisk.score > 70) {
      blockNonEssentialCookies(parsed.hostname, domain);
    }
  }, 1000);
}

// ─── Cookie Management ────────────────────────────────────────────────────────
async function blockNonEssentialCookies(hostname, domain) {
  const cookies = await chrome.cookies.getAll({ domain: hostname });
  const toDelete = cookies.filter(c => {
    const { category } = analyzeCookies([c], domain);
    return category !== "Essential";
  });

  for (const c of toDelete) {
    const url = `http${c.secure ? "s" : ""}://${c.domain.replace(/^\./, "")}${c.path}`;
    await chrome.cookies.remove({ url, name: c.name });
  }
}

// ─── Update UI & History helper ───────────────────────────────────────────────
async function updateUIAndHistory(tab, domain, result) {
  // 7. Cache + store
  await domainCache.set(domain, result);
  tabResults.set(tab.id, result);

  // Update History
  const { phishermanHistory } = await chrome.storage.local.get("phishermanHistory");
  let history = phishermanHistory || [];
  history.push({ 
    url: result.url, 
    domain, 
    score: result.score, 
    riskLevel: result.riskLevel, 
    time: Date.now(),
    reasons: result.topReasons || [] 
  });
  // Keep last 1000 items
  if (history.length > 1000) history = history.slice(-1000);
  await chrome.storage.local.set({ phishermanHistory: history });

  // 8. Update UI
  updateIcon(tab.id, result.color);
  notifyPopup(tab.id, result);

  // 9. Tiered Phishing Alert System
  if (result.riskLevel === "Phishing" && result.confidence !== "Low") {
    try {
      // High Risk (>70): Show full-page overlay
      await chrome.tabs.sendMessage(tab.id, { type: "SHOW_OVERLAY", result });
    } catch (e) {
      console.debug("[Phisherman] Could not send overlay message:", e.message);
    }
  } else if (result.riskLevel === "Suspicious") {
    try {
      // Suspicious (40-70): Show top banner
      await chrome.tabs.sendMessage(tab.id, { type: "SHOW_BANNER", result });
    } catch (e) {
      console.debug("[Phisherman] Could not send banner message:", e.message);
    }
  }
  // Safe (<40): No action (handled by background badge/popup)

  // 10. Send Tracking Indicator
  if (result.cookieIntelligence) {
    try {
      await chrome.tabs.sendMessage(tab.id, { 
        type: "SHOW_TRACKING_INDICATOR", 
        trackingLevel: result.cookieIntelligence.risk.trackingLevel,
        cookieRiskColor: result.cookieIntelligence.risk.color
      });
    } catch (e) {
       console.debug("[Phisherman] Could not send tracking indicator message:", e.message);
    }
  }
}

// ─── Page Feature Extractor (runs in page context) ────────────────────────────
function extractPageFeatures() {
  const forms = document.querySelectorAll("form");
  let hasLoginForm = false;
  let hasPasswordField = false;
  let externalFormAction = false;

  forms.forEach(form => {
    const inputs = form.querySelectorAll("input");
    inputs.forEach(input => {
      const type = (input.type || "").toLowerCase();
      if (type === "password") { hasLoginForm = true; hasPasswordField = true; }
      if (type === "email" || input.name?.toLowerCase().includes("user") ||
          input.name?.toLowerCase().includes("login")) hasLoginForm = true;
    });

    const action = form.action || "";
    if (action && !action.startsWith(window.location.origin) && action.startsWith("http")) {
      externalFormAction = true;
    }
  });

  // Hidden elements
  const hiddenElements = document.querySelectorAll("[style*='display:none'],[style*='display: none'],[style*='visibility:hidden'],[hidden]");

  // Suspicious scripts (eval / base64 patterns)
  const scripts = document.querySelectorAll("script");
  let suspiciousScripts = 0;
  scripts.forEach(s => {
    const src = s.textContent || "";
    if (src.includes("eval(") || src.includes("unescape(") ||
        src.includes("fromCharCode") || /[A-Za-z0-9+/]{80,}={0,2}/.test(src)) {
      suspiciousScripts++;
    }
  });

  const iframes = document.querySelectorAll("iframe");

  return {
    hasLoginForm,
    hasPasswordField,
    hasHiddenFields: hiddenElements.length > 5,
    externalFormAction,
    title: document.title || "",
    hasSSLMismatch: location.protocol !== "https:",
    suspiciousScripts,
    iframeCount: iframes.length,
    hiddenElementCount: hiddenElements.length,
  };
}

// ─── Icon Updater ─────────────────────────────────────────────────────────────
function updateIcon(tabId, color) {
  const iconPaths = {
    safe:       "icons/icon_safe.png",
    suspicious: "icons/icon_warning.png",
    danger:     "icons/icon_danger.png",
  };

  // Badge color
  const badgeColors = { safe: "#22c55e", suspicious: "#f59e0b", danger: "#ef4444" };
  const badgeTexts = { safe: "✓", suspicious: "!", danger: "⚠" };

  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColors[color] || "#6b7280" });
  chrome.action.setBadgeText({ tabId, text: badgeTexts[color] || "" });
  
  if (iconPaths[color]) {
    chrome.action.setIcon({ tabId, path: iconPaths[color] }).catch(() => {});
  }
}

// ─── Popup Notification ───────────────────────────────────────────────────────
function notifyPopup(tabId, result) {
  chrome.runtime.sendMessage({ type: "ANALYSIS_RESULT", tabId, result }).catch(() => {});
}

// ─── Event Listeners ──────────────────────────────────────────────────────────
chrome.webNavigation.onCommitted.addListener(async details => {
  if (details.frameId !== 0) return;
  const tab = await chrome.tabs.get(details.tabId).catch(() => null);
  if (tab) {
    tabResults.delete(tab.id);
    analyzeTab(tab); // Trigger immediate stage 1
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab && !tabResults.has(tabId)) analyzeTab(tab);
});

// Message router for popup requests
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_RESULT") {
    const result = tabResults.get(msg.tabId) || null;
    sendResponse({ result });
    return true;
  }
  if (msg.type === "RE_ANALYZE") {
    chrome.tabs.get(msg.tabId).then(tab => {
      tabResults.delete(msg.tabId);
      analyzeTab(tab);
    });
    sendResponse({ ok: true });
    return true;
  }
});


chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SEND_SMS_ALERT") {
    chrome.storage.local.get("phishermanPhone", (res) => {
       const phone = res.phishermanPhone || "unknown number";
       console.log(`[SMS SIMULATION] Sending alert to ${phone}: Child attempted to access high risk site ${msg.domain}`);
    });
  }
  
  if (msg.type === "DELETE_SITE_COOKIES") {
    chrome.tabs.get(msg.tabId).then(async tab => {
      if (!tab.url) return;
      const url = new URL(tab.url);
      const cookies = await chrome.cookies.getAll({ domain: url.hostname });
      for (const c of cookies) {
        const cUrl = `http${c.secure ? "s" : ""}://${c.domain.replace(/^\./, "")}${c.path}`;
        await chrome.cookies.remove({ url: cUrl, name: c.name });
      }
      sendResponse({ ok: true });
    });
    return true;
  }
});

// Update history with score and trend
function updateSiteHistory(domain, score) {
    chrome.storage.local.get("phishermanHistoryExt", (res) => {
        const history = res.phishermanHistoryExt || {};
        if (!history[domain]) history[domain] = { scores: [] };
        history[domain].scores.push(score);
        
        let trend = "stable";
        const scores = history[domain].scores;
        if (scores.length > 1) {
            trend = score > scores[scores.length-2] ? "increasing" : "decreasing";
        }
        history[domain].trend = trend;
        history[domain].lastVisited = Date.now();
        
        chrome.storage.local.set({ phishermanHistoryExt: history });
    });
}
