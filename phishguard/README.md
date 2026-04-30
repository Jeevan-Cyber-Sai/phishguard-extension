# 🛡️ Phisherman – Real-Time Phishing Detection Chrome Extension

A production-quality Chrome Extension (Manifest V3) that detects phishing websites in real time, with smart risk scoring, user-friendly explanations, and a clean modern UI.

---

## 📁 Project Structure

```
phisherman/
├── manifest.json                   # Extension manifest (MV3)
├── icons/
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
└── src/
    ├── background/
    │   └── service-worker.js       # Core orchestration logic
    ├── content/
    │   ├── content.js              # In-page banner + phishing overlay
    │   └── content.css             # Styles for in-page UI
    ├── popup/
    │   ├── popup.html              # Extension popup
    │   ├── popup.css               # Popup styles
    │   └── popup.js                # Popup logic
    ├── utils/
        ├── scorer.js               # URL + content scoring engine
        ├── cache.js                # Domain result caching
        ├── cookie-intelligence.js   # Cookie classification logic
        └── cookie-risk-engine.js    # Cookie risk scoring logic
```

---

## 🚀 How to Install (Load Unpacked)

### Step 1 – Download & Extract
Download the ZIP and extract it. You should have a `phisherman/` folder.

### Step 2 – Open Chrome Extensions Page
1. Open **Google Chrome**
2. Go to: `chrome://extensions/`
3. Enable **Developer Mode** (toggle in the top-right corner)

### Step 3 – Load the Extension
1. Click **"Load unpacked"**
2. Select the `phisherman/` folder (the one containing `manifest.json`)
3. Phisherman will appear in your extensions list ✅

### Step 4 – Pin the Extension (Recommended)
1. Click the puzzle icon 🧩 in the Chrome toolbar
2. Click the pin icon next to **Phisherman**
3. The shield icon will now appear in your toolbar

---

## 🧪 How to Test

### Test Safe Site
- Visit `https://google.com` → Should show **Safe** (green)
- Visit `https://github.com` → Should show **Safe** (green)

### Test Suspicious Site
- Visit any HTTP (not HTTPS) page with a login form
- Visit sites with unusual domain structures (many hyphens, deep subdomains)

### Test Phishing Detection
- Visit `http://paypa1-secure-login.tk` (if it resolves) → Should trigger **Phishing overlay**
- Or use a known phishing test page: `https://www.wicar.org/test-malware.html` (safe test site)

### Manual Test (Developer Tools)
1. Open any page
2. Open DevTools → Console
3. The background service worker logs analysis details

---

## 🎨 UI Overview

### Popup
| Element | Description |
|---|---|
| **Score Ring** | Animated circular progress showing risk score (0–100) |
| **Risk Badge** | Safe / Suspicious / Phishing with color coding |
| **Confidence** | Low / Medium / High based on signal strength |
| **Domain Pill** | Shows current domain + Trusted badge if applicable |
| **Top Findings** | Up to 3 plain-English explanations |
| **Show more** | Expandable section for all signals |
| **Go Back** | Quick action button for phishing sites |

### In-Page Warnings
| Type | Trigger | Behavior |
|---|---|---|
| **Yellow Banner** | Suspicious (35–65) | Non-intrusive top banner, auto-dismisses in 12s |
| **Red Overlay** | Phishing (>65, Medium+ confidence) | Full-screen modal with blur, Go Back + Continue options |

### AI Evidence Dashboard
The dashboard provides a deep-dive into why a site was flagged:
- **Evidence Log**: Detailed breakdown of every signal triggered.
- **Security Trend**: Historical risk tracking for individual domains.
- **Parental Center**: Child mode with SMS alert simulation.

---

## ⚙️ Scoring System

### Risk Levels
| Score | Level | Color |
|---|---|---|
| 0–34 | Safe | 🟢 Green |
| 35–64 | Suspicious | 🟡 Yellow |
| 65–100 | Phishing | 🔴 Red |

### URL Signals (55% weight)
| Signal | Points |
|---|---|
| No HTTPS | +20 |
| IP address as hostname | +30 |
| Suspicious TLD (.tk, .ml, etc.) | +15 |
| 3+ subdomain levels | +12 |
| Brand name impersonation (paypa1, g00gle, etc.) | +35 |
| Phishing keywords in URL | +20 |
| 3+ hyphens in domain | +10 |
| URL length > 150 chars | +8 |
| High entropy subdomain (DGA detection) | +15 |
| @ symbol in URL | +25 |
| Double slashes in path | +8 |

### Content Signals (45% weight)
| Signal | Points |
|---|---|
| Login form submitting to external domain | +30 |
| Password field over insecure connection | +20 |
| 10+ hidden elements | +10 |
| Obfuscated JavaScript (eval, base64, etc.) | +8 per script (max 20) |
| More than 3 iframes | +8 |
| Alarming page title keywords | +12 |

### Advanced AI Heuristics
| Signal | Description | Points |
|---|---|---|
| **Fuzzy Brand Matching** | Detects domains slightly different from trusted ones (e.g., `g00gle.com`) using Levenshtein distance | +45 |
| **Homograph Detection** | Detects use of punycode or lookalike international characters | +40 |
| **Encoded URL Check** | Detects excessive %-encoding used to hide malicious URLs | +15 |

### Cookie Intelligence (Privacy)
| Signal | Description | Weight |
|---|---|---|
| **Tracking Cookies** | Third-party cookies from known ad/tracking domains | High |
| **Analytics Cookies** | Cookies used for behavioral monitoring (GA, Hotjar, etc.) | Medium |
| **Suspicious Patterns** | High-entropy random identifiers from unknown domains | Critical |
| **Cookie Volume** | Total volume of cookies exceeding functional necessity | Low |

### Trust Adjustments
| Condition | Effect |
|---|---|
| Known trusted domain (Google, PayPal, etc.) | Score × 0.2 (80% reduction) |
| Visited 5+ times before | Score × 0.7 (30% reduction) |

---

## 🔒 Privacy Guarantee

Phisherman processes everything **locally in your browser**:
- ✅ No data sent to external servers
- ✅ No keystrokes or form content collected
- ✅ No tracking or analytics
- ✅ No personal information stored
- ✅ Cache stored locally in `chrome.storage.session` (cleared when browser closes)
- ✅ Visit counts stored locally in `chrome.storage.local`

---

## 🐛 Debugging Tips

### View Service Worker Logs
1. Go to `chrome://extensions/`
2. Find Phisherman → Click **"Service Worker"** link
3. DevTools opens showing background script console

### View Content Script Logs
1. Open any webpage
2. Open DevTools (F12) → Console
3. Phisherman content script logs appear here

### Force Re-Analysis
- Click the **refresh icon** (↻) in the popup top-right corner
- Or send message from console: `chrome.runtime.sendMessage({type: "RE_ANALYZE", tabId: <id>})`

### Clear Cache
```javascript
// Run in DevTools console on any page:
chrome.storage.session.clear(() => console.log("Session cache cleared"));
chrome.storage.local.clear(() => console.log("Visit history cleared"));
```

### Check Stored Data
```javascript
chrome.storage.session.get(null, console.log);  // See cached results
chrome.storage.local.get(null, console.log);    // See visit counts
```

---

## 🔧 Configuration & Customization

### Adjust Risk Thresholds
In `src/utils/scorer.js`, find `computeFinalScore()` and modify:
```javascript
if (combined < 35)       // Change 35 to tune Safe boundary
else if (combined < 65)  // Change 65 to tune Suspicious boundary
```

### Add Trusted Domains
In `src/utils/scorer.js`, add to `TRUSTED_DOMAINS`:
```javascript
export const TRUSTED_DOMAINS = new Set([
  "yourcompany.com",  // ← Add here
  // ...existing domains
]);
```

### Adjust Cache TTL
In `src/utils/cache.js`:
```javascript
const CACHE_TTL_MS = 60 * 60 * 1000; // Change to desired milliseconds
```

### Disable Overlay (Only Banner)
In `src/background/service-worker.js`, comment out the overlay section:
```javascript
// if (result.riskLevel === "Phishing" ...) {
//   await chrome.tabs.sendMessage(tab.id, { type: "SHOW_OVERLAY", result });
// }
```

---

## ⚠️ Known Limitations

1. **Dynamic phishing pages** – Some sophisticated phishing pages load content dynamically after the initial scan. Phisherman addresses this with its Stage 2 content scan.
2. **Local heuristics** – While advanced, some zero-day threats may require cloud-based ML for 100% accuracy.
3. **HTTPS doesn't mean safe** – Many phishing sites now have valid SSL certificates. Phisherman accounts for this.

---

## 🛣️ Roadmap / Enhancements

| Feature | Priority |
|---|---|
| Google Safe Browsing API integration | High |
| PhishTank/OpenPhish blocklist | High |
| User-reported false positives feedback | Medium |
| ML model for domain classification | Medium |
| Password field interception warning | Medium |
| Export report as PDF | Low |

---

## 🤝 Browser Compatibility

| Browser | Support |
|---|---|
| Chrome 88+ | ✅ Full support |
| Edge (Chromium) 88+ | ✅ Full support |
| Brave | ✅ Full support |
| Firefox | ❌ Uses MV2, would need porting |
| Safari | ❌ Different extension API |

---

## 📄 License

MIT License – Free to use, modify, and distribute.

---

*Built with Phisherman v1.0.0 · Privacy-first phishing protection*

phisherman-4ce86#   P h i s h e r m a n  
 