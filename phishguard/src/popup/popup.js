/**
 * Phisherman – Popup Script
 * Fetches analysis result from background and renders the UI.
 */

import { getCurrentPlan, trackScan, getUsageStats, hasFeature } from '../utils/plan-manager.js';

(function () {
  "use strict";

  // ─── DOM Refs ──────────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);

  const loadingState = $("loading-state");
  const nodataState = $("nodata-state");
  const resultState = $("result-state");

  const scoreNum = $("score-num");
  const ringFill = $("ring-fill");
  const riskBadge = $("risk-badge");
  const confValue = $("conf-value");
  const domainText = $("domain-text");
  const trustedBadge = $("trusted-badge");
  const reasonsList = $("reasons-list");
  const toggleMore = $("toggle-more");
  const toggleText = $("toggle-text");
  const actionsEl = $("actions");
  const refreshBtn = $("refresh-btn");
  const btnAnalyze = $("btn-analyze");
  const siteActionsContainer = $("site-actions-container");
  const scanStatus = $("scan-status");
  const statusText = $("status-text");
  
  const cookieSection = $("cookie-section");
  const cookieScoreEl = $("cookie-score");
  const cookieBadgeEl = $("cookie-badge");
  const cookieCountEl = $("cookie-count");
  const cookieExplanationsEl = $("cookie-explanations");
  const overallSection = $("overall-section");
  const overallScoreEl = $("overall-score");
  const btnDeleteCookies = $("btn-delete-cookies");
  
  const riskBarFill = $("risk-bar-fill");
  const btnBlockSite = $("btn-block-site");
  const btnAnalyzePage = $("btn-analyze-page");
  const btnReportIssue = $("btn-report-issue");

  // ─── Helpers ──────────────────────────────────────────────────────────────
  function show(el) { el.classList.remove("hidden"); }
  function hide(el) { el.classList.add("hidden"); }

  function setState(name) {
    hide(loadingState);
    hide(nodataState);
    hide(resultState);
    if (name === "loading") show(loadingState);
    else if (name === "nodata") show(nodataState);
    else if (name === "result") show(resultState);
  }

  // ─── Ring Progress ─────────────────────────────────────────────────────────
  const CIRCUMFERENCE = 2 * Math.PI * 50; // r=50

  function setRing(score) {
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    ringFill.style.strokeDasharray = CIRCUMFERENCE;
    ringFill.style.strokeDashoffset = CIRCUMFERENCE; // start at 0
    requestAnimationFrame(() => {
      setTimeout(() => {
        ringFill.style.strokeDashoffset = offset;
      }, 80);
    });
  }

  // ─── Progress Bar (Removed) ────────────────────────────────────────────────
  function setProgressBar(score) {
    // Intentionally empty, feature removed per user request
  }

  // ─── Render Reasons ────────────────────────────────────────────────────────
  function renderReasons(reasons, container, color, baseDelay = 0) {
    container.innerHTML = "";
    reasons.forEach((msg, i) => {
      const li = document.createElement("li");
      li.className = `reason-item ${color} fade-in-up`;
      li.style.animationDelay = `${baseDelay + (i * 0.1)}s`;
      const icon = color === "safe" ? "✓" : color === "suspicious" ? "⚠" : "🚩";
      li.innerHTML = `<span class="reason-icon">${icon}</span><span>${msg}</span>`;
      container.appendChild(li);
    });
  }

  // ─── Render Result ─────────────────────────────────────────────────────────
  function renderResult(result) {
    if (!result) { setState("loading"); return; }
    
    // If it's a preliminary result but has data, show the result state
    setState("result");

    const { score, riskLevel, color, confidence, topReasons, allReasons, domain, isTrusted, loading, cookieIntelligence } = result;

    // Show scan status if still performing content analysis
    if (loading) {
      show(scanStatus);
      if (statusText) statusText.textContent = "URL Analysis Complete. Checking page content…";
    } else {
      hide(scanStatus);
    }

    // Theme
    document.body.className = `theme-${color}`;

    // Score ring + number
    scoreNum.textContent = score;
    setRing(score);
    setProgressBar(score);

    // Badge
    riskBadge.textContent = riskLevel;
    riskBadge.className = `risk-badge ${color}`;

    if (confValue) {
      const confColors = { Low: "#7d8590", Medium: "#f59e0b", High: color === "safe" ? "#22c55e" : "#ef4444" };
      confValue.textContent = confidence;
      confValue.style.color = confColors[confidence] || "#e6edf3";
    }

    // Domain
    const rawDomain = domain || "—";
    let formattedDomain = rawDomain;
    let siteActions = ['• Read content', '• Interact with page'];

    if (rawDomain !== "—") {
      let parts = rawDomain.replace(/^www\./, '').split('.');
      formattedDomain = parts[0];

      const actionsMap = {
        'gemini': ['• Chat with AI', '• Generate content'],
        'google': ['• Search the web', '• Use Google services'],
        'github': ['• Browse repositories', '• Contribute code'],
        'youtube': ['• Watch videos', '• Upload content'],
        'amazon': ['• Shop for products', '• View orders']
      };
      if (actionsMap[formattedDomain.toLowerCase()]) {
        siteActions = actionsMap[formattedDomain.toLowerCase()];
      }
    }

    domainText.textContent = formattedDomain;
    if (trustedBadge) {
      if (isTrusted) { show(trustedBadge); } else { hide(trustedBadge); }
    }

    if (siteActionsContainer) {
      siteActionsContainer.innerHTML = siteActions.map(a => `<p>${a}</p>`).join('');
    }

    // Risk Progress Bar
    if (riskBarFill) {
      setTimeout(() => {
        riskBarFill.style.width = `${score}%`;
      }, 300);
    }

    // Reasons
    if (reasonsList) {
      if (riskLevel === "Safe" && (!topReasons || topReasons.length === 0)) {
        reasonsList.innerHTML = `
          <li class="safe-message">
            <span>✓</span>
            <span>No suspicious signals detected on this page.</span>
          </li>`;
      } else {
        renderReasons(topReasons || [], reasonsList, color, 0);
      }
    }

    // Cookie Intelligence Rendering
    if (cookieIntelligence) {
      show(cookieSection);
      show(overallSection);
      
      const { stats, risk, explanations, overallSafety } = cookieIntelligence;
      
      cookieScoreEl.textContent = risk.score;
      cookieScoreEl.style.color = `var(--c-${risk.color})`;
      cookieBadgeEl.textContent = risk.riskLevel + " Risk";
      cookieBadgeEl.style.color = `var(--c-${risk.color})`;
      cookieCountEl.textContent = `${stats.total} Cookies (${stats.tracking} Trackers)`;
      
      cookieExplanationsEl.innerHTML = explanations.map((e, i) => 
        `<li class="fade-in-up" style="animation-delay: ${0.4 + (i * 0.1)}s;">${e}</li>`
      ).join("");
      
      overallScoreEl.textContent = overallSafety;
      // overallScore color handled by theme class on body
    } else {
      hide(cookieSection);
      hide(overallSection);
    }

    // Actions
    actionsEl.innerHTML = "";
    if (riskLevel === "Phishing") {
      const btn = document.createElement("button");
      btn.className = "action-btn primary";
      btn.textContent = "⬅ Go Back to Safety";
      btn.addEventListener("click", () => {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
          chrome.tabs.goBack(tabs[0].id);
        });
      });
      actionsEl.appendChild(btn);
    }

    const reportBtn = document.createElement("button");
    reportBtn.className = "action-btn secondary";
    reportBtn.textContent = riskLevel === "Safe" ? "Report as suspicious" : "Mark as safe";
    reportBtn.title = "Report to Community Consensus";
    reportBtn.addEventListener("click", async () => {
      reportBtn.textContent = "✓ Reported – thank you!";
      reportBtn.disabled = true;
      try {
        await fetch("http://127.0.0.1:5000/report", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: result.url })
        });
      } catch (e) {
        console.debug("Failed to report to community", e);
      }
    });
    actionsEl.appendChild(reportBtn);
  }

  // ─── Toggle More Reasons ───────────────────────────────────────────────────
  let extraOpen = false;
  toggleMore?.addEventListener("click", () => {
    extraOpen = !extraOpen;
    if (extraOpen) {
      show(reasonsList);
      toggleText.textContent = "Hide analysis";
    } else {
      hide(reasonsList);
      toggleText.textContent = "View analysis";
    }
  });

  // ─── Navigation ───────────────────────────────────────────────────────────
  const dashboardBtn = $("dashboard-btn");
  const viewDashboardLink = $("view-dashboard-link");

  const openDashboard = () => {
    const url = chrome.runtime.getURL("src/dashboard/dashboard.html");
    chrome.tabs.query({ url: url }, (tabs) => {
      if (tabs.length > 0) {
        chrome.tabs.update(tabs[0].id, { active: true });
        // Send message to switch to landing tab
        chrome.tabs.sendMessage(tabs[0].id, { type: "DASHBOARD_SWITCH_TAB", tab: "home" });
      } else {
        chrome.tabs.create({ url: url });
      }
    });
  };

  dashboardBtn?.addEventListener("click", openDashboard);
  viewDashboardLink?.addEventListener("click", (e) => {
    e.preventDefault();
    openDashboard();
  });

  // ─── Refresh / Re-analyze ─────────────────────────────────────────────────
  async function triggerReanalysis(tabId) {
    const usage = await trackScan();
    if (usage.exceeded) {
      alert("Scan limit reached for your current plan. Please upgrade to Pro.");
      return;
    }
    updatePlanUI();

    refreshBtn?.classList.add("spinning");
    setState("loading");
    chrome.runtime.sendMessage({ type: "RE_ANALYZE", tabId }, () => {
      // Result will come via listener below
    });
    // Safety fallback
    setTimeout(() => refreshBtn?.classList.remove("spinning"), 4000);
  }

  refreshBtn?.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) triggerReanalysis(tabs[0].id);
    });
  });

  btnAnalyze?.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) triggerReanalysis(tabs[0].id);
    });
  });

  // ─── Live updates from background ─────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "ANALYSIS_RESULT") {
      refreshBtn?.classList.remove("spinning");
      renderResult(msg.result);
    }
  });

  // ─── Auth System ───────────────────────────────────────────────────────────
  const authView = $("auth-view");
  const appView = $("app");
  const logoutBtn = $("logout-btn");
  const authHeaderText = $("auth-header-text");

  // Dynamically setup the Auth View depending on state
  async function setupAuthUI() {
    const { phishermanMasterPassword } = await chrome.storage.local.get("phishermanMasterPassword");
    const container = document.getElementById("auth-form-container");

    if (!phishermanMasterPassword) {
      authHeaderText.textContent = "Create an account to continue";
      container.innerHTML = `
        <div class="auth-buttons-wrap">
          <button class="btn-auth-social" id="btn-google">
            <svg viewBox="0 0 24 24" width="16" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
            Sign in with Google
          </button>
          
          <div class="auth-divider"><span>or</span></div>
          
          <button class="btn-auth-social" id="btn-email-signup">
            Create Account with Password
          </button>
        </div>
      `;

      // Real Google Identity Logins
      const googleLogin = async (event) => {
        const btn = event.currentTarget;
        btn.innerHTML = `<span class="loading-ring" style="width:16px;height:16px;border-width:2px;"></span> Connecting...`;

        // 1. Tell Chrome to pop open the native Google Login window
        chrome.identity.getAuthToken({ interactive: true }, async function (token) {
          if (chrome.runtime.lastError || !token) {
            console.error(chrome.runtime.lastError);
            btn.innerHTML = `Sign in with Google`;
            alert("Google login failed or was cancelled.");
            return;
          }

          // 2. We have the token! Save the session and unlock the extension.
          await chrome.storage.local.set({ phishermanMasterPassword: "google-authenticated" });
          await chrome.storage.session.set({ phishermanUnlocked: true });

          // Start the app!
          startApp();
        });
      };

      document.getElementById("btn-google").addEventListener("click", googleLogin);

      document.getElementById("btn-email-signup").addEventListener("click", () => {
        authHeaderText.textContent = "Secure your account";
        container.innerHTML = `
          <form class="auth-form" id="setup-form">
            <input type="tel" class="auth-input" id="setup-phone" placeholder="Phone Number (for Alerts)" required>
            <input type="password" class="auth-input" id="new-pwd" placeholder="New Password" required minlength="8">
            <input type="password" class="auth-input" id="confirm-pwd" placeholder="Confirm Password" required minlength="8">
            <label style="display:flex;gap:8px;font-size:11px;color:var(--c-muted);margin-bottom:8px;">
              <input type="checkbox" id="auth-terms" required> I agree to the Terms of Use
            </label>
            <p id="setup-error" class="auth-error hidden"></p>
            <button type="submit" class="btn-auth-primary">Create Account</button>
            <button type="button" class="btn-auth-social" id="btn-back" style="margin-top:4px;">Back</button>
          </form>
        `;
        document.getElementById("btn-back").addEventListener("click", setupAuthUI);
        document.getElementById("setup-form").addEventListener("submit", async (e) => {
          e.preventDefault();
          const p1 = document.getElementById("new-pwd").value;
          const p2 = document.getElementById("confirm-pwd").value;
          const phone = document.getElementById("setup-phone").value;
          const err = document.getElementById("setup-error");

          if (p1 !== p2) {
            err.textContent = "Passwords do not match";
            err.classList.remove("hidden");
            return;
          }

          await chrome.storage.local.set({ phishermanMasterPassword: p1, phishermanPhone: phone });
          await chrome.storage.session.set({ phishermanUnlocked: true });
          startApp();
        });
      });

    } else {
      // Unlock Screen
      authHeaderText.textContent = "Welcome Back!";
      container.innerHTML = `
        <form class="auth-form" id="unlock-form">
          <input type="password" class="auth-input" id="unlock-pwd" placeholder="Enter Password" required>
          <p id="auth-error" class="auth-error hidden"></p>
          <button type="submit" class="btn-auth-primary">Unlock</button>
        </form>
        <div class="auth-divider"><span>or</span></div>
        <button class="btn-auth-social" id="btn-google-unlock" style="width: 100%;">
          <svg viewBox="0 0 24 24" width="16" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
          Sign in with Google
        </button>
      `;

      const googleLogin = async (event) => {
        const btn = event.currentTarget;
        btn.innerHTML = `<span class="loading-ring" style="width:16px;height:16px;border-width:2px;"></span> Connecting...`;
        chrome.identity.getAuthToken({ interactive: true }, async function(token) {
          if (chrome.runtime.lastError || !token) {
            btn.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg> Sign in with Google`;
            alert("Google login failed.");
            return;
          }
          await chrome.storage.session.set({ phishermanUnlocked: true });
          startApp();
        });
      };
      document.getElementById("btn-google-unlock").addEventListener("click", googleLogin);
      document.getElementById("unlock-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const input = document.getElementById("unlock-pwd").value;
        const err = document.getElementById("auth-error");
        if (input === phishermanMasterPassword || phishermanMasterPassword === "google-authenticated") {
          await chrome.storage.session.set({ phishermanUnlocked: true });
          startApp();
        } else {
          err.textContent = "Incorrect password";
          err.classList.remove("hidden");
        }
      });
    }
  }

  logoutBtn?.addEventListener("click", async () => {
    await chrome.storage.session.remove("phishermanUnlocked");
    hide(appView);
    show(authView);
    document.body.className = "";
    setupAuthUI();
  });


  // Block and Favorite Logic
  const btnFavorite = $("btn-favorite");
  const btnBlock = $("btn-block");
  const childModeToggle = $("child-mode-toggle");

  if (btnFavorite && btnBlock) {
    btnFavorite.addEventListener("click", async () => {
      const score = parseInt($("score-num").textContent) || 0;
      const { phishermanChildMode } = await chrome.storage.local.get("phishermanChildMode");
      if (score >= 60) {
        alert("Cannot add a high-risk site (Score >= 60) to favorites.");
        return;
      }
      const { phishermanFavorites } = await chrome.storage.local.get("phishermanFavorites");
      const fav = phishermanFavorites || [];
      const domain = $("domain-text").textContent;
      if (!fav.includes(domain)) fav.push(domain);
      await chrome.storage.local.set({ phishermanFavorites: fav });
      btnFavorite.textContent = "★ Favorited";
    });

    btnBlock.addEventListener("click", async () => {
      const { phishermanBlocklist } = await chrome.storage.local.get("phishermanBlocklist");
      const bl = phishermanBlocklist || [];
      const domain = $("domain-text").textContent;
      if (!bl.includes(domain)) bl.push(domain);
      await chrome.storage.local.set({ phishermanBlocklist: bl });
      btnBlock.textContent = "⃠ Blocked";
      chrome.tabs.reload(); // Reload to trigger block
    });
  }

  if (btnDeleteCookies) {
    btnDeleteCookies.addEventListener("click", () => {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (!tabs[0]) return;
        chrome.runtime.sendMessage({ type: "DELETE_SITE_COOKIES", tabId: tabs[0].id }, (res) => {
          if (res?.ok) {
            btnDeleteCookies.textContent = "✓ Cookies Deleted";
            // Send toast to content script
            chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_TOAST", text: "Cookies deleted for this site.", icon: "🗑️" });
            setTimeout(() => {
                btnDeleteCookies.textContent = "🗑 Delete Cookies for Site";
                triggerReanalysis(tabs[0].id);
            }, 1500);
          }
        });
      });
    });
  }

  // Quick Actions Handlers
  btnBlockSite?.addEventListener("click", async () => {
    const domain = $("domain-text").textContent;
    const { phishermanBlocklist } = await chrome.storage.local.get("phishermanBlocklist");
    const bl = phishermanBlocklist || [];
    if (!bl.includes(domain)) bl.push(domain);
    await chrome.storage.local.set({ phishermanBlocklist: bl });
    
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_TOAST", text: "Site added to blocklist.", icon: "🚫" });
        setTimeout(() => chrome.tabs.reload(tabs[0].id), 1000);
      }
    });
  });

  btnAnalyzePage?.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) {
        triggerReanalysis(tabs[0].id);
        chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_TOAST", text: "Re-scanning page...", icon: "🔍" });
      }
    });
  });

  btnReportIssue?.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_TOAST", text: "Issue reported to Phisherman AI.", icon: "🚩" });
      }
    });
  });

  if (childModeToggle) {
    chrome.storage.local.get(["phishermanChildMode"], (res) => {
      childModeToggle.checked = !!res.phishermanChildMode;
    });

    childModeToggle.addEventListener("change", async (e) => {
      const isChecked = e.target.checked;
      if (isChecked) {
        const pin = prompt("Set a 4-digit PIN for Child Mode:");
        if (pin && pin.length >= 4) {
          await chrome.storage.local.set({ phishermanChildMode: true, phishermanChildPin: pin });
        } else {
          alert("Invalid PIN.");
          e.target.checked = false;
        }
      } else {
        const { phishermanChildPin } = await chrome.storage.local.get("phishermanChildPin");
        const pin = prompt("Enter PIN to disable Child Mode:");
        if (pin === phishermanChildPin) {
          await chrome.storage.local.set({ phishermanChildMode: false });
        } else {
          alert("Incorrect PIN.");
          e.target.checked = true;
        }
      }
    });
  }

  // ─── Plan & Usage UI ───────────────────────────────────────────────────────
  async function updatePlanUI() {
    const stats = await getUsageStats();
    const plan = stats.plan;
    
    // Update Badge
    const badge = $("plan-badge");
    if (badge) {
      badge.textContent = plan.badge;
      badge.style.background = plan.color;
      badge.style.color = plan.id === "free" ? "#020617" : "#FFF";
    }

    // Update Usage Text
    const usageText = $("usage-text");
    if (usageText) {
      usageText.textContent = `Scans: ${stats.scansToday} / ${stats.scanLimit === Infinity ? "Unlimited" : stats.scanLimit}`;
    }

    // Update Upgrade Link
    const upgradeLink = $("upgrade-link");
    if (upgradeLink) {
      if (plan.id !== "free") {
        hide(upgradeLink);
      } else {
        show(upgradeLink);
        upgradeLink.onclick = (e) => {
          e.preventDefault();
          chrome.tabs.create({ url: chrome.runtime.getURL("src/dashboard/dashboard.html#settings") });
        };
      }
    }

    // Disable Child Mode toggle if not allowed
    const childToggle = $("child-mode-toggle");
    const childLabel = $("child-mode-label");
    if (childToggle && childLabel) {
      if (!plan.features.parentalControls) {
        childToggle.disabled = true;
        childLabel.textContent = "Child Mode (Pro)";
        childLabel.style.color = "var(--c-muted)";
      }
    }
  }

  // ─── Init ──────────────────────────────────────────────────────────────────
  async function initAuth() {
    updatePlanUI();
    const { phishermanUnlocked } = await chrome.storage.session.get("phishermanUnlocked");
    if (phishermanUnlocked) {
      startApp();
    } else {
      hide(appView);
      show(authView);
      setupAuthUI();
    }
  }

  function startApp() {
    hide(authView);
    show(appView);
    setState("loading");

    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      const tab = tabs[0];
      if (!tab) { setState("nodata"); return; }

      if (!tab.url?.startsWith("http")) {
        nodataState.querySelector("p").textContent =
          "Phisherman doesn't run on browser internal pages.";
        setState("nodata");
        return;
      }

      chrome.runtime.sendMessage({ type: "GET_RESULT", tabId: tab.id }, response => {
        const result = response?.result;
        if (!result || result.loading) {
          setState("loading");
          chrome.runtime.sendMessage({ type: "RE_ANALYZE", tabId: tab.id });
        } else {
          renderResult(result);
        }
      });
    });
  }

  initAuth();

})();
