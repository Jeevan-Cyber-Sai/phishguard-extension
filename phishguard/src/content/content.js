/**
 * Phisherman – Content Script
 * Handles in-page UI: soft warning banner + phishing overlay.
 */

(function () {
  "use strict";

  let bannerShown = false;
  let overlayShown = false;

  // ─── Listen for messages from background ─────────────────────────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SHOW_OVERLAY" && !overlayShown) {
      overlayShown = true;
      showPhishingOverlay(msg.result);
    }
    if (msg.type === "SHOW_BANNER" && !bannerShown) {
      bannerShown = true;
      showSuspiciousBanner(msg.result);
    }
  });

  // ─── Suspicious Banner (non-intrusive) ────────────────────────────────────
  function showSuspiciousBanner(result) {
    if (document.getElementById("phisherman-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phisherman-banner";
    banner.innerHTML = `
      <div class="phisherman-banner-inner">
        <div class="phisherman-banner-icon">⚠️</div>
        <div class="phisherman-banner-content">
          <strong>Phisherman Warning</strong>
          <span>${result.topReasons?.[0] || "This site shows some signs of being suspicious."}</span>
        </div>
        <button class="phisherman-banner-close" id="phisherman-banner-close" aria-label="Dismiss">✕</button>
      </div>
    `;

    document.body.prepend(banner);

    document.getElementById("phisherman-banner-close").addEventListener("click", () => {
      banner.classList.add("phisherman-banner-hide");
      setTimeout(() => banner.remove(), 400);
    });

    // Auto-dismiss after 12 seconds
    setTimeout(() => {
      if (document.contains(banner)) {
        banner.classList.add("phisherman-banner-hide");
        setTimeout(() => banner.remove(), 400);
      }
    }, 12000);
  }

  // ─── Phishing Overlay (full-screen, high risk only) ────────────────────────
  function showPhishingOverlay(result) {
    if (document.getElementById("phisherman-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "phisherman-overlay";
    overlay.setAttribute("role", "alertdialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-labelledby", "phisherman-overlay-title");

    const topReasons = (result.topReasons || []).slice(0, 3);
    const reasonsHTML = topReasons.map(r =>
      `<li class="phisherman-reason-item">
        <span class="phisherman-reason-icon">⚠</span>
        <span>${r}</span>
      </li>`
    ).join("");

    overlay.innerHTML = `
      <div class="phisherman-overlay-backdrop"></div>
      <div class="phisherman-overlay-card">
        <div class="phisherman-overlay-shield"><img src="${chrome.runtime.getURL('icons/icon128.png')}" width="80" height="80" alt="Logo" style="vertical-align: middle;"></div>
        <h1 class="phisherman-overlay-title" id="phisherman-overlay-title">
          Danger: Possible Phishing Site
        </h1>
        <p class="phisherman-overlay-subtitle">
          Phisherman has detected signs that this website may be trying to steal your personal information or passwords.
        </p>
        <div class="phisherman-overlay-score">
          <span class="phisherman-score-num">${result.score}</span>
          <span class="phisherman-score-label">Risk Score</span>
        </div>
        ${topReasons.length ? `
        <ul class="phisherman-reasons-list">
          ${reasonsHTML}
        </ul>` : ""}
        <div class="phisherman-overlay-actions">
          <button class="phisherman-btn-back" id="phisherman-go-back">
            ← Go Back (Recommended)
          </button>
          <button class="phisherman-btn-continue" id="phisherman-continue">
            Continue Anyway
          </button>
        </div>
        <p class="phisherman-overlay-footer">
          Phisherman · Your privacy is our priority
        </p>
      </div>
    `;

    document.body.appendChild(overlay);

    // Prevent background scroll
    document.body.style.overflow = "hidden";

    // Animate in
    requestAnimationFrame(() => overlay.classList.add("phisherman-overlay-visible"));

    document.getElementById("phisherman-go-back").addEventListener("click", () => {
      history.back();
      setTimeout(() => window.close(), 300);
    });

    document.getElementById("phisherman-continue").addEventListener("click", () => {
      overlay.classList.remove("phisherman-overlay-visible");
      setTimeout(() => {
        overlay.remove();
        document.body.style.overflow = "";
      }, 400);
      // Show a persistent small badge so user stays informed
      showSuspiciousBanner({ topReasons: ["You chose to continue on a flagged site. Be cautious."] });
    });
  }

})();


  // ─── Visual Scanner & Auto Protection ────────────────────────────────────
  function visualScanner() {
      // Find suspicious links
      const links = document.querySelectorAll('a');
      links.forEach(link => {
          if (link.href && link.hostname && link.hostname !== window.location.hostname) {
              // Highlight external redirects or suspicious links
              link.style.border = "2px solid red";
              link.style.boxSizing = "border-box";
              link.title = "Suspicious external link";
          }
      });
  }

  function autoProtectPage(isChildMode) {
      if (isChildMode) {
          // Blue screen of death (protection)
          document.documentElement.innerHTML = `
            <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; background-color:#0284c7; color:white; font-family:sans-serif; text-align:center;">
              <h1 style="font-size:64px; margin-bottom:20px;"><img src="${chrome.runtime.getURL('icons/icon128.png')}" width="80" height="80" alt="Logo" style="vertical-align: middle;"> Phisherman</h1>
              <h2>Access Blocked by Child Mode</h2>
              <p>You were entering an unsafe website, but we have got you safe and secure.</p>
              <button onclick="history.back()" style="margin-top:30px; padding:15px 30px; font-size:18px; border:none; border-radius:8px; background:white; color:#0284c7; cursor:pointer;">Return to Previous Page</button>
            </div>
          `;
          return;
      }

      // Blur sensitive fields and disable forms
      const forms = document.querySelectorAll('form');
      forms.forEach(form => {
          const inputs = form.querySelectorAll('input, button');
          inputs.forEach(input => {
              input.disabled = true;
              if (input.type === 'password' || input.type === 'text') {
                  input.style.filter = "blur(4px)";
              }
          });
      });
      
      const banner = document.createElement("div");
      banner.style.position = "fixed";
      banner.style.top = "0"; banner.style.left = "0"; banner.style.width = "100%";
      banner.style.background = "#ef4444"; banner.style.color = "white";
      banner.style.textAlign = "center"; banner.style.padding = "10px";
      banner.style.zIndex = "999999";
      banner.innerHTML = `Phisherman Auto-Protection: Forms Disabled. <button id="phisherman-override" style="background:white; color:#ef4444; border:none; padding:5px 10px; border-radius:4px; cursor:pointer;">Override</button>`;
      document.body.prepend(banner);

      document.getElementById("phisherman-override").addEventListener("click", () => {
          banner.remove();
          forms.forEach(form => {
              const inputs = form.querySelectorAll('input, button');
              inputs.forEach(input => {
                  input.disabled = false;
                  input.style.filter = "none";
              });
          });
      });
  }

  function showRiskFeedback(score) {
      let color = score < 40 ? '#22c55e' : (score < 70 ? '#f59e0b' : '#ef4444');
      const feedback = document.createElement("div");
      feedback.style.position = "fixed";
      feedback.style.top = "0"; feedback.style.left = "0"; feedback.style.width = "100%"; feedback.style.height = "5px";
      feedback.style.background = color;
      feedback.style.zIndex = "999999";
      feedback.style.transition = "opacity 2s";
      document.body.appendChild(feedback);
      setTimeout(() => feedback.style.opacity = "0", 2000);
      setTimeout(() => feedback.remove(), 4000);
  }

  // Check enforcement on load
  chrome.storage.local.get(["phishermanBlocklist", "phishermanChildMode"], (res) => {
      const bl = res.phishermanBlocklist || [];
      const isChildMode = res.phishermanChildMode || false;
      const domain = window.location.hostname.replace(/^www\./, '');
      
      if (bl.includes(domain)) {
          document.documentElement.innerHTML = `<div style="padding:50px; text-align:center; font-family:sans-serif; background:#f0f9ff; height:100vh;"><h1>Site Blocked by Phisherman</h1><p>You have manually blocked this site.</p></div>`;
          return;
      }
      
      // Request analysis score to apply overlay/protection
      chrome.runtime.sendMessage({ type: "CHECK_PHISHING" }, (result) => {
          if (result && result.score !== undefined) {
              showRiskFeedback(result.score);
              if (result.score >= 70) {
                  autoProtectPage(isChildMode);
                  if (isChildMode) {
                      chrome.runtime.sendMessage({ type: "SEND_SMS_ALERT", domain: domain });
                  }
              }
              visualScanner();
          }
      });
  });
