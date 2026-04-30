/**
 * Phisherman – Dashboard Logic
 * Manages the premium Command Center, history, parental controls, and engine settings.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const tabs = document.querySelectorAll('.nav-btn');
  const contents = document.querySelectorAll('.tab-content');

  // ─── Tab Switching ────────────────────────────────────────────────────────
  function switchTab(tabId) {
    tabs.forEach(t => t.classList.remove('active'));
    contents.forEach(c => {
      c.classList.add('hidden');
      c.classList.remove('active');
    });
    
    const activeBtn = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
    if (activeBtn) activeBtn.classList.add('active');
    
    const targetContent = document.getElementById(`tab-${tabId}`);
    if (targetContent) {
      targetContent.classList.remove('hidden');
      targetContent.classList.add('active');
    }
  }

  tabs.forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Listener for messages from popup (e.g. to open a specific tab)
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "DASHBOARD_SWITCH_TAB") {
      switchTab(msg.tab);
    }
  });

  // ─── Global Safety Score & Stats ──────────────────────────────────────────
  async function updateGlobalStatus() {
    const { phishermanHistory } = await chrome.storage.local.get("phishermanHistory");
    const history = phishermanHistory || [];
    
    const statScanned = document.getElementById("stat-scanned");
    const statBlocked = document.getElementById("stat-blocked");
    const statSafe    = document.getElementById("stat-safe");
    const statCookies = document.getElementById("stat-cookies-neutralized");
    const statPrivacy = document.getElementById("stat-privacy-threats");
    const statusText  = document.getElementById("status-text");

    const total = history.length;
    const blocked = history.filter(h => h.riskLevel === "Phishing").length;
    const safe = history.filter(h => h.riskLevel === "Safe").length;
    
    let totalTrackers = 0;
    let highPrivacyRiskSites = 0;
    
    history.forEach(h => {
        if (h.cookieIntelligence) {
            totalTrackers += h.cookieIntelligence.stats.tracking;
            if (h.cookieIntelligence.risk.score > 50) highPrivacyRiskSites++;
        }
    });

    if (statScanned) statScanned.textContent = total;
    if (statBlocked) statBlocked.textContent = blocked;
    if (statSafe)    statSafe.textContent = safe;
    if (statCookies) statCookies.textContent = totalTrackers;
    if (statPrivacy) statPrivacy.textContent = highPrivacyRiskSites;

    // Calculate Global Safety Score (Simple heuristic: % of safe sites vs total)
    let safetyScore = 100;
    if (total > 0) {
      safetyScore = Math.round((safe / total) * 100);
    }

    // Update Status Text
    if (statusText) {
      if (safetyScore > 90) statusText.textContent = "System Optimized: All Clear";
      else if (safetyScore > 70) statusText.textContent = "Stable Protection: Minor Threats";
      else statusText.textContent = "Critical Alert: High Threat Volume";
    }
  }

  // ─── Engine Settings ──────────────────────────────────────────────────────
  const { phishermanSettings } = await chrome.storage.local.get("phishermanSettings");
  let settings = phishermanSettings || { paranoia: 2, safelist: [], blocklist: [] };

  const paranoiaSlider = document.getElementById("paranoia-slider");
  const currentParanoiaText = document.getElementById("current-paranoia-text");
  
  if (paranoiaSlider) {
    paranoiaSlider.value = settings.paranoia;
    const labels = ["Lenient", "Balanced", "Paranoid"];
    if (currentParanoiaText) currentParanoiaText.textContent = labels[settings.paranoia - 1];

    paranoiaSlider.addEventListener("change", async (e) => {
      settings.paranoia = parseInt(e.target.value);
      if (currentParanoiaText) currentParanoiaText.textContent = labels[settings.paranoia - 1];
      await chrome.storage.local.set({ phishermanSettings: settings });
    });
  }

  // ─── Parental Center ──────────────────────────────────────────────────────
  async function loadParentalSettings() {
    const { phishermanChildMode, phishermanChildPin, phishermanPhone } = await chrome.storage.local.get([
      "phishermanChildMode", "phishermanChildPin", "phishermanPhone"
    ]);

    const childToggle = document.getElementById("p-child-toggle");
    const childPinInput = document.getElementById("p-child-pin");
    const alertPhoneInput = document.getElementById("p-alert-phone");

    if (childToggle) childToggle.checked = !!phishermanChildMode;
    if (childPinInput && phishermanChildPin) childPinInput.value = phishermanChildPin;
    if (alertPhoneInput && phishermanPhone) alertPhoneInput.value = phishermanPhone;

    document.getElementById("btn-save-pin")?.addEventListener("click", async () => {
      const pin = childPinInput.value.trim();
      if (pin.length >= 4) {
        await chrome.storage.local.set({ phishermanChildPin: pin });
        alert("Parental PIN updated successfully.");
      } else {
        alert("PIN must be at least 4 digits.");
      }
    });

    document.getElementById("btn-save-phone")?.addEventListener("click", async () => {
      const phone = alertPhoneInput.value.trim();
      await chrome.storage.local.set({ phishermanPhone: phone });
      alert("Alert phone number saved.");
    });

    childToggle?.addEventListener("change", async (e) => {
      const isChecked = e.target.checked;
      const { phishermanChildPin } = await chrome.storage.local.get("phishermanChildPin");
      
      if (!isChecked) {
        const pin = prompt("Enter Parental PIN to disable Child Mode:");
        if (pin === phishermanChildPin) {
          await chrome.storage.local.set({ phishermanChildMode: false });
        } else {
          alert("Incorrect PIN.");
          e.target.checked = true;
        }
      } else {
        await chrome.storage.local.set({ phishermanChildMode: true });
      }
    });

    const autoProtectToggle = document.getElementById("auto-protect-toggle");
    const { phishermanAutoProtect } = await chrome.storage.local.get("phishermanAutoProtect");
    if (autoProtectToggle) {
        autoProtectToggle.checked = !!phishermanAutoProtect;
        autoProtectToggle.addEventListener("change", async (e) => {
            await chrome.storage.local.set({ phishermanAutoProtect: e.target.checked });
        });
    }
  }

  // ─── Lists & Tools ────────────────────────────────────────────────────────
  function renderLists() {
    const safeList = document.getElementById("safe-list");
    const blockList = document.getElementById("block-list");
    
    if (safeList) {
      safeList.innerHTML = settings.safelist.map((domain, i) => `
        <li>${domain} <button onclick="removeDomain('safe', ${i})">✕</button></li>
      `).join("");
    }
    
    if (blockList) {
      blockList.innerHTML = settings.blocklist.map((domain, i) => `
        <li>${domain} <button onclick="removeDomain('block', ${i})">✕</button></li>
      `).join("");
    }
  }

  window.removeDomain = async (type, index) => {
    if (type === 'safe') settings.safelist.splice(index, 1);
    else settings.blocklist.splice(index, 1);
    await chrome.storage.local.set({ phishermanSettings: settings });
    renderLists();
  };

  document.getElementById("btn-add-safe")?.addEventListener("click", async () => {
    const val = document.getElementById("safe-input").value.trim().toLowerCase();
    if (val && !settings.safelist.includes(val)) {
      settings.safelist.push(val);
      await chrome.storage.local.set({ phishermanSettings: settings });
      document.getElementById("safe-input").value = "";
      renderLists();
    }
  });

  document.getElementById("btn-add-block")?.addEventListener("click", async () => {
    const val = document.getElementById("block-input").value.trim().toLowerCase();
    if (val && !settings.blocklist.includes(val)) {
      settings.blocklist.push(val);
      await chrome.storage.local.set({ phishermanSettings: settings });
      document.getElementById("block-input").value = "";
      renderLists();
    }
  });

  // ─── Export / Import ──────────────────────────────────────────────────────
  document.getElementById("btn-export-settings")?.addEventListener("click", () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(settings));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "phisherman_config.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  });

  const importFile = document.getElementById("import-file");
  document.getElementById("btn-import-settings")?.addEventListener("click", () => importFile.click());

  importFile?.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const imported = JSON.parse(event.target.result);
        if (imported.paranoia && imported.safelist) {
          settings = imported;
          await chrome.storage.local.set({ phishermanSettings: settings });
          renderLists();
          alert("Configuration imported successfully!");
        }
      } catch (err) {
        alert("Invalid configuration file.");
      }
    };
    reader.readAsText(file);
  });

  // ─── History Logic ────────────────────────────────────────────────────────
  async function loadHistory() {
    const { phishermanHistory } = await chrome.storage.local.get("phishermanHistory");
    const history = phishermanHistory || [];
    const tbody = document.getElementById("history-tbody");
    if (!tbody) return;

    const thead = tbody.closest('table').querySelector('thead');
    if (thead) {
        thead.innerHTML = `
            <tr>
              <th>Time</th>
              <th>Domain</th>
              <th>Phish Score</th>
              <th>Cookie Risk</th>
              <th>Status</th>
              <th>Detailed Analysis</th>
            </tr>
        `;
    }

    tbody.innerHTML = history.slice().reverse().slice(0, 50).map((item) => `
      <tr data-time="${item.time}">
        <td>${new Date(item.time).toLocaleTimeString()}</td>
        <td>${item.domain || "Unknown"}</td>
        <td style="font-weight:700;">${item.score}</td>
        <td style="font-weight:700; color: ${item.cookieIntelligence ? 'var(--c-' + item.cookieIntelligence.risk.color + ')' : 'var(--c-muted)'}">
            ${item.cookieIntelligence ? item.cookieIntelligence.risk.score : '--'}
        </td>
        <td>
          <span class="status-pill ${item.riskLevel === 'Phishing' ? 'danger' : 'safe'}">
            ${item.riskLevel}
          </span>
        </td>
        <td>
          <button class="primary-btn view-btn" style="padding: 4px 12px; font-size: 11px;" 
            data-url="${item.url}" data-domain="${item.domain}">Inspect AI Evidence</button>
        </td>
      </tr>
    `).join("");

    tbody.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const domain = e.target.dataset.domain;
        const time = parseInt(e.target.closest('tr').dataset.time);
        const item = history.find(h => h.domain === domain && h.time === time);
        openExplainPanel(domain, item);
      });
    });
  }

  document.getElementById("btn-clear-history")?.addEventListener("click", async () => {
    if (confirm("Are you sure you want to clear all security logs?")) {
      await chrome.storage.local.set({ phishermanHistory: [] });
      loadHistory();
      updateGlobalStatus();
    }
  });

  // ─── Explain Modal ────────────────────────────────────────────────────────
  const explainPanel = document.getElementById("explain-panel");
  const closeExplain = document.getElementById("close-explain");
  const explainDomain = document.getElementById("explain-domain");
  const explainScore = document.getElementById("explain-score");
  const explainTrend = document.getElementById("explain-trend");
  const explainReasons = document.getElementById("explain-reasons");

  closeExplain?.addEventListener("click", () => explainPanel.classList.add("hidden"));

  async function openExplainPanel(domain, historyItem) {
    explainPanel.classList.remove("hidden");
    explainDomain.textContent = domain;
    explainReasons.innerHTML = "<li class='pulse'>Extracting deep analysis data...</li>";
    
    const { phishermanHistoryExt } = await chrome.storage.local.get("phishermanHistoryExt");
    const hist = (phishermanHistoryExt && phishermanHistoryExt[domain]) || { scores: [], trend: "stable" };
    
    explainScore.textContent = historyItem ? historyItem.score : (hist.scores.length > 0 ? hist.scores[hist.scores.length - 1] : "--");
    explainTrend.textContent = hist.trend.toUpperCase();
    explainTrend.style.color = hist.trend === "increasing" ? "var(--c-danger)" : "var(--c-safe)";

    if (historyItem && historyItem.reasons && historyItem.reasons.length > 0) {
      explainReasons.innerHTML = historyItem.reasons.map(r => `
        <li style="border-left: 3px solid ${historyItem.score < 35 ? 'var(--c-safe)' : 'var(--c-danger)'}">
          ${r}
        </li>
      `).join("");
    } else {
      // Fallback: Try to fetch from session cache if it's the current session
      chrome.storage.session.get(["phisherman_cache"], (res) => {
        const cache = res.phisherman_cache || {};
        const entry = cache[domain];
        if (entry && entry.data && entry.data.topReasons) {
          explainReasons.innerHTML = entry.data.topReasons.map(r => `
            <li style="border-left: 3px solid ${entry.data.score < 35 ? 'var(--c-safe)' : 'var(--c-danger)'}">
              ${r}
            </li>
          `).join("");
        } else {
          explainReasons.innerHTML = "<li>No detailed analysis available for this historical entry.</li>";
        }
      });
    }
  }

  // Initial Load
  updateGlobalStatus();
  loadHistory();
  renderLists();
  loadParentalSettings();
});
