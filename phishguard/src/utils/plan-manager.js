/**
 * Phisherman – Plan Manager
 * Handles freemium tier logic, feature gating, and usage tracking.
 */

// ─── Plan Definitions ─────────────────────────────────────────────────────────
export const PLANS = {
  free: {
    id: "free",
    name: "Free",
    price: "₹0",
    badge: "FREE",
    color: "#94A3B8",
    scansPerDay: 50,
    historyDays: 7,
    features: {
      basicDetection: true,
      cookieIntelligence: false,
      parentalControls: false,
      weeklyReport: false,
      emailLeakChecker: false,
      priorityUpdates: false,
      exportConfig: true,
      unlimitedScans: false,
    }
  },
  pro: {
    id: "pro",
    name: "Pro",
    price: "₹299/mo",
    priceYearly: "₹2,499/yr",
    badge: "PRO",
    color: "#3B82F6",
    scansPerDay: Infinity,
    historyDays: 90,
    features: {
      basicDetection: true,
      cookieIntelligence: true,
      parentalControls: true,
      weeklyReport: true,
      emailLeakChecker: true,
      priorityUpdates: true,
      exportConfig: true,
      unlimitedScans: true,
    }
  },
  enterprise: {
    id: "enterprise",
    name: "Enterprise",
    price: "₹399/user/mo",
    badge: "ENTERPRISE",
    color: "#10B981",
    scansPerDay: Infinity,
    historyDays: 365,
    features: {
      basicDetection: true,
      cookieIntelligence: true,
      parentalControls: true,
      weeklyReport: true,
      emailLeakChecker: true,
      priorityUpdates: true,
      exportConfig: true,
      unlimitedScans: true,
    }
  }
};

// ─── Plan Manager ─────────────────────────────────────────────────────────────

/** Get current plan from storage */
export async function getCurrentPlan() {
  const { phishermanPlan } = await chrome.storage.local.get("phishermanPlan");
  return PLANS[phishermanPlan] || PLANS.free;
}

/** Set plan */
export async function setPlan(planId) {
  if (!PLANS[planId]) return false;
  await chrome.storage.local.set({ phishermanPlan: planId });
  return true;
}

/** Check if a feature is available */
export async function hasFeature(featureKey) {
  const plan = await getCurrentPlan();
  return !!plan.features[featureKey];
}

/** Track daily scan usage */
export async function trackScan() {
  const plan = await getCurrentPlan();
  const today = new Date().toISOString().slice(0, 10);
  const { phishermanUsage } = await chrome.storage.local.get("phishermanUsage");
  const usage = phishermanUsage || {};

  if (usage.date !== today) {
    usage.date = today;
    usage.scans = 0;
  }

  usage.scans = (usage.scans || 0) + 1;
  await chrome.storage.local.set({ phishermanUsage: usage });

  return {
    used: usage.scans,
    limit: plan.scansPerDay,
    remaining: plan.scansPerDay === Infinity ? Infinity : plan.scansPerDay - usage.scans,
    exceeded: usage.scans > plan.scansPerDay
  };
}

/** Get usage stats */
export async function getUsageStats() {
  const plan = await getCurrentPlan();
  const today = new Date().toISOString().slice(0, 10);
  const { phishermanUsage } = await chrome.storage.local.get("phishermanUsage");
  const usage = phishermanUsage || {};

  const scansToday = (usage.date === today) ? (usage.scans || 0) : 0;

  return {
    plan: plan,
    scansToday,
    scanLimit: plan.scansPerDay,
    remaining: plan.scansPerDay === Infinity ? "Unlimited" : Math.max(0, plan.scansPerDay - scansToday),
    historyDays: plan.historyDays,
  };
}
