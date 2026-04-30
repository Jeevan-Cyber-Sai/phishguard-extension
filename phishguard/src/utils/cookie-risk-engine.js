/**
 * Phisherman – Cookie Risk Engine
 * Computes a normalized risk score based on cookie volume and intent.
 */

export function computeCookieRiskScore(stats) {
  let score = 0;

  // 1. Third-Party Tracking Impact (Primary Driver)
  // Each tracking cookie adds significant risk
  score += stats.tracking * 12;

  // 2. Analytics Impact
  score += stats.analytics * 5;

  // 3. Suspicious Pattern Impact (High Severity)
  score += stats.suspicious * 25;

  // 4. Volume Penalty
  if (stats.total > 20) {
    score += (stats.total - 20) * 1.5;
  }

  // 5. Ratio Penalty
  const trackingRatio = stats.total > 0 ? (stats.tracking + stats.analytics) / stats.total : 0;
  if (trackingRatio > 0.5) {
    score += 15; // Penalty for sites that are mostly trackers
  }

  // Normalize to 0-100
  score = Math.min(Math.round(score), 100);

  // Classification
  let riskLevel = "Low";
  let color = "safe";

  if (score > 60) {
    riskLevel = "High";
    color = "danger";
  } else if (score > 30) {
    riskLevel = "Moderate";
    color = "suspicious";
  }

  return {
    score,
    riskLevel,
    color,
    trackingLevel: score > 65 ? "High Tracking" : score > 35 ? "Moderate Tracking" : "Low Tracking"
  };
}

/**
 * Combines phishing and cookie risks into a unified safety score.
 */
export function computeOverallSafety(phishScore, cookieScore) {
  // Weighted average: Phishing is usually more critical (60/40)
  const combined = (phishScore * 0.6) + (cookieScore * 0.4);
  return Math.min(Math.round(combined), 100);
}
