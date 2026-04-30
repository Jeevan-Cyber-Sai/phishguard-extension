/**
 * Phisherman – Cookie Intelligence Engine
 * Classifies cookies into Essential, Analytics, Tracking, and Suspicious.
 */

const ANALYTICS_KEYWORDS = [
  "_ga", "_gid", "_gat", "amplitude", "mixpanel", "segment", "hotjar", "optimizely", "intercom"
];

const TRACKING_KEYWORDS = [
  "fbp", "ad", "track", "pixel", "remarketing", "retargeting", "marketing", "doubleclick", "adnxs", "crto", "rlas"
];

const ESSENTIAL_KEYWORDS = [
  "session", "login", "auth", "token", "csrf", "xsrf", "sid", "user_id", "remember", "cart", "checkout"
];

/**
 * Classifies a cookie based on its name, domain, and values.
 */
export function classifyCookie(cookie, pageDomain) {
  const name = cookie.name.toLowerCase();
  const domain = cookie.domain.toLowerCase();
  const isThirdParty = !domain.includes(pageDomain);

  // 1. Suspicious Patterns
  // High entropy names (random-looking long strings) or unusual characters
  if (name.length > 20 && /^[a-z0-9]{20,}$/.test(name)) {
    return { category: "Suspicious", weight: 40, msg: "Randomly generated identifier" };
  }

  // 2. Advertising / Tracking
  if (TRACKING_KEYWORDS.some(kw => name.includes(kw) || domain.includes(kw))) {
    return { category: "Tracking", weight: 30, msg: "Third-party advertising tracker" };
  }

  // 3. Analytics
  if (ANALYTICS_KEYWORDS.some(kw => name.includes(kw) || domain.includes(kw))) {
    return { category: "Analytics", weight: 15, msg: "Behavioral analytics tracker" };
  }

  // 4. Essential
  if (ESSENTIAL_KEYWORDS.some(kw => name.includes(kw)) || !isThirdParty) {
    // If it's first-party and doesn't match tracker patterns, assume it's essential/functional
    return { category: "Essential", weight: 0, msg: "Functional cookie" };
  }

  // Default to functional if first party, otherwise tracking
  return isThirdParty 
    ? { category: "Tracking", weight: 20, msg: "General third-party cookie" }
    : { category: "Essential", weight: 0, msg: "Site functional data" };
}

/**
 * Analyzes a list of cookies for a given domain and returns summary statistics.
 */
export function analyzeCookies(cookies, pageDomain) {
  const stats = {
    total: cookies.length,
    essential: 0,
    analytics: 0,
    tracking: 0,
    suspicious: 0,
    details: []
  };

  cookies.forEach(c => {
    const classification = classifyCookie(c, pageDomain);
    const cat = classification.category.toLowerCase();
    stats[cat]++;
    stats.details.push({
      name: c.name,
      domain: c.domain,
      category: classification.category,
      explanation: classification.msg,
      isThirdParty: !c.domain.includes(pageDomain),
      weight: classification.weight
    });
  });

  return stats;
}

/**
 * Generates user-friendly explanations for cookie risk.
 */
export function getCookieExplanations(stats) {
  const explanations = [];

  if (stats.tracking > 5) {
    explanations.push("This site uses multiple tracking cookies to follow your activity.");
  } else if (stats.tracking > 0) {
    explanations.push("Third-party tracking cookies are present on this page.");
  }

  if (stats.analytics > 3) {
    explanations.push("Behavioral analytics tools are monitoring your session.");
  }

  if (stats.suspicious > 0) {
    explanations.push("Detected unusual or suspicious cookie patterns from unknown domains.");
  }

  if (stats.tracking + stats.analytics > stats.essential) {
    explanations.push("The volume of tracking cookies outweighs functional site cookies.");
  }

  return explanations.slice(0, 3); // Max 3 for brevity
}
