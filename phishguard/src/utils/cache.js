/**
 * Phisherman – Domain Cache
 * Stores analysis results per domain with TTL expiration.
 */

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

export const domainCache = {
  async get(domain) {
    return new Promise(resolve => {
      chrome.storage.session.get(["phisherman_cache"], result => {
        const cache = result.phisherman_cache || {};
        const entry = cache[domain];
        if (!entry) return resolve(null);
        if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
          // Expired – clean up
          delete cache[domain];
          chrome.storage.session.set({ phisherman_cache: cache });
          return resolve(null);
        }
        resolve(entry.data);
      });
    });
  },

  async set(domain, data) {
    return new Promise(resolve => {
      chrome.storage.session.get(["phisherman_cache"], result => {
        const cache = result.phisherman_cache || {};
        cache[domain] = { data, timestamp: Date.now() };
        // Prune if over 200 entries
        const keys = Object.keys(cache);
        if (keys.length > 200) {
          keys.sort((a, b) => cache[a].timestamp - cache[b].timestamp);
          keys.slice(0, 50).forEach(k => delete cache[k]);
        }
        chrome.storage.session.set({ phisherman_cache: cache }, resolve);
      });
    });
  }
};

export async function getVisitCount(domain) {
  return new Promise(resolve => {
    chrome.storage.local.get(["phisherman_visits"], result => {
      const visits = result.phisherman_visits || {};
      resolve(visits[domain] || 0);
    });
  });
}

export async function incrementVisitCount(domain) {
  return new Promise(resolve => {
    chrome.storage.local.get(["phisherman_visits"], result => {
      const visits = result.phisherman_visits || {};
      visits[domain] = (visits[domain] || 0) + 1;
      chrome.storage.local.set({ phisherman_visits: visits }, resolve);
    });
  });
}
