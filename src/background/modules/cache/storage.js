/**
 * Storage — chrome.storage.local wrapper for security module data.
 *
 * Data is keyed by hostname and namespaced by module name so multiple
 * modules can share the same storage layer without collisions.
 *
 * Schema per entry:
 *   threat-sense:<module>:<hostname> => { data: {...}, ts: <epoch ms> }
 */

const KEY_PREFIX = 'threat-sense';
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function makeKey(moduleName, hostname) {
  return `${KEY_PREFIX}:${moduleName}:${hostname}`;
}

/**
 * Store a record for a hostname under the given module namespace.
 * @param {string} moduleName
 * @param {string} hostname
 * @param {object} data
 */
export async function set(moduleName, hostname, data) {
  const key = makeKey(moduleName, hostname);
  await chrome.storage.local.set({ [key]: { data, ts: Date.now() } });
}

/**
 * Retrieve a record, returning null if missing or expired.
 * @param {string} moduleName
 * @param {string} hostname
 * @param {number} [ttlMs]
 * @returns {Promise<object|null>}
 */
export async function get(moduleName, hostname, ttlMs = DEFAULT_TTL_MS) {
  const key = makeKey(moduleName, hostname);
  const result = await chrome.storage.local.get(key);
  const entry = result[key];
  if (!entry) return null;
  if (Date.now() - entry.ts > ttlMs) {
    await chrome.storage.local.remove(key);
    return null;
  }
  return entry.data;
}

/**
 * Return all stored records for a module, sorted by most recent first.
 * @param {string} moduleName
 * @param {number} [ttlMs]
 * @returns {Promise<Array<{hostname: string, data: object, ts: number}>>}
 */
export async function getAll(moduleName, ttlMs = DEFAULT_TTL_MS) {
  const prefix = `${KEY_PREFIX}:${moduleName}:`;
  const allItems = await chrome.storage.local.get(null);
  const now = Date.now();

  return Object.entries(allItems)
    .filter(([key]) => key.startsWith(prefix))
    .filter(([, entry]) => now - entry.ts <= ttlMs)
    .map(([key, entry]) => ({
      hostname: key.slice(prefix.length),
      data: entry.data,
      ts: entry.ts,
    }))
    .sort((a, b) => b.ts - a.ts);
}

/**
 * Remove a stored record for a hostname.
 */
export async function remove(moduleName, hostname) {
  await chrome.storage.local.remove(makeKey(moduleName, hostname));
}

/**
 * Clear all records for a module.
 */
export async function clearModule(moduleName) {
  const prefix = `${KEY_PREFIX}:${moduleName}:`;
  const allItems = await chrome.storage.local.get(null);
  const keys = Object.keys(allItems).filter((k) => k.startsWith(prefix));
  if (keys.length > 0) {
    await chrome.storage.local.remove(keys);
  }
}
