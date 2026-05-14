/**
 * ModuleRegistry — plugin system for security modules.
 *
 * Each module must implement:
 *   - name: string
 *   - version: string
 *   - initialize(eventBus): Promise<void>
 *   - onRequest(details, securityInfo): Promise<void>
 *   - getStatus(hostname): Promise<object>
 */

const registry = new Map();

/**
 * Register a security module.
 * @param {object} module
 */
export function registerModule(module) {
  const required = ['name', 'version', 'initialize', 'onRequest', 'getStatus'];
  for (const field of required) {
    if (typeof module[field] === 'undefined') {
      throw new Error(`Module missing required field: "${field}"`);
    }
  }
  if (registry.has(module.name)) {
    console.warn(`[ModuleRegistry] Module "${module.name}" already registered — skipping.`);
    return;
  }
  registry.set(module.name, module);
  console.log(`[ModuleRegistry] Registered module: ${module.name} v${module.version}`);
}

/**
 * Initialize all registered modules.
 * @param {object} eventBus
 */
export async function initializeModules(eventBus) {
  for (const module of registry.values()) {
    try {
      await module.initialize(eventBus);
      console.log(`[ModuleRegistry] Initialized: ${module.name}`);
    } catch (err) {
      console.error(`[ModuleRegistry] Failed to initialize ${module.name}:`, err);
    }
  }
}

/**
 * Dispatch a request event to all registered modules.
 * @param {object} details       — chrome.webRequest details
 * @param {object} securityInfo  — chrome.webRequest.SecurityInfo
 */
export async function dispatchRequest(details, securityInfo) {
  for (const module of registry.values()) {
    try {
      await module.onRequest(details, securityInfo);
    } catch (err) {
      console.error(`[ModuleRegistry] ${module.name}.onRequest error:`, err);
    }
  }
}

/**
 * Get status for a hostname from all modules.
 * @param {string} hostname
 * @returns {Promise<object>} Map of moduleName -> status
 */
export async function getStatusForHost(hostname) {
  const result = {};
  for (const module of registry.values()) {
    try {
      result[module.name] = await module.getStatus(hostname);
    } catch (err) {
      console.error(`[ModuleRegistry] ${module.name}.getStatus error:`, err);
      result[module.name] = { error: err.message };
    }
  }
  return result;
}

/** Return all registered module names and versions. */
export function listModules() {
  return Array.from(registry.values()).map(({ name, version }) => ({ name, version }));
}
