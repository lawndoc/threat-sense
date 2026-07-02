/**
 * ClickFix Module — detects ClickFix / ClearFake clipboard-hijack payloads.
 *
 * Unlike request-based modules, detection here is driven by clipboard change
 * events forwarded from:
 *   - content/clipboard-interceptor-relay.js  (write intercept, all browsers)
 *   - offscreen/offscreen.js                  (clipboardchange event or polling)
 *
 * The service worker calls onClipboardChange() for each CLIPBOARD_CHANGED
 * message, then injects warning-overlay.js into the active tab if a threat
 * is found.
 */

import { analyzeClipboard } from './detector.js';
import * as storage from '../cache/storage.js';

const MODULE_NAME    = 'clickfix';
const MODULE_VERSION = '0.1.0';

export const clickfixModule = {
  name:    MODULE_NAME,
  version: MODULE_VERSION,

  /** @param {object} eventBus */
  async initialize(eventBus) {
    this._eventBus = eventBus;
    await ensureOffscreenDocument();
    console.log('[ClickFix] Module initialized');
  },

  /**
   * No-op: ClickFix detection is clipboard-driven, not request-driven.
   */
  async onRequest(_details, _hostname) {},

  /**
   * Analyse clipboard text; persist and emit an event if a threat is found.
   *
   * @param {string} text       Raw clipboard text
   * @param {number} tabId      Active tab ID
   * @param {string} hostname   Active tab hostname
   * @returns {Promise<import('./detector.js').DetectionResult>}
   */
  async onClipboardChange(text, tabId, hostname) {
    const result = analyzeClipboard(text);

    if (result.status !== 'detected') return result;

    const existing = await storage.get(MODULE_NAME, hostname);
    let list = [];
    if (existing) {
      list = Array.isArray(existing) ? existing : [existing];
    }

    const record = {
      ...result,
      hostname,
      detectedAt: result.detectedAt || Date.now(),
    };

    list.push(record);

    if (list.length > 50) {
      list.shift();
    }

    await storage.set(MODULE_NAME, hostname, list);

    if (this._eventBus) {
      this._eventBus.emit('clickfix:detected', { hostname, tabId, result });
    }

    console.log(`[ClickFix] Detected on ${hostname}: ${result.indicator.label} (${result.indicator.confidence})`);
    return result;
  },

  /**
   * Return the stored detection result for a hostname.
   * @param {string} hostname
   * @returns {Promise<object|null>}
   */
  async getStatus(hostname) {
    const existing = await storage.get(MODULE_NAME, hostname);
    if (!existing) return null;
    const list = Array.isArray(existing) ? existing : [existing];
    return list.length > 0 ? list[list.length - 1] : null;
  },

  /**
   * Return all stored ClickFix detections, most recent first.
   * @returns {Promise<Array>}
   */
  async getHistory() {
    const rawHistory = await storage.getAll(MODULE_NAME);
    const flattened = [];
    for (const entry of rawHistory) {
      const detections = Array.isArray(entry.data) ? entry.data : [entry.data];
      for (const detection of detections) {
        flattened.push({
          hostname: entry.hostname,
          data: detection,
          ts: detection.detectedAt || entry.ts,
        });
      }
    }
    return flattened.sort((a, b) => b.ts - a.ts);
  },
};

// ── Offscreen document lifecycle ─────────────────────────────────────────────

async function ensureOffscreenDocument() {
  if (!chrome.offscreen) {
    console.warn('[ClickFix] chrome.offscreen API not available — clipboard monitoring disabled');
    return;
  }
  try {
    const exists = await chrome.offscreen.hasDocument();
    if (exists) return;
    await chrome.offscreen.createDocument({
      url:           chrome.runtime.getURL('offscreen/offscreen.html'),
      reasons:       ['CLIPBOARD'],
      justification: 'Monitor clipboard for ClickFix/ClearFake malicious payloads',
    });
  } catch (err) {
    console.warn('[ClickFix] Could not create offscreen document:', err.message);
  }
}
