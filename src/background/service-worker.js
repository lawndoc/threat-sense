/**
 * Service Worker — Threat Sense extension background entry point.
 *
 * Responsibilities:
 *  1. Initialize the module registry with the ClickFix security module.
 *  2. Handle CLIPBOARD_CHANGED messages from content scripts and the offscreen
 *     document, dispatching to the ClickFix module and injecting a warning
 *     overlay when a threat is detected.
 *  3. Handle messages from the popup (getStatus, getHistory, listModules).
 *
 * Note: MV3 service workers are non-persistent. All event listeners MUST be
 * registered at the top level (not inside async blocks) so Chrome can
 * re-register them when the worker restarts.
 */

import * as registry from './modules/core/module-registry.js';
import eventBus from './modules/core/event-bus.js';
import { clickfixModule } from './modules/clickfix/index.js';

// ── Module registration (synchronous, top-level) ─────────────────────────────

registry.registerModule(clickfixModule);

// ── Bootstrap (runs once per service worker lifetime) ────────────────────────

(async () => {
  await registry.initializeModules(eventBus);
  console.log('[Threat Sense] Service worker ready. Modules:', registry.listModules());
})();

// ── Message handler (popup ↔ service worker, content scripts → service worker) ─

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch((err) => {
    console.error('[Threat Sense] Message handler error:', err);
    sendResponse({ error: err.message });
  });
  return true; // keep channel open for async response
});

/**
 * Route messages from the popup, content scripts, and offscreen document.
 * @param {{ type: string, payload?: * }} message
 * @param {chrome.runtime.MessageSender}  sender
 */
async function handleMessage(message, sender) {
  switch (message.type) {
    case 'CLIPBOARD_CHANGED': {
      const { text, source } = message;
      const tab = sender?.tab ?? await getActiveTab();
      if (!tab?.id) return { ok: false, reason: 'no active tab' };

      let hostname = 'unknown';
      try { hostname = new URL(tab.url).hostname; } catch { /* non-url tab */ }

      const result = await clickfixModule.onClipboardChange(text, tab.id, hostname);
      if (result?.status === 'detected') {
        await injectWarningOverlay(tab.id, result.snippet ?? '');
      }
      return { ok: true, source };
    }

    case 'GET_CLICKFIX_STATUS': {
      const { hostname } = message.payload;
      const status = await clickfixModule.getStatus(hostname);
      return { status };
    }

    case 'GET_CLICKFIX_HISTORY': {
      const history = await clickfixModule.getHistory();
      return { history };
    }

    case 'LIST_MODULES': {
      return { modules: registry.listModules() };
    }

    default:
      throw new Error(`Unknown message type: "${message.type}"`);
  }
}

// ── ClickFix helpers ──────────────────────────────────────────────────────────

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab ?? null;
}

async function injectWarningOverlay(tabId, snippet) {
  try {
    // Pass the snippet to the overlay script via a page-scoped temporary global.
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (s) => { window.__ss_overlay_snippet = s; },
      args:  [snippet],
    });
    await chrome.scripting.executeScript({
      target: { tabId },
      files:  ['content/warning-overlay.js'],
    });
  } catch (err) {
    // Tab may be a privileged page (chrome://, PDF, etc.) where scripting is blocked.
    console.warn('[ClickFix] Could not inject warning overlay into tab', tabId, '—', err.message);
  }
}
