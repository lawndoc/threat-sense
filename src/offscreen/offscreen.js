/**
 * Offscreen document — clipboard monitoring for ClickFix/ClearFake detection.
 *
 * Two-tier detection strategy (most-capable tier wins at runtime):
 *
 *   Tier 1 — clipboardchange event (Chrome/Edge 144+, Opera 128+)
 *     Fires whenever the system clipboard changes. Event-driven; most efficient.
 *     Feature-detected at startup; used when available.
 *
 *   Tier 2 — setInterval polling (Chrome 116+ for offscreen; universal fallback)
 *     Polls navigator.clipboard.readText() every POLL_INTERVAL_MS.
 *     Active only when Tier 1 is not available.
 *
 * On any detected change the new clipboard text is forwarded to the service
 * worker via chrome.runtime.sendMessage({ type: 'CLIPBOARD_CHANGED', ... }).
 */

const POLL_INTERVAL_MS = 2000;

let lastKnownClipboard = null;
let pollingInterval    = null;

// ── Shared handler ────────────────────────────────────────────────────────────

async function onClipboardChange(source) {
  let text;
  try {
    text = await navigator.clipboard.readText();
  } catch {
    // Permission denied or clipboard unavailable — silent fail.
    return;
  }

  if (text === lastKnownClipboard) return;
  lastKnownClipboard = text;

  if (!text) return;

  chrome.runtime.sendMessage({ type: 'CLIPBOARD_CHANGED', text, source });
}

// ── Tier 1: clipboardchange event ────────────────────────────────────────────

if ('onclipboardchange' in navigator.clipboard) {
  navigator.clipboard.addEventListener('clipboardchange', () => onClipboardChange('offscreen-event'));
  console.log('[ClickFix:offscreen] Tier 1 active — clipboardchange event');

} else {
  // ── Tier 2: polling fallback ──────────────────────────────────────────────
  startPolling();
  console.log('[ClickFix:offscreen] Tier 2 active — polling every', POLL_INTERVAL_MS, 'ms');
}

// ── Polling helpers (Tier 2) ──────────────────────────────────────────────────

function startPolling() {
  if (pollingInterval !== null) return;
  pollingInterval = setInterval(() => onClipboardChange('offscreen-poll'), POLL_INTERVAL_MS);
}

function stopPolling() {
  if (pollingInterval === null) return;
  clearInterval(pollingInterval);
  pollingInterval = null;
}

// ── Message listener (service worker → offscreen) ────────────────────────────

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'START_POLLING') startPolling();
  if (message.type === 'STOP_POLLING')  stopPolling();
});
