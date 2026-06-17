/**
 * Clipboard interceptor relay — ISOLATED world (extension content script).
 *
 * Listens for CustomEvents dispatched by clipboard-interceptor-main.js
 * (which runs in the page's MAIN world) and forwards clipboard write payloads
 * to the service worker via chrome.runtime.sendMessage.
 *
 * This two-script pattern is required because MAIN-world scripts cannot
 * access chrome.runtime, while ISOLATED-world scripts can.
 *
 * Requires: content_scripts entry with default world, run_at: "document_start"
 */

window.addEventListener('__ss_clipboard_write', (event) => {
  const text = event?.detail?.text;
  if (typeof text !== 'string' || text.length === 0) return;

  chrome.runtime.sendMessage({ type: 'CLIPBOARD_CHANGED', text, source: 'content-script' });
});
