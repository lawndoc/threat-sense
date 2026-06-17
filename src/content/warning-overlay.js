/**
 * Warning overlay — injected into the active tab when a ClickFix payload is detected.
 *
 * Reads the sanitized payload snippet from window.__ss_overlay_snippet (set by
 * the service worker immediately before this script is injected).
 *
 * Uses a closed Shadow DOM so extension styles are fully isolated from the host
 * page. Idempotent: does nothing if the overlay is already present.
 */

(function () {
  'use strict';

  const OVERLAY_HOST_ID = '__ss-warning-overlay-host';
  if (document.getElementById(OVERLAY_HOST_ID)) return;

  const snippet = typeof window.__ss_overlay_snippet === 'string'
    ? window.__ss_overlay_snippet
    : '';
  delete window.__ss_overlay_snippet;

  // Escape text for safe insertion as Shadow DOM text content via innerHTML.
  function esc(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  const host = document.createElement('div');
  host.id = OVERLAY_HOST_ID;
  // Reset ALL inherited styles; position the host as a full-viewport layer.
  host.setAttribute('style', [
    'all:initial',
    'position:fixed',
    'inset:0',
    'z-index:2147483647',
    'display:flex',
    'align-items:flex-start',
    'justify-content:center',
    'padding-top:32px',
    'pointer-events:none',
  ].join(';'));

  const shadow = host.attachShadow({ mode: 'closed' });

  const snippetBlock = snippet
    ? `<pre class="overlay__snippet" aria-label="Clipboard content preview">${esc(snippet)}</pre>`
    : '';

  shadow.innerHTML = `
    <style>
      .overlay {
        pointer-events: auto;
        background: #1a1d27;
        border: 2px solid #ef4444;
        border-radius: 10px;
        padding: 28px 34px;
        max-width: 760px;
        width: calc(100vw - 24px);
        box-shadow: 0 8px 32px rgba(0,0,0,0.75);
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        font-size: 16px;
        line-height: 1.5;
        color: #e2e8f0;
        display: flex;
        flex-direction: column;
        gap: 18px;
      }
      .overlay__header {
        display: flex;
        align-items: center;
        gap: 12px;
        color: #ef4444;
        font-weight: 700;
        font-size: 22px;
      }
      .overlay__icon {
        font-size: 32px;
        line-height: 1;
        flex-shrink: 0;
      }
      .overlay__body {
        color: #cbd5e1;
        font-size: 15px;
      }
      .overlay__body strong {
        color: #f1f5f9;
      }
      .overlay__snippet {
        background: #0f1117;
        border: 1px solid #2a2d3e;
        border-radius: 4px;
        padding: 12px 14px;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 13px;
        color: #f59e0b;
        word-break: break-all;
        white-space: pre-wrap;
        max-height: 132px;
        overflow: hidden;
        user-select: none;
        margin: 0;
      }
      .overlay__footer {
        display: flex;
        justify-content: flex-end;
      }
      .overlay__dismiss {
        background: #ef4444;
        color: #fff;
        border: none;
        border-radius: 6px;
        padding: 10px 24px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.15s;
      }
      .overlay__dismiss:hover { background: #dc2626; }
      .overlay__dismiss:focus-visible {
        outline: 2px solid #f87171;
        outline-offset: 2px;
      }
    </style>
    <div class="overlay" role="alertdialog" aria-labelledby="ss-warn-title" aria-live="assertive">
      <div class="overlay__header">
        <span class="overlay__icon" aria-hidden="true">&#x26A0;&#xFE0F;</span>
        <span id="ss-warn-title">Suspicious clipboard content detected</span>
      </div>
      <p class="overlay__body">
        This page may have placed a malicious command in your clipboard.<br>
        <strong>Do not paste this into Run&nbsp;(Win+R), Terminal, or any command prompt.</strong>
      </p>
      ${snippetBlock}
      <div class="overlay__footer">
        <button class="overlay__dismiss">Dismiss</button>
      </div>
    </div>`;

  shadow.querySelector('.overlay__dismiss').addEventListener('click', () => host.remove());

  // Append to <html> rather than <body> so it works even on pages that delay
  // body creation or replace document.body after DOMContentLoaded.
  document.documentElement.appendChild(host);

  // Move focus to dismiss button so screen readers announce the alert.
  shadow.querySelector('.overlay__dismiss').focus();
})();
