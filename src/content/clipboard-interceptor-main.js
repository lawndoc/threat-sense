/**
 * Clipboard interceptor — MAIN world (page JS context).
 *
 * Wraps navigator.clipboard.writeText so any write by the page is observed.
 * This catches ClickFix/ClearFake attacks that silently push a malicious
 * command onto the clipboard when the user clicks a fake "I'm not a robot"
 * button, before the user has a chance to paste it.
 *
 * CANNOT use chrome.runtime here — runs in the page's own JS world.
 * Communicates to the ISOLATED world relay script via CustomEvent on window.
 *
 * Requires: content_scripts entry with world: "MAIN", run_at: "document_start"
 */

if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
  const _origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);

  navigator.clipboard.writeText = function writeText(text) {
    try {
      window.dispatchEvent(
        new CustomEvent('__ss_clipboard_write', { detail: { text: String(text) } })
      );
    } catch {
      // Never let instrumentation break the original API call.
    }
    return _origWriteText(text);
  };
}
