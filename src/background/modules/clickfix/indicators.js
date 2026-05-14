/**
 * ClickFix / ClearFake Indicators — regex patterns for detecting malicious
 * clipboard payloads planted by fake-CAPTCHA social-engineering pages.
 *
 * These are matched against the raw text content of the system clipboard.
 * Patterns are intentionally broad to maximise recall; a `confidence` field
 * is provided so callers can apply thresholds for low-confidence matches.
 *
 * Categories:
 *   execution   — direct process/command execution
 *   obfuscation — encoded or obfuscated payloads (high-risk indicator)
 */

/**
 * @typedef {{ pattern: RegExp, label: string, category: 'execution'|'obfuscation', confidence: 'high'|'medium' }} ClickFixIndicator
 */

/** @type {ClickFixIndicator[]} */
export const CLICKFIX_INDICATORS = [
  // ── PowerShell download-and-execute ─────────────────────────────────────
  {
    pattern: /powershell[^\n]{0,300}(iex|invoke-expression|downloadstring|net\.webclient|downloadfile|start-bitstransfer)/i,
    label: 'PowerShell download-execute',
    category: 'execution',
    confidence: 'high',
  },

  // ── Base64-encoded command (-EncodedCommand / -enc) ─────────────────────
  {
    pattern: /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/]{20,}/i,
    label: 'Base64-encoded command',
    category: 'obfuscation',
    confidence: 'high',
  },

  // ── mshta remote payload ─────────────────────────────────────────────────
  {
    pattern: /mshta\s+(https?:\/\/|javascript:|vbscript:)/i,
    label: 'mshta remote payload',
    category: 'execution',
    confidence: 'high',
  },

  // ── Windows Script Host (wscript / cscript) ──────────────────────────────
  {
    pattern: /\b(wscript|cscript)\b/i,
    label: 'Windows Script Host execution',
    category: 'execution',
    confidence: 'medium',
  },

  // ── cmd /c or cmd /k ─────────────────────────────────────────────────────
  {
    pattern: /cmd(\.exe)?\s+(\/c|\/k)\s+.{10,}/i,
    label: 'cmd /c execution',
    category: 'execution',
    confidence: 'medium',
  },

  // ── curl / wget / Invoke-WebRequest pipe-to-execute ──────────────────────
  {
    pattern: /(curl|wget|iwr|invoke-webrequest)[^\n]{0,200}(iex|invoke-expression|\|\s*powershell)/i,
    label: 'Download pipe-execute',
    category: 'execution',
    confidence: 'high',
  },

  // ── Start-Process launching remote or script resources ───────────────────
  {
    pattern: /Start-Process[^\n]{0,150}(https?:\/\/|\.exe|\.bat|\.cmd|\.ps1|\.vbs)/i,
    label: 'Start-Process remote launch',
    category: 'execution',
    confidence: 'high',
  },

  // ── regsvr32 scriptlet / COM object abuse ────────────────────────────────
  {
    pattern: /regsvr32[^\n]{0,150}(\/s|\/u|\/i:|scrobj\.dll)/i,
    label: 'regsvr32 scriptlet execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── rundll32 JavaScript / remote payload ─────────────────────────────────
  {
    pattern: /rundll32[^\n]{0,150}(javascript:|https?:\/\/|\\\\)/i,
    label: 'rundll32 remote execution',
    category: 'execution',
    confidence: 'high',
  },
];

/**
 * Return the first matching indicator for the given clipboard text, or null.
 *
 * @param {string} text
 * @returns {ClickFixIndicator|null}
 */
export function matchIndicator(text) {
  if (!text || typeof text !== 'string') return null;
  return CLICKFIX_INDICATORS.find((ind) => ind.pattern.test(text)) ?? null;
}
