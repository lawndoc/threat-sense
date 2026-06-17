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
  // ── CMD caret obfuscation ────────────────────────────────────────────────
  {
    pattern: /[a-zA-Z]\^[a-zA-Z]/,
    label: 'CMD caret obfuscation',
    category: 'obfuscation',
    confidence: 'high',
  },

  // ── PowerShell backtick obfuscation ──────────────────────────────────────
  {
    pattern: /[a-zA-Z]`[a-zA-Z]/,
    label: 'PowerShell backtick obfuscation',
    category: 'obfuscation',
    confidence: 'high',
  },

  // ── PowerShell download-and-execute ─────────────────────────────────────
  {
    pattern: /powershell[\s\S]{0,300}(iex|invoke-expression|downloadstring|net\.webclient|downloadfile|start-bitstransfer)/i,
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

  // ── cmd /c or cmd /k (including %COMSPEC%) ────────────────────────────────
  {
    pattern: /(cmd(\.exe)?\s+(\/c|\/k)\s+.{10,}|%COMSPEC%\s+(\/c|\/k)\s+.{5,})/i,
    label: 'cmd /c execution',
    category: 'execution',
    confidence: 'medium',
  },

  // ── curl / wget / Invoke-WebRequest pipe-to-execute ──────────────────────
  {
    pattern: /(curl|wget|iwr|invoke-webrequest)[\s\S]{0,200}(iex|invoke-expression|\|\s*powershell)/i,
    label: 'Download pipe-execute',
    category: 'execution',
    confidence: 'high',
  },

  // ── Start-Process launching remote or script resources ───────────────────
  {
    pattern: /Start-Process[\s\S]{0,150}(https?:\/\/|\.exe|\.bat|\.cmd|\.ps1|\.vbs)/i,
    label: 'Start-Process remote launch',
    category: 'execution',
    confidence: 'high',
  },

  // ── regsvr32 scriptlet / COM object abuse ────────────────────────────────
  {
    pattern: /regsvr32[\s\S]{0,150}(\/s|\/u|\/i:|scrobj\.dll)/i,
    label: 'regsvr32 scriptlet execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── rundll32 JavaScript / remote payload ─────────────────────────────────
  {
    pattern: /rundll32[\s\S]{0,150}(javascript:|https?:\/\/|\\\\)/i,
    label: 'rundll32 remote execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── bitsadmin remote download (LOLBin — T1197) ───────────────────────────
  // Covers both one-shot (/transfer) and job-based (/addfile) download
  // patterns observed in APT41, Cobalt Strike, and ransomware campaigns.
  {
    pattern: /bitsadmin[\s\S]{0,200}(\/transfer|\/addfile)[\s\S]{0,200}https?:\/\//i,
    label: 'bitsadmin remote download',
    category: 'execution',
    confidence: 'high',
  },

  // ── certutil remote download (-urlcache / -verifyctl / -URL) ─────────────
  {
    pattern: /certutil[\s\S]{0,150}(-urlcache|-verifyctl|-URL)[\s\S]{0,150}https?:\/\//i,
    label: 'certutil remote download',
    category: 'execution',
    confidence: 'high',
  },

  // ── certutil decode/decodehex payload staging ─────────────────────────────
  {
    pattern: /certutil[\s\S]{0,100}-(decode|decodehex)\b/i,
    label: 'certutil payload decode',
    category: 'obfuscation',
    confidence: 'medium',
  },

  // ── msiexec remote MSI install (quiet/silent) ─────────────────────────────
  {
    pattern: /msiexec[\s\S]{0,150}(\/q|\/quiet|\/passive)[\s\S]{0,150}https?:\/\//i,
    label: 'msiexec remote install',
    category: 'execution',
    confidence: 'high',
  },

  // ── HTML Help remote payload (CHM/URL) ────────────────────────────────────
  {
    pattern: /\bhh(\.exe)?\s+https?:\/\//i,
    label: 'hh.exe remote payload',
    category: 'execution',
    confidence: 'high',
  },

  // ── PowerShell Clipboard execution / Get-Clipboard abuse ─────────────────
  {
    pattern: /(Get-Clipboard|gcb)[\s\S]{0,150}(iex|invoke-expression)/i,
    label: 'PowerShell clipboard execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── PowerShell inline Base64 memory decoding ─────────────────────────────
  {
    pattern: /\[System\.Convert\]::FromBase64String/i,
    label: 'PowerShell Base64 decoding',
    category: 'obfuscation',
    confidence: 'high',
  },

  // ── macOS clipboard pipe execution ───────────────────────────────────────
  {
    pattern: /pbpaste\s*\|\s*(bash|sh|zsh)/i,
    label: 'macOS clipboard pipe execution',
    category: 'execution',
    confidence: 'high',
  },
  {
    pattern: /eval\s+.*pbpaste/i,
    label: 'macOS clipboard pipe execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── macOS AppleScript execution (osascript) ──────────────────────────────
  {
    pattern: /\bosascript\s+-e\s+['"].*do\s+shell\s+script.*(curl|wget|bash|sh|zsh|pbpaste)/i,
    label: 'macOS AppleScript execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── Obfuscated Shell pipe-to-execute ─────────────────────────────────────
  {
    pattern: /(curl|wget)[\s\S]{0,200}(base64|decode|openssl|xxd)[\s\S]{0,100}\|\s*(bash|sh|zsh)/i,
    label: 'Obfuscated pipe-execute',
    category: 'execution',
    confidence: 'high',
  },

  // ── Python inline execution / base64 execution ───────────────────────────
  {
    pattern: /python(3)?\s+-c\s+['"].*(import\s+(urllib|requests|base64|sys|os)|exec|eval)/i,
    label: 'Python remote/encoded execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── Node.js inline execution ─────────────────────────────────────────────
  {
    pattern: /node\s+(-e|--eval)\s+['"].*(require\s*\(\s*['"]child_process['"]\)|exec|eval)/i,
    label: 'Node.js code execution',
    category: 'execution',
    confidence: 'high',
  },

  // ── Staged download-and-execute chain (e.g. curl && mshta) ───────────────
  {
    pattern: /(curl|wget|certutil|bitsadmin)[\s\S]{0,250}&&\s*(mshta|powershell|cmd|start|wscript|cscript|regsvr32|rundll32)/i,
    label: 'Download chain execution',
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

  // 1. Run direct checks on the original text (catches raw carets/backticks first)
  const directMatch = CLICKFIX_INDICATORS.find((ind) => ind.pattern.test(text));
  if (directMatch) return directMatch;

  // 2. Normalize/de-obfuscate by removing carets and backticks, then check again
  const normalized = text.replace(/\^/g, '').replace(/`/g, '');
  if (normalized !== text) {
    return CLICKFIX_INDICATORS.find((ind) => ind.pattern.test(normalized)) ?? null;
  }

  return null;
}
