/**
 * ClickFix Detector — pure analysis function; no Chrome API dependencies.
 *
 * Analyses raw clipboard text against the known ClickFix/ClearFake indicator
 * set and returns a structured DetectionResult.
 */

import { matchIndicator } from './indicators.js';

/**
 * @typedef {{
 *   status:    'detected' | 'not-detected',
 *   indicator: { label: string, category: string, confidence: string } | null,
 *   snippet:   string | null,
 *   detectedAt: number,
 * }} DetectionResult
 */

/**
 * Analyse clipboard text for ClickFix / ClearFake indicators.
 *
 * @param {string} text  Raw clipboard text
 * @returns {DetectionResult}
 */
export function analyzeClipboard(text) {
  if (!text || typeof text !== 'string') {
    return { status: 'not-detected', indicator: null, snippet: null, detectedAt: Date.now() };
  }

  const indicator = matchIndicator(text);

  if (!indicator) {
    return { status: 'not-detected', indicator: null, snippet: null, detectedAt: Date.now() };
  }

  // Build a sanitized, single-line snippet for display purposes.
  const raw = text.replace(/[\r\n\t]+/g, ' ').trim();
  const snippet = raw.length > 120 ? `${raw.slice(0, 120)}\u2026` : raw;

  return {
    status: 'detected',
    indicator: {
      label:      indicator.label,
      category:   indicator.category,
      confidence: indicator.confidence,
    },
    snippet,
    detectedAt: Date.now(),
  };
}
