import type { Detector, DetectorContext, DetectionSignal } from './types';

/**
 * Confusable code points that fold to an ASCII letter under our normalizer but
 * are NOT folded by NFKC alone (Cyrillic/Greek/Armenian look-alikes, math
 * alphanumerics, fullwidth forms). Every entry is a non-ASCII code point
 * (> 127); plain ASCII digits and symbols are deliberately excluded so that
 * benign numeric or punctuated text does not register as disguise.
 */
const CONFUSABLES = new Set<string>([
  'а',
  'е',
  'о',
  'р',
  'с',
  'х',
  'у',
  'і',
  'ј',
  'ѕ',
  'ԁ',
  'һ',
  'ӏ',
  'ԛ',
  'ԝ',
  'ѵ',
  'ё',
  'А',
  'В',
  'Е',
  'К',
  'М',
  'Н',
  'О',
  'Р',
  'С',
  'Т',
  'Х',
  'ο',
  'α',
  'ν',
  'ι',
  'κ',
  'ρ',
  'τ',
  'υ',
  'χ',
  'Α',
  'Β',
  'Ε',
  'Ν',
  'Ο',
  'Ρ',
  'Τ',
  'օ',
  'ɡ',
  'ɩ',
  'ⅼ',
  'ⅰ',
  'ℓ',
  'ℯ',
  'ℴ',
  '𝐢',
  '𝐧',
  '𝐨',
  '𝑖',
  '𝓲',
  '𝔦',
  '𝕚',
  '𝚒',
  'ｉ',
  'ｇ',
  'ｎ',
  'ｏ',
  'ｒ',
  'ｅ',
  'ｓ',
  'ｔ',
  'ｍ',
]);

const isAsciiConfusable = (cp: string): boolean => {
  const code = cp.codePointAt(0);
  if (code === undefined || code <= 127) return false;
  return CONFUSABLES.has(cp);
};

/**
 * Invisible/format characters a normalizer strips. Counted independently of
 * confusables because even a handful of these between letters is a strong
 * disguise signal (zero-width spacing of an override trigger).
 */
const ZERO_WIDTH = new Set<string>([
  '​',
  '‌',
  '‍',
  '⁠',
  '﻿',
  '­',
  '‪',
  '‫',
  '‬',
  '‭',
  '‮',
  '⁦',
  '⁧',
  '⁨',
  '⁩',
]);

const isZeroWidth = (cp: string): boolean => {
  if (ZERO_WIDTH.has(cp)) return true;
  const code = cp.codePointAt(0);
  if (code === undefined) return false;
  // Unicode Tag block carries fully invisible smuggled instructions.
  return code >= 0xe0000 && code <= 0xe007f;
};

const clampScore = (value: number): number => (value < 0 ? 0 : value > 1 ? 1 : value);

const truncateEvidence = (text: string, max = 120): string =>
  text.length <= max ? text : `${text.slice(0, max - 1)}…`;

/**
 * Flags inputs whose visible characters were materially disguised: a meaningful
 * fraction of confusable look-alikes, or any non-trivial run of invisible
 * characters. Score grows with the share of the input that had to be folded.
 */
export const obfuscationDetector: Detector = {
  id: 'obfuscation',
  category: 'obfuscation',
  run(ctx: DetectorContext): DetectionSignal[] {
    const { original } = ctx;
    if (original.length === 0) return [];

    let confusables = 0;
    let zeroWidth = 0;
    let total = 0;
    for (const ch of original) {
      total += 1;
      if (isZeroWidth(ch)) zeroWidth += 1;
      else if (isAsciiConfusable(ch)) confusables += 1;
    }
    if (total === 0) return [];

    const foldedRatio = (confusables + zeroWidth) / total;
    const hasZeroWidth = zeroWidth >= 1;
    const materiallyFolded = foldedRatio > 0.1;
    if (!materiallyFolded && !hasZeroWidth) return [];

    // Ratio drives the bulk of the score; any invisible character earns a
    // high-medium baseline even in a long, otherwise-plain input.
    const ratioScore = Math.min(foldedRatio * 4, 0.9);
    const zeroWidthScore = hasZeroWidth ? Math.min(0.5 + zeroWidth * 0.05, 0.9) : 0;
    const score = clampScore(Math.max(ratioScore, zeroWidthScore));
    const severity = score >= 0.7 ? 'high' : 'medium';

    const parts: string[] = [];
    if (confusables > 0) parts.push(`${confusables} confusable char(s)`);
    if (zeroWidth > 0) parts.push(`${zeroWidth} invisible char(s)`);
    const pct = Math.round(foldedRatio * 100);

    return [
      {
        id: 'obfuscation.normalization-delta',
        category: 'obfuscation',
        severity,
        score,
        message: `Input was visually disguised (${parts.join(', ')}; ${pct}% of characters folded during normalization).`,
        evidence: truncateEvidence(original),
        source: 'original',
      },
    ];
  },
};

/**
 * Measures how much two strings overlap by character set, used as a cheap proxy
 * for "the decoded text is real hidden content, not just a re-encoding of what
 * was already visible." Returns 1 when fully contained, 0 when disjoint.
 */
const containmentRatio = (decoded: string, haystack: string): number => {
  if (decoded.length === 0) return 1;
  const window = 64;
  const lowerHay = haystack.toLowerCase();
  const lowerDec = decoded.toLowerCase();
  let covered = 0;
  for (let i = 0; i < lowerDec.length; i += window) {
    const chunk = lowerDec.slice(i, i + window);
    if (lowerHay.includes(chunk)) covered += chunk.length;
  }
  return covered / lowerDec.length;
};

const PRINTABLE = /[\x20-\x7e]/g;

const printableRatio = (text: string): number => {
  if (text.length === 0) return 0;
  const matches = text.match(PRINTABLE);
  return (matches ? matches.length : 0) / text.length;
};

/**
 * Fires when a decode layer surfaced genuinely hidden text: a non-rot13
 * transform (base64/hex/url/decimal/etc.) whose output is substantial, mostly
 * printable, and not already present verbatim in the original. rot13 is
 * excluded because it is a trivial in-place letter substitution that the
 * pattern layer already rescans, not a smuggling channel.
 */
export const encodingAnomalyDetector: Detector = {
  id: 'encoding',
  category: 'obfuscation',
  run(ctx: DetectorContext): DetectionSignal[] {
    const { decoded, original } = ctx;
    if (decoded.length === 0) return [];

    const signals: DetectionSignal[] = [];
    for (const layer of decoded) {
      const method = layer.method.toLowerCase();
      if (method === 'rot13' || method === 'rot-n') continue;

      const text = layer.text;
      if (text.length < 8) continue;
      // Garbled binary decodes are noise, not smuggled instructions.
      if (printableRatio(text) < 0.8) continue;
      // Skip layers that merely echo content already visible in the original.
      if (containmentRatio(text, original) > 0.6) continue;

      // Presence of a hidden encoded layer is, on its own, only weak evidence:
      // a benign base64/hex blob of ordinary text is common. Escalation comes
      // from the pattern layer rescanning the decoded text and adding its own
      // signals, so this standalone signal stays low.
      const lengthScore = Math.min(0.2 + text.length / 1000, 0.35);
      const score = clampScore(lengthScore);

      signals.push({
        id: `encoding.hidden-${method}`,
        category: 'obfuscation',
        severity: 'low',
        score,
        message: `Hidden content surfaced via ${layer.method} decode (${text.length} chars not visible in the original).`,
        evidence: truncateEvidence(text),
        source: layer.method,
      });
    }
    return signals;
  },
};
