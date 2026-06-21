/**
 * Text normalization for injection detection. The goal is to collapse the many
 * visually-equivalent encodings an attacker can use (homoglyphs, zero-width
 * padding, fullwidth forms, mixed case, irregular whitespace) into one canonical
 * form that downstream string matchers can scan reliably.
 *
 * Every function here is total: it must never throw, regardless of input size or
 * content, because it sits on the hot path of an untrusted-input scanner.
 */

/**
 * Homoglyph and look-alike folding map. NFKC handles compatibility forms
 * (fullwidth, some math styles) but deliberately does NOT fold cross-script
 * look-alikes such as Cyrillic 'а' -> Latin 'a', so those must be listed
 * explicitly here. Fullwidth and math-style entries are kept as a safety net for
 * any code path that folds before NFKC or for forms NFKC leaves untouched.
 */
export const BUILTIN_CONFUSABLES: Record<string, string> = {
  // Cyrillic lowercase look-alikes.
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  х: 'x',
  у: 'y',
  і: 'i',
  ј: 'j',
  ѕ: 's',
  ԁ: 'd',
  һ: 'h',
  ӏ: 'l',
  ԛ: 'q',
  ԝ: 'w',
  ѵ: 'v',
  ё: 'e',
  // Cyrillic uppercase look-alikes.
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  Х: 'X',
  // Greek lowercase look-alikes.
  ο: 'o',
  α: 'a',
  ν: 'v',
  ι: 'i',
  κ: 'k',
  ρ: 'p',
  τ: 't',
  υ: 'u',
  χ: 'x',
  // Greek uppercase look-alikes.
  Α: 'A',
  Β: 'B',
  Ε: 'E',
  Ν: 'N',
  Ο: 'O',
  Ρ: 'P',
  Τ: 'T',
  // Armenian and Latin-extension look-alikes.
  օ: 'o',
  ɡ: 'g',
  ɩ: 'i',
  // Letterlike and roman-numeral forms.
  ⅼ: 'l',
  ⅰ: 'i',
  ℓ: 'l',
  ℯ: 'e',
  ℴ: 'o',
  // Mathematical alphanumeric styles (kept as a fallback to NFKC).
  '\u{1d422}': 'i', // 𝐢
  '\u{1d427}': 'n', // 𝐧
  '\u{1d428}': 'o', // 𝐨
  '\u{1d456}': 'i', // 𝑖
  '\u{1d4f2}': 'i', // 𝓲
  '\u{1d526}': 'i', // 𝔦
  '\u{1d55a}': 'i', // 𝕚
  '\u{1d692}': 'i', // 𝚒
  // Fullwidth Latin (kept as a fallback to NFKC).
  ｉ: 'i',
  ｇ: 'g',
  ｎ: 'n',
  ｏ: 'o',
  ｒ: 'r',
  ｅ: 'e',
  ｓ: 's',
  ｔ: 't',
  ｍ: 'm',
};

/**
 * Code points removed by {@link stripZeroWidth}. Covers zero-width spaces and
 * joiners (U+200B-200F), word joiner (U+2060), BOM/zero-width no-break space
 * (U+FEFF), the Mongolian vowel separator (U+180E), zero-width no-break legacy
 * forms, and bidi controls (U+202A-202E, U+2066-2069) used in Trojan-Source
 * style reordering attacks.
 */
const ZERO_WIDTH_PATTERN =
  /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\u180E-\u180E\uFEFF-\uFEFF]/g;

/**
 * Unicode Tag block (U+E0000-E007F): entirely invisible characters that can
 * carry instructions a model reads but a human reviewer never sees.
 */
const TAG_BLOCK_PATTERN = /[\u{E0000}-\u{E007F}]/gu;

/** Combining marks (Mn/Mc/Me) used for Zalgo stacking and accent obfuscation. */
const COMBINING_MARK_PATTERN = /\p{M}/gu;

/**
 * Remove zero-width, invisible, and bidi-control characters, the invisible Tag
 * block, and combining marks. Combining marks are dropped so that stacked forms
 * like "i̵g̷n̶o̴r̵e̸" reduce to their base letters.
 */
export function stripZeroWidth(text: string): string {
  if (text.length === 0) {
    return '';
  }
  try {
    return text
      .replace(ZERO_WIDTH_PATTERN, '')
      .replace(TAG_BLOCK_PATTERN, '')
      .replace(COMBINING_MARK_PATTERN, '');
  } catch {
    return text;
  }
}

/**
 * Fold homoglyphs and look-alikes to their ASCII equivalents using
 * {@link BUILTIN_CONFUSABLES}, optionally extended or overridden by `extra`.
 * Iterates by code point so astral-plane characters (math-style letters) fold
 * correctly.
 */
export function foldConfusables(text: string, extra?: Record<string, string>): string {
  if (text.length === 0) {
    return '';
  }
  try {
    const map = extra ? { ...BUILTIN_CONFUSABLES, ...extra } : BUILTIN_CONFUSABLES;
    let out = '';
    for (const ch of text) {
      const mapped = map[ch];
      out += mapped ?? ch;
    }
    return out;
  } catch {
    return text;
  }
}

/** Matches any run of Unicode whitespace, collapsed to a single ASCII space. */
const WHITESPACE_RUN_PATTERN = /\s+/gu;

/**
 * Canonicalize input for matching:
 * NFKC -> strip invisibles/marks -> fold confusables -> collapse whitespace
 * runs to a single space -> trim -> lowercase.
 *
 * NFKC runs first so compatibility decomposition (fullwidth, ligatures) happens
 * before confusable folding, minimizing the entries the explicit map must carry.
 */
export function normalize(text: string): string {
  if (text.length === 0) {
    return '';
  }
  try {
    let result = text.normalize('NFKC');
    result = stripZeroWidth(result);
    result = foldConfusables(result);
    result = result.replace(WHITESPACE_RUN_PATTERN, ' ').trim();
    return result.toLowerCase();
  } catch {
    // String.prototype.normalize can throw a RangeError only on an invalid form
    // argument, which we never pass; this guard keeps the contract total.
    return text;
  }
}
