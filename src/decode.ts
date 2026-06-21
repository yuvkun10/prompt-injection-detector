import type { DecodedLayer } from './types';

/**
 * Reversible decoders and a layer scanner for surfacing encoded payloads.
 *
 * Every decoder is total: it returns null (never throws) for input it cannot
 * confidently decode. "Confidence" means the charset matches and the result is
 * mostly printable ASCII, so we don't surface binary garbage as a decoded layer.
 */

/** Upper bound on decoded bytes we accept, to avoid amplification from a small encoded blob. */
const MAX_DECODED_BYTES = 64 * 1024;

/** Minimum token length we bother treating as an encoded candidate. */
const MIN_TOKEN_LENGTH = 12;

/** Upper bound on characters retained in any returned layer's text. */
const MAX_LAYER_TEXT = 256;

/**
 * Fraction of characters that must be printable ASCII for a decode to count.
 * Printable here is space..~ plus tab/newline/carriage-return.
 */
const PRINTABLE_THRESHOLD = 0.85;

function isPrintableAscii(code: number): boolean {
  return code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126);
}

/**
 * Returns true when a decoded string is mostly printable ASCII. Empty input is
 * rejected: an empty decode is never useful evidence.
 */
function isMostlyPrintable(s: string): boolean {
  if (s.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    if (isPrintableAscii(s.charCodeAt(i))) printable++;
  }
  return printable / s.length >= PRINTABLE_THRESHOLD;
}

export function tryBase64(s: string): string | null {
  const stripped = s.trim().replace(/-/g, '+').replace(/_/g, '/');
  if (stripped.length < 4) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(stripped)) return null;
  const padded = stripped + '='.repeat((4 - (stripped.length % 4)) % 4);
  if (padded.length % 4 !== 0) return null;
  try {
    const buf = Buffer.from(padded, 'base64');
    if (buf.length === 0 || buf.length > MAX_DECODED_BYTES) return null;
    // base64 silently ignores invalid input, so re-encode and compare (ignoring
    // padding) to reject strings that only partially decode.
    if (buf.toString('base64').replace(/=+$/, '') !== padded.replace(/=+$/, '')) {
      return null;
    }
    const out = buf.toString('latin1');
    return isMostlyPrintable(out) ? out : null;
  } catch {
    return null;
  }
}

export function tryHex(s: string): string | null {
  const trimmed = s.trim();
  if (trimmed.length < 2 || trimmed.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]+$/.test(trimmed)) return null;
  try {
    const buf = Buffer.from(trimmed, 'hex');
    if (buf.length === 0 || buf.length > MAX_DECODED_BYTES) return null;
    const out = buf.toString('latin1');
    return isMostlyPrintable(out) ? out : null;
  } catch {
    return null;
  }
}

export function tryRot13(s: string): string | null {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 65 && code <= 90) {
      out += String.fromCharCode(((code - 65 + 13) % 26) + 65);
    } else if (code >= 97 && code <= 122) {
      out += String.fromCharCode(((code - 97 + 13) % 26) + 97);
    } else {
      out += s[i];
    }
  }
  return out;
}

export function tryUrl(s: string): string | null {
  const trimmed = s.trim();
  // Only attempt when there is something to decode, to avoid trivial identity hits.
  if (!/%[0-9a-fA-F]{2}/.test(trimmed)) return null;
  try {
    const out = decodeURIComponent(trimmed);
    if (out.length > MAX_DECODED_BYTES) return null;
    if (out === trimmed) return null;
    return isMostlyPrintable(out) ? out : null;
  } catch {
    return null;
  }
}

export function tryDecimalCharCodes(s: string): string | null {
  const trimmed = s.trim();
  if (!/^\d{1,7}(?:[\s,]+\d{1,7})+$/.test(trimmed)) return null;
  const parts = trimmed.split(/[\s,]+/).filter((p) => p.length > 0);
  if (parts.length < 2) return null;
  let out = '';
  for (const part of parts) {
    const code = Number.parseInt(part, 10);
    if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return null;
    if (out.length > MAX_DECODED_BYTES) return null;
    try {
      out += String.fromCodePoint(code);
    } catch {
      return null;
    }
  }
  return isMostlyPrintable(out) ? out : null;
}

interface TokenDecoder {
  method: string;
  decode: (token: string) => string | null;
}

const TOKEN_DECODERS: TokenDecoder[] = [
  { method: 'base64', decode: tryBase64 },
  { method: 'hex', decode: tryHex },
  { method: 'url', decode: tryUrl },
  { method: 'decimal-charcodes', decode: tryDecimalCharCodes },
];

/**
 * A candidate span: contiguous run that could be a single encoded token. We use
 * a permissive character class (the union of all token charsets) and let each
 * decoder validate its own format; spans shorter than the minimum are skipped.
 */
const TOKEN_SPAN = /\d{1,7}(?:[\s,]+\d{1,7})+|[A-Za-z0-9+/=%]+/g;

export function decodeLayers(text: string): DecodedLayer[] {
  const layers: DecodedLayer[] = [];
  const seen = new Set<string>();

  const push = (method: string, decoded: string, span?: { start: number; end: number }): void => {
    if (seen.has(decoded)) return;
    seen.add(decoded);
    const text = decoded.slice(0, MAX_LAYER_TEXT);
    layers.push(span ? { method, text, span } : { method, text });
  };

  // Whole-text rot13 is always present so callers can rescan it unconditionally.
  const rot = tryRot13(text);
  if (rot !== null) push('rot13', rot);

  let match: RegExpExecArray | null;
  TOKEN_SPAN.lastIndex = 0;
  while ((match = TOKEN_SPAN.exec(text)) !== null) {
    const raw = match[0];
    const start = match.index;
    const end = start + raw.length;
    if (raw.trim().length < MIN_TOKEN_LENGTH) continue;

    for (const { method, decode } of TOKEN_DECODERS) {
      let decoded: string | null;
      try {
        decoded = decode(raw);
      } catch {
        decoded = null;
      }
      if (decoded !== null && decoded !== raw) {
        push(method, decoded, { start, end });
      }
    }
  }

  return layers;
}
