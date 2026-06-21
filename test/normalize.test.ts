import { describe, it, expect } from 'vitest';
import { stripZeroWidth, foldConfusables, normalize, BUILTIN_CONFUSABLES } from '../src/normalize';

describe('stripZeroWidth', () => {
  it('returns empty string for empty input', () => {
    expect(stripZeroWidth('')).toBe('');
  });

  it('removes zero-width spaces inserted between letters', () => {
    // U+200B between each letter of "ignore".
    const padded = 'i​g​n​o​r​e';
    expect(stripZeroWidth(padded)).toBe('ignore');
  });

  it('removes the BOM / zero-width no-break space (U+FEFF)', () => {
    expect(stripZeroWidth('﻿hello﻿')).toBe('hello');
  });

  it('removes the word joiner (U+2060) and zero-width joiner (U+200D)', () => {
    expect(stripZeroWidth('a⁠b‍c')).toBe('abc');
  });

  it('removes bidi control characters (Trojan-Source reordering)', () => {
    // U+202E right-to-left override.
    expect(stripZeroWidth('admin‮')).toBe('admin');
  });

  it('removes invisible Tag-block characters (U+E0000-U+E007F)', () => {
    expect(stripZeroWidth('x\u{E0041}\u{E0042}y')).toBe('xy');
  });

  it('drops combining marks so Zalgo stacking reduces to base letters', () => {
    // "ignore" with combining marks (U+0335/U+0337/...) stacked on each letter.
    const zalgo = 'i̵g̷n̶o̴r̵e̸';
    expect(stripZeroWidth(zalgo)).toBe('ignore');
  });

  it('leaves ordinary ASCII text untouched', () => {
    expect(stripZeroWidth('plain text 123')).toBe('plain text 123');
  });

  it('does not throw on lone surrogates or binary-like input', () => {
    expect(() => stripZeroWidth('𐀀\uDFFF')).not.toThrow();
    expect(() => stripZeroWidth('\x00\x01\x02')).not.toThrow();
  });
});

describe('foldConfusables', () => {
  it('returns empty string for empty input', () => {
    expect(foldConfusables('')).toBe('');
  });

  it('maps a Cyrillic look-alike to its ASCII equivalent', () => {
    // U+0430 Cyrillic small a -> ASCII 'a'.
    expect(foldConfusables('а')).toBe('a');
  });

  it('folds a fully Cyrillic-spelled "ignore" to ASCII', () => {
    // і о are Cyrillic (U+0456, U+043E); other letters are ASCII look-alikes.
    const cyrillic = 'іgnоre'; // іgnоre
    expect(foldConfusables(cyrillic)).toBe('ignore');
  });

  it('folds Greek look-alikes to ASCII', () => {
    // U+03BF Greek omicron -> 'o', U+03B1 Greek alpha -> 'a'.
    expect(foldConfusables('οα')).toBe('oa');
  });

  it('folds astral-plane math-style letters by code point', () => {
    // U+1D422 mathematical bold small i -> 'i'.
    expect(foldConfusables('\u{1D422}')).toBe('i');
  });

  it('leaves plain ASCII digits and symbols unchanged', () => {
    expect(foldConfusables('0135 @$|')).toBe('0135 @$|');
  });

  it('leaves characters absent from the table unchanged', () => {
    expect(foldConfusables('zZ-_.')).toBe('zZ-_.');
  });

  it('honors caller-supplied extra mappings and overrides', () => {
    expect(foldConfusables('Z', { Z: 'z' })).toBe('z');
    // extra overrides a builtin entry for the same key.
    expect(foldConfusables('о', { о: 'O' })).toBe('O');
  });

  it('exposes a non-empty builtin confusables table', () => {
    expect(Object.keys(BUILTIN_CONFUSABLES).length).toBeGreaterThan(0);
    expect(BUILTIN_CONFUSABLES['а']).toBe('a');
  });

  it('does not throw on odd input', () => {
    expect(() => foldConfusables('\uD800')).not.toThrow();
  });
});

describe('normalize', () => {
  it('returns empty string for empty input', () => {
    expect(normalize('')).toBe('');
  });

  it('lowercases the result', () => {
    expect(normalize('IGNORE')).toBe('ignore');
  });

  it('collapses runs of mixed whitespace to a single space and trims', () => {
    expect(normalize('  ignore\t\n  previous   instructions  ')).toBe(
      'ignore previous instructions',
    );
  });

  it('applies NFKC folding to fullwidth forms', () => {
    // Fullwidth "ignore" (U+FF49 etc.) folds via NFKC to ASCII, then lowercases.
    const fullwidth = 'ＩＧＮＯＲＥ'; // ＩＧＮＯＲＥ
    expect(normalize(fullwidth)).toBe('ignore');
  });

  it('strips zero-width padding before matching', () => {
    const padded = 'i​g​n​o​r​e previous instructions';
    expect(normalize(padded)).toBe('ignore previous instructions');
  });

  it('folds Cyrillic homoglyphs that NFKC leaves alone', () => {
    // "іgnоre" with Cyrillic і (U+0456) and о (U+043E).
    expect(normalize('іgnоre')).toBe('ignore');
  });

  it('combines NFKC, zero-width removal, folding, collapse, and lowercasing', () => {
    // Fullwidth I + zero-width + Cyrillic о, extra spaces, uppercase tail.
    const messy = 'Ｉ​gnоre   PREVIOUS';
    expect(normalize(messy)).toBe('ignore previous');
  });

  it('reduces Zalgo combining marks to base letters', () => {
    const zalgo = 'I̵G̷N̶O̴R̵E̸';
    expect(normalize(zalgo)).toBe('ignore');
  });

  it('does not throw on empty, whitespace-only, or odd inputs', () => {
    expect(() => normalize('')).not.toThrow();
    expect(normalize('   \t\n  ')).toBe('');
    expect(() => normalize('𐀀\uDFFF')).not.toThrow();
    expect(() => normalize('\x00\x01binary\x02')).not.toThrow();
  });

  it('is idempotent on an already-normalized string', () => {
    const once = normalize('Ignore  Previous   Instructions');
    expect(normalize(once)).toBe(once);
  });
});
