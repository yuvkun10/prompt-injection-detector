import { describe, it, expect } from 'vitest';
import { aggregate, scoreToSeverity } from '../src/score';
import { DetectionSignal, Severity, SEVERITY_RANK, DEFAULT_THRESHOLDS } from '../src/types';

function signal(score: number, severity: Severity): DetectionSignal {
  return {
    id: `test.${severity}.${score}`,
    category: 'instruction-override',
    severity,
    score,
    message: 'test signal',
    source: 'original',
  };
}

describe('aggregate', () => {
  it('returns allow/0/none when there are no signals', () => {
    const result = aggregate([]);
    expect(result).toEqual({ score: 0, severity: 'none', verdict: 'allow' });
  });

  it('combines two medium signals higher than either alone via probabilistic OR', () => {
    const single = aggregate([signal(0.5, 'medium')]);
    const pair = aggregate([signal(0.5, 'medium'), signal(0.5, 'medium')]);

    // 1 - (1-0.5)(1-0.5) = 0.75 > 0.5; strictly greater than either alone.
    expect(pair.score).toBeGreaterThan(single.score);
    expect(pair.score).toBe(75);
    expect(single.score).toBe(50);
  });

  it('keeps the combined score bounded at 100 even with many strong signals', () => {
    const many = Array.from({ length: 20 }, () => signal(0.95, 'critical'));
    const result = aggregate(many);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });

  it('never lets probabilistic OR exceed 100 for individual high-confidence signals', () => {
    const result = aggregate([signal(0.99, 'critical'), signal(0.99, 'critical')]);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it('maps a low aggregate score to the allow verdict', () => {
    // 1 - (1-0.1)(1-0.1) = 0.19 -> 19, below the flag threshold of 35.
    const result = aggregate([signal(0.1, 'low'), signal(0.1, 'low')]);
    expect(result.score).toBe(19);
    expect(result.verdict).toBe('allow');
  });

  it('maps a mid-range score at the flag threshold to flag', () => {
    const result = aggregate([signal(0.35, 'medium')]);
    expect(result.score).toBe(35);
    expect(result.score).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.flag);
    expect(result.score).toBeLessThan(DEFAULT_THRESHOLDS.block);
    expect(result.verdict).toBe('flag');
  });

  it('maps a score at or above the block threshold to block', () => {
    const result = aggregate([signal(0.7, 'high')]);
    expect(result.score).toBe(70);
    expect(result.score).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.block);
    expect(result.verdict).toBe('block');
  });

  it('respects custom thresholds when mapping a score to a verdict', () => {
    const thresholds = { flag: 10, block: 20 };
    expect(aggregate([signal(0.15, 'low')], thresholds).verdict).toBe('flag');
    expect(aggregate([signal(0.25, 'low')], thresholds).verdict).toBe('block');
    expect(aggregate([signal(0.05, 'low')], thresholds).verdict).toBe('allow');
  });

  it('reports a severity at least as high as the strongest signal severity', () => {
    // A single critical signal with a modest confidence: the band would be 'low',
    // but the signal severity must win so the result is not under-reported.
    const result = aggregate([signal(0.2, 'critical')]);
    expect(result.score).toBe(20);
    expect(result.severity).toBe('critical');
  });

  it('uses the score band severity when it exceeds every signal severity', () => {
    // Two low-severity signals whose confidences combine into the 'critical' band.
    const result = aggregate([signal(0.9, 'low'), signal(0.9, 'low')]);
    expect(result.score).toBe(99);
    expect(result.severity).toBe('critical');
  });

  it('clamps out-of-range and NaN signal confidences without throwing', () => {
    const result = aggregate([signal(5, 'high'), signal(-3, 'low'), signal(Number.NaN, 'low')]);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.score).toBeGreaterThanOrEqual(0);
    // The clamped-to-1 signal saturates the combined probability.
    expect(result.score).toBe(100);
  });
});

describe('scoreToSeverity', () => {
  it('maps representative scores to their bands', () => {
    expect(scoreToSeverity(0)).toBe('none');
    expect(scoreToSeverity(14)).toBe('none');
    expect(scoreToSeverity(15)).toBe('low');
    expect(scoreToSeverity(34)).toBe('low');
    expect(scoreToSeverity(35)).toBe('medium');
    expect(scoreToSeverity(59)).toBe('medium');
    expect(scoreToSeverity(60)).toBe('high');
    expect(scoreToSeverity(79)).toBe('high');
    expect(scoreToSeverity(80)).toBe('critical');
    expect(scoreToSeverity(100)).toBe('critical');
  });

  it('is monotonic: severity rank never decreases as the score increases', () => {
    let previousRank = -1;
    for (let score = 0; score <= 100; score++) {
      const rank = SEVERITY_RANK[scoreToSeverity(score)];
      expect(rank).toBeGreaterThanOrEqual(previousRank);
      previousRank = rank;
    }
  });
});
