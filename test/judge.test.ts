import { describe, expect, it } from 'vitest';
import { createDetector, noopJudge } from '../src/index';
import type { Detector, LlmJudge } from '../src/types';

/** A detector that emits one signal with a caller-chosen confidence. */
function fixedDetector(score: number): Detector {
  return {
    id: 'test.fixed',
    category: 'instruction-override',
    run: () => [
      {
        id: 'test.fixed',
        category: 'instruction-override',
        severity: 'medium',
        score,
        message: 'synthetic signal',
        source: 'normalized',
      },
    ],
  };
}

/** A judge that records whether it was consulted. */
function spyJudge(score: number): LlmJudge & { calls: number } {
  return {
    name: 'spy',
    calls: 0,
    async judge() {
      this.calls += 1;
      return { score, rationale: 'synthetic opinion' };
    },
  };
}

describe('judge integration', () => {
  it('consults the judge for a borderline score and folds in its opinion', async () => {
    const judge = spyJudge(0.95);
    const detector = createDetector({ detectors: [fixedDetector(0.5)], judge });

    const result = await detector.detect('borderline input');

    expect(judge.calls).toBe(1);
    const judgeSignal = result.signals.find((s) => s.category === 'external-judge');
    expect(judgeSignal).toBeDefined();
    expect(judgeSignal?.id).toBe('judge.spy');
    // A high-confidence opinion pushes a flag-band score up toward block.
    expect(result.score).toBeGreaterThan(50);
  });

  it('does not consult the judge at or above the block threshold', async () => {
    const judge = spyJudge(0.1);
    const detector = createDetector({ detectors: [fixedDetector(0.99)], judge });

    const result = await detector.detect('clearly malicious input');

    expect(judge.calls).toBe(0);
    expect(result.verdict).toBe('block');
    expect(result.signals.some((s) => s.category === 'external-judge')).toBe(false);
  });

  it('does not consult the judge below the band when nothing fires', async () => {
    const judge = spyJudge(0.9);
    const detector = createDetector({ detectors: [], judge });

    const result = await detector.detect('completely benign input');

    expect(judge.calls).toBe(0);
    expect(result.verdict).toBe('allow');
    expect(result.score).toBe(0);
  });

  it('treats an abstaining judge as a no-op', async () => {
    const detector = createDetector({ detectors: [fixedDetector(0.5)], judge: noopJudge });

    const result = await detector.detect('borderline input');

    expect(result.signals.some((s) => s.category === 'external-judge')).toBe(false);
  });
});
