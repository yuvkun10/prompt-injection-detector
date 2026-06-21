import { DEFAULT_THRESHOLDS, SEVERITY_RANK } from './types';
import type { DetectionSignal, Severity, Verdict, Thresholds } from './types';

/** Map a 0-100 score onto a severity band. */
export function scoreToSeverity(score: number): Severity {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  if (score >= 15) return 'low';
  return 'none';
}

/** Highest-ranked severity among the given signals, or 'none' if there are none. */
function maxSignalSeverity(signals: DetectionSignal[]): Severity {
  let best: Severity = 'none';
  for (const signal of signals) {
    if (SEVERITY_RANK[signal.severity] > SEVERITY_RANK[best]) {
      best = signal.severity;
    }
  }
  return best;
}

/** Constrain a value to the inclusive [min, max] range, mapping NaN to min. */
function clamp(value: number, min: number, max: number): number {
  if (Number.isNaN(value)) return min;
  return Math.min(max, Math.max(min, value));
}

/**
 * Combine signal confidences with a probabilistic OR and derive a verdict.
 *
 * Probabilistic OR (1 - product(1 - s_i)) treats each signal as independent
 * evidence: many weak signals accumulate without any single one being able to
 * exceed the others, and the result stays bounded in [0,1] without saturating
 * the way a plain sum would.
 */
export function aggregate(
  signals: DetectionSignal[],
  thresholds: Thresholds = DEFAULT_THRESHOLDS,
): { score: number; severity: Severity; verdict: Verdict } {
  if (signals.length === 0) {
    return { score: 0, severity: 'none', verdict: 'allow' };
  }

  let inverse = 1;
  for (const signal of signals) {
    inverse *= 1 - clamp(signal.score, 0, 1);
  }
  const combined = 1 - inverse;
  const score = clamp(Math.round(combined * 100), 0, 100);

  const bandSeverity = scoreToSeverity(score);
  const signalSeverity = maxSignalSeverity(signals);
  const severity =
    SEVERITY_RANK[signalSeverity] >= SEVERITY_RANK[bandSeverity] ? signalSeverity : bandSeverity;

  const verdict: Verdict =
    score >= thresholds.block ? 'block' : score >= thresholds.flag ? 'flag' : 'allow';

  return { score, severity, verdict };
}
