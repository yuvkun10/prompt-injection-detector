import { normalize } from './normalize';
import { decodeLayers } from './decode';
import { defaultRules, createPatternDetector } from './rules';
import { obfuscationDetector, encodingAnomalyDetector } from './detectors';
import { aggregate, scoreToSeverity } from './score';
import { DEFAULT_THRESHOLDS } from './types';
import type {
  DetectorConfig,
  DetectorContext,
  DetectionResult,
  DetectionSignal,
  DetectorInstance,
  Detector,
} from './types';

const DEFAULT_MAX_EVIDENCE_LENGTH = 120;
const DEFAULT_JUDGE_BAND = { low: 25, high: 70 } as const;
const DEFAULT_MAX_INPUT_CHARS = 20000;

/**
 * Truncate evidence to a bounded length so a single signal cannot carry an
 * unbounded slice of attacker-controlled input into logs or callers.
 */
function truncateEvidence(signal: DetectionSignal, maxLength: number): DetectionSignal {
  if (signal.evidence === undefined || signal.evidence.length <= maxLength) {
    return signal;
  }
  return { ...signal, evidence: signal.evidence.slice(0, maxLength) };
}

function runDetector(detector: Detector, ctx: DetectorContext): DetectionSignal[] {
  // A faulty or maliciously-triggered detector must never break detection of
  // the others, so every run is isolated. Detectors are declared synchronous.
  try {
    return detector.run(ctx);
  } catch {
    return [];
  }
}

/**
 * Build a detector configured with the given (or default) detector set. The
 * returned object exposes a single async `detect` method; the only IO is the
 * optional judge, which is consulted solely for borderline scores.
 */
export function createDetector(config: DetectorConfig = {}): DetectorInstance {
  const detectors = config.detectors ?? [
    createPatternDetector(defaultRules),
    obfuscationDetector,
    encodingAnomalyDetector,
  ];
  const maxEvidenceLength = config.maxEvidenceLength ?? DEFAULT_MAX_EVIDENCE_LENGTH;
  const judgeBand = config.judgeBand ?? DEFAULT_JUDGE_BAND;
  const maxInputChars = config.maxInputChars ?? DEFAULT_MAX_INPUT_CHARS;
  const blockThreshold = (config.thresholds ?? DEFAULT_THRESHOLDS).block;
  const { judge } = config;

  async function detect(text: string): Promise<DetectionResult> {
    const start = performance.now();

    const truncated = text.length > maxInputChars;
    const analyzed = truncated ? text.slice(0, maxInputChars) : text;

    const normalized = normalize(analyzed);
    const decoded = decodeLayers(analyzed);
    const ctx: DetectorContext = { original: analyzed, normalized, decoded };

    const signals: DetectionSignal[] = [];
    for (const detector of detectors) {
      for (const signal of runDetector(detector, ctx)) {
        signals.push(truncateEvidence(signal, maxEvidenceLength));
      }
    }

    let { score, severity, verdict } = aggregate(signals, config.thresholds);

    if (judge !== undefined && score >= judgeBand.low && score < blockThreshold) {
      const opinion = await consultJudge(judge, analyzed);
      if (opinion !== null) {
        signals.push(
          truncateEvidence(
            {
              id: `judge.${judge.name}`,
              category: 'external-judge',
              severity: scoreToSeverity(opinion.score * 100),
              score: opinion.score,
              message: opinion.rationale,
              source: 'judge',
            },
            maxEvidenceLength,
          ),
        );
        ({ score, severity, verdict } = aggregate(signals, config.thresholds));
      }
    }

    return {
      verdict,
      score,
      severity,
      signals,
      length: analyzed.length,
      decoded,
      elapsedMs: performance.now() - start,
      truncated,
    };
  }

  return { detect };
}

/**
 * Isolate judge IO: a rejected promise from an external model must downgrade to
 * abstention rather than failing an otherwise-complete detection.
 */
async function consultJudge(
  judge: NonNullable<DetectorConfig['judge']>,
  text: string,
): Promise<{ score: number; rationale: string } | null> {
  try {
    return await judge.judge(text);
  } catch {
    return null;
  }
}
