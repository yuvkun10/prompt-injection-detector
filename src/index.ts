import type { DetectorConfig, DetectionResult } from './types';
import { createDetector } from './detector';

export * from './types';

export { createDetector } from './detector';

export { normalize, foldConfusables, stripZeroWidth, BUILTIN_CONFUSABLES } from './normalize';

export { decodeLayers } from './decode';

export { defaultRules, createPatternDetector, type PatternRule } from './rules';

export { obfuscationDetector, encodingAnomalyDetector } from './detectors';

export { aggregate, scoreToSeverity } from './score';

export { noopJudge, AnthropicJudge, resolveJudge } from './llm/provider';

export type { AnthropicJudgeOptions } from './llm/provider';

/** Package version, kept in sync with package.json. */
export const VERSION = '0.1.0';

/**
 * Analyze a single input with a fresh detector built from {@link config}.
 *
 * Constructing per call keeps the convenience helper stateless; callers that
 * scan many inputs should build one detector with {@link createDetector} and
 * reuse it to avoid rebuilding the rule set each time.
 */
export function detect(text: string, config?: DetectorConfig): Promise<DetectionResult> {
  return createDetector(config).detect(text);
}
