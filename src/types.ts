/** Ordered severity levels, lowest to highest. */
export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';

/** Numeric rank for a severity, used for comparison and max(). */
export const SEVERITY_RANK: Record<Severity, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** The action a caller should take based on a result. */
export type Verdict = 'allow' | 'flag' | 'block';

/** Broad family a signal belongs to. */
export type SignalCategory =
  | 'instruction-override'
  | 'role-confusion'
  | 'system-exfiltration'
  | 'delimiter-injection'
  | 'refusal-suppression'
  | 'data-exfiltration'
  | 'code-execution'
  | 'obfuscation'
  | 'external-judge';

/** A decoded view of the input produced by a reversible transform. */
export interface DecodedLayer {
  /** Transform that produced this layer, e.g. 'base64' or 'rot13'. */
  method: string;
  /** The decoded text. */
  text: string;
  /** Location of the encoded span in the source, if known. */
  span?: { start: number; end: number };
}

/** One piece of evidence that the input may be an injection attempt. */
export interface DetectionSignal {
  /** Stable identifier for the rule or detector that fired, e.g. 'rule.ignore-previous'. */
  id: string;
  category: SignalCategory;
  severity: Severity;
  /** Confidence in [0,1] that this signal indicates an attack. */
  score: number;
  /** Human-readable explanation of why it fired. */
  message: string;
  /** The substring that triggered the signal, truncated to a safe length. */
  evidence?: string;
  /** Layer the signal came from: 'original', 'normalized', or a decode method. */
  source: string;
}

/** Read-only context handed to every detector. */
export interface DetectorContext {
  /** The raw input as received. */
  original: string;
  /** Normalized form: NFKC, confusables folded, zero-width stripped, lowercased. */
  normalized: string;
  /** Decoded layers discovered in the input. */
  decoded: DecodedLayer[];
}

/** A unit of detection logic. Implementations must be pure and synchronous. */
export interface Detector {
  id: string;
  category: SignalCategory;
  run(ctx: DetectorContext): DetectionSignal[];
}

/** Score thresholds (on a 0-100 scale) that map an aggregate score to a verdict. */
export interface Thresholds {
  /** At or above this score the verdict becomes 'flag'. */
  flag: number;
  /** At or above this score the verdict becomes 'block'. */
  block: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = { flag: 35, block: 70 };

/** The complete outcome of analyzing one input. */
export interface DetectionResult {
  verdict: Verdict;
  /** Aggregate risk score in [0,100]. */
  score: number;
  severity: Severity;
  signals: DetectionSignal[];
  /** Number of characters analyzed. */
  length: number;
  /** Decode layers that were inspected. */
  decoded: DecodedLayer[];
  /** Wall-clock analysis time in milliseconds. */
  elapsedMs: number;
  /** True when the input exceeded the analysis cap and only a prefix was scanned. */
  truncated: boolean;
}

/** A reusable detector produced by createDetector. */
export interface DetectorInstance {
  /** Analyze one input and return a full result. */
  detect(text: string): Promise<DetectionResult>;
}

/** A judge's opinion about a single input. */
export interface JudgeOpinion {
  /** Risk score in [0,1]. */
  score: number;
  /** Short human-readable rationale. */
  rationale: string;
}

/** Score window (0-100) within which the optional judge is consulted. */
export interface JudgeBand {
  /** Lower bound, inclusive. */
  low: number;
  /** Upper bound, exclusive. */
  high: number;
}

/** Optional asynchronous second opinion from an LLM. */
export interface LlmJudge {
  readonly name: string;
  /** Risk score plus a short rationale, or null to abstain. */
  judge(text: string): Promise<JudgeOpinion | null>;
}

/** Configuration for a detector instance. */
export interface DetectorConfig {
  /** Override the default flag/block thresholds. */
  thresholds?: Thresholds;
  /** Replace or extend the built-in detector set. */
  detectors?: Detector[];
  /** Maximum characters of evidence retained per signal. Defaults to 120. */
  maxEvidenceLength?: number;
  /** Optional LLM judge, consulted only for borderline inputs. */
  judge?: LlmJudge;
  /** Score window in which the judge is consulted. The judge is never consulted at or above the block threshold. Defaults to { low: 25, high: 70 }. */
  judgeBand?: JudgeBand;
  /** Maximum characters analyzed; longer input is truncated to this prefix. Defaults to 20000. */
  maxInputChars?: number;
}
