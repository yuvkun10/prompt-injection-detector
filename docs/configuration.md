# Configuration

`DetectorConfig` (passed to `detect` or `createDetector`):

| Field               | Default                                  | Meaning                                                                |
| ------------------- | ---------------------------------------- | ---------------------------------------------------------------------- |
| `thresholds`        | `{ flag: 35, block: 70 }`                | Score cutoffs (0 to 100) mapping the aggregate score to `flag` / `block`. |
| `detectors`         | pattern + obfuscation + encoding-anomaly | Replace the built-in detector set entirely.                            |
| `maxEvidenceLength` | `120`                                    | Maximum characters of `evidence` retained per signal.                  |
| `judge`             | none                                     | An `LlmJudge` consulted only for borderline scores.                    |
| `judgeBand`         | `{ low: 25, high: 70 }`                  | Inclusive score window in which the judge is consulted.                |

### Thresholds

`flag` and `block` are on the 0 to 100 scale. The default `DEFAULT_THRESHOLDS` is `{ flag: 35, block: 70 }`. Raising thresholds reduces false positives at the cost of recall; lowering them does the reverse. The CLI and HTTP API both accept threshold overrides per request.

### Judge

A judge implements `LlmJudge`: `judge(text): Promise<{ score, rationale } | null>` returning a `[0,1]` risk score or `null` to abstain. Two are provided:

- `noopJudge`: always abstains; the default, so the engine runs fully offline.
- `AnthropicJudge`: calls the Anthropic Messages API. It clamps input length, caps output tokens, and treats any error as abstention.

The CLI and HTTP server select a judge with `resolveJudge(env)`. It returns an `AnthropicJudge` only when **both** `PID_LLM_PROVIDER=anthropic` and `ANTHROPIC_API_KEY` are set, otherwise the `noopJudge`:

| Variable            | Purpose                                           |
| ------------------- | ------------------------------------------------- |
| `PID_LLM_PROVIDER`  | Must equal `anthropic` to enable the judge.       |
| `ANTHROPIC_API_KEY` | API key for the Anthropic Messages API.           |
| `ANTHROPIC_MODEL`   | Optional model id; defaults to `claude-opus-4-8`. |

When you call `detect` / `createDetector` directly, no judge is used unless you pass one in `config.judge`.
