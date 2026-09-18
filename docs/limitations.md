# Limitations

This is a heuristic content filter. It produces signals and a recommendation, not a guarantee. The [threat model](threat-model.md) covers blind spots and known evasions in more depth.

- **Heuristic, not exhaustive.** Detection rests on a pattern catalog and a handful of heuristics. It will miss novel phrasings, paraphrases, and attacks not represented in the rules. A `verdict` of `allow` is not a safety guarantee.
- **English-centric with partial multilingual coverage.** There are hand-written rules for several non-English languages, but coverage is uneven and far from complete.
- **False positives.** Several rules (notably the softer social-engineering, educational-framing, and disclaimer-suppression rules) collide with benign text. Some code-execution phrases (e.g. `wget`, `drop table`, `truncate`) appear legitimately in technical content. Tune thresholds for your traffic; treat `flag` as "review," not "reject."
- **Decoding is bounded and conservative.** Decoders cap size, require mostly-printable output, and cover only base64, hex, URL-encoding, decimal char codes, and rot13. Deeply nested, custom, or chunked encodings will not be unwrapped. Decoded layers are scanned for known patterns; novel content inside a decode is only caught by the encoding-anomaly heuristic, not understood.
- **Single-input, stateless.** Each call analyzes one string with no conversation history or surrounding context. Multi-turn attacks that are benign per message are out of scope.
- **The confusable map is finite.** `BUILTIN_CONFUSABLES` covers common look-alikes; unusual scripts or rare homoglyphs may slip through normalization.
- **The judge is optional and best-effort.** It is off by default, only consulted for borderline scores, and abstains on any error. Do not rely on it as a primary control. When enabled, it sends the input text to a third-party API.
- **Not a substitute for defense in depth.** Use this as one layer alongside least-privilege tool access, output filtering, and human review for high-risk actions.
