# prompt-injection-detector

A layered detector for prompt-injection and jailbreak attempts in text that will be
fed to an LLM. It runs as a library, an HTTP API, or a CLI, and the core detection
path has no network dependency: normalization, decoding, and rules do the work, with
an optional LLM judge reserved for genuinely ambiguous cases.

Status: scaffolding. The detection engine lands in the first feature PR.

## Why this exists

Most "guardrail" wrappers are a single regex or a single model call. Real injection
attempts hide behind unicode look-alikes, base64/hex/rot13 encoding, instructions
smuggled inside data, and role confusion (the classic "ignore previous instructions,
you are now ..."). This project treats detection as a pipeline of independent,
individually testable stages and reports a calibrated severity instead of a yes/no
guess.

## Install

    pnpm install
    pnpm run build

## Development

    pnpm run lint
    pnpm run typecheck
    pnpm run test:cov

## License

MIT
