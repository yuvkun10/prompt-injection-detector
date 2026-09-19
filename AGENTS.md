# AGENTS.md

`prompt-injection-detector` is a TypeScript library, HTTP API and CLI that scores text for prompt injection and jailbreak attempts and returns an `allow`, `flag` or `block` verdict.

## Setup

Node.js 20 or newer and pnpm 10 (`packageManager` is `pnpm@10.33.2`).

```sh
pnpm install
pnpm build
```

No environment variables are required. `PID_LLM_PROVIDER`, `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL` only enable the optional judge. See [docs/configuration.md](docs/configuration.md).

## Commands

```sh
pnpm dev           # tsx watch src/cli.ts
pnpm api           # tsx src/server.ts
pnpm build         # tsup
pnpm lint          # eslint .
pnpm format:check  # prettier --check .
pnpm typecheck     # tsc --noEmit
pnpm test          # vitest run
pnpm test:cov      # vitest run --coverage (used in CI)
```

## Project structure

- `src/normalize.ts`, `src/decode.ts`: input normalization and payload decoding.
- `src/rules.ts`, `src/detectors.ts`, `src/score.ts`, `src/detector.ts`: rules, heuristics, scoring.
- `src/llm/provider.ts`: optional LLM judge.
- `src/server.ts`, `src/cli.ts`: HTTP API and CLI.
- `test/`: Vitest suites and `fixtures.ts`.

Details are in [docs/architecture.md](docs/architecture.md).

## Conventions

- TypeScript `strict`. Prettier: single quotes, semicolons, 100 character lines, trailing commas.
- Every rule or stage ships with fixtures in `test/` for a true positive and a near miss false positive.
- Keep dependencies minimal. The core detection path must not need network access.
- No commit convention is enforced. Do not add attribution trailers.

## Testing

Before a PR run `pnpm run lint && pnpm run typecheck && pnpm run test:cov && pnpm run build`. CI runs the same.

## Safety

- Never commit `.env` files or API keys.
- The detector is a heuristic filter, not a guarantee. Do not describe it otherwise. See [docs/limitations.md](docs/limitations.md).

## More

- [docs/README.md](docs/README.md): docs index
- [docs/threat-model.md](docs/threat-model.md): threat model
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution rules
