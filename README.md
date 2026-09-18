# prompt-injection-detector

A layered detector for prompt injection and jailbreak attempts in text destined for an LLM. It normalizes the input, decodes embedded payloads, runs pattern rules and obfuscation heuristics, and returns a 0 to 100 risk score with an `allow`, `flag` or `block` verdict. Detection is local and deterministic, and an optional LLM judge can be consulted for borderline scores. It is for engineers who screen LLM input, and ships as a library, an HTTP API and a CLI. Status: version 0.1.0. It is a heuristic filter, not a guarantee. See [docs/limitations.md](docs/limitations.md).

## Installation

Prerequisites:

- Node.js 20 or newer.
- pnpm 10 (`packageManager` is `pnpm@10.33.2`) for development.

As a dependency:

```sh
pnpm add prompt-injection-detector
# or: npm install prompt-injection-detector
```

From a checkout:

```sh
pnpm install
pnpm build
```

No environment variables are required. `PID_LLM_PROVIDER`, `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL` only enable the optional judge. See [docs/configuration.md](docs/configuration.md).

## Usage

```ts
import { detect } from 'prompt-injection-detector';

const result = await detect(inputText);
console.log(result.verdict, result.score);
```

Daily commands:

```sh
pnpm dev          # watch the CLI via tsx
pnpm api          # run the HTTP server via tsx, PORT or 3000
pnpm build        # bundle with tsup
pid scan --file ./suspicious.txt   # CLI after build, exit code 0 allow, 1 flag, 2 block
```

The HTTP server exposes `POST /detect` and `GET /health`. The library API, request and response shapes, and all CLI flags are in [docs/usage.md](docs/usage.md). The repo has no deployment configuration. You run the server yourself and put authentication and rate limiting in front of it.

## Project structure

```text
├── .github
│   └── workflows
│       └── ci.yml
├── docs
│   ├── architecture.md
│   ├── threat-model.md
│   ├── diagrams
│   └── archive
├── src
│   ├── index.ts
│   ├── detector.ts
│   ├── normalize.ts
│   ├── decode.ts
│   ├── rules.ts
│   ├── detectors.ts
│   ├── score.ts
│   ├── llm
│   │   └── provider.ts
│   ├── server.ts
│   └── cli.ts
├── test
├── vault
├── CONTRIBUTING.md
├── package.json
└── tsconfig.json
```

Components and data flow are described in [docs/architecture.md](docs/architecture.md).

## Coding style

ESLint (`eslint.config.js`) and Prettier (`.prettierrc.json`: single quotes, semicolons, 100 character lines, trailing commas) are configured. TypeScript runs with `strict: true`. No commit convention or git hooks are configured. [CONTRIBUTING.md](CONTRIBUTING.md) asks that every rule or stage ships with a true positive and a near miss fixture.

```sh
pnpm lint
pnpm format:check
pnpm typecheck
```

CI runs lint, typecheck, tests with coverage, and build.

## Test

```sh
pnpm test         # vitest run
pnpm test:cov     # with coverage, used in CI
```

The suites in `test/` cover normalization, decoding, the rule catalog, the detectors, scoring, the full detector, the judge, the HTTP server, and a smoke test.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Usage reference](docs/usage.md)
- [Configuration](docs/configuration.md)
- [Limitations](docs/limitations.md)
- [Pipeline diagram source](docs/diagrams/pipeline.mmd)

## License

MIT. See [LICENSE](LICENSE).
