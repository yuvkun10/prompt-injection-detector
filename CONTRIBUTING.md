# Contributing

This repo is small on purpose. Before opening a PR:

1. `pnpm install`
2. `pnpm run lint && pnpm run typecheck && pnpm run test:cov && pnpm run build`

Detection logic lives in `src/`. Every rule or stage should ship with fixtures in
`test/` that cover both a true positive and a near-miss false positive — the
false-positive case is the one that keeps the detector usable in production.

Keep dependencies minimal. The core detection path must not require network access.
