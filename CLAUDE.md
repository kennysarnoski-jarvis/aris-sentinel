# Aris Sentinel

Defensive runtime agent: detects autonomous-LLM attackers on a host by their
self-narration, and alerts or kills before the destructive step. See README.md for
architecture and THESIS.md for positioning. HANDOFF.md records the 2026-11-07
reliability fixes and what is still unverified live.

## The one rule about the detector
`agent/sentinel-core.mjs` is the ONLY place a pattern, a prompt, a threshold or the
decision policy lives. `detector/*.ts` re-export it; the agents and the demo import it.
`bun test` fails if you copy a pattern anywhere else, and fails if a corpus verdict
moves — regenerate `test/corpus-snapshot.json` with `bun run corpus:snapshot` only for an
intentional change, and commit the diff.

## Commands (key-free)
- `bun run test:all`: everything below in one go
- `bun run test`: tier-1 corpus (expect precision/recall 1.00)
- `bun test`: unit tests (expect 111 pass)
- `bun run typecheck`: tsc over detector/ and test/ (expect clean)
- `bun run windows`: PowerShell corpus (expect 5/5)
- `bun run pipeline:stub`: two-tier routing (expect 6/6)
- `bun run selftest` and `bun run win:mock`: agent smoke tests

Key-needed runs (`tier2`, `pipeline`, `fpRate`, `matrix`) read `KIMI_API_KEY` /
`ANTHROPIC_API_KEY` and write results to `test/*-results.md`. Read those files; don't
paste payload output.

## Rules
- The agent and core stay dependency-free plain Node ≥18; the core stays ONE file
  (install.sh copies it as-is). MONITOR is the default mode; `alert` and `error`
  decisions never kill.
- Don't commit or push without Kenny's go-ahead. The GitHub repo is public.
