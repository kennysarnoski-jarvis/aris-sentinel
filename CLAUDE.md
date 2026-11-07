# Aris Sentinel

Defensive runtime agent: detects autonomous-LLM attackers on a customer's box by their
self-narration, and alerts or kills before the destructive step. See README.md for
architecture and THESIS.md for positioning.

## Start here
**Read [HANDOFF.md](HANDOFF.md) first.** It lists open reliability bugs (with file:line),
the verified test baseline, constraints and the definition of done for the current work.

## Commands (key-free)
- `bun run test`: tier-1 corpus (expect precision/recall 1.00)
- `bun run windows`: PowerShell corpus (expect 5/5)
- `bun run pipeline:stub`: two-tier routing (expect 6/6)
- `node agent/sentinel-agent.mjs --selftest` and `npm run win:mock`: agent smoke tests

Key-needed runs (`tier2`, `pipeline`, `fpRate`) read `KIMI_API_KEY` / `ANTHROPIC_API_KEY`
and write results to `test/*-results.md`. Read those files; don't paste payload output.

## Rules
- The agent stays dependency-free plain Node ≥18; MONITOR is the default mode.
- Don't commit or push without Kenny's go-ahead.
