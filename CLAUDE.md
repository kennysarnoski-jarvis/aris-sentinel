# Aris Sentinel

Defensive runtime agent: detects autonomous-LLM attackers on a host by their
self-narration, and alerts or kills before the destructive step. See README.md for
architecture and docs/THESIS.md for positioning. docs/HANDOFF.md records the 2026-11-07
reliability fixes and what is still unverified live.

## The one rule about the detector
`agent/sentinel-core.mjs` is the ONLY place a pattern, a prompt, a threshold or the
decision policy lives. `detector/*.ts` re-export it; the agents and the demo import it.
`bun test` fails if you copy a pattern anywhere else, and fails if a corpus verdict
moves — regenerate `test/corpus-snapshot.json` with `bun run corpus:snapshot` only for an
intentional change, and commit the diff. New corpus samples are scored BEFORE any pattern
change and the result recorded in corpus/README.md (see its rules).

## Commands (key-free)
- `bun run score <file>`: score a file the way the agent would (verdict, signals, evidence)
- `bun run test:all`: everything below in one go
- `bun run test`: tier-1 corpus (expect precision 1.00, tier-1 recall 0.61, pipeline-reachable recall 1.00, FP=0)
- `bun test`: unit tests (expect 255 pass)
- `bun run typecheck`: tsc over detector/ and test/ (expect clean)
- `bun run windows`: PowerShell corpus (expect 10/10)
- `bun run pipeline:stub`: two-tier routing (expect 6/6)
- `bun run sessions:stub`: session evidence routing over corpus/sessions (expect 11/11)
- `bun run score --session <files|x.jsonl>`: score inputs as ONE session
- `bun run selftest` and `bun run win:mock`: agent smoke tests

Key-needed runs (`tier2`, `pipeline`, `fpRate`, `matrix`, `sessions`) use whatever tier-2 judges are
configured (`ANTHROPIC_API_KEY`, `OPENAI_BASE_URL`+`OPENAI_MODEL`, `KIMI_API_KEY`) and
write results to `test/*-results.md`. Read those files; don't
paste payload output.

## Session evidence (decideSession)
Both agents call `decideSession(sessionKey, payload)`: narration-bearing payloads are kept
per session and the window is judged as a transcript once it reaches the block band.
Invariant: session evidence may alert, or block WITH a judge's verdict; it never convicts
at tier 1. A fail-closed run of a key-needed harness is not a result: `sessions` reports
INVALID when the judge never answered.

## Session kill (Linux agent, --enforce --kill-session)
Opt-in twice. On a block it kills the offender's tree, then every process sharing its sid
under the same protected-process guard, and quarantines the sid (execs in it are killed
unscored). Never on `alert`, never in monitor, never the agent's own session. The kill
primitives are on `deps` (`killTree`, `killPid`, `sessionPids`, `procName`, `now`, `mode`);
tests MUST stub them before flipping `deps.mode.enforce`, or they would signal real pids.
Live check (needs the Lima VM; ask Kenny first): `docs/demo-kill/validate-session-kill.sh`,
expect 23/23. For an interpreter exec only the FIRST positional argument is read as the
script (`scriptToken`); never widen that to "any argument that is a file".

## Rules
- The agent and core stay dependency-free plain Node ≥18; the core stays ONE file
  (install.sh copies it as-is). MONITOR is the default mode; `alert` and `error`
  decisions never kill.
- Don't commit or push without Kenny's go-ahead. The GitHub repo is public.
- Ask Kenny before starting Ollama, loading a local model or booting the demo VM: his Mac
  runs other RAM-heavy work. Prefer the hosted judge for measurements.
