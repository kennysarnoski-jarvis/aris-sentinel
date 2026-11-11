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
- `bun test`: unit tests (expect 463 pass)
- `bun run typecheck`: tsc over detector/ and test/ (expect clean)
- `bun run windows`: PowerShell corpus (expect 10/10)
- `bun run pipeline:stub`: two-tier routing (expect 6/6)
- `bun run sessions:stub`: session evidence routing over corpus/sessions (expect 11/11)
- `bun run behavior`: session behavior over corpus/behavior (expect 21/21)
- `bun run score --session <files|x.jsonl>`: score inputs as ONE session (also shows the areas each command asks about and where the session becomes a sweep)
- `bun run selftest` and `bun run win:mock`: agent smoke tests

Key-needed runs (`tier2`, `pipeline`, `fpRate`, `matrix`, `sessions`, `tripwire:bait`) use whatever tier-2 judges are
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
Opt-in twice. On a block it kills every process sharing the offender's sid under the same
protected-process guard, THEN the offender's tree, and quarantines the sid (execs in it are
killed unscored). The order is load-bearing: the session dies first, the offender's
ancestors outermost first, the offender last. Killing the offender first wakes the shell
that is waiting on it, and it ran one more command (found live 2026-11-10). Never on
`alert`, never in monitor, never the agent's own session. The kill primitives are on `deps`
(`killTree`, `killPid`, `sessionPids`, `ancestorsOf`, `procName`, `now`, `mode`);
tests MUST stub them before flipping `deps.mode.enforce`, or they would signal real pids.
Live check (needs the Lima VM; ask Kenny first): `docs/demo-kill/validate-session-kill.sh`,
expect 24/24. For an interpreter exec only the FIRST positional argument is read as the
script (`scriptToken`); never widen that to "any argument that is a file".

## Tripwire (--tripwire, both agents)
Opt-in. The agent plants decoy directories (README + inert helper that holds its caller
for `TRIPWIRE_HOLD_S` seconds so a session kill lands before the caller's next command;
text and policy in the core) and matches a per-host random token. Invariants: the token executed = tier-1 block
with no judge; the decoy merely addressed = alert, never a kill; a token payload never
enters a session window or reaches a judge; the token never appears in a log line, an
incident or a test fixture (`redact()` puts a fingerprint there). Never put a real token on
a command line: on a host with the agent armed that is a conviction. Tests build their own
matcher with `createTripwire` and plant only in a temp directory. `bun run tripwire:bait`
(key-needed) measures how often a model runs the canary command; live check (needs the
Lima VM; ask Kenny first): `docs/demo-kill/validate-tripwire.sh`, expect 26/26.
The decoy's LOOK (README wording, helper name, flag, directories) is per host: the
published defaults are in the core and public, a host's own come from
`ARIS_TRIPWIRE_README` / `_HELPER` / `_FLAG` / `_DIRS` (`tripwireLook`,
`tripwireLookFromEnv`). Invariants: the published decoy stays byte-for-byte what it is
(every bait rate was measured on it); the matcher never reads the look; an unusable look
plants nothing and keeps the decoys already there matched (`held`), never falls back to
the published one; a decoy or helper the settings no longer ask for is removed. Never
commit a host's own wording, and never print it in a results file.

## Session behavior (--behavior, both agents)
Opt-in. The core reads each command line (`behaviorCategories`), names the areas of the
host it asks about (`BEHAVIOR_CATEGORIES`, four of them sensitive) and keeps them per
session for `BEHAVIOR.windowMs`; five areas with two sensitive is a sweep. Invariants: a
sweep is an alert and NEVER a kill, a quarantine or a judge call, in any mode; it is
reported once per window; the tracker keeps area names and times, never command text; a
payload carrying the tripwire token is never observed; the Linux agent passes the command
line only (`ctx.command`), never the script file it appended for the narration scorer.
`corpus/behavior/*.jsonl` (`{"t": seconds, "payload": ...}`) holds the sessions, including
three agentic ones that are EXPECTED misses and one benign one that is an EXPECTED alert:
do not "fix" those, they are the stated limits. The thresholds were fixed before the
samples were scored; change one only by the corpus rule (score first, record it, snapshot).
A lookup aimed at the `sudo`, `wheel` or `admin` group (`getent group sudo`, `grep '^sudo:'
/etc/group`) is `privilege` ONLY, not also `accounts`: counted as both, one command supplies
both sensitive areas (measured in corpus/README.md, 2026-11-11). Do not "simplify" it to both.
A sweep's `steps` groups execs under `BEHAVIOR.stepMs` apart: one command line fans out
into several execs a millisecond apart, so only the pauses between steps mean anything.
Live check (needs the Lima VM; ask Kenny first): `docs/demo-kill/validate-behavior.sh`,
expect 29/29. `docs/demo-kill/soak-behavior.sh` (same VM) runs real admin activity under
the agent and prints what was reported; it is a measurement, not a pass/fail.
`bun run tripwire:bait -- --tasks survey` (key-needed) measures the rule on a real model.

## Long payloads (WINDOW_LINES)
`inspect()` scores a payload longer than `WINDOW_LINES` (120) lines in overlapping windows
and returns the strongest; `scoredLayer` is then that window and `windowed` is true. Tier 1
convicts CONCENTRATED narration only. This exists because, scored as one text, 2 of the
1,727 scripts a stock Ubuntu ships were tier-1 blocks (`docs/demo-kill/scan-system-scripts.mjs`
reproduces it). Never window session evidence (`narrationScore(win.text)` stays whole), and
never raise the corpus above 120 lines per file without re-reading this.

## Rules
- The agent and core stay dependency-free plain Node ≥18; the core stays ONE file
  (install.sh copies it as-is). MONITOR is the default mode; `alert` and `error`
  decisions never kill.
- Don't commit or push without Kenny's go-ahead. The GitHub repo is public.
- Ask Kenny before starting Ollama, loading a local model or booting the demo VM: his Mac
  runs other RAM-heavy work. Prefer the hosted judge for measurements.
