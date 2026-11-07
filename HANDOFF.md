# Handoff: reliability fixes (2026-11-07)

A review of the Linux agent, Windows agent, shared core, TS detector and Langflow demo
turned up the bugs below. **None of them is fixed yet**: the repo is unchanged from
commit `3a5ea76`. Every item is a reliability/correctness fix. None of them changes
what the detector looks for.

## Baseline (verified 2026-11-07, all key-free)

| command | result |
|---|---|
| `bun run test` | TP=7 FP=0 FN=0 TN=20, precision 1.00 / recall 1.00 |
| `bun run windows` | 5/5 as expected |
| `bun run pipeline:stub` | 6/6, tier-2 called only for the escalate band |
| `node agent/sentinel-agent.mjs --selftest` | block / allow / allow as expected |
| `npm run win:mock` | 3 narrated events detected, benign + terse not flagged |

`detector/inspect.ts` and `agent/sentinel-core.mjs` give **identical** verdicts and
scores on all 32 corpus files today. Keep it that way: snapshot every corpus file's
verdict and score before refactoring, then diff afterwards.

## Findings, in suggested fix order

### 1. Three hand-copied detectors that have drifted apart
- `detector/features.ts` + `decode.ts` (TS, used by the tests)
- `agent/sentinel-core.mjs` (what actually runs on customer boxes)
- `interposition/sentinel-langflow-demo.mjs` (its own inline copy of tier 1 + tier 2)

They already differ. The TS `diagnosis_then_fix` has a `since … failed/blocked …`
pattern that the core lacks. `agent_first_person` has `now I'll` in TS and
`I (proceed|will proceed)` in the core. Only TS has hex decoding. Tier 2 is the
Kimi → Anthropic provider chain in TS but Anthropic-only in the core and the demo.
**Net effect: the tests prove a different detector from the one deployed.**

Fix: make one canonical module (plain dependency-free ESM, so the agent can still run
on bare Node). Have the TS files become thin typed wrappers that re-export it, and have
the Langflow demo import it. Take the union of the existing patterns so no current
detection is lost. Add a test asserting that no file other than the core defines
feature regexes.

### 2. A detector crash silently allows the process
- `agent/sentinel-agent.mjs:223`: `try { d = await decide(...) } catch (e) { return; }`
- `agent/win/sentinel-agent-win.mjs:76`: same thing

Any exception in `decide()` means the payload is never judged and nothing is logged.
Fix: log the error and write an incident (`decision: "error"`), and report it to the
cloud. Don't drop it.

### 3. The tier-2 verdict is trusted without validation
- `agent/sentinel-core.mjs:117` and `interposition/sentinel-langflow-demo.mjs:139`: `return JSON.parse(m[0])`
- `detector/adjudicate.ts:102`: `JSON.parse(m[0]) as Adjudication`

The model reply is used as-is. Then `a.confidence.toFixed(2)` runs at
`sentinel-core.mjs:142`, `detector/decide.ts:64` and `sentinel-langflow-demo.mjs:194,199`.
If `confidence` comes back as a string (or is missing), that throws, and in the agents it
lands in finding #2: a silent allow. An `"agentic": "false"` string is also truthy.
Fix: strictly validate the verdict (agentic must be a boolean or exactly "true"/"false";
confidence must be numeric, clamped to 0–1; reasoning must be a string). Treat anything
invalid as no verdict, which means try the next provider, then fail closed.

### 4. No timeout on tier-2 calls
- `agent/sentinel-core.mjs:106` and `interposition/sentinel-langflow-demo.mjs:119`: bare `fetch` with no AbortController.

If the API hangs, `decide()` never returns. Fix: give each attempt a timeout plus an
overall deadline (env-configurable). A timeout counts as a failed attempt and falls
through to the existing fail-closed path.

### 5. Script files are resolved against the agent's cwd, not the process's
- `agent/sentinel-agent.mjs:120`: `existsSync(tok)` with a relative path
- `agent/aris_rules.yaml:14`: the output has no `%proc.cwd`

Example: `python3 job.py` launched from `/tmp`. The agent looks for `job.py` in its own
WorkingDirectory (`/usr/local/lib/<name>`), so it either misses the script or reads an
unrelated file with the same name. Fix: add `cwd=%proc.cwd` to the rule output. Resolve
relative tokens against `proc.cwd`, falling back to `/proc/<pid>/cwd/`, and never against
the agent's own cwd. Also: `:117` only checks for exact `-c`/`-e`, so combined flags like
`bash -lc` or `python3 -Bc` get treated as scripts. Note that a changed rules file has to
be re-copied by `install.sh` on existing pilots.

### 6. Escalate with no tier-2 key behaves differently per entry point
- `detector/decide.ts`: no key → `adjudicate()` fails closed → **block**
- `agent/sentinel-core.mjs:133`: no key → **allow**

Pick one policy and use it everywhere. Suggested: add a third decision, `alert`, meaning
an incident is logged and reported but nothing is killed, even in `--enforce`. Use it
when the escalate band can't be adjudicated. Keep the real refusal/error → fail-closed
block behaviour as designed. Both agents and the cloud alert formatter
(`agent/aris-cloud-endpoint.py`) then need to handle `alert`.

### 7. No cost/rate control on tier 2
Each escalate-band exec is a fresh LLM call: no cache, no concurrency cap, no budget. A
cron job re-running the same verbose script every minute gets billed every minute. Fix:
a verdict cache keyed by a hash of the scored layer (cache real verdicts only, never
fail-closed ones), in-flight dedup, a concurrency cap, and a per-minute budget. Once the
budget is exhausted the result becomes `alert` (see #6), not a silent allow.

## Constraints to respect
- The agent must stay **dependency-free plain Node ≥18** (it's copied onto bare boxes).
  Tier 2 there is raw `fetch`, not the SDK.
- `agent/install.sh:36-40` copies `sentinel-core.mjs` as `core.mjs` and `sed`s the import
  in `agentd.mjs`. Any new file the agent imports must be added to the installer and
  `uninstall.sh` the same way.
- The Kimi endpoint is the Anthropic wire at `api.kimi.com/coding` (`/v1/messages`) with a
  Bearer token and model slug `k3`. Don't use `api.moonshot.ai` (separate key pool,
  OpenAI wire). See `detector/adjudicateKimi.ts`.
- Keep `claude-opus-4-8` and the existing prompts unless Kenny asks to change them.
- `test/adjudicatorMatrix.ts` uses the SDK-based `attempt()` / `SYSTEM_AUTHORSHIP` from
  `detector/adjudicate.ts`, so keep those exports working.
- MONITOR stays the default. Never make a change that kills processes by default.

## Done looks like
All seven fixed, with unit tests (`bun test`) for validation, timeout, the provider-chain
order (stubbed fetch), cache/budget/concurrency, cwd resolution and the alert path. The
baseline table above is unchanged, corpus verdicts/scores match the snapshot (or any
difference is explained), README/DEPLOY updated, committed.
