# Handoff: reliability fixes — RESOLVED (2026-11-07)

The 2026-11-07 review found seven reliability bugs in the Linux agent, Windows agent,
shared core, TS detector and Langflow demo. **All seven are fixed** in this tree, with
unit tests (`bun test`, 111 tests). The corpus verdicts did not move: every one of the
44 snapshot rows (32 corpus files + 12 FP samples) has the same score, verdict and
signals as before the refactor (`test/corpus-snapshot.json`).

## Baseline (re-verified after the fixes, all key-free)

| command | result |
|---|---|
| `bun run test` | TP=7 FP=0 FN=0 TN=20, precision 1.00 / recall 1.00 |
| `bun test` | 111 pass, 0 fail |
| `bun run windows` | 5/5 |
| `bun run pipeline:stub` | 6/6, tier-2 called only for the escalate band |
| `bun run selftest` | BLOCK / ALLOW / ALLOW |
| `bun run win:mock` | 3 narrated events detected, benign + terse not flagged |

## Findings → fixes

| # | finding | fix | test |
|---|---|---|---|
| 1 | three hand-copied detectors had drifted; tests proved a different detector than the deployed one | `agent/sentinel-core.mjs` is the single canonical module (union of all patterns, hex decode included). `detector/*.ts` are typed re-exports; both agents and the Langflow demo import it. `@anthropic-ai/sdk` dropped: the whole repo is dependency-free. | `single-source.test.ts` fails if any other file defines a pattern or prompt; `corpus-snapshot.test.ts` freezes every verdict |
| 2 | a detector exception silently allowed the process | both agents log it, write an incident with `decision: "error"`, report it off-box. Nothing killed. | `agent.test.ts`, `agent-win.test.ts` |
| 3 | tier-2 verdict trusted as-is (`"false"` truthy, string confidence crashed `.toFixed`) | `normalizeVerdict()`: `agentic` boolean or exactly `"true"`/`"false"`, confidence numeric + clamped 0–1, reasoning string. Invalid = no verdict → next provider → fail-closed. Applied to injected adjudicators too. | `core.test.ts` "verdict validation", "garbage adjudicator" |
| 4 | no timeout on tier-2 calls | `AbortController` per attempt (`ARIS_TIER2_TIMEOUT_MS`, 20 s) + chain deadline (`ARIS_TIER2_DEADLINE_MS`, 45 s). Timeout = failed attempt → fail-closed. | `core.test.ts` "attempt", "provider chain" |
| 5 | script paths resolved against the agent's cwd; `-lc` / `-Bc` treated as scripts | rule emits `cwd=%proc.cwd`; `resolveScript()` uses it, then `/proc/<pid>/cwd/`, never the agent's cwd. `hasInlineCode()` understands combined flag groups per interpreter. **Re-run `install.sh` on existing pilots** (it re-copies the rule). | `agent.test.ts` |
| 6 | escalate with no key: TS blocked, core allowed | one policy in `decide()`: no key or budget spent → **`alert`** (logged + reported, never killed). Real refusal/error → fail-closed block as designed; `ARIS_FAIL_MODE=alert` downgrades that to alert. Both agents, the demo and the cloud formatter handle `alert` and `error`. | `core.test.ts` "decide: policy" |
| 7 | no cost/rate control on tier 2 | the governor: verdict cache by payload hash (real verdicts only, TTL), in-flight dedup, concurrency cap, per-minute budget → `alert` when spent, never a silent allow | `core.test.ts` "governor" |

## Constraints respected
- Agent + core are plain Node ≥ 18, zero deps; the core is still one file (`install.sh` unchanged).
- Kimi endpoint is `api.kimi.com/coding` (Anthropic wire, Bearer, slug `k3`).
- Both prompts unchanged. `attempt()` / `SYSTEM_AUTHORSHIP` exports kept for `test/adjudicatorMatrix.ts`.
- **Later on 2026-11-07, with Kenny's OK:** the default judge moved from Kimi K3 to Claude
  Opus 5.5 with server-side fallbacks + a de-fanged-prompt retry, and an OpenAI-wire leg
  was added so a local model (Ollama/vLLM) can judge with nothing leaving the box. Chain
  order is `ARIS_TIER2_ORDER` (default `local,anthropic,openai,kimi`). Fail-closed policy
  unchanged.
- **Later still:** the key-needed suites ran live on a local qwen2.5:14b (Ollama): pipeline
  74/74, fpRate 0/12, tier2 5/5, matrix 8/8 with the two-criteria prompt, which now leads
  on every leg (see corpus/README.md). Hosted judges (Claude, Kimi) still unmeasured on
  the new chain.
- MONITOR is still the default; `alert` and `error` never kill, even in `--enforce`.

## Not done here
- Live re-validation on a Linux box with Falco and on Windows Server (the kill paths are
  unchanged in logic, but the agents were edited; run the DEPLOY.md / WINDOWS.md demos
  before the next pilot).
- The key-needed suites (`tier2`, `pipeline`, `fpRate`, `matrix`) were not re-run; their
  last results are in `test/*-results.md`. Stubbed-fetch unit tests cover the wire shape.
