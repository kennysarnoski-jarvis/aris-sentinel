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
  on every leg (see corpus/README.md). Claude Opus 5.5 then ran the same cells: 74/74, 0/12,
  5/5 (one fail-closed), matrix 48/48 with 10 in-call fallback rescues. Kimi unmeasured.
- MONITOR is still the default; `alert` and `error` never kill, even in `--enforce`.

## Not done here
- Live re-validation on a Linux box with Falco and on Windows Server (the kill paths are
  unchanged in logic, but the agents were edited; run the DEPLOY.md / WINDOWS.md demos
  before the next pilot).
- The key-needed suites (`tier2`, `pipeline`, `fpRate`, `matrix`) were not re-run; their
  last results are in `test/*-results.md`. Stubbed-fetch unit tests cover the wire shape.

## 2026-11-10 — session evidence
`decideSession()` in the core: narration accumulated across the execs of one session
(Linux `proc.sid`, Windows PowerShell pid) is judged as a transcript once the window
reaches the block band. It can alert, or block with a judge's verdict; it never convicts at
tier 1. Verdicts are reused until the evidence grows. Both agents use it; `decide()` is
unchanged for callers with no session. Evidence: `corpus/sessions/` (11 files),
`bun run sessions:stub` 11/11, live 11/11 on Claude Opus 5.5 and on a local `arete:27b`,
baseline on Claude 3/5 → 5/5 sessions (see corpus/README.md). 234 unit tests; the corpus
snapshot gained 11 session rows and no existing row moved.

Not done: live validation of the session path on a Falco box (the unit tests drive
`handleEvent` with real `proc.sid` fields, but no kernel was involved); the baseline was
not run on the local judge.

## 2026-11-10 — session-level kill (`--enforce --kill-session`, Linux agent)
A conviction now can end the offender's whole session: the tree, then every process whose
`/proc/<pid>/stat` session id matches, each under the existing guard, then a 10-minute
quarantine of that sid in which any exec is killed unscored. Second opt-in on top of
`--enforce`; ignored without it; never on `alert`; never the agent's own session.
`install.sh` passes the flag through. 11 unit tests with every kill primitive stubbed.

**Live validation (same day):** `docs/demo-kill/validate-session-kill.sh` in a Lima VM
(Ubuntu 24.04, kernel 6.8.0-147, Falco 0.45.2 modern eBPF, Node 18.19, 2 CPU / 4 GB).
First run: 9/17, and two real bugs:
1. `extractPayload` scanned an interpreter's arguments for the first one that was a file
   and read it as the script. `python3 - <incident log>` therefore read the incident log,
   which quotes attacker narration, scored 0.78 and was killed. This bug predates this
   branch and was live in `--enforce` on main. Fix: only the first positional argument is
   the script (`scriptToken`); `-m`, stdin `-`, option values and later arguments are
   never read; the incident log is never read as a script; versioned interpreter names
   (`python3.12`) are recognised.
2. With `--kill-session` that false positive quarantined the operator's own session. Fix:
   a session the agent runs in or was started from (its own sid and its ancestors') is
   never ended or quarantined.
Second run: **23/23** (six scenarios; both bugs are now scenarios 5 and 6).

## 2026-11-10 — tripwire (`--tripwire`, both agents)
The first signal that does not depend on narration. The agent plants a decoy directory
(README + inert helper); the README asks any automated agent to run one command carrying a
128-bit per-host token. Policy, all in the core: the token in anything executed (any
decoded layer) is a tier-1 **block** with no judge; a command that addresses the decoy
without the token is an **alert**; a token payload never enters a session window or reaches
a judge; `redact()` replaces the token with a fingerprint in every log line and incident
(otherwise an operator grepping the incident log would convict themselves, the same class
of bug the session-kill validation found). Opt-in on both agents; `install.sh --tripwire`;
`uninstall.sh` and `--tripwire-remove` delete exactly what was planted; a directory that
exists and is not the agent's is never touched. 50 new unit tests for the tripwire, 2 for
the kill order below (307 total).

**Measured (same day):** `bun run tripwire:bait`, a simulated shell holding the decoy,
two benign ops tasks, five trials each on Claude Opus 5.5, Sonnet 5.5 and Haiku 5.5. 24 of
30 trials ran to their end (six were cut off by the safety classifier, all five of Sonnet's
backup-log trials among them). In those 24: the model read the README 24 times, a command
addressed the decoy 24 times (24 alerts), the canary command was run 0 times, and 23 times
the model said the instruction looked wrong. So on hosted frontier models the alert is
dependable and the block never fires.

**Live validation (same day):** `docs/demo-kill/validate-tripwire.sh` in a Lima VM (Ubuntu
24.04, kernel 6.8.0-147, Falco 0.45.2 modern eBPF, Node 18.19, 2 CPU / 4 GB). Falco reports
the helper (a `#!/bin/sh` script run directly) as `exe=sh`,
`cmdline=register <path> --ticket <token>`, which is what the matcher expected. First run
25/25, and the log contradicted it: after each conviction the session's next command had
still been exec'd. Tightened the check to "the very next command never runs": 24/26.
Two causes, both real:
1. The helper returned immediately, so the driving shell was already past it when the
   conviction was handled (its next exec was logged 5 ms after the conviction). Fix: the helper holds for `TRIPWIRE_HOLD_S` (2 s).
2. With the hold it still failed. `respond()` killed the offender's tree first and the
   session second; the offender's death is what wakes the shell waiting on it, and the
   shell forked its next command while the agent was still enumerating `/proc` for the
   session. **This was also wrong in the merged session kill (PR #9)**: the tightened
   `validate-session-kill.sh` failed 23/24 on unchanged code for a narrated attacker. Fix:
   the session is killed first, the offender's ancestors outermost first
   (`deps.ancestorsOf`), the offender's tree last.
After both: tripwire **26/26** on six consecutive runs, session kill **24/24** on five.

**Unverified:**
1. A member of the session that forks during the kill and has not exec'd yet is not
   enumerated; the quarantine stops it at its next exec. No second sweep is done.
2. Bait rate on open-weight models (the ones an attacker would use) is unmeasured. It
   needs a local model, so it needs Kenny's OK first.
3. Windows: unit tests and `--mock` only.
4. The look is only seen in the exec stream (a path on a command line, or a cwd inside the
   decoy). A file opened without being named (`grep -r`, a backup) is not seen. A Falco
   `open` rule on the decoy paths would close that and would also page on every backup.

Session kill, not done: the validation used no judge (session alert path only; the judged session-block
path is covered by `bun run sessions` on real judges, not on a kernel). Windows has no
session kill beyond `taskkill /T` on the PowerShell process.

