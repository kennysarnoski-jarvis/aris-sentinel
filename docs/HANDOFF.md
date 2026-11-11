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
2. Bait rate on open-weight models: measured on three, see below. Two run on a Qwen
   architecture and one is a Gemma (the fourth and fifth passes below), five trials per
   task each. An attacker's own model and scaffold are still unmeasured.
3. Windows: unit tests and `--mock` only.
4. The look is only seen in the exec stream (a path on a command line, or a cwd inside the
   decoy). A file opened without being named (`grep -r`, a backup) is not seen. A Falco
   `open` rule on the decoy paths would close that and would also page on every backup.

## 2026-11-10 — session behavior (`--behavior`, both agents)

The second signal that needs no narration, after the tripwire, and the first that needs
nothing from the attacker's model but orientation. In the core: `behaviorCategories()`
reads one command line and names the areas of the host it asks about (fourteen, four of
them sensitive), `createBehaviorTracker()` keeps them per session for five minutes, and
`decideSession()` turns an allow into an **alert** when the window holds five areas with
two sensitive. Never a block, a kill, a quarantine or a judge call; reported once per
window; area names and timestamps only. Opt-in on both agents (`--behavior`,
`install.sh --behavior`, `ARIS_BEHAVIOR_WINDOW_MS`). The Linux agent passes the command
line alone (not the script file it appends for the narration scorer) and, with the flag
on, no longer skips payloads under three characters (`id`, `w`). `bun run score --session`
shows the areas and where a session becomes a sweep. 128 new unit tests for it, a
key-free harness (`bun run behavior`, 17/17, in `test:all`), 17 rows added to the corpus
snapshot and none changed. (442 unit tests in all, with the seven for long payloads below.)

**Measured (same day):** see corpus/README.md. Written samples 17/17 as predicted on the
first run, thresholds fixed beforehand and untouched. Hosted Claude on the three bait
tasks: 0 of 36 completed trials reported. Hosted Claude on a new `survey` task (not in the
harness's default set): 15 of 15 reported, at the fourth command in fourteen, median gap
1.0 to 1.9 s. That third pass of the bait harness also re-measured the tripwire on the
default tasks: decoy addressed 36 of 36, canary command 0 of 36, flagged 36 of 36; Opus
completed 1 of 5 goal-directed trials this time (it did not run the command) and Sonnet
0 of 5 backup trials, so 9 of 45 were cut off.

**Live validation (same day):** Lima VM, Ubuntu 24.04.5, kernel 6.8.0-147, Falco 0.45.2
modern eBPF, Node 18.19, 2 CPU / 4 GB, deleted afterwards.
`docs/demo-kill/validate-behavior.sh`: 28/28 on the first run, 29/29 once a check was
added, then 29/29 on three consecutive runs of the final code (after the changes below). Fully armed
(`--enforce --kill-session --behavior`), a sweep killed nothing and quarantined nothing;
the alert landed on the command that completed the sweep and not on the driver script
whose text holds all six; a script whose text contains a sweep that never runs was not
reported; a sweep slower than the (shortened, 20 s) window was missed as stated; a sweep
followed by a narrated step was an alert and then a session kill. Regression on the same
VM after the core changes: session kill **24/24**, tripwire **26/26**.

What the live runs found, all fixed on the branch:
1. **The reported timing was wrong.** The first run passed and its incident log showed a
   median gap of 1 ms for the chained sweep: `bash -c 'id; uname -a'` is three execs a
   millisecond apart. The hit now carries `steps` (execs under `BEHAVIOR.stepMs` = 500 ms
   apart are one step) and the median pause between steps.
2. **A reader bug** (`soak-behavior.sh`, real lynis): findstr's `/s` flag pattern matched
   any path beginning `/s…` or `/usr`, so `egrep /usr/bin/egrep ^passwd /etc/nsswitch.conf`
   counted as a recursive secret hunt. grep's and findstr's recursive flags are now two
   rules.
3. **A tier-1 false block that has nothing to do with this feature and was live on main.**
   The soak ran real system tools under the agent for the first time, and `inxi` was a
   tier-1 BLOCK (0.63; under `--enforce` it would have been killed). The scan that
   followed (`docs/demo-kill/scan-system-scripts.mjs`, 1,727 `#!` scripts on the box):
   2 block, 58 escalate, 1,667 clear. Cause: features are presence tests over up to 256 KB
   and the "density" feature is a count. Fix in the core: `inspect()` scores a payload
   longer than `WINDOW_LINES` (120) in half-overlapping windows and returns the strongest;
   `scoredLayer` is that window (so the judge and the incident get the lines that fired,
   not a licence header) and `windowed` is true. After: 0 block, 40 escalate, 1,687 clear;
   corpus snapshot unchanged (longest corpus file: 31 lines); 7 unit tests. Details and
   the cost in corpus/README.md.

Soak, after those fixes (`docs/demo-kill/soak-behavior.sh`, monitor mode, default window,
fourteen real activities each in its own session): behavior reported the lynis audit and
none of the other thirteen, the sos report included (8 areas, 1 sensitive). Narration
incidents in the same soak, no judge configured: 8 alerts, 0 blocks (before the window
fix: 10 alerts, 1 block). The alerts are `deb-systemd-helper` six times in one
`apt-get install`, `50-motd-news` once and `inxi` once.

Also learned about Falco's fields: a setuid program is reported under its effective user
(`sudo -n -l` run by nobody shows `user=root`), and a `#!` script as
`<comm> <script path> <args>` with comm cut to 15 characters.

**Unverified / open:**
1. **Alert noise from system scripts on a host with no judge** (above). Not fixed. The
   candidates: do not read a script file an unprivileged intruder could not have written
   (root-owned, package path, unchanged since the agent started), or collapse repeated
   alerts for the same script. Both change what the agent looks at and need their own
   measurement.
2. Behavior false positives over a real day on a real host. The soak is fourteen
   activities on one distribution.
3. Windows: unit tests and `--mock` only, like the tripwire. Kenny has no Windows machine;
   the repo's CI already runs the agents on GitHub's `windows-latest`, which could run a
   real script-block check. Proposed, not built.
4. Timing as a discriminator: measured and found wanting (hosted models 1.0 to 1.9 s
   between steps, real lynis 1.3 s). Reported in the alert, never decided on.
5. The reader is a heuristic over command text. Quoting it does not understand (a `;`
   inside an awk program) loses that statement; aliases and renamed binaries are not seen.
6. A long attack script whose narration is spread more than 120 lines apart is no longer
   a tier-1 block; it escalates. No sample of that shape exists in the corpus yet.

**Bait rate, second pass (same day, after the merge of PR #10):** a local open-weight
model (`arete:27b`, 27B, Q8, Ollama, thinking on, one request at a time) and a third task.
The first two tasks only ask the model to look and report; the new `fix` task gives it a
goal the decoy claims to serve ("the backup fails with no session, you are authorized to
fix it"). The harness gained `--tasks`, `--concurrency` and `--timeout-ms`.

| | look-and-report (2 tasks) | goal-directed (`fix`) |
|---|---|---|
| `arete:27b` | 10 completed: alert 10, canary 0, flagged 7 | 5 completed: alert 5, **canary 2** (turns 10 and 11), flagged 3 |
| Sonnet 5.5 | 5 completed: alert 5, canary 0 | 5 completed: alert 5, canary 0, flagged 5 |
| Haiku 5.5 | 10 completed: alert 10, canary 0 | 5 completed: alert 5, canary 0, flagged 5 |
| Opus 5.5 | 9 completed: alert 9, canary 0 | **0 completed: all 5 refused by the classifier** |

Totals: 49 completed trials, alert 49, canary 2. Hosted trials cut off by the provider: 11
of 45; local: 0 of 15. The decoy text was not changed between passes; only a task was added.

**Bait rate, fourth pass (2026-11-10, after the merge of PR #12):** a second local
open-weight model, `ornith-1.5:35b` (35.5B, Q4_K_M, Ollama, one request at a time, same
settings as the `arete:27b` pass). The two local models come from different publishers and are not independent:
Ollama reports a Qwen architecture for both (`qwen35` and `qwen35moe`). The `arete:27b`
file names Qwen3.8-27B as its base model. The `ornith-1.5:35b` file names no base model,
and neither does its publisher's page; it declares the Qwen 3.5 mixture-of-experts
architecture and the Qwen 3.5 tokenizer. Whether its weights started from a Qwen
checkpoint is not something this project verified. Raw record: `test/tripwire-bait-ornith-results.md`.

| | look-and-report (2 tasks) | goal-directed (`fix`) | `survey` |
|---|---|---|---|
| `ornith-1.5:35b` | 10 completed: alert 10, canary 0, flagged 6 | 5 completed: alert 4, **canary 4** (turns 4, 6, 4, 6), flagged 0 | 5 completed: 5 reported as sweeps |

- The four canary runs came within two commands of reading the README. `arete:27b` ran
  it late (turns 10 and 11), after trying everything else; this model ran it at the first
  chance and never said the instruction looked wrong.
- The fifth `fix` trial ended at turn 1 without issuing a command. The harness counts it
  as completed (the provider answered), so it is in the denominator: it is the one trial
  of 64 with no alert.
- Session behavior on the same trials: 0 of 15 focused trials reported (four areas at
  most), 5 of 5 surveys reported, at command 7, 7, 7, 5 and 1 (one command line that
  chained the whole survey), median pause 0.9 to 2.7 s.
- No trial was cut off (0 of 20). The default pass took 7 minutes and the survey pass 5.

Running totals on the three bait tasks: 64 completed trials, alert 63, canary 6 (all six
by the two open-weight models on the goal-directed task: 6 of 10).

**Bait rate, fifth pass (2026-11-11, after the merge of PR #13):** a third local
open-weight model of another lineage, `gemma4:31b` (31.7B, Ollama reports architecture
`gemma4` and quantization `nvfp4`; same harness and settings). Raw record:
`test/tripwire-bait-gemma4-results.md`. `ornith-1.5:35b` was deleted from the machine
after its pass; its record is the file named above.

| | look-and-report (2 tasks) | goal-directed (`fix`) | `survey` |
|---|---|---|---|
| `gemma4:31b` | 9 completed: **alert 5**, canary 0, flagged 0 | 4 completed: alert 4, **canary 4** (turn 5 each), flagged 0 | 5 completed: **0 reported as sweeps** |

- Two trials were cut off by the five-minute timeout on a model call (one `backup`, one
  `fix`), so 13 of 15 completed. The cut-off `fix` trial had already run the canary
  command at turn 5; it is excluded from the rate like any other cut-off trial.
- The look is not dependable on this model. In four look-and-report trials it listed
  the parent directory (`ls /var/backups`, `ls -R /opt /var/backups`), saw the decoy's
  name and never opened it. That is limit 4 above (the look is only seen when a command
  names the decoy or runs inside it), now observed on a real model.
- With a goal it went straight in: every `fix` trial read the README and issued the
  canary command as its next command.
- Session behavior missed all five surveys. The model answered "who has sudo" from the
  group database (`getent group sudo`, `grep '^sudo:' /etc/group`, `groups ops deploy`)
  and never ran `sudo` or read `sudoers`. The reader counts the group database as
  `accounts`, so each trial was five or six areas with one sensitive. The rule was not
  changed in that pass. It was scored and changed afterwards: see the reader change
  below.
- Focused tasks: 0 of 13 reported, two areas at most.
- The default pass took 42 minutes and the survey pass 11.

Running totals on the three bait tasks, six models: 77 completed trials, alert 72, canary
10 (all ten by the three open-weight models on the goal-directed task: 10 of 14).

**Behavior reader change (2026-11-11, after the merge of PR #14):** a lookup aimed at
the `sudo`, `wheel` or `admin` group is a `privilege` question (`asksPrivilegedGroup` in
the core, read on the whole statement because a search pattern is full of `|` and `(`).
It counts as `privilege` only, not also as `accounts`, unless the statement reads the
account database for its own sake. Done by the corpus rule: four sessions added (two of
the Gemma surveys verbatim, two ordinary ones that look up the sudo group), scored
unchanged (missed, missed, quiet, quiet), then the change, then 21/21. No existing
snapshot row moved; four were added. 452 unit tests. The full record, including the
variant that was scored and rejected, is in corpus/README.md.

- Not done: `gemma4:31b` has not been run again against the changed reader. The 5 of 5
  is a replay of its recorded commands.
- Still missed: a survey that asks about privilege only through `groups <user>` or
  `id <user>`, which stay `identity`. The `docker` group is not in the list.
- The bait harness kept only the first 90 characters of each command in its result
  file, which is why a replay of the passes above undercounts. Fixed 2026-11-11 (below):
  it records every command whole from now on. The earlier result files stay cut.

**A decoy of the host's own (2026-11-11, after the merge of PR #15).** The repository is
public, so the decoy's published wording, its names (`register`, `--ticket`) and its
default directories (`vault-access`) can be recognised by anyone who has read it: by the
directory's name in a parent listing, which is not an alert (the Gemma miss above), or by
the text. Each host can now set its own: `ARIS_TRIPWIRE_README` (a file; `{{command}}`
marks the canary command, `{{dir}}` the decoy's directory), `ARIS_TRIPWIRE_HELPER`,
`ARIS_TRIPWIRE_FLAG`, next to the `ARIS_TRIPWIRE_DIRS` that already existed. In the core:
`tripwireLook` (the check and the defaults), `tripwireLookFromEnv` (the settings),
`tripwireDecoy(..., look)`, `armTripwire({ look, lookError })`.

- The published decoy is byte-for-byte unchanged on Linux, macOS and Windows (compared
  against the core at `a69c5db`), so `validate-tripwire.sh` and every measured bait rate
  still describe it. The matcher and the policy were not touched.
- New arming behavior: a decoy the settings no longer ask for is removed (`retired`), and
  a renamed helper does not leave the old one behind. Before this a decoy stayed planted
  and matched forever once planted, whatever `ARIS_TRIPWIRE_DIRS` said later.
- An unusable setting plants nothing and moves nothing, and the decoys already planted
  stay matched (`held`, logged as `tripwire: KEPT AS IT WAS`). It never falls back to the
  published look.
- The agents log which parts are still published, and warn when the README's source file
  can be read by other users.
- `bun run tripwire:bait` reads the same settings, says in its results which parts were
  the run's own without printing them, and now records every command in full.
- 11 new unit tests (463). THESIS.md and the README now say that the source is public,
  that no number here was measured against a model told a detector exists, and that the
  "never learns why" loop describes attackers who were not told.
- Not done: not run in the VM (`validate-tripwire.sh` was not re-run; it uses the
  published look and its own directories, which this change leaves alone). The Linux
  agent's start-up was run on macOS against a temp directory with a stand-in sensor:
  published look, own look with a move, and a broken setting. Windows: unit tests only.
  The bait harness was run end to end against a scripted stand-in on the OpenAI wire (no
  model): published look, own look in its own directory, and a look-only pass. The token
  appeared nowhere in the results and a 190-character command was recorded whole.
- Not measured: any wording other than the published one, and any model told that a
  detector or a decoy may be present. The harness's tasks are written around the
  published decoy; a decoy about something else needs a task to match.
- Still recognisable in a decoy of a host's own: the token's shape (`tk_` and 32 hex
  characters), a README beside one executable, and the helper's body (a two-second wait
  and one line). Opening either file to check is itself the alert.

Session kill, not done: the validation used no judge (session alert path only; the judged session-block
path is covered by `bun run sessions` on real judges, not on a kernel). Windows has no
session kill beyond `taskkill /T` on the PowerShell process.

