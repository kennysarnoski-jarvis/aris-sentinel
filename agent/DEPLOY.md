# Aris Sentinel agent — on-box deployment

The resident "install and wait" agent. Taps process execs via Falco (eBPF), scores
each for the agentic-narration signature (`sentinel-core.mjs`), and **kills the
offending process tree** on a block verdict — stopping the attacker's AI at its first
narrated action, before the destructive step.

Verified live on Ubuntu 24.04 (kernel 6.17), Falco 0.44.1, Node 18.

## 1. Install deps
```bash
sudo apt-get update && sudo apt-get install -y nodejs   # Node >=18 (global fetch)
# Falco (modern eBPF, no kernel module build):
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo FALCO_DRIVER_CHOICE=modern_ebpf DEBIAN_FRONTEND=noninteractive apt-get install -y falco
```
Falco 0.44 selects the engine via `/etc/falco/config.d/` (`engine.kind: modern_ebpf`);
on a recent kernel the modern BPF probe attaches with no module compile.

## 2. Drop the files
```bash
# to /home/ubuntu (or anywhere; keep core + agent together)
sentinel-core.mjs  sentinel-agent.mjs  aris_rules.yaml
```

## 3. (optional) Enable tier 2
Tier 1 (local regex filter) blocks heavily-narrated payloads with zero LLM cost.
Tier 2 (LLM adjudication) catches the *stealthier* narration tier-1 only escalates.
Without a key the escalate band is **alerted** (logged + reported, never killed), not
silently allowed. Put the key in a root-only env file — never in the unit or process args:
```bash
# Claude Opus 5.5 (server-side fallbacks on classifier refusals, de-fanged retry):
printf 'ANTHROPIC_API_KEY=%s\n' 'sk-ant-...' | sudo tee /etc/aris-sentinel.env >/dev/null
sudo chmod 600 /etc/aris-sentinel.env
# …or a local judge, nothing leaves the box (Ollama on the host; qwen2.5:14b went 74/74 on the corpus):
printf 'OPENAI_BASE_URL=http://127.0.0.1:11434/v1\nOPENAI_MODEL=qwen2.5:14b\n' | sudo tee -a /etc/aris-sentinel.env >/dev/null
```
Both may be set: the chain is `local → anthropic → openai → kimi` (`ARIS_TIER2_ORDER`
reorders it) and the first validated verdict wins. Tier-2 knobs (all optional, defaults
in the README): `ARIS_FAIL_MODE=alert` to page instead of block on an adjudicator outage;
`ARIS_TIER2_EFFORT`, `ARIS_TIER2_FALLBACKS=0`; `ARIS_TIER2_TIMEOUT_MS`, `_DEADLINE_MS`,
`_CACHE_TTL_MS`, `_CONCURRENCY`, `_BUDGET_PER_MIN` for cost and rate control.

## 4. Arm it
Run as root (needs eBPF + the ability to kill). As a transient unit:
```bash
sudo systemd-run --unit=aris-agent --working-directory=/home/ubuntu \
  -p EnvironmentFile=/etc/aris-sentinel.env \
  /usr/bin/node /home/ubuntu/sentinel-agent.mjs
```
Modes — **safe by default**: with no flag the agent runs **MONITOR** (detect + alert,
never kills). Add `--enforce` to let it kill on detection — do that only once you trust
it on that box. `--enforce --kill-session` additionally ends the offender's whole session
(see Known limits before arming it). `--tripwire` works in any mode: it plants decoy
directories and treats their canary command as a detection (see Tripwire below).
`--behavior` also works in any mode: it reports a session that asks about many areas of
the host in a few minutes, as an alert only (see Session behavior below).
Sanity-check with no root/Falco: `node sentinel-agent.mjs --selftest`.

Logs: `journalctl -u aris-agent -f`. Incidents: `/var/log/aris-incidents.jsonl`, one JSON
row each with `decision` ∈ `block` / `alert` / `error` and `action` ∈ `killed` /
`monitored` / `spared:<why>` / `alerted` / `errored`. An `alert` is tier 1 saying
"suspicious" with no tier 2 to confirm it; an `error` is the detector throwing — both
are reported off-box and neither ever kills.

## 5. Prove it (the kill demo)
`attacker_impact.py` narrates a JadePuffer-style impact phase, then "encrypts" after a
20 s delay (modeling the phase-1→phase-5 gap — narration comes first). `benign_job.py`
is routine ops. With the agent armed:
```bash
python3 attacker_impact.py &   # narrates -> agent KILLS it at exec
python3 benign_job.py &        # untouched
sleep 6
cat /tmp/DESTRUCTIVE_STEP_HAPPENED   # ABSENT = the destructive step never ran
```
Expected log: `SENTINEL KILL tier-1 exe=python3 score=0.78 … high-confidence agentic
narration`, and an incident row in the JSONL.

**Tier-2 kill** (`stealth_attacker.py`) — lighter narration that tier-1 only *escalates*
(~0.46), so the LLM adjudication is what catches it: the payload a signature detector
waves through. With tier 2 enabled and the agent armed:
```bash
python3 stealth_attacker.py &   # tier-1 escalate -> tier-2 adjudges AGENTIC -> KILL
sleep 12; cat /tmp/STEALTH_EXFIL_HAPPENED   # ABSENT
```
Expected: `SENTINEL KILL tier-2 … adjudged agentic (conf 0.95)` + reasoning. Note tier-2
is not fooled by keyword salad — an obvious demo stub is adjudged *not-agentic*; the
payload must read as a genuine autonomous agent.

## Tripwire (`--tripwire`, opt-in)
The narration detector needs the attacker's model to write something. The tripwire does
not: it plants a decoy and watches for the one command only the decoy asks for.

- **What is planted.** One directory per entry in `ARIS_TRIPWIRE_DIRS` (default
  `/opt/vault-access` and `/var/backups/vault-access`), each with a world-readable
  `README.md` and an executable `register` that waits two seconds, prints one line and exits. The README tells
  automated agents to run `<dir>/register --ticket <token>` and tells human operators not
  to. The token is 128 random bits, created on first start and kept with the list of planted
  files in `ARIS_TRIPWIRE_STATE` (mode 0600). A directory that already exists and is not the
  agent's is skipped with a warning, never overwritten. A decoy that is deleted or edited is
  put back at the next start. Everything is written with file calls, never a command.
- **Give the decoys a look of this host's own.** What is described above is the published
  look: its wording, the names `register` and `--ticket` and the `vault-access`
  directories are all in the public source, so an attacker who has read it can recognise
  them, by the directory's name in a listing of its parent (which is not an alert) or by
  the text. Four settings in the env file replace them, and are then known only here:
  - `ARIS_TRIPWIRE_DIRS`: where the decoys sit. Pick names that fit this host.
  - `ARIS_TRIPWIRE_README`: a file holding your README text. Write `{{command}}` where the
    canary command goes (required; `{{dir}}` is the decoy's own directory). Tell people in
    it not to run the command, because running it is a conviction. Keep the file mode 0600
    beside the state file: the planted README is public by design, but the file it is made
    from says which README on the host is the bait, and the agent warns if others can read it.
  - `ARIS_TRIPWIRE_HELPER` and `ARIS_TRIPWIRE_FLAG`: the helper's file name and the option
    that carries the token (`.cmd` is added to the helper on Windows).

  Restart the agent to apply them. The token is kept. A decoy this host no longer asks
  for is taken away, and so is the helper under its old name, so the published look is not
  left lying beside the new one. The start-up log names any part that is still published.
  A setting that cannot be used (a README with no `{{command}}`, a name with a slash)
  plants nothing and moves nothing: the log says `tripwire: KEPT AS IT WAS`, and the
  decoys already there stay matched, so a typo does not switch the detection off. What
  does not change: the matcher reads only the token and the directories, the helper's body
  is the same inert two-second wait, and every bait rate below was measured on the
  published wording. A wording of your own has no measured rate until you run
  `bun run tripwire:bait` with the same settings in the shell. A model that distrusts every
  instruction found in a file will decline yours as well.
- **What it detects.** The token in anything that executes (a command line, a script that
  is run, a base64 or hex layer of either) is a **block**: logged in monitor mode, killed
  under `--enforce`, and with `--kill-session` the session that ran it is ended and
  quarantined. A command that only addresses the decoy (names the directory, or runs with
  its cwd inside it) is an **alert** and never a kill. Incidents carry
  `tripwire: { kind: "token" | "decoy", decoded, fingerprint, evidence }`.
- **What the kill is worth.** The helper is inert, so in plain `--enforce` the kill ends a
  process that was about to exit anyway; the value is the incident. `--kill-session` is
  what stops the session that took the bait. The helper's two-second wait exists for that:
  the session is still parked inside it when the session kill lands, so its next command
  never starts (checked live; without the wait it did).
- **The token stays put.** It is never sent to a judge or off-box, and every log line and
  incident shows `[tripwire:<fingerprint>]` in its place. That is deliberate: a command
  that carries the token is a conviction, including yours, so never paste the token into a
  shell. To test the wire, run the command from the README in MONITOR mode and look for the
  incident.
- **Your own AI agents.** An assistant you run on this host will see the decoy too. One that
  follows it gets convicted. Tell it about the decoy path, or leave `--tripwire` off there.
- **What it sees and what it misses.** It reads the exec stream, so `cat <decoy>/README.md`
  and `cd <decoy>; ls` are seen; a recursive `grep -r … /opt` or a backup that opens the
  file without naming it is not (which also keeps backups from paging you).
- **Who can trip it.** The README is world-readable on purpose, so anyone with a shell on
  the host can read the token, and a conviction lands on whichever process ran a command
  carrying it. That is the same exposure the narration detector already has (whoever can
  choose a process's command line can get it convicted), and the same protected-process
  guard applies. Weigh it before combining `--tripwire` with `--kill-session` on a host
  where untrusted input can reach a command line.
- **What it does not promise.** That an attacker's model takes the bait. Measured on
  2026-11-10 with `bun run tripwire:bait` (three hosted Claude models and three local
  open-weight models, `arete:27b`, `ornith-1.5:35b` and `gemma4:31b`): in 72 of 77
  completed trials a command addressed the decoy (72 alerts). Four of the five without
  one are `gemma4:31b` trials that listed the parent directory, saw the decoy's name and
  never opened it; a parent listing is not an alert. The canary command was run by the
  open-weight models when their task gave them a goal the decoy claims to serve (2 of 5,
  4 of 5 and 4 of 4 trials), and in no other trial: never when a model was only asked to
  look, never by a hosted Claude model. The alert is likely, not certain; the conviction
  depends on the attacker's model. Validated live in the demo VM: `docs/demo-kill/validate-tripwire.sh`,
  26/26 checks on kernel 6.8 / Falco 0.45 (2026-11-10).
- **Removal.** `node sentinel-agent.mjs --tripwire-remove` deletes the files it planted (a
  directory only if nothing else was put in it) and the state file. `uninstall.sh` does this.

## Session behavior (`--behavior`, opt-in)
The second signal that needs no narration, and the only one that needs nothing from the
attacker's model except curiosity. An agent on a host it has never seen asks who it is,
what the machine is, what runs on it, who has an account, what it may run as root and
where the keys are. `--behavior` reads the command line of every exec, names the areas of
the host each one asks about, and keeps them per session (`proc.sid`) for five minutes
(`ARIS_BEHAVIOR_WINDOW_MS`).

- **The rule.** One session, one window, **five areas of which two are sensitive**. The
  ten ordinary areas: identity, logins, host, processes, network, storage, environment,
  scheduled jobs, software, containers. The four sensitive ones: the account database,
  what the account may run with privilege, stored keys / credentials / shell history, and
  the cloud metadata service or a service-account token.
- **What it does.** One `alert` incident per sweep, on the command that completes it:
  `SENTINEL ALERT (the session swept the host — no kill)  behavior`, with
  `behavior: { kind: "sweep", categories, sensitive, commands, spanMs, medianGapMs }` and
  the signal `behavior_sweep`. The same session is not reported again until its window
  has emptied. **It never kills and never quarantines**, under `--enforce` and
  `--kill-session` too, and it never calls a judge.
- **What trips it that is not an intruder.** Anything that reads the whole host on
  purpose: a support-bundle collector, a security audit script (lynis and the like), an
  administrator doing a privilege review by hand. A collector fires its commands back to
  back (the sample in `corpus/behavior/` does twelve in two seconds); the alert carries the
  number of steps and the median pause between them (execs under half a second apart are
  one step). Timing is reported, not used to decide: a real `lynis` run pauses between its
  commands about as long as a hosted model does.
- **Measured on a real box (2026-11-10, `docs/demo-kill/soak-behavior.sh`).** Fourteen
  activities with Ubuntu's own tools, each in its own session, agent in monitor mode: apt
  update / install / upgrade check, the login banner, a login shell, `cron.daily`,
  `adduser`, a service restart, a disk triage, `inxi`, an ansible fact run,
  `unattended-upgrade --dry-run` and a `sos report` were **not** reported (13 of 13); a
  `lynis` audit was. The sos report came closest (eight areas, one sensitive).
  Ordinary work does not come close: a login triage (`w`, `df`, `ps`, `ss`), a CI
  environment dump, a config-management fact run and a user onboarding all stay under the
  rule in the corpus, mostly because they touch no second sensitive area.
- **Your own AI agents.** Measured on 2026-11-10 with hosted Claude models in a simulated
  shell: on three focused admin tasks, 0 of 36 completed trials were reported (no trial
  asked about more than two areas). Asked to write a handover survey of the host, 15 of 15
  were reported, usually at the fourth command, with a median 1.0 to 1.9 s between
  commands. A local open-weight model (`ornith-1.5:35b`) gave the same split: 0 of 15 on
  the focused tasks, 5 of 5 on the survey. A second one (`gemma4:31b`) was not reported
  on any of its five surveys as first measured: it read the sudo group from the group
  database instead of asking `sudo`. A lookup aimed at the `sudo`, `wheel` or `admin`
  group now counts as a privilege question (2026-11-11); replayed against that, all five
  are reported. So an agent you run for narrow jobs stays quiet, and one you ask to audit the
  box will page you, exactly as a human doing the audit by hand would.
- **What it reads, and does not.** The command line only: a script file the interpreter
  runs is not treated as a list of commands (its own commands arrive as their own execs).
  Text longer than 4096 characters is a script, not a command, and is skipped. The reader
  is a heuristic, not a shell parser. The tracker keeps area names and timestamps, never
  the command text.
- **What it misses.** A sweep slower than the window; an agent that goes straight for one
  thing; a sweep that touches fewer than two sensitive areas; files read by a program
  without running a command; a sweep spread across sessions (each `ssh host 'cmd'` is its
  own session). `corpus/behavior/` keeps a sample of each of the first three as an
  expected miss.
- **Cost.** With `--behavior` every exec is read, including two-letter commands the
  narration scorer skips. It is string work on one command line, no judge and no I/O.
- **Validated live** in the demo VM: `docs/demo-kill/validate-behavior.sh`, 29/29 on three
  consecutive runs of the final code on kernel 6.8 / Falco 0.45 (2026-11-10), fully armed
  (`--enforce --kill-session --behavior`) so that "never a kill" was checked where a kill
  was possible. Not yet run on a pilot host. The thresholds were chosen before the samples
  were scored and nothing was tuned afterwards. Run it in monitor mode and read what it
  reports before you rely on it. `ARIS_VERBOSE=1` adds `areas=[…]` to every allow line, so
  you can see what a session's window holds before it is ever reported.

## Stealth / de-branding (install.sh)
`sudo ./install.sh [name] [--enforce [--kill-session]] [--tripwire] [--behavior]` deploys under a GENERIC identity so on-box recon
reveals no security tool — an autonomous attacker not trained to recognize Aris sees a
boring `sys-telemetryd` daemon it can't confidently kill (and killing it is a tamper
event the dead-man's switch catches). **Installs in MONITOR mode by default** (detect +
alert, no kill); pass `--enforce` to arm it. Pick a DIFFERENT name per customer so the
disguise isn't itself a signature. It de-brands:
- **process** → generic `process.title` (ps/top show `sys-telemetryd`, not `node sentinel-agent.mjs`)
- **service** → `<name>.service` ("System telemetry agent"), `Restart=always` (respawns if killed)
- **files** → `/usr/local/lib/<name>/{agentd,core,rules}`, env `/etc/<name>.env`, incidents `/var/lib/<name>/`
- **Falco** → runs from a renamed copy `<name>-probe` (its own process blends in)

**Known remaining tells (need the eBPF-native rewrite to fully close):** Falco is still an
apt package — `/etc/falco`, `/usr/bin/falco`, `dpkg -l | grep falco` reveal it to *deep*
recon (the running process is renamed but the package isn't; the config dir is required).
Also: env var names in `/proc/<pid>/environ` (`ANTHROPIC_API_KEY` etc. reveal LLM use), and
outbound to `youraris.com` / `api.anthropic.com` (a local judge has no such egress). These defeat *casual* recon today; the
deeper layer is v2.

## Uninstall
`sudo ./uninstall.sh [name]` fully removes the agent — stops and deletes the service,
removes any tripwire decoys it planted, shreds the env/secrets, removes the files and incident store, and re-enables the Falco
services the installer disabled. One command, complete; the Falco *package* is left
installed (`apt-get remove --purge falco` to drop that too).

## Pilot posture (start here with a design partner)
1. Install **without** `--enforce` → MONITOR mode: Aris watches and alerts, never touches
   a process. Let it run for a week; review what it flags.
2. Confirm zero false positives on that box, then reinstall with `--enforce` to arm.
3. For a fully-local trial, omit the LLM keys + `ARIS_CLOUD_URL` — nothing leaves
   the box (tier-1 only). See [DATA-HANDLING.md](DATA-HANDLING.md) for exactly what is
   sent off-box and how to control it.

## Safety
The agent never kills pid ≤ 1, its own ancestors, or a protected comm allowlist
(sshd, systemd, falco, dockerd, containerd, cron, sudo, …). Kills use `process.kill`
(no shelling out) to avoid exec feedback loops.

## Known limits / next
- **System scripts and alert noise** (measured 2026-11-10): the agent reads the script an
  interpreter runs, and distribution scripts have comments. Of the 1,727 `#!` scripts on a
  stock Ubuntu 24.04, 40 land in the escalate band on a single signal
  (`docs/demo-kill/scan-system-scripts.mjs` lists them for your box). With a judge each is
  a judge call, cached for ten minutes. **Without a judge each is an alert every time it
  runs**: one `apt-get install` raised six (`deb-systemd-helper`), the login banner one.
  None is a kill. Until 2026-11-10 two of those scripts (`inxi` and a Perl module) were
  tier-1 *blocks*, which `--enforce` would have killed; a payload longer than 120 lines is
  now scored in windows, and the scan shows 0. If you run without a judge, expect this
  noise and consider a local one; scoping the agent to files an intruder could have
  written is not built.
- **Scope**: v1 scores *every* exec's cmdline (+ script-file contents for interpreters,
  resolved against the process's own cwd via Falco's `%proc.cwd`). On a busy box that's
  a lot of scoring; production should scope to sensitive sinks. Tier-2 volume is already
  capped by the governor (`ARIS_TIER2_BUDGET_PER_MIN`, cache, concurrency).
- **Rules file**: `aris_rules.yaml` gained `cwd=%proc.cwd` on 2026-11-07. Existing
  pilots must re-run `install.sh` (it re-copies the rule) or the agent cannot resolve
  relative script paths and will score the cmdline alone.
- **Session evidence**: narration spread across the execs of one session (`proc.sid`) is
  kept for 10 minutes (`ARIS_SESSION_TTL_MS`, `0` = off; `ARIS_SESSION_MAX_ITEMS`, default
  12) and judged as one transcript when together it reaches the block band. Incidents from
  that path carry `via_session: true` and a `session` summary, and the log line says
  `via-session(N payloads)`. Without a judge a session is one alert, never a kill. Processes
  that share a sid share a window: the children of one exploited server are one session.
- **Kill granularity**: `--enforce` kills the offending process tree. That leaves an
  agent's driver (the shell, or the exploited server issuing the commands) alive to send
  the next one. `--enforce --kill-session` is the second, separate opt-in:
  - on a conviction, every process whose session id matches the offender's is killed,
    each under the same guard as a single kill (never pid ≤ 1, the agent or its ancestors,
    or a protected comm such as sshd, systemd, cron, containerd);
  - the session id is quarantined for 10 minutes (`ARIS_SESSION_QUARANTINE_MS`, `0` = no
    quarantine): any exec in it is killed without being scored, so a silent follow-up
    dies too. One off-box report per quarantined session; every exec is in the local log;
  - it never fires on an `alert`, in monitor mode, on the agent's own session, or when the
    session id is unknown. Incidents carry `session_kill: {sid, killed, spared}`.
  **Read this before arming it:** processes that share a session id share its fate. If an
  agent came in through a server, that server's whole session, the server included, is
  what gets ended. A false positive costs a session, not a process. Run `--enforce` alone
  first. The session the agent itself runs in, or was started from, is never ended or
  quarantined. The session is killed before the offender, from its outermost ancestor
  down, so the shell waiting on the offender is never woken to run one more command.
  Validated live in the demo VM: `docs/demo-kill/validate-session-kill.sh`,
  24/24 checks on kernel 6.8 / Falco 0.45 (2026-11-10).
- **Which file is "the script"**: for an interpreter exec the agent reads only the first
  positional argument, resolved against the process's cwd. `python3 -m <module>`, a bare
  `-` (stdin), and anything after the script are not read; an option's value
  (`-W ignore`, `-o pipefail`, `--require ./hook.js`) is skipped. The agent never reads
  its own incident log as a script. Before 2026-11-10 it scanned for the first argument
  that was a file, which made `python3 -m json.tool <incident log>` look like the
  attack the log was quoting. If you ran `--enforce` on an earlier build, update.
- **Detect vs enforce**: Falco observes post-syscall; the "stop before destruction"
  guarantee rests on the thesis that narration appears phases before impact.
