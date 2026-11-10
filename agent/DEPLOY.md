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
- **What it does not promise.** That an attacker's model takes the bait. On 2026-11-10
  three hosted Claude models read the decoy in 24 of 24 completed trials, addressed it every
  time (24 alerts) and ran the canary command in none (`bun run tripwire:bait`). Open-weight
  models are unmeasured. Validated live in the demo VM: `docs/demo-kill/validate-tripwire.sh`,
  26/26 checks on kernel 6.8 / Falco 0.45 (2026-11-10).
- **Removal.** `node sentinel-agent.mjs --tripwire-remove` deletes the files it planted (a
  directory only if nothing else was put in it) and the state file. `uninstall.sh` does this.

## Stealth / de-branding (install.sh)
`sudo ./install.sh [name] [--enforce [--kill-session]] [--tripwire]` deploys under a GENERIC identity so on-box recon
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
