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
Put the key in a root-only env file — never in the unit or process args:
```bash
printf 'ANTHROPIC_API_KEY=%s\n' 'sk-ant-...' | sudo tee /etc/aris-sentinel.env >/dev/null
sudo chmod 600 /etc/aris-sentinel.env
```

## 4. Arm it
Run as root (needs eBPF + the ability to kill). As a transient unit:
```bash
sudo systemd-run --unit=aris-agent --working-directory=/home/ubuntu \
  -p EnvironmentFile=/etc/aris-sentinel.env \
  /usr/bin/node /home/ubuntu/sentinel-agent.mjs
```
Modes — **safe by default**: with no flag the agent runs **MONITOR** (detect + alert,
never kills). Add `--enforce` to let it kill on detection — do that only once you trust
it on that box. Sanity-check with no root/Falco: `node sentinel-agent.mjs --selftest`.

Logs: `journalctl -u aris-agent -f`. Incidents: `/var/log/aris-incidents.jsonl`.

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

## Stealth / de-branding (install.sh)
`sudo ./install.sh [name] [--enforce]` deploys under a GENERIC identity so on-box recon
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
Also: env var names in `/proc/<pid>/environ` (`ANTHROPIC_API_KEY` reveals LLM use), and
outbound to `youraris.com` / `api.anthropic.com`. These defeat *casual* recon today; the
deeper layer is v2.

## Uninstall
`sudo ./uninstall.sh [name]` fully removes the agent — stops and deletes the service,
shreds the env/secrets, removes the files and incident store, and re-enables the Falco
services the installer disabled. One command, complete; the Falco *package* is left
installed (`apt-get remove --purge falco` to drop that too).

## Pilot posture (start here with a design partner)
1. Install **without** `--enforce` → MONITOR mode: Aris watches and alerts, never touches
   a process. Let it run for a week; review what it flags.
2. Confirm zero false positives on that box, then reinstall with `--enforce` to arm.
3. For a fully-local trial, omit `ANTHROPIC_API_KEY` + `ARIS_CLOUD_URL` — nothing leaves
   the box (tier-1 only). See [DATA-HANDLING.md](DATA-HANDLING.md) for exactly what is
   sent off-box and how to control it.

## Safety
The agent never kills pid ≤ 1, its own ancestors, or a protected comm allowlist
(sshd, systemd, falco, dockerd, containerd, cron, sudo, …). Kills use `process.kill`
(no shelling out) to avoid exec feedback loops.

## Known limits / next
- **Scope**: v1 scores *every* exec's cmdline (+ script-file contents for interpreters).
  On a busy box that's a lot of scoring; production should scope to sensitive sinks and
  cap tier-2 escalation volume.
- **Per-session dedup**: a single attack fans out into several execs (the interpreter +
  its children), so the same payload can be adjudicated by tier-2 more than once — N LLM
  calls where 1 would do. Cache verdicts by (session, payload-hash) before escalating.
- **Kill granularity**: kills the offending process tree, not the whole attacker session.
  A `--kill-session` mode (terminate the sid) is the next increment for multi-phase kill.
- **Detect vs enforce**: Falco observes post-syscall; the "stop before destruction"
  guarantee rests on the thesis that narration appears phases before impact.
