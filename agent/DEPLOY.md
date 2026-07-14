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
Modes: `--dry-run` (detect + log, never kill) while you tune; drop it to go live.
Sanity-check with no root/Falco: `node sentinel-agent.mjs --selftest`.

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

## Safety
The agent never kills pid ≤ 1, its own ancestors, or a protected comm allowlist
(sshd, systemd, falco, dockerd, containerd, cron, sudo, …). Kills use `process.kill`
(no shelling out) to avoid exec feedback loops.

## Known limits / next
- **Scope**: v1 scores *every* exec's cmdline (+ script-file contents for interpreters).
  On a busy box that's a lot of scoring; production should scope to sensitive sinks and
  cap tier-2 escalation volume.
- **Kill granularity**: kills the offending process tree, not the whole attacker session.
  A `--kill-session` mode (terminate the sid) is the next increment for multi-phase kill.
- **Detect vs enforce**: Falco observes post-syscall; the "stop before destruction"
  guarantee rests on the thesis that narration appears phases before impact.
