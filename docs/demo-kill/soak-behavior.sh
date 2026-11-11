#!/usr/bin/env bash
# What does session behavior (--behavior) make of REAL system activity?
#
# Run INSIDE the demo VM (docs/demo-kill/lima.yaml), as root, from the mounted repo:
#   limactl shell aris-demo -- sudo bash <repo>/docs/demo-kill/soak-behavior.sh
#
# validate-behavior.sh checks the mechanism with sessions written for it. This script is the
# other half: it runs ordinary administration with the distribution's own tools, each in a
# session of its own, under the agent in MONITOR mode with `--behavior` and the default
# five-minute window, and prints what each session asked about and whether it was reported.
# Nobody wrote these command lines: they are whatever apt, adduser, the login banner,
# cron.daily, ansible, sos and lynis really execute. It installs packages (the VM is a
# throwaway) and needs the network for that. There is no pass or fail: it is a measurement.
set -u
R="$(cd "$(dirname "$0")/../.." && pwd)"
W=/tmp/aris-soak
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -e /sys/kernel/btf/vmlinux ] || { echo "no BTF: Falco's modern eBPF probe will not attach here"; exit 1; }
pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null; sleep 1
rm -rf "$W"; mkdir -p "$W/out"; chmod 755 "$W"; chmod 1777 "$W/out"; cd "$W"

echo "== installing the tools the activities use (before the agent is armed, so this is not measured)"
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq ansible-core sosreport lynis inxi > "$W/apt-prep.log" 2>&1 || echo "   (some tools did not install; their rows will say so)"

echo "== arming: node agent/sentinel-agent.mjs --behavior (MONITOR, default window, verbose)"
env -u ANTHROPIC_API_KEY -u OPENAI_BASE_URL -u OPENAI_API_KEY -u KIMI_API_KEY ARIS_VERBOSE=1 \
  ARIS_RULES="$R/agent/aris_rules.yaml" ARIS_INCIDENTS="$W/incidents.jsonl" \
  setsid nohup node "$R/agent/sentinel-agent.mjs" --behavior > "$W/agent.log" 2>&1 < /dev/null &
for _ in $(seq 1 30); do grep -q "armed" "$W/agent.log" 2>/dev/null && break; sleep 1; done
sleep 3
grep -E "mode:|session behavior:" "$W/agent.log" | sed 's/^/    /'

NAMES=()
# act <name> <timeout seconds> <command line>: one activity, in a session of its own.
act() {
  local name="$1" secs="$2"; shift 2
  NAMES+=("$name")
  printf '%s\n' "awk '{print \$6}' /proc/\$\$/stat > $W/out/$name.sid" "$*" > "$W/$name.sh"
  timeout "$secs" setsid --wait bash "$W/$name.sh" > "$W/out/$name.log" 2>&1 < /dev/null
  echo "$?" > "$W/out/$name.rc"
  sleep 2
}

echo "== running the activities"
act apt_update          120 'apt-get update'
act apt_install         180 'apt-get install -y --reinstall cron logrotate'
act apt_upgrade_check   120 'apt list --upgradable; apt-get -s dist-upgrade'
act login_banner         60 'run-parts /etc/update-motd.d'
act login_shell          60 'su - "$(id -un 1000 2>/dev/null || echo root)" -c "true"'
act cron_daily          180 'run-parts --report /etc/cron.daily'
act add_user             60 'adduser --disabled-password --gecos "" soakuser && usermod -aG sudo soakuser && id soakuser && deluser --remove-home soakuser'
act service_restart      60 'systemctl restart cron && systemctl status cron --no-pager && journalctl -u cron -n 20 --no-pager'
act disk_triage          60 'df -h; du -sh /var/log; lsblk; free -m; uptime'
act sysinfo_inxi         90 'inxi -F -c 0'
act ansible_facts       180 'ansible localhost -m setup'
act unattended_upgrades 180 'unattended-upgrade --dry-run'
act lynis_audit         600 'lynis audit system --quick --no-colors'
act sos_report          900 'sos report --batch --tmp-dir /tmp/aris-soak/out'

sleep 3
pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null

echo; echo "== what each session asked about"
python3 - "$W" "${NAMES[@]}" <<'PY'
import json, re, sys, os
W = sys.argv[1]; names = sys.argv[2:]
SENSITIVE = {"accounts", "privilege", "secrets", "cloud"}
inc = [json.loads(l) for l in open(f"{W}/incidents.jsonl")] if os.path.exists(f"{W}/incidents.jsonl") else []
log = open(f"{W}/agent.log", errors="replace").read().split("\n")
seen = {}   # sid -> [execs, set(areas)]
for line in log:
    m = re.search(r"allow\s+tier-\d\s+pid=\d+ sid=(\d+) .*?areas=\[([a-z,]*)\]", line)
    if not m: continue
    s = seen.setdefault(int(m.group(1)), [0, set()]); s[0] += 1
    s[1].update(a for a in m.group(2).split(",") if a)
print(f"  {'activity':<20} {'exit':>4} {'execs':>6}  {'areas':>5} {'sens':>4}  reported  areas asked about")
reported = 0
for n in names:
    try: sid = int(open(f"{W}/out/{n}.sid").read().strip())
    except Exception: print(f"  {n:<20}  did not start"); continue
    rc = open(f"{W}/out/{n}.rc").read().strip() if os.path.exists(f"{W}/out/{n}.rc") else "?"
    sweeps = [r for r in inc if r.get("sid") == sid and (r.get("behavior") or {}).get("kind") == "sweep"]
    execs, areas = seen.get(sid, [0, set()])
    for r in sweeps: areas |= set(r["behavior"]["categories"]); execs += 1
    other = [r for r in inc if r.get("sid") == sid and not (r.get("behavior") or {})]
    how = ""
    if sweeps:
        b = sweeps[0]["behavior"]; reported += 1
        how = f"  <- on `{sweeps[0]['cmdline'][:50]}`: {b['commands']} commands, {b['steps']} step(s), {b['spanMs']/1000:.1f}s"
    extra = f"  [+{len(other)} narration incident(s): {','.join(sorted({r['decision'] for r in other}))}]" if other else ""
    print(f"  {n:<20} {rc:>4} {execs:>6}  {len(areas):>5} {len(areas & SENSITIVE):>4}  {'YES' if sweeps else 'no ':<8}  {', '.join(sorted(areas)) or '-'}{how}{extra}")
others = [r for r in inc if (r.get("behavior") or {}).get("kind") == "sweep"]
print(f"\n  reported: {reported} of {len(names)} activities; sweep alerts in total (any session on the host): {len(others)}; other incidents: {len(inc) - len(others)}")
PY
echo; echo "kernel $(uname -r), $(falco --version 2>&1 | grep -m1 -o 'Falco version: [0-9.]*'), node $(node --version), $(. /etc/os-release; echo "$PRETTY_NAME")"
