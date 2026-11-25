#!/usr/bin/env bash
# What does the --behavior service rule make of REAL services doing their ordinary work?
#
# Run INSIDE the demo VM (docs/demo-kill/lima.yaml), as root, from the mounted repo:
#   limactl shell aris-demo -- sudo bash <repo>/docs/demo-kill/soak-services.sh
#
# A command that descends from a web or application server, a database, or a runtime nobody
# logged in to start is reported at three areas of the host, one of them sensitive. The
# corpus sessions for that rule were written by its author. This script is the other half:
# it installs servers and web applications from the distribution's own packages, starts and
# restarts them, asks them for pages, starts the stock systemd units that run as
# `python3 <script>`, and prints what the agent (MONITOR, `--behavior`, default five-minute
# window) reported and what each service's commands asked about. Nobody here wrote those
# command lines. Two of the applications are ones that look at the host for a living
# (phpsysinfo, netdata). It installs packages (the VM is a throwaway) and needs the network.
# There is no pass or fail: it is a measurement, and a small one. It is not a day of traffic.
set -u
R="$(cd "$(dirname "$0")/../.." && pwd)"
W=/tmp/aris-soak-services
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -e /sys/kernel/btf/vmlinux ] || { echo "no BTF: Falco's modern eBPF probe will not attach here"; exit 1; }
pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null; sleep 1
rm -rf "$W"; mkdir -p "$W"; cd "$W"

echo "== installing servers and applications (before the agent is armed, so this is not measured)"
apt-get update -qq > /dev/null 2>&1
PKGS="nginx php-fpm apache2 libapache2-mod-php phpsysinfo gitweb git postgresql redis-server tomcat10 tomcat10-examples netdata curl"
for p in $PKGS; do apt-get install -y -qq "$p" >> "$W/apt-prep.log" 2>&1 || echo "   ($p did not install; its rows will be missing)"; done
# nginx on 80, apache on 8081, tomcat on its own 8080; nginx and apache both serve the
# packaged phpsysinfo, apache also gitweb
sed -i -E 's/^Listen (80|8080)$/Listen 8081/' /etc/apache2/ports.conf 2>/dev/null
sed -i -E 's/<VirtualHost \*:(80|8080)>/<VirtualHost *:8081>/' /etc/apache2/sites-available/000-default.conf 2>/dev/null
a2enmod -q cgi > /dev/null 2>&1; a2enconf -q gitweb > /dev/null 2>&1
ln -sfn /usr/share/phpsysinfo /var/www/html/phpsysinfo
[ -e /etc/phpsysinfo/phpsysinfo.ini ] || cp /usr/share/phpsysinfo/phpsysinfo.ini.new /etc/phpsysinfo/phpsysinfo.ini 2>/dev/null
[ -e /usr/share/phpsysinfo/phpsysinfo.ini ] || cp /usr/share/phpsysinfo/phpsysinfo.ini.new /usr/share/phpsysinfo/phpsysinfo.ini 2>/dev/null
mkdir -p /var/lib/git && git init -q --bare /var/lib/git/demo.git 2>/dev/null
FPM="$(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1; exit}')"
SOCK="$(ls /run/php/php*-fpm.sock 2>/dev/null | head -1)"
cat > /etc/nginx/sites-available/default <<EOF
server { listen 80 default_server; root /var/www/html; index index.php index.html;
  location ~ \.php\$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:${SOCK:-/run/php/php-fpm.sock}; } }
EOF
systemctl stop nginx apache2 ${FPM:-php-fpm} postgresql redis-server tomcat10 netdata > /dev/null 2>&1

echo "== arming: node agent/sentinel-agent.mjs --behavior (MONITOR, default window, verbose)"
env -u ANTHROPIC_API_KEY -u OPENAI_BASE_URL -u OPENAI_API_KEY -u KIMI_API_KEY -u ARIS_BEHAVIOR_SERVICES ARIS_VERBOSE=1 \
  ARIS_RULES="$R/agent/aris_rules.yaml" ARIS_INCIDENTS="$W/incidents.jsonl" \
  setsid nohup node "$R/agent/sentinel-agent.mjs" --behavior > "$W/agent.log" 2>&1 < /dev/null &
for _ in $(seq 1 30); do grep -q "armed" "$W/agent.log" 2>/dev/null && break; sleep 1; done
sleep 3
grep -E "mode:|session behavior:" "$W/agent.log" | sed 's/^/    /'

get() { curl -s -o /dev/null -m 30 -w "    %{http_code} $1\n" "$1"; }
# who leads each session now (a restart replaces the sessions, so this is noted more than once)
leaders() { ps -eo sid=,pid=,comm= | awk '$1==$2{print $1, $3}' >> "$W/leaders.txt"; }
echo "== starting every server (their own start-up commands are measured)"
systemctl start ${FPM:-php-fpm} nginx apache2 postgresql redis-server tomcat10 netdata 2>&1 | sed 's/^/    /'
sleep 20; leaders
echo "== asking for pages"
for round in 1 2 3; do
  get "http://127.0.0.1/phpsysinfo/index.php"; get "http://127.0.0.1/phpsysinfo/xml.php?plugin=complete&json"
  get "http://127.0.0.1:8081/phpsysinfo/index.php"; get "http://127.0.0.1:8081/phpsysinfo/xml.php?plugin=complete&json"
  get "http://127.0.0.1:8081/gitweb/"; get "http://127.0.0.1:8081/gitweb/?p=demo.git;a=summary"
  get "http://127.0.0.1:8080/examples/"; get "http://127.0.0.1:8080/examples/servlets/servlet/HelloWorldExample"
  get "http://127.0.0.1:19999/api/v1/info"
  sudo -u postgres psql -qAtc "select version(); vacuum;" > /dev/null 2>&1
  redis-cli ping > /dev/null 2>&1; redis-cli bgsave > /dev/null 2>&1
  sleep 15; leaders
done
echo "== restarting every server, and starting the stock units that run as python3 <script>"
systemctl restart ${FPM:-php-fpm} nginx apache2 postgresql redis-server tomcat10 netdata 2>&1 | sed 's/^/    /'
PYUNITS="$(grep -lsE '^ExecStart=.*python3 ' /usr/lib/systemd/system/*.service /lib/systemd/system/*.service 2>/dev/null | xargs -r -n1 basename | sort -u | grep -v '@' | tr '\n' ' ')"
echo "    python3 units: ${PYUNITS:-none}"
for u in $PYUNITS; do timeout 120 systemctl start "$u" > /dev/null 2>&1; leaders; done
sleep 45; leaders

python3 - "$W" <<'PY'
import json, os, re, sys, collections
W = sys.argv[1]
inc = [json.loads(l) for l in open(f"{W}/incidents.jsonl") if l.strip()] if os.path.exists(f"{W}/incidents.jsonl") else []
beh = lambda r: r.get("behavior") or {}
svc = [r for r in inc if beh(r).get("kind") == "service"]
print(f"\n== reported as a service's commands: {len(svc)}")
for r in svc:
    b = beh(r)
    print(f"   {b.get('service')}: {','.join(b.get('categories') or [])} (sensitive: {','.join(b.get('sensitive') or [])}) on `{(r.get('cmdline') or '')[:70]}` sid={r.get('sid')} user={r.get('user')}")
other = [r for r in inc if beh(r).get("kind") != "service"]
print(f"== other incidents: {len(other)}" + "".join(f"\n   {r['decision']} {(r.get('signals') or [])} `{(r.get('cmdline') or '')[:60]}`" for r in other))
# what each session's commands asked about, from the verbose allow lines (areas only)
areas, n = collections.defaultdict(set), collections.Counter()
for line in open(f"{W}/agent.log", errors="replace"):
    m = re.search(r"allow\s+tier-\d\s+pid=\d+ sid=(\d+) exe=(\S*).*?areas=\[([^\]]*)\]", line)
    if not m: continue
    n[m.group(1)] += 1
    for a in filter(None, m.group(3).split(",")): areas[m.group(1)].add(a)
led = dict(l.split(None, 1) for l in open(f"{W}/leaders.txt").read().splitlines() if " " in l) if os.path.exists(f"{W}/leaders.txt") else {}
leader = lambda sid: led.get(sid, "(short-lived)")
SENS = {"accounts", "privilege", "secrets", "cloud"}
print("== sessions whose commands asked about the host (leader of the session, execs, areas; * = sensitive)")
for sid, a in sorted(areas.items(), key=lambda kv: -len(kv[1])):
    print(f"   {leader(sid):<18} sid={sid:<7} execs={n[sid]:<5} {len(a)} areas: {', '.join(sorted(x + ('*' if x in SENS else '') for x in a))}")
print(f"== execs seen in all: {sum(n.values())}, in {len(n)} sessions")
PY
pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null
echo; echo "(kernel $(uname -r), $(falco --version 2>&1 | grep -m1 -o 'Falco version: [0-9.]*'), node $(node --version))"
