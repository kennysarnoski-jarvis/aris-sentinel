#!/usr/bin/env bash
# Live validation of the tripwire (--tripwire) on a real kernel.
#
# Run INSIDE the demo VM (docs/demo-kill/lima.yaml), as root, from the mounted repo:
#   limactl shell aris-demo -- sudo bash <repo>/docs/demo-kill/validate-tripwire.sh
#
# It arms the agent with `--enforce --kill-session --tripwire` and no judge, with the decoys
# under /tmp/aris-tripwire (not /opt), then checks on real processes as Falco reports them:
#   0. PLANTED     the decoys exist, are readable and runnable by an unprivileged user, the
#                  state file is root-only, and the agent's log names no token.
#   1. LOOK        an unprivileged session reads the decoy README: an alert, nothing killed,
#                  the session carries on.
#   2. BAIT        a stand-in for an agent reads the README, runs the command it found there
#                  and tries to carry on. The canary command is a conviction: the process and
#                  the whole session are ended, and the session never reaches its next line.
#   3. ENCODED     the same, with the command wrapped in base64. Decoding it is the detector's
#                  job, so the wrapper itself is convicted, at its own exec.
#   4. CONTROL     an unrelated session that lists the decoy's PARENT directory is untouched.
#   5. NO LEAK     the token is in neither the agent's log nor the incident log.
#   6. RESTART     a restart keeps the same token and puts a deleted decoy back.
#   7. REMOVE      --tripwire-remove takes every decoy and the state file away.
# In 2 and 3 the stand-in's VERY NEXT command must not run. The first live run showed it
# did: the helper returned at once and the session was one command ahead of the kill.
# The helper now holds its caller for two seconds, which is what these checks pin down.
# The "agent" here is a six-line shell script; the decoy helper waits, then prints one line. Nothing in
# this script ever puts the token on a command line (that would trip the wire): it is only
# ever read inside python. Exit code 0 = every check passed.
set -u
R="$(cd "$(dirname "$0")/../.." && pwd)"
W=/tmp/aris-tripwire
D1="$W/opt/vault-access"; D2="$W/backups/vault-access"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $*"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
members() { ps -o pid= -s "$1" 2>/dev/null | wc -l | tr -d ' '; }
inc()  { python3 - "$W/incidents.jsonl" "$@" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
sid = int(sys.argv[2]); what = sys.argv[3]
mine = [r for r in rows if r.get("sid") == sid]
trip = lambda r: (r.get("tripwire") or {})
if what == "token_blocks":   print(sum(1 for r in mine if r["decision"] == "block" and trip(r).get("kind") == "token"))
elif what == "decoded":      print(sum(1 for r in mine if trip(r).get("kind") == "token" and trip(r).get("decoded")))
elif what == "decoy_alerts": print(sum(1 for r in mine if r["decision"] == "alert" and trip(r).get("kind") == "decoy"))
elif what == "any_kill":     print(sum(len(r.get("killed") or []) for r in mine))
elif what == "session_killed": print(sum(len((r.get("session_kill") or {}).get("killed") or []) for r in mine))
elif what == "decisions":    print(",".join(sorted({r["decision"] + ":" + r["action"] for r in mine})))
PY
}
# How many of the given files contain the token. The token is read here and nowhere else.
leaks() { python3 - "$W/state/tripwire.json" "$@" <<'PY'
import json, sys
token = json.load(open(sys.argv[1]))["token"]
print(sum(1 for f in sys.argv[2:] if token in open(f, errors="replace").read()))
PY
}
start_agent() {
  env -u ANTHROPIC_API_KEY -u OPENAI_BASE_URL -u OPENAI_API_KEY -u KIMI_API_KEY \
    ARIS_RULES="$R/agent/aris_rules.yaml" ARIS_INCIDENTS="$W/incidents.jsonl" \
    ARIS_TRIPWIRE_STATE="$W/state/tripwire.json" ARIS_TRIPWIRE_DIRS="$D1,$D2" \
    setsid nohup node "$R/agent/sentinel-agent.mjs" --enforce --kill-session --tripwire > "$1" 2>&1 < /dev/null &
  for _ in $(seq 1 30); do grep -q "armed" "$1" 2>/dev/null && break; sleep 1; done
  sleep 3 # let Falco's probe settle
}
# Run a driver script as an unprivileged user in its OWN session. setpriv only drops
# privileges and execs (no fork, no new session of its own), and every driver writes the
# session id the kernel gave it to out/<name>.sid, so the checks never guess a sid.
as_nobody() { setsid setpriv --reuid 65534 --regid 65534 --clear-groups bash "$@" > /dev/null 2>&1 < /dev/null & }
sid_of() { tr -d ' \n' < "$W/out/$1.sid" 2>/dev/null || echo 0; }
stop_agent() { pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null; sleep 1; }
fp() { grep -m1 "tripwire: ON" "$1" | sed -E 's/.*token ([0-9a-f]{12}).*/\1/'; }

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -e /sys/kernel/btf/vmlinux ] || { echo "no BTF: Falco's modern eBPF probe will not attach here"; exit 1; }

stop_agent
rm -rf "$W"; mkdir -p "$W/opt" "$W/backups" "$W/out"; chmod 755 "$W" "$W/opt" "$W/backups"; chmod 1777 "$W/out"; cd "$W"

echo "== arming: node agent/sentinel-agent.mjs --enforce --kill-session --tripwire (no judge configured)"
start_agent "$W/agent.log"
grep -E "mode:|session kill:|tripwire:|armed" "$W/agent.log" | sed 's/^/    /'

echo; echo "== 0. PLANTED"
check "agent armed with the tripwire ON and a new token"          'grep -q "tripwire: ON (new token" "$W/agent.log" && grep -q "armed" "$W/agent.log"'
check "both decoys were planted (README 644, helper 755)"         '[ "$(stat -c %a "$D1/README.md")" = "644" ] && [ "$(stat -c %a "$D1/register")" = "755" ] && [ "$(stat -c %a "$D2/README.md")" = "644" ] && [ "$(stat -c %a "$D2/register")" = "755" ]'
check "the state file is root-only (600)"                         '[ "$(stat -c %a "$W/state/tripwire.json")" = "600" ]'
check "an unprivileged user can read the README but not the state" 'runuser -u nobody -- test -r "$D1/README.md" && runuser -u nobody -- test -x "$D1/register" && ! runuser -u nobody -- test -r "$W/state/tripwire.json"'
check "the agent's log names a fingerprint, never the token"      '[ "$(leaks "$W/agent.log")" = "0" ] && [ -n "$(fp "$W/agent.log")" ]'

echo; echo "== 1. LOOK: an unprivileged session reads the decoy and carries on"
cat > "$W/look.sh" <<EOS
awk '{print \$6}' /proc/\$\$/stat > $W/out/look.sid
cat $D1/README.md > /dev/null
sleep 1
touch $W/out/LOOK_CONTINUED
EOS
as_nobody "$W/look.sh"
sleep 5
SID1=$(sid_of look)
check "the driver ran in a session of its own"                    '[ "$SID1" -gt 1 ] && [ "$SID1" != "$(ps -o sid= -p $$ | tr -d " ")" ]'
check "reading the decoy raised a tripwire alert"                 '[ "$(inc $SID1 decoy_alerts)" -ge 1 ]'
check "a look kills nothing"                                      '[ "$(inc $SID1 any_kill)" = "0" ] && [ "$(inc $SID1 token_blocks)" = "0" ]'
check "the session that only looked ran to its end"               '[ -e "$W/out/LOOK_CONTINUED" ]'

echo; echo "== 2. BAIT: a stand-in agent reads the README, runs what it says, tries to carry on"
cat > "$W/bait.sh" <<EOS
awk '{print \$6}' /proc/\$\$/stat > $W/out/bait.sid
sleep 300 &
cmd=\$(grep -m1 -- '--ticket' $D1/README.md | sed 's/^ *//')
\$cmd
touch $W/out/BAIT_NEXT
sleep 3
touch $W/out/BAIT_CONTINUED
EOS
as_nobody "$W/bait.sh"
sleep 7
SID2=$(sid_of bait)
check "the canary command was convicted by the tripwire"          '[ "$(inc $SID2 token_blocks)" -ge 1 ] && grep -q "SENTINEL KILL  tripwire" "$W/agent.log"'
check "the agent announced a session kill for sid $SID2"          'grep -q "SESSION KILL sid=$SID2" "$W/agent.log"'
check "no process is left in session $SID2 (was: shell + sleep 300 + helper)" '[ "$(members $SID2)" = "0" ]'
check "the session's very next command never ran"                 '[ ! -e "$W/out/BAIT_NEXT" ]'
check "the session never reached its later lines"                 '[ ! -e "$W/out/BAIT_CONTINUED" ]'
check "the incident records the session members it killed"        '[ "$(inc $SID2 session_killed)" -ge 2 ]'

echo; echo "== 3. ENCODED: the same command wrapped in base64"
cat > "$W/enc.sh" <<EOS
awk '{print \$6}' /proc/\$\$/stat > $W/out/enc.sid
cmd=\$(grep -m1 -- '--ticket' $D2/README.md | sed 's/^ *//')
b=\$(printf '%s' "\$cmd" | base64 -w0)
bash -c "echo \$b | base64 -d | sh"
touch $W/out/ENC_NEXT
sleep 3
touch $W/out/ENC_CONTINUED
EOS
as_nobody "$W/enc.sh"
sleep 7
SID3=$(sid_of enc)
check "the encoded canary command was convicted, and marked as decoded" '[ "$(inc $SID3 decoded)" -ge 1 ]'
check "its session was ended too, before its very next command"   '[ "$(members $SID3)" = "0" ] && [ ! -e "$W/out/ENC_NEXT" ] && [ ! -e "$W/out/ENC_CONTINUED" ]'

echo; echo "== 4. CONTROL: an unrelated session that lists the decoy's parent directory"
cat > "$W/control.sh" <<EOS
awk '{print \$6}' /proc/\$\$/stat > $W/out/control.sid
ls -la $W/opt > /dev/null
sleep 1
touch $W/out/CONTROL_DONE
EOS
as_nobody "$W/control.sh"
sleep 5
SID4=$(sid_of control)
check "the control ran to completion"                             '[ -e "$W/out/CONTROL_DONE" ]'
check "nothing was recorded against the control session"          '[ -z "$(inc $SID4 decisions)" ]'

echo; echo "== 5. NO LEAK"
check "the token is in neither the agent log nor the incident log" '[ "$(leaks "$W/agent.log" "$W/incidents.jsonl")" = "0" ]'
check "the incidents show the redaction mark instead"             'grep -q "\[tripwire:$(fp "$W/agent.log")\]" "$W/incidents.jsonl"'

echo; echo "== 6. RESTART: same token, a deleted decoy is put back"
stop_agent
rm -rf "$D2"
start_agent "$W/agent2.log"
check "the restarted agent reused the existing token"             'grep -q "tripwire: ON (existing token" "$W/agent2.log" && [ "$(fp "$W/agent.log")" = "$(fp "$W/agent2.log")" ]'
check "the deleted decoy is back"                                 '[ -r "$D2/README.md" ] && [ -x "$D2/register" ]'

echo; echo "== 7. REMOVE"
stop_agent
ARIS_TRIPWIRE_STATE="$W/state/tripwire.json" node "$R/agent/sentinel-agent.mjs" --tripwire-remove | sed -E 's/^\[[^]]+\] /    /'
check "both decoy directories are gone"                           '[ ! -e "$D1" ] && [ ! -e "$D2" ]'
check "the state file (and the token with it) is gone"            '[ ! -e "$W/state/tripwire.json" ]'
check "the parent directories were left alone"                    '[ -d "$W/opt" ] && [ -d "$W/backups" ]'

echo; echo "---- agent log (decisions) ----"
grep -hE "SENTINEL|SESSION KILL|session [0-9]+:" "$W/agent.log" "$W/agent2.log" | sed -E 's/^\[[^]]+\] //' | cut -c1-170
echo; echo "RESULT: $PASS passed, $FAIL failed   (kernel $(uname -r), $(falco --version 2>&1 | grep -m1 -o 'Falco version: [0-9.]*'), node $(node --version))"
[ "$FAIL" -eq 0 ]
