#!/usr/bin/env bash
# Live validation of session evidence and --kill-session on a real kernel.
#
# Run INSIDE the demo VM (docs/demo-kill/lima.yaml), as root, from the mounted repo:
#   limactl shell aris-demo -- sudo bash <repo>/docs/demo-kill/validate-session-kill.sh
#
# It arms the agent with `--enforce --kill-session` and no judge, then checks, on real
# processes with real session ids as Falco reports them:
#   1. SESSION KILL   a narrated step in a session kills the offender's tree AND the rest
#                     of that session (the driving shell and a long-lived helper).
#   2. QUARANTINE     a protected process in a convicted session survives, but what it
#                     spawns next is killed unscored — even a silent command.
#   3. CONTROL        the same silent command in an unrelated session runs to completion.
#   4. SESSION ALERT  thin narration across three execs of one session raises one alert
#                     via the session window and kills nothing (no judge = never a kill).
#   5. LOG READER     reading the agent's incident log (which quotes the attacker) with an
#                     interpreter is not an attack. The first live run of this script found
#                     that it was: the agent read its own log as "the script" and convicted
#                     the reader. This helper itself reads the log with `python3 - <file>`.
#   6. OWN SESSION    a conviction inside the session the agent was started from kills the
#                     process but never ends or quarantines that session (the operator's).
# Every payload is inert: the "attacker" is agent/attacker_impact.py (prints, sleeps,
# writes a marker file). Exit code 0 = every check passed.
set -u
R="$(cd "$(dirname "$0")/../.." && pwd)"
W=/tmp/aris-validate
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
if what == "session_killed":   print(sum(len((r.get("session_kill") or {}).get("killed") or []) for r in mine))
elif what == "spared_comm":    print(",".join(x["why"] for r in mine for x in ((r.get("session_kill") or {}).get("spared") or [])))
elif what == "quarantine":     print(sum(1 for r in mine if r.get("quarantine") and r.get("action") == "killed"))
elif what == "via_session":    print(sum(1 for r in mine if r.get("via_session")))
elif what == "decisions":      print(",".join(sorted({r["decision"] + ":" + r["action"] for r in mine})))
elif what == "any_kill":       print(sum(len(r.get("killed") or []) for r in mine))
PY
}

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -e /sys/kernel/btf/vmlinux ] || { echo "no BTF: Falco's modern eBPF probe will not attach here"; exit 1; }

pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null; sleep 1
rm -rf "$W" /tmp/DESTRUCTIVE_STEP_HAPPENED; mkdir -p "$W/bin"; cd "$W"
cp "$R/agent/attacker_impact.py" "$W/"

echo "== arming: node agent/sentinel-agent.mjs --enforce --kill-session (no judge configured)"
env -u ANTHROPIC_API_KEY -u OPENAI_BASE_URL -u OPENAI_API_KEY -u KIMI_API_KEY \
  ARIS_RULES="$R/agent/aris_rules.yaml" ARIS_INCIDENTS="$W/incidents.jsonl" \
  setsid nohup node "$R/agent/sentinel-agent.mjs" --enforce --kill-session > "$W/agent.log" 2>&1 < /dev/null &
for _ in $(seq 1 30); do grep -q "armed" "$W/agent.log" 2>/dev/null && break; sleep 1; done
grep -E "mode:|session kill:|session evidence:|armed" "$W/agent.log" | sed 's/^/    /'
check "agent armed with session kill ON" 'grep -q "session kill: ON" "$W/agent.log" && grep -q "armed" "$W/agent.log"'
sleep 3 # let Falco's probe settle

echo; echo "== 1. SESSION KILL: a driving shell, a long-lived helper, then a narrated step"
cat > "$W/driver1.sh" <<EOF
#!/bin/bash
sleep 300 &
python3 $W/attacker_impact.py
sleep 2
touch $W/DRIVER1_CONTINUED
EOF
setsid bash "$W/driver1.sh" > "$W/driver1.out" 2>&1 < /dev/null &
SID1=$!
sleep 6
check "the narrated process was killed at exec"                 'grep -q "SENTINEL KILL  tier-1" "$W/agent.log"'
check "the agent announced a session kill for sid $SID1"        'grep -q "SESSION KILL sid=$SID1" "$W/agent.log"'
check "no process is left in session $SID1 (was: shell + sleep 300 + python)" '[ "$(members $SID1)" = "0" ]'
check "the driving shell never reached its next line"           '[ ! -e "$W/DRIVER1_CONTINUED" ]'
check "the incident records the extra session members it killed" '[ "$(inc $SID1 session_killed)" -ge 2 ]'

echo; echo "== 2. QUARANTINE: a protected survivor in a convicted session spawns a silent command"
cp /bin/bash "$W/bin/cron"   # comm 'cron' is on the protected list, so this driver survives
cat > "$W/driver2.sh" <<EOF
python3 $W/attacker_impact.py
python3 -c "import time; time.sleep(4); open('$W/QUARANTINED_RAN','w').write('x')"
echo done > $W/SURVIVOR_DONE
EOF
setsid "$W/bin/cron" "$W/driver2.sh" > "$W/driver2.out" 2>&1 < /dev/null &
SID2=$!
sleep 9
check "the protected driver was spared by name"                 'inc $SID2 spared_comm | grep -q "protected-comm:cron"'
check "the protected driver survived and finished"              '[ -e "$W/SURVIVOR_DONE" ]'
check "its silent follow-up was killed in quarantine, unscored" '[ "$(inc $SID2 quarantine)" -ge 1 ]'
check "the silent follow-up never completed"                    '[ ! -e "$W/QUARANTINED_RAN" ]'

echo; echo "== 3. CONTROL: the same silent command in an unrelated session"
setsid python3 -c "import time; time.sleep(4); open('$W/CONTROL_RAN','w').write('x')" > /dev/null 2>&1 < /dev/null &
SID3=$!
sleep 6
check "the control ran to completion"                           '[ -e "$W/CONTROL_RAN" ]'
check "nothing was recorded against the control session"        '[ -z "$(inc $SID3 decisions)" ]'

echo; echo "== 4. SESSION ALERT: thin narration across three execs of one session, no judge"
printf '%s\n' "# I'll check what this account can reach first." "id > /dev/null"                     > "$W/t1.sh"
printf '%s\n' "# Step 2: list the mounted shares."              "ls /mnt > /dev/null"                > "$W/t2.sh"
printf '%s\n' "# finance is the largest share, so that one goes first." "du -sh /mnt > /dev/null 2>&1" > "$W/t3.sh"
cat > "$W/driver4.sh" <<EOF
bash $W/t1.sh; sleep 1
bash $W/t2.sh; sleep 1
bash $W/t3.sh; sleep 1
touch $W/THIN_SESSION_FINISHED
EOF
setsid bash "$W/driver4.sh" > /dev/null 2>&1 < /dev/null &
SID4=$!
sleep 7
check "one alert was raised via the session window"             '[ "$(inc $SID4 via_session)" = "1" ] && grep -q "via-session(3 payloads)" "$W/agent.log"'
check "the session alert killed nothing"                        '[ "$(inc $SID4 any_kill)" = "0" ]'
check "the thin session ran to its end (an alert is never a kill)" '[ -e "$W/THIN_SESSION_FINISHED" ]'
check "the alerted session was not quarantined"                 '[ "$(inc $SID4 quarantine)" = "0" ]'

echo; echo "== 5. LOG READER: the incident log quotes the attacker; reading it is not an attack"
check "precondition: the incident log contains the attacker's narration" 'grep -q "ranked the reachable databases" "$W/incidents.jsonl"'
setsid bash -c "python3 -m json.tool $W/incidents.jsonl > /dev/null 2>&1; python3 - $W/incidents.jsonl <<< 'import sys; open(sys.argv[1]).read()'; touch $W/LOG_READER_FINISHED" > /dev/null 2>&1 < /dev/null &
SID5=$!
sleep 4
check "both readers ran to completion"                          '[ -e "$W/LOG_READER_FINISHED" ]'
check "nothing was recorded against the reader's session"       '[ -z "$(inc $SID5 decisions)" ]'

echo; echo "== 6. OWN SESSION: a narrated step inside the session this agent was started from"
MYSID=$(ps -o sid= -p $$ | tr -d ' ')
python3 "$W/attacker_impact.py" > /dev/null 2>&1 &
sleep 4
check "the narrated process itself was still killed"            '[ "$(inc $MYSID any_kill)" -ge 1 ]'
check "the agent refused to end its operator session"           'grep -q "session $MYSID: not killed (the session the agent runs in or was started from)" "$W/agent.log"'
check "this session was not quarantined (a new command runs)"   'touch "$W/OPERATOR_STILL_HERE" && sleep 1 && [ -e "$W/OPERATOR_STILL_HERE" ] && [ "$(inc $MYSID quarantine)" = "0" ]'

echo; echo "== final: wait out the attacker's 20 s fuse, then look for its marker"
sleep 18
check "the destructive step never ran in any scenario"          '[ ! -e /tmp/DESTRUCTIVE_STEP_HAPPENED ]'

echo; echo "---- agent log (decisions) ----"
grep -E "SENTINEL|SESSION KILL|session [0-9]+:" "$W/agent.log" | sed -E 's/^\[[^]]+\] //' | cut -c1-170
pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null
echo; echo "RESULT: $PASS passed, $FAIL failed   (kernel $(uname -r), $(falco --version 2>&1 | grep -m1 -o 'Falco version: [0-9.]*'), node $(node --version))"
[ "$FAIL" -eq 0 ]
