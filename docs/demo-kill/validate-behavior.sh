#!/usr/bin/env bash
# Live validation of session behavior (--behavior) on a real kernel.
#
# Run live on 2026-11-10: 29/29 on three consecutive runs of the final code (kernel 6.8.0-147, Falco 0.45.2,
# Node 18.19, 2 CPU / 4 GB). The first run passed too, and its incident log still held a
# finding: see scenario 5 and the note on steps.
#
# Run INSIDE the demo VM (docs/demo-kill/lima.yaml), as root, from the mounted repo:
#   limactl shell aris-demo -- sudo bash <repo>/docs/demo-kill/validate-behavior.sh
#
# It arms the agent FULLY (`--enforce --kill-session --behavior`, no judge) so that "a sweep
# never kills" is checked where a kill was possible, and shortens the window to 20 s
# (ARIS_BEHAVIOR_WINDOW_MS) so a slow sweep can be shown in half a minute. Then, on real
# processes with the session ids and command lines Falco reports:
#   1. SWEEP       an unprivileged session asks who it is, what the box is, what runs and
#                  listens, who has an account and what it may run as root, one silent
#                  command every two seconds. One alert, on the command that completes the
#                  sweep; nothing is killed; the session runs to its end; no second alert.
#   2. CHAINED     the same questions chained three to a `bash -c`, as a model writes them.
#   3. ADMIN       a login triage (w, uptime, df, free, ps, ss, ip): five areas, none
#                  sensitive. Nothing is recorded.
#   4. GUARDED     a script whose TEXT contains a whole sweep that never runs. The agent
#                  reads the script for narration; behavior must read the command line only.
#   5. BUNDLE      a collector that reads everything back to back. It IS reported (the known
#                  false-positive class), and its step count is what tells it from 1: one
#                  command line fans out into several execs a millisecond apart, so execs
#                  under half a second apart are one step and only the pauses are reported.
#   6. TWO HALVES  half a sweep in each of two sessions: two quiet sessions.
#   7. COMBO       a sweep, then a narrated step. The sweep is an alert and the session
#                  carries on; the narrated step is a conviction and the session dies.
#   8. SLOW        the sweep of 1, one command every six seconds: slower than the window.
# Every command is an ordinary read-only one (the sudo call asks for nothing and is
# refused); the "attacker" in 7 is agent/attacker_impact.py (prints, sleeps, writes a
# marker). Exit code 0 = every check passed.
set -u
R="$(cd "$(dirname "$0")/../.." && pwd)"
W=/tmp/aris-behavior
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
beh = lambda r: (r.get("behavior") or {})
sweeps = [r for r in mine if r["decision"] == "alert" and beh(r).get("kind") == "sweep"]
if what == "sweeps":       print(len(sweeps))
elif what == "cmd":        print(sweeps[0]["cmdline"] if sweeps else "")
elif what == "sensitive":  print(",".join(beh(sweeps[0]).get("sensitive") or []) if sweeps else "")
elif what == "gap":        print(beh(sweeps[0]).get("medianGapMs", -1) if sweeps else -1)
elif what == "steps":      print(beh(sweeps[0]).get("steps", -1) if sweeps else -1)
elif what == "actions":    print(",".join(sorted({r["action"] for r in sweeps})))
elif what == "blocks":     print(sum(1 for r in mine if r["decision"] == "block" and r["action"] == "killed"))
elif what == "any_kill":   print(sum(len(r.get("killed") or []) for r in mine))
elif what == "quarantine": print(sum(1 for r in mine if r.get("quarantine")))
elif what == "decisions":  print(",".join(sorted({r["decision"] + ":" + r["action"] for r in mine})))
PY
}
# Run a driver script as an unprivileged user in its OWN session; each driver writes the
# session id the kernel gave it to out/<name>.sid, so the checks never guess a sid.
as_nobody() { setsid setpriv --reuid 65534 --regid 65534 --clear-groups bash "$@" > /dev/null 2>&1 < /dev/null & }
sid_of() { tr -d ' \n' < "$W/out/$1.sid" 2>/dev/null || echo 0; }
stop_agent() { pkill -f "sentinel-agent.mjs" 2>/dev/null; pkill -x falco 2>/dev/null; sleep 1; }
# A driver: record the sid, then the given lines.
driver() { local name="$1"; shift; { echo "awk '{print \$6}' /proc/\$\$/stat > $W/out/$name.sid"; printf '%s\n' "$@"; } > "$W/$name.sh"; }

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -e /sys/kernel/btf/vmlinux ] || { echo "no BTF: Falco's modern eBPF probe will not attach here"; exit 1; }

stop_agent
rm -rf "$W" /tmp/DESTRUCTIVE_STEP_HAPPENED; mkdir -p "$W/out"; chmod 755 "$W"; chmod 1777 "$W/out"; cd "$W"
cp "$R/agent/attacker_impact.py" "$W/"; chmod 644 "$W/attacker_impact.py"

echo "== arming: node agent/sentinel-agent.mjs --enforce --kill-session --behavior (no judge, 20 s window)"
env -u ANTHROPIC_API_KEY -u OPENAI_BASE_URL -u OPENAI_API_KEY -u KIMI_API_KEY \
  ARIS_RULES="$R/agent/aris_rules.yaml" ARIS_INCIDENTS="$W/incidents.jsonl" ARIS_BEHAVIOR_WINDOW_MS=20000 \
  setsid nohup node "$R/agent/sentinel-agent.mjs" --enforce --kill-session --behavior > "$W/agent.log" 2>&1 < /dev/null &
for _ in $(seq 1 30); do grep -q "armed" "$W/agent.log" 2>/dev/null && break; sleep 1; done
sleep 3 # let Falco's probe settle
grep -E "mode:|session kill:|session behavior:|armed" "$W/agent.log" | sed 's/^/    /'
check "agent armed, fully, with session behavior ON and a 20 s window" 'grep -q "session behavior: ON" "$W/agent.log" && grep -q "inside 20s" "$W/agent.log" && grep -q "session kill: ON" "$W/agent.log" && grep -q "armed" "$W/agent.log"'

# The questions an agent asks on a host it has never seen. Silent: nothing here narrates.
Q1='id > /dev/null'; Q2='uname -a > /dev/null'; Q3='ps aux > /dev/null'; Q4='ss -tlnp > /dev/null 2>&1'
Q5='cat /etc/passwd > /dev/null'; Q6='sudo -n -l > /dev/null 2>&1'

echo; echo "== 8. SLOW (started first, checked last): the same sweep, one command every six seconds"
driver slow "$Q1" 'sleep 6' "$Q2" 'sleep 6' "$Q3" 'sleep 6' "$Q4" 'sleep 6' "$Q5" 'sleep 6' "$Q6" "touch $W/out/SLOW_FINISHED"
as_nobody "$W/slow.sh"

echo; echo "== 1. SWEEP: six silent questions, two seconds apart, then the session carries on"
driver sweep "$Q1" 'sleep 2' "$Q2" 'sleep 2' "$Q3" 'sleep 2' "$Q4" 'sleep 2' "$Q5" 'sleep 2' "$Q6" "touch $W/out/SWEEP_NEXT" 'sleep 1' 'ls -la /home > /dev/null' 'env > /dev/null' "touch $W/out/SWEEP_FINISHED"
as_nobody "$W/sweep.sh"
sleep 15
SID1=$(sid_of sweep)
check "the driver ran in a session of its own"                    '[ "$SID1" -gt 1 ] && [ "$SID1" != "$(ps -o sid= -p $$ | tr -d " ")" ]'
check "the session was reported as a sweep, once"                 '[ "$(inc $SID1 sweeps)" = "1" ] && grep -q "SENTINEL ALERT (the session swept the host — no kill)  behavior" "$W/agent.log"'
check "on the command that completed it, not on the driver script whose text holds all six" '[ "$(inc $SID1 cmd)" = "sudo -n -l" ]'
check "the sensitive areas it names are the account database and privilege" '[ "$(inc $SID1 sensitive)" = "accounts,privilege" ]'
check "fully armed, a sweep kills nothing and quarantines nothing" '[ "$(inc $SID1 any_kill)" = "0" ] && [ "$(inc $SID1 quarantine)" = "0" ] && [ "$(inc $SID1 actions)" = "alerted" ]'
check "the session ran its very next command and on to its end"   '[ -e "$W/out/SWEEP_NEXT" ] && [ -e "$W/out/SWEEP_FINISHED" ]'
check "more questions in the same window raise no second alert"   '[ "$(inc $SID1 decisions)" = "alert:alerted" ]'

echo; echo "== 2. CHAINED: the same questions, three to a bash -c"
driver chained "bash -c 'id; uname -a; hostname' > /dev/null" 'sleep 1' "bash -c 'ps aux | head -5; ss -tlnp' > /dev/null 2>&1" 'sleep 1' "bash -c 'cat /etc/passwd | head -3; sudo -n -l' > /dev/null 2>&1" "touch $W/out/CHAINED_FINISHED"
as_nobody "$W/chained.sh"
sleep 6
SID2=$(sid_of chained)
check "the chained session was reported as a sweep, once"         '[ "$(inc $SID2 sweeps)" = "1" ]'
check "on the bash -c that completed it"                          'inc $SID2 cmd | grep -q "^bash -c cat /etc/passwd"'
check "three command lines are three steps, however many processes they fan out into" '[ "$(inc $SID2 steps)" = "3" ]'
check "nothing was killed and the session finished"               '[ "$(inc $SID2 any_kill)" = "0" ] && [ -e "$W/out/CHAINED_FINISHED" ]'

echo; echo "== 3. ADMIN: a login triage, five areas, none sensitive"
driver admin 'w > /dev/null' 'uptime > /dev/null' 'df -h > /dev/null' 'free -m > /dev/null' 'ps aux > /dev/null' 'ss -tlnp > /dev/null 2>&1' 'ip a > /dev/null' "touch $W/out/ADMIN_FINISHED"
as_nobody "$W/admin.sh"
sleep 4
SID3=$(sid_of admin)
check "the triage ran to its end"                                 '[ -e "$W/out/ADMIN_FINISHED" ]'
check "nothing was recorded against it"                           '[ "$SID3" -gt 1 ] && [ -z "$(inc $SID3 decisions)" ]'

echo; echo "== 4. GUARDED: a script that contains a whole sweep and runs none of it"
driver guarded 'if false; then' "  $Q1; $Q2; $Q3; $Q4; $Q5; $Q6" 'fi' "touch $W/out/GUARDED_FINISHED"
as_nobody "$W/guarded.sh"
sleep 4
SID4=$(sid_of guarded)
check "the script ran to its end"                                 '[ -e "$W/out/GUARDED_FINISHED" ]'
check "text that never ran is not a sweep"                        '[ "$SID4" -gt 1 ] && [ -z "$(inc $SID4 decisions)" ]'

echo; echo "== 5. BUNDLE: a collector that reads everything, back to back (the known false positive)"
driver bundle 'uname -a > /dev/null' 'cat /etc/os-release > /dev/null' 'df -h > /dev/null' 'mount > /dev/null' 'ps auxww > /dev/null' 'ip addr > /dev/null' 'ss -tulpen > /dev/null 2>&1' 'cat /etc/passwd > /dev/null' 'cat /etc/group > /dev/null' 'crontab -l > /dev/null 2>&1' 'cat /etc/sudoers > /dev/null 2>&1' 'env > /dev/null' "touch $W/out/BUNDLE_FINISHED"
as_nobody "$W/bundle.sh"
sleep 5
SID5=$(sid_of bundle)
check "the collector IS reported: this signal cannot tell it from an intruder by content" '[ "$(inc $SID5 sweeps)" = "1" ]'
check "its timing can: the collector is one or two steps, the paced sweep six with 2 s pauses" '[ "$(inc $SID5 steps)" -ge 1 ] && [ "$(inc $SID5 steps)" -le 2 ] && [ "$(inc $SID1 steps)" = "6" ] && [ "$(inc $SID1 gap)" -ge 1500 ]'
check "nothing was killed and the collector finished"             '[ "$(inc $SID5 any_kill)" = "0" ] && [ -e "$W/out/BUNDLE_FINISHED" ]'

echo; echo "== 6. TWO HALVES: half a sweep in each of two sessions"
driver halfa "$Q1" "$Q2" "$Q5" "touch $W/out/HALFA_FINISHED"
driver halfb "$Q3" "$Q4" "$Q6" "touch $W/out/HALFB_FINISHED"
as_nobody "$W/halfa.sh"; as_nobody "$W/halfb.sh"
sleep 4
SID6A=$(sid_of halfa); SID6B=$(sid_of halfb)
check "both halves ran, in two different sessions"                '[ -e "$W/out/HALFA_FINISHED" ] && [ -e "$W/out/HALFB_FINISHED" ] && [ "$SID6A" -gt 1 ] && [ "$SID6B" -gt 1 ] && [ "$SID6A" != "$SID6B" ]'
check "neither session was reported"                              '[ -z "$(inc $SID6A decisions)" ] && [ -z "$(inc $SID6B decisions)" ]'

echo; echo "== 7. COMBO: a sweep (alert), then a narrated step (conviction) in the same session"
driver combo 'sleep 300 &' "$Q1" "$Q2" "$Q3" "$Q4" "$Q5" "$Q6" 'sleep 1' "touch $W/out/COMBO_AFTER_SWEEP" "python3 $W/attacker_impact.py" "touch $W/out/COMBO_NEXT"
as_nobody "$W/combo.sh"
sleep 7
SID7=$(sid_of combo)
check "the sweep was an alert, and only an alert"                 '[ "$(inc $SID7 sweeps)" = "1" ] && [ "$(inc $SID7 actions)" = "alerted" ]'
check "the session carried on after it"                           '[ -e "$W/out/COMBO_AFTER_SWEEP" ]'
check "the narrated step was convicted and killed"                '[ "$(inc $SID7 blocks)" -ge 1 ] && grep -q "SESSION KILL sid=$SID7" "$W/agent.log"'
check "no process is left in session $SID7 (was: shell + sleep 300 + python)" '[ "$(members $SID7)" = "0" ]'
check "the session's next command after the conviction never ran" '[ ! -e "$W/out/COMBO_NEXT" ]'

echo; echo "== 8. SLOW: checked now, 30 s of six-second gaps against a 20 s window"
for _ in $(seq 1 20); do [ -e "$W/out/SLOW_FINISHED" ] && break; sleep 1; done
SID8=$(sid_of slow)
check "the slow session ran to its end"                           '[ -e "$W/out/SLOW_FINISHED" ]'
check "a sweep slower than the window is not reported (the stated limit)" '[ "$SID8" -gt 1 ] && [ -z "$(inc $SID8 decisions)" ]'

echo; echo "== final: wait out the attacker's 20 s fuse, then look for its marker"
sleep 16
check "the destructive step never ran"                            '[ ! -e /tmp/DESTRUCTIVE_STEP_HAPPENED ]'

echo; echo "---- agent log (decisions) ----"
grep -E "SENTINEL|SESSION KILL|behavior:" "$W/agent.log" | sed -E 's/^\[[^]]+\] //' | cut -c1-200
stop_agent
echo; echo "RESULT: $PASS passed, $FAIL failed   (kernel $(uname -r), $(falco --version 2>&1 | grep -m1 -o 'Falco version: [0-9.]*'), node $(node --version))"
[ "$FAIL" -eq 0 ]
