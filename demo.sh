#!/usr/bin/env bash
# Aris Sentinel — live demo: stop the JadePuffer / CVE-2025-3248 attack.
#
# PRECONDITIONS (already true on the demo box):
#   - Langflow 1.2.0 running on 127.0.0.1:7860  (the real unauth RCE)
#   - Sentinel running: `nohup node interposition/sentinel-langflow-demo.mjs > ~/sentinel.log 2>&1 &`
#
# Record it:
#   asciinema rec sentinel-demo.cast -c ./demo.sh      # clean, shareable
#   ...or just screen-capture your terminal while it runs.
set -u
say()  { echo; echo "=== $* ==="; sleep 2; }
beat() { sleep "${1:-2}"; }

say "Aris Sentinel  vs  the JadePuffer attack (CVE-2025-3248) — live, on a real server"

say "1/4  Target: a real Langflow 1.2.0 with the actual unauthenticated RCE"
sudo docker exec langflow rm -f /tmp/SENTINEL_DEMO_RCE_PROOF 2>/dev/null
echo "   marker cleared. clean slate."
beat

say "2/4  ATTACK DIRECTLY (no Sentinel in the path)"
python3 attack/attack.py http://127.0.0.1:7860
echo
echo "   did the attacker's agent code execute inside the server?"
if sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF 2>/dev/null; then
  echo "   ^^^ RCE SUCCEEDED. The attacker ran code on the box. This is how JadePuffer got in."
fi
beat 3

say "3/4  Reset, then send the IDENTICAL payload THROUGH Aris Sentinel"
sudo docker exec langflow rm -f /tmp/SENTINEL_DEMO_RCE_PROOF
python3 attack/attack.py http://127.0.0.1:8000
beat

say "4/4  Did the payload reach Langflow's exec() this time?"
if sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF 2>/dev/null; then
  echo "   ^ NOT blocked (unexpected — check Sentinel is running)"
else
  echo "   'No such file' — the RCE NEVER fired. Sentinel stopped it before Langflow saw it."
fi
echo
echo "   What Sentinel caught (it decoded the base64 and saw the AI narrating its own attack):"
grep "SENTINEL BLOCK" ~/sentinel.log | tail -1

say "Same attack, same server. Unprotected: pwned.  With Sentinel: blocked, zero execution."
