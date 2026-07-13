# Aris Sentinel — Langflow (CVE-2025-3248) demo runbook

Goal: show the exact JadePuffer entry attack **fire** against a vulnerable Langflow,
then show **Aris Sentinel block it** — by decoding the payload and catching the AI's
narration before Langflow's `exec()` runs.

Target box: Ubuntu 24.04, 4 GB, Lightsail. Everything runs on the box; nothing
vulnerable is exposed to the internet.

---

## 0. Lock the firewall (do this in the Lightsail console FIRST)
Delete the **HTTP / TCP 80** rule. Leave **only SSH (22)**. We reach nothing over
the public net; Langflow binds to localhost. This is non-negotiable — CVE-2025-3248
is actively exploited in the wild.

## 1. SSH in + install deps
Use Lightsail's **Connect** (browser SSH) or your terminal.
```bash
sudo apt-get update && sudo apt-get install -y docker.io python3 nodejs
```

## 2. Run the VULNERABLE Langflow, bound to localhost only
```bash
# pin a pre-1.3.0 tag (CVE-2025-3248 is fixed in 1.3.0). If 1.2.0 isn't on Docker Hub,
# pick the nearest available <1.3.0 tag.
sudo docker run -d --name langflow -p 127.0.0.1:7860:7860 langflowai/langflow:1.2.0
sleep 60 && sudo docker logs --tail 15 langflow   # wait for boot
```
`127.0.0.1:7860` = reachable only from the box itself, never the internet.

## 3. Get the two Sentinel demo files onto the box
Either scp from your Mac (needs your Lightsail `.pem` key):
```bash
scp -i <LightsailKey>.pem \
  ~/Projects/aris-sentinel/interposition/sentinel-langflow-demo.mjs \
  ~/Projects/aris-sentinel/attack/attack.py \
  ubuntu@<box-public-ip>:~/
```
…or `git clone` the repo if you've pushed it.

## 4. Start the Sentinel interposition (leave running)
Node **>=18** required (global `fetch`). To enable **tier 2** (the LLM adjudication
that catches the stealth payload tier-1 only escalates), export your key first —
without it the demo runs tier-1 only and still blocks the narrated payload:
```bash
export ANTHROPIC_API_KEY=sk-ant-...   # optional; enables tier 2
node sentinel-langflow-demo.mjs       # listens :8000  ->  Langflow 127.0.0.1:7860
```
The startup line reports whether tier 2 is ENABLED or disabled. Open a SECOND SSH
session for the attack.

## 5. Fire the attack — the money moment
```bash
# (a) DIRECT at Langflow, no Sentinel -> the RCE fires
python3 attack.py http://127.0.0.1:7860                        # narrated payload
python3 attack.py http://127.0.0.1:7860 stealth                # stealth payload
sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF          # EXISTS = narrated ran
sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF_STEALTH  # EXISTS = stealth ran

# reset
sudo docker exec langflow rm -f /tmp/SENTINEL_DEMO_RCE_PROOF /tmp/SENTINEL_DEMO_RCE_PROOF_STEALTH

# (b) THROUGH Sentinel -> blocked before Langflow ever sees it
python3 attack.py http://127.0.0.1:8000                        # narrated -> HTTP 403 (TIER 1)
python3 attack.py http://127.0.0.1:8000 stealth                # stealth  -> HTTP 403 (TIER 2)
sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF          # NO file = never reached exec()
sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF_STEALTH  # NO file = never reached exec()
```

**The result that sells it:**
- (a) direct → both proof files appear = the CVE-2025-3248 RCE executed both agent payloads.
- (b) via Sentinel → both `HTTP 403`, no proof files. The console shows the two tiers:
  - narrated → `SENTINEL BLOCK  tier-1 … (base64-decoded) signals=[roi_target_prioritization, …]`
    — the fast local filter caught heavy narration, zero LLM cost.
  - stealth → `SENTINEL BLOCK  tier-2 … tier1=0.31(escalate)  adjudged AGENTIC` + a reasoning line
    — tier-1 alone only escalated it; **the LLM adjudication caught what a signature-only
    detector would miss.** (With no `ANTHROPIC_API_KEY`, tier-2 is off and the stealth payload
    passes — that's the honest tier-1-only limit the key closes.)

## 6. Teardown
`sudo docker rm -f langflow`, then stop/snapshot/delete the Lightsail instance.
