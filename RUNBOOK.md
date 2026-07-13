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
```bash
node sentinel-langflow-demo.mjs      # listens :8000  ->  Langflow 127.0.0.1:7860
```
Open a SECOND SSH session for the attack.

## 5. Fire the attack — the money moment
```bash
# (a) DIRECT at Langflow, no Sentinel -> the RCE fires
python3 attack.py http://127.0.0.1:7860
sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF     # file EXISTS = code executed

# reset
sudo docker exec langflow rm -f /tmp/SENTINEL_DEMO_RCE_PROOF

# (b) THROUGH Sentinel -> blocked before Langflow ever sees it
python3 attack.py http://127.0.0.1:8000                       # -> HTTP 403
sudo docker exec langflow cat /tmp/SENTINEL_DEMO_RCE_PROOF     # NO such file = never reached exec()
```

**The result that sells it:**
- (a) direct → the proof file appears = the CVE-2025-3248 RCE executed the agent payload.
- (b) via Sentinel → `HTTP 403`, no proof file, and the Sentinel console logs
  `SENTINEL BLOCK … (base64-decoded) signals=[roi_target_prioritization, agent_first_person, …]`
  — it decoded the base64 payload and caught the AI narrating its own attack.

## 6. Teardown
`sudo docker rm -f langflow`, then stop/snapshot/delete the Lightsail instance.
