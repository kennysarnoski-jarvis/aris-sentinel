# Aris Sentinel — data handling

What the agent sends off your box, when, and how to control it. Written to be shared
with a security team evaluating a pilot. No hand-waving.

## The principle: almost everything stays local

Aris Sentinel scores every process on your box **locally**. The fast filter (a regex
feature scorer, no network) runs on-device. The overwhelming majority of activity —
everything that scores clearly benign or clearly malicious — is decided **without any
data leaving the host.**

## What NEVER leaves the box

- The full stream of process executions. Aris watches them all locally; they are not
  transmitted.
- Anything the local filter resolves on its own (clear → allowed, or high-confidence
  agentic → flagged). No payload leaves for these.
- Your files, environment, credentials, and application data. Aris reads the command
  line and, for interpreter execs, the script being run — nothing else.

## What leaves the box, and exactly when

Only the **ambiguous middle** — a payload the local filter can neither clear nor
convict (the "escalate" band, a small fraction of executions) — is sent off-box, to two
destinations:

1. **The LLM adjudicator (Anthropic API).** The decoded payload text is sent to a Claude
   model for a single yes/no classification: "was this authored by an autonomous AI
   attacker?" Anthropic is SOC 2 Type II and **does not train on API inputs.**
2. **Aris Cloud (operated by Aris Tech LLC), only on a detection.** When Aris flags an
   attack it sends an **incident alert**: host identifier, pid/session/user, the command
   line, a short narration snippet, and the verdict + reasoning. This can contain
   fragments of the offending command — by design, so the alert tells you what the
   attacker was doing.

Nothing else is transmitted. There is no bulk telemetry, no file upload, no keystroke or
credential capture.

## Third parties

| Who | Role | Posture |
|---|---|---|
| Anthropic (Claude) | LLM adjudicator | SOC 2 Type II; API inputs not used for training |
| Aris Tech LLC (Aris Cloud) | Alert relay → operator | Alerts held for the operator; not sold or shared |

## Retention

- **On your box:** incident records are written to a root-only local file and stay until
  you remove the agent (`uninstall.sh` deletes them).
- **Aris Cloud:** incident alerts are retained for the managed-detection operator for a
  window agreed per engagement (default 30 days), then purged.
- **Anthropic:** per Anthropic's API data-retention policy.

## Controls you have

- **Fully local mode.** Run with no `ANTHROPIC_API_KEY` and no `ARIS_CLOUD_URL`:
  **nothing leaves the box at all.** You get the local filter only (catches the loud
  attacks; misses the subtle ones). Escalation to the cloud is entirely opt-in.
- **Monitor mode is the default.** The agent detects and alerts but **does not kill any
  process** unless you explicitly run it with `--enforce`. You choose when it's allowed
  to act.
- **Redaction / scoping.** Sensitive paths or arguments can be scoped out of what's sent;
  the deploy-time sink map can narrow what's inspected at all.
- **One-command removal.** `sudo ./uninstall.sh` removes the agent, its files, and its
  secrets, and restores the host.

## Network & host posture

- **Outbound only, HTTPS/TLS.** The agent makes outbound calls to the adjudicator and
  Aris Cloud. It opens **no inbound ports.**
- Runs as a root service (required to observe process execs via eBPF and to act on a
  threat). It ships de-branded and is supervised by systemd (`Restart=always`).

## Contact

Security questions: **support@youraris.com**
