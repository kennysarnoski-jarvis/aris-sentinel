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
destinations. Since 2026-11-10 that unit can also be a **session transcript**: when several
commands from one session together reach the block band, up to 12 of that session's
narration-bearing payloads (each clipped to 2,000 characters) are sent as one request, in
place of the single payload. Commands with no narration signal are never part of it.

1. **The LLM adjudicator — whichever judges YOU configure, in the order you set.** The
   decoded payload text is sent for a single yes/no classification: "was this authored by
   an autonomous AI attacker?" Legs, each optional (`ARIS_TIER2_ORDER`, default
   `local,anthropic,openai,kimi`):
   - **local** — an OpenAI-compatible model on loopback (`OPENAI_BASE_URL` pointing at
     Ollama / vLLM on the box). **Nothing leaves the host.** First in the chain by
     default when configured.
   - **anthropic** — Claude (`ANTHROPIC_API_KEY`). Anthropic's server-side fallback may
     re-run a declined request on another Anthropic model inside the same call.
   - **openai** — api.openai.com or any remote OpenAI-compatible endpoint you point
     `OPENAI_BASE_URL` at (`OPENAI_API_KEY`, `OPENAI_MODEL`).
   - **kimi** — Kimi K3 (Moonshot AI, `api.kimi.com`).
   Each provider's own API data policy applies to what it receives — review it before
   enabling a hosted judge on a regulated host. Configure no judge and nothing is sent:
   the escalate band is alerted locally instead.
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
| none (local model on the box) | LLM adjudicator (`OPENAI_BASE_URL` on loopback) | nothing leaves the host |
| Anthropic (Claude) | LLM adjudicator (`ANTHROPIC_API_KEY`) | SOC 2 Type II; API inputs not used for training |
| OpenAI or the endpoint you choose | LLM adjudicator (`OPENAI_API_KEY` / remote `OPENAI_BASE_URL`) | per that provider's API data policy |
| Moonshot AI (Kimi K3) | LLM adjudicator (`KIMI_API_KEY`) | per Moonshot AI's API data policy |
| Aris Tech LLC (Aris Cloud) | Alert relay → operator | Alerts held for the operator; not sold or shared |

## Retention

- **On your box:** incident records are written to a root-only local file and stay until
  you remove the agent (`uninstall.sh` deletes them).
- **Aris Cloud:** incident alerts are retained for the managed-detection operator for a
  window agreed per engagement (default 30 days), then purged.
- **LLM provider:** per the configured provider's API data-retention policy; a local
  judge retains nothing off-box. Verdicts are cached on the box (in memory, 10 min by
  default) so a repeated payload is not re-sent.

## Controls you have

- **Fully local mode.** Run with no hosted judge key and no `ARIS_CLOUD_URL`: **nothing
  leaves the box at all.** With no judge you get the local filter only (blocks the loud
  attacks; alerts on the ambiguous ones). With a local model (`OPENAI_BASE_URL` on
  loopback) you get both tiers and still nothing leaves. Escalation off-box is entirely
  opt-in.
- **Session evidence off.** `ARIS_SESSION_TTL_MS=0` disables session windows entirely:
  only single payloads are ever escalated, as before. The window itself is held in the
  agent's memory only, for 10 minutes, and is never written to disk.
- **Rate-limited escalation.** Tier-2 calls are capped per minute
  (`ARIS_TIER2_BUDGET_PER_MIN`, default 30) and deduplicated; past the cap the agent
  alerts locally rather than sending more.
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
