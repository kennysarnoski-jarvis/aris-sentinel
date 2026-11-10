# Aris Sentinel -> Aris Cloud alert endpoint.
#
# PASTE the marked block into local.py (anywhere after `_send_telegram_message` is
# defined, ~line 3197). It adds ONE additive route — no existing code changes.
#
# The on-box Sentinel agent POSTs an incident here the instant it kills an AI attacker;
# this formats a plain-English readout of what the enemy AI was trying to do and
# Telegram-pings you. You get the alert, then you call the customer.
#
# Two env vars on the cloud:
#   ARIS_SENTINEL_KEY       shared secret; must match the agent's ARIS_INGEST_KEY
#   SENTINEL_ALERT_CHAT_ID  your Telegram chat id (where alerts go)
#
# Run this file directly to PREVIEW the exact message:  python3 aris-cloud-endpoint.py


def _format_sentinel_alert(inc: dict) -> str:
    """Plain-text Telegram readout. Aris read the attacker's own reasoning, so the
    alert says what the enemy AI was TRYING to do — not a cryptic anomaly score.

    Three incident kinds arrive here (see sentinel-core.mjs / sentinel-agent.mjs):
      decision=block  caught — killed in enforce, monitored in monitor mode
      decision=alert  suspicious but tier-2 could NOT adjudicate (no key / budget spent)
      decision=error  the detector threw on this payload; it was NOT judged
    """
    host = inc.get("host", "unknown-host")
    decision = inc.get("decision", "block")
    tier = inc.get("tier")
    words = f"\n\n\U0001f5e3 In its own words:\n{inc.get('narration')}" if inc.get("narration") else ""
    # Session evidence: the narration was spread across several commands of one session.
    sess = inc.get("session") or {}
    if inc.get("via_session") and sess:
        words = (f"\n\n\U0001f9f5 Evidence is a SESSION: {sess.get('size')} commands that together score "
                 f"{float(sess.get('score') or 0):.2f} (this one alone: {float(sess.get('payloadScore') or 0):.2f}).") + words
    cmd = f"cmd: {str(inc.get('cmdline', ''))[:100]}"

    # Tripwire: the evidence is an action, not narration. The agent never sends the token.
    trip = inc.get("tripwire") or {}
    if trip.get("kind") == "decoy" and decision == "alert":
        return (
            f"\u26a0\ufe0f Aris TRIPWIRE on {host}: the decoy was looked at\n"
            f"{inc.get('ts', '')}\n\n"
            f"\U0001faa4 A command addressed the decoy directory {trip.get('evidence')} without running its canary command "
            f"(pid {inc.get('pid')}, user '{inc.get('user')}', session sid={inc.get('sid')}). Nothing legitimate lives there.\n"
            f"Nothing was killed: a look is not proof, and an administrator can do it too.\n\n"
            f"\u2705 Next steps:\n"
            f"\u2022 Was that you or a colleague? If not, somebody is exploring {host}.\n"
            f"\u2022 Watch session sid={inc.get('sid')}; review what user '{inc.get('user')}' ran around {inc.get('ts', '')}.\n\n"
            f"{cmd}"
        )

    if decision == "error":
        return (
            f"\u2757 Aris detector ERROR on {host}\n"
            f"{inc.get('ts', '')}\n\n"
            f"The scorer threw on a payload (pid {inc.get('pid')}, user '{inc.get('user')}') and it was NOT judged. "
            f"A crash on one payload can be a bug or an evasion attempt — either way, look.\n"
            f"error: {str(inc.get('error', ''))[:300]}"
            f"{words}\n\n"
            f"\u2705 Next steps:\n"
            f"\u2022 Review the incident row on {host}; reproduce with --selftest\n"
            f"\u2022 If this repeats for the same session (sid={inc.get('sid')}), treat as hostile.\n\n"
            f"{cmd}"
        )

    if decision == "alert":
        return (
            f"\u26a0\ufe0f Aris ALERT on {host} (needs a human)\n"
            f"{inc.get('ts', '')}\n\n"
            f"A payload tripped the narration filter (score {float(inc.get('score') or 0):.2f}, "
            f"signals: {', '.join(inc.get('signals') or []) or 'n/a'}) but tier 2 could not adjudicate it: "
            f"{inc.get('reason')}.\n"
            f"Nothing was killed. pid {inc.get('pid')}, user '{inc.get('user')}'."
            f"{words}\n\n"
            f"\u2705 Next steps:\n"
            f"\u2022 Read the narration above — does it read like an AI narrating an attack?\n"
            f"\u2022 If yes: isolate {host}, rotate creds for '{inc.get('user')}'. If tier 2 was off, enable it.\n\n"
            f"{cmd}"
        )

    if tier == 2:
        caught = f"caught by tier 2 (LLM adjudication, confidence {inc.get('conf')})"
    else:
        caught = f"caught by tier 1 (narration filter, score {float(inc.get('score') or 0):.2f})"
    intent = inc.get("reasoning") or ("agentic-narration signals: " + ", ".join(inc.get("signals") or []) or "n/a")
    if trip.get("kind") == "token":
        caught = "caught by the TRIPWIRE (it ran the decoy's canary command; no narration needed)"
        intent = ("it read the planted decoy and did what the decoy told an automated agent to do"
                  + (", wrapped in an encoded layer" if trip.get("decoded") else "")
                  + ". Nothing legitimate on this host runs that command.")
    if inc.get("action") == "killed":
        did = f"\U0001f52a I killed it (pid {inc.get('pid')}, process tree) before the destructive step. No damage."
    else:
        did = f"\u26a0\ufe0f Action: {inc.get('action')} (pid {inc.get('pid')})."
    if trip.get("kind") == "token" and inc.get("action") == "killed":
        # The decoy helper is inert, so killing it prevents nothing by itself. Say what matters.
        did = (f"\U0001f52a I killed the process that ran it (pid {inc.get('pid')}). The decoy helper itself is harmless; "
               f"what matters is the session that chose to run it (sid={inc.get('sid')}), which is ended too when the agent runs with --kill-session.")
    return (
        f"\U0001f6a8 Aris caught an AI attacker on {host}\n"
        f"{inc.get('ts', '')}\n\n"
        f"\U0001f916 An autonomous AI agent was {caught}.\n"
        f"\U0001f3af What it was doing: {intent}"
        f"{words}\n\n"
        f"{did}\n\n"
        f"\u2705 Next steps:\n"
        f"\u2022 Isolate {host}; preserve /var/log/aris-incidents.jsonl\n"
        f"\u2022 Rotate creds for '{inc.get('user')}'; review session sid={inc.get('sid')}\n"
        f"\u2022 Then call the customer.\n\n"
        f"{cmd}"
    )


# ============================ PASTE INTO local.py ============================
# import os
# from fastapi import Request
#
# @router.post("/sentinel/alert")
# async def sentinel_alert(request: Request):
#     """Aris Sentinel on-box agent reports a caught AI attacker -> Telegram the operator."""
#     key = os.environ.get("ARIS_SENTINEL_KEY", "")
#     if key and request.headers.get("x-aris-key") != key:
#         raise HTTPException(status_code=401, detail="unauthorized")
#     inc = await request.json()
#     chat_id = os.environ.get("SENTINEL_ALERT_CHAT_ID", "")
#     if not chat_id:
#         print("[SENTINEL] alert received but SENTINEL_ALERT_CHAT_ID not set")
#         return {"ok": False, "error": "no chat id configured"}
#     msg = _format_sentinel_alert(inc)
#     print(f"[SENTINEL] ALERT host={inc.get('host')} tier={inc.get('tier')} pid={inc.get('pid')}")
#     _send_telegram_message(chat_id, msg)
#     return {"ok": True}
# ==========================================================================


if __name__ == "__main__":
    sample = {
        "host": "prod-db-01", "ts": "2026-07-14T02:44:30Z", "tier": 2, "conf": 0.95,
        "action": "killed", "pid": 6997, "sid": 6977, "user": "ubuntu",
        "cmdline": "python3 /home/ubuntu/stealth_attacker.py",
        "signals": ["agent_first_person", "plan_act_observe"],
        "reasoning": "The payload narrates first-person offensive reasoning with stated intent, a numbered plan-act-observe sequence, target-path selection, and self-justified evasion decisions characteristic of an autonomous LLM agent.",
        "narration": "Objective: escalate to admin on this host. The deploy account can write to a directory a root cron job sources. That is my path up, so I will place my own command there. I will avoid editing sudoers since that is monitored.",
    }
    alert = {
        "host": "prod-db-01", "ts": "2026-07-14T02:50:11Z", "decision": "alert", "tier": 1, "score": 0.41,
        "action": "alerted", "pid": 7012, "sid": 6977, "user": "ubuntu", "signals": ["agent_first_person", "plan_act_observe"],
        "reason": "tier-1: escalate, tier-2 unavailable (no KIMI_API_KEY / ANTHROPIC_API_KEY) -> alert",
        "cmdline": "python3 /home/ubuntu/job.py",
        "narration": "Plan: 1) check the schema version, 2) apply deltas in order. I roll back on any failure.",
    }
    err = {
        "host": "prod-db-01", "ts": "2026-07-14T02:51:00Z", "decision": "error", "tier": None,
        "action": "errored", "pid": 7020, "sid": 6977, "user": "ubuntu", "error": "RangeError: Maximum call stack size exceeded",
        "cmdline": "python3 /home/ubuntu/weird.py",
    }
    session = {
        "host": "prod-db-01", "ts": "2026-11-10T02:52:40Z", "decision": "block", "tier": 2, "conf": 0.9,
        "action": "killed", "pid": 7101, "sid": 7090, "user": "deploy", "via_session": True,
        "session": {"key": "sid:7090", "size": 4, "score": 0.78, "payloadScore": 0.31, "payloadVerdict": "escalate"},
        "signals": ["agent_first_person", "plan_act_observe", "roi_target_prioritization"],
        "reasoning": "Across four commands the session narrates reconnaissance, ranks a target by value and stages data for removal in a first-person planning voice.",
        "cmdline": "bash step4.sh",
        "narration": "I'll check what this account can reach first. Step 2: list the mounted shares. finance is the largest share, so that one goes first.",
    }
    tripwire = {
        "host": "prod-db-01", "ts": "2026-11-10T03:10:02Z", "decision": "block", "tier": 1, "score": 0.0,
        "action": "killed", "pid": 7210, "sid": 7190, "user": "www-data", "signals": ["tripwire_token"],
        "tripwire": {"kind": "token", "decoded": False, "fingerprint": "9bf7e3b77de1", "evidence": "/opt/vault-access/register --ticket [tripwire:9bf7e3b77de1]"},
        "cmdline": "/opt/vault-access/register --ticket [tripwire:9bf7e3b77de1]", "narration": "",
    }
    looked = {
        "host": "prod-db-01", "ts": "2026-11-10T03:09:41Z", "decision": "alert", "tier": 1, "score": 0.0,
        "action": "alerted", "pid": 7204, "sid": 7190, "user": "www-data", "signals": ["tripwire_decoy"],
        "tripwire": {"kind": "decoy", "decoded": False, "fingerprint": "9bf7e3b77de1", "evidence": "/opt/vault-access"},
        "cmdline": "cat /opt/vault-access/README.md", "narration": "",
    }
    for inc in (sample, session, tripwire, looked, alert, err):
        print("=" * 70)
        print(_format_sentinel_alert(inc))
    print("=" * 70)
