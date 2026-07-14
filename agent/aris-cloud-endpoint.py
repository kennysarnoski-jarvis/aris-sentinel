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
    alert says what the enemy AI was TRYING to do — not a cryptic anomaly score."""
    host = inc.get("host", "unknown-host")
    tier = inc.get("tier")
    if tier == 2:
        caught = f"caught by tier 2 (LLM adjudication, confidence {inc.get('conf')})"
    else:
        caught = f"caught by tier 1 (narration filter, score {float(inc.get('score', 0)):.2f})"
    intent = inc.get("reasoning") or ("agentic-narration signals: " + ", ".join(inc.get("signals") or []) or "n/a")
    words = f"\n\n\U0001f5e3 In its own words:\n{inc.get('narration')}" if inc.get("narration") else ""
    if inc.get("action") == "killed":
        did = f"\U0001f52a I killed it (pid {inc.get('pid')}, process tree) before the destructive step. No damage."
    else:
        did = f"⚠️ Action: {inc.get('action')} (pid {inc.get('pid')})."
    return (
        f"\U0001f6a8 Aris caught an AI attacker on {host}\n"
        f"{inc.get('ts', '')}\n\n"
        f"\U0001f916 An autonomous AI agent was {caught}.\n"
        f"\U0001f3af What it was doing: {intent}"
        f"{words}\n\n"
        f"{did}\n\n"
        f"✅ Next steps:\n"
        f"• Isolate {host}; preserve /var/log/aris-incidents.jsonl\n"
        f"• Rotate creds for '{inc.get('user')}'; review session sid={inc.get('sid')}\n"
        f"• Then call the customer.\n\n"
        f"cmd: {str(inc.get('cmdline', ''))[:100]}"
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
    print("=" * 70)
    print(_format_sentinel_alert(sample))
    print("=" * 70)
