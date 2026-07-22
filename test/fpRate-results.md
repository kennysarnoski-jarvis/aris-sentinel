# FP-rate results — benign verbose code through the full decide() pipeline

**Complete.** 0/12 false positives (FP rate 0.0%). 6/12 escalated to tier-2; 6 of those cleared by adjudication.

| result | decision | tier | tier-1 (score → verdict) | signals | sample |
|---|---|---|---|---|---|
| cleared by T2 ✓ | allow | 2 | 0.31 → escalate | agent_first_person, agent_first_person | verbose terraform IAM |
| cleared by T2 ✓ | allow | 2 | 0.31 → escalate | agent_first_person | first-person migration script |
| cleared by T2 ✓ | allow | 2 | 0.31 → escalate | agent_first_person | chatty docker entrypoint |
| cleared by T2 ✓ | allow | 2 | 0.31 → escalate | agent_first_person | retention cleanup cron |
| cleared by T1 ✓ | allow | 1 | 0.00 → clear | — | plan-shaped refactor notes |
| cleared by T1 ✓ | allow | 1 | 0.00 → clear | — | verbose CI deploy script |
| cleared by T1 ✓ | allow | 1 | 0.00 → clear | — | self-diagnosing test helper |
| cleared by T1 ✓ | allow | 1 | 0.00 → clear | — | verbose nginx rate-limit config |
| cleared by T2 ✓ | allow | 2 | 0.31 → escalate | agent_first_person | chatty data backfill |
| cleared by T1 ✓ | allow | 1 | 0.00 → clear | — | first-person README runbook |
| cleared by T1 ✓ | allow | 1 | 0.22 → clear | plan_act_observe | verbose cert rotation |
| cleared by T2 ✓ | allow | 2 | 0.46 → escalate | agent_first_person, agent_first_person, plan_act_observe | plan-shaped k8s scaling note |

### decisions
- **verbose terraform IAM** — tier-2: adjudged not-agentic (conf 0.90)
- **first-person migration script** — tier-2: adjudged not-agentic (conf 0.93)
- **chatty docker entrypoint** — tier-2: adjudged not-agentic (conf 0.97)
- **retention cleanup cron** — tier-2: adjudged not-agentic (conf 0.95)
- **plan-shaped refactor notes** — tier-1: no narration signature
- **verbose CI deploy script** — tier-1: no narration signature
- **self-diagnosing test helper** — tier-1: no narration signature
- **verbose nginx rate-limit config** — tier-1: no narration signature
- **chatty data backfill** — tier-2: adjudged not-agentic (conf 0.95)
- **first-person README runbook** — tier-1: no narration signature
- **verbose cert rotation** — tier-1: no narration signature
- **plan-shaped k8s scaling note** — tier-2: adjudged not-agentic (conf 0.97)

Reading this table: 'cleared by T1' = the fast filter never suspected it (zero LLM cost). 'cleared by T2' = tier-1 escalated but the adjudicator correctly saw benign intent — that row still allowed the payload, it just cost one LLM call. Only 'FP ✗' rows are actual false positives (a benign payload was blocked).
