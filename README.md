# Aris Sentinel

Runtime defense agent that runs on a server and detects **agentic AI attackers** — autonomous LLM-driven intrusions like [JADEPUFFER](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) — and stops them **before the destructive step**.

We are the good guys. Sentinel's job is to catch the attacker's own AI narrating itself.

Plain Node ≥ 18, **zero dependencies**, monitor-only by default. Linux (Falco/eBPF exec tap) and Windows (PowerShell script-block log).

## The thesis

An agentic AI attacker can't stop narrating its intent. JADEPUFFER's payloads were "saturated with natural-language commentary explaining *why* each action is taken" — ROI rankings, plan-act-observe labels, diagnosis-then-fix comments. **Humans never narrate payloads; agents always do.** That narration is present from the *first* payload — five phases before anything gets encrypted.

Sentinel detects that signature. It is **app-agnostic** — it looks at the attacker's LLM, not your code — so the same detector ships everywhere with **zero per-host tuning**.

JADEPUFFER is the **existence proof, not the target**. A pure JADEPUFFER signature would be worthless the moment the next crew changes its prompt. Sentinel productizes the *category* — self-narration — so it catches agentic attackers it was never tuned on. See [THESIS.md](THESIS.md).

## How it decides

```
exec / script-block  ─►  decode (base64 · hex · nested)  ─►  tier 1: narration score
                                                                 │
                              block ◄── ≥0.60 ──────────────────┤
                              allow ◄── <0.30 ──────────────────┤
                                                      escalate (0.30–0.60)
                                                                 │
                                        tier 2: LLM adjudication (Kimi K3 → Anthropic)
                                                                 │
                     block ◄── agentic / fail-closed ────────────┼──── not-agentic ──► allow
                     alert ◄── no key · budget spent ────────────┘
```

| decision | what the agent does |
|---|---|
| **block** | convicted. MONITOR (default): log + report. `--enforce`: SIGKILL / `taskkill` the process tree. |
| **alert** | suspicious (escalate band) but tier 2 could **not** judge it — no provider key, or the per-minute budget is spent. Logged + reported, **never killed**, even in `--enforce`. |
| **allow** | clear at tier 1, or tier 2 says not-agentic. |
| **error** | the detector threw. Logged + reported as an incident, never dropped silently. Nothing killed. |

Tier 1 resolves `block`/`allow` locally with zero LLM spend; only the escalate band pays for adjudication, and the tier-2 governor caches verdicts, collapses duplicate in-flight calls, caps concurrency and enforces a per-minute budget.

Tier 2 **fails closed**: a refusal, API error or timeout on an escalate-band payload is a `block`, never a pass. Set `ARIS_FAIL_MODE=alert` if you would rather page than kill on an API outage.

## Layout — one detector, three entry points

- **[`agent/sentinel-core.mjs`](agent/sentinel-core.mjs)** — **the** detector. The only file that defines a pattern, a prompt or the decision policy: tier-1 features, decode stage, tier-2 provider chain (raw `fetch`, per-attempt timeout + overall deadline, strict verdict validation), the tier-2 governor, and `decide()`. A unit test fails if any other file defines a pattern.
- **`detector/*.ts`** — thin typed re-exports of the core for the TypeScript test harnesses (`sentinel-core.d.mts` carries the types).
- **`agent/sentinel-agent.mjs`** — Linux agent: Falco exec stream → `decide()` → respond. Reads the script file for interpreter execs, resolved against the *process's* cwd. Protected-process allowlist, per-session dedup, `--selftest`.
- **`agent/win/sentinel-agent-win.mjs`** + `sensor.ps1` — Windows agent: PowerShell Script Block Logging (4104, auto-deobfuscated) → same `decide()` → `taskkill`.
- **`interposition/sentinel-langflow-demo.mjs`** — reverse proxy that blocks the CVE-2025-3248 payload at Langflow's exec sink. Imports the core.
- **`corpus/`** — 32 labeled samples: narrated agentic attacks, verbose-but-benign ops code (the false-positive test), terse human malware (the specificity test), narrated PowerShell.

## Tests

| command | what it proves | key |
|---|---|---|
| `bun run test` | tier-1 corpus: **precision 1.00 / recall 1.00**, decode stage defeats base64 + exec-wrapping | no |
| `bun test` | **111 unit tests**: verdict validation, timeouts, provider-chain order, governor (cache / dedup / concurrency / budget), block/alert/allow policy, cwd resolution, inline-flag detection, alert + error incidents on both agents, corpus snapshot, single-source guard | no |
| `bun run windows` | 5/5: the same detector catches narrated **PowerShell** unchanged | no |
| `bun run pipeline:stub` | routing: only the escalate band reaches tier 2 | no |
| `bun run selftest` / `bun run win:mock` | agent smoke: block / allow / alert paths end to end, no root | no |
| `bun run typecheck` | `tsc --noEmit` over `detector/` + `test/` against the core's declaration file | no |
| `bun run test:all` | all of the above except typecheck | no |
| `bun run tier2` | tier 2 catches the 3 attacks tier 1 only escalates; benign + terse stay not-agentic | **yes** |
| `bun run pipeline` | end to end: attacks blocked, all 12 benign files allowed at tier 1 or tier 2 | **yes** |
| `bun run fpRate` | 12 benign-but-loud samples through both tiers: **0 false positives** | **yes** |
| `bun run matrix` | provider × prompt matrix on the samples Anthropic's input screen refused | **yes** |

Key-needed runs read `KIMI_API_KEY` / `ANTHROPIC_API_KEY` and write to `test/*-results.md` (gitignored). `test/corpus-snapshot.json` freezes every corpus verdict; a detector change that moves one fails `bun test` until you regenerate (`bun run corpus:snapshot`) and commit the diff — that diff is the review.

**The result that sells it:** attacks blocked (tier 1 *or* tier 2), benign allowed at **both** tiers, terse human malware clear. The escalate band on verbose ops code is a *cost* (one cached LLM call), not a false positive.

## Configuration

| env | default | meaning |
|---|---|---|
| `KIMI_API_KEY` | — | enables tier 2, Kimi K3 first (`api.kimi.com/coding`, Anthropic wire; **not** `api.moonshot.ai`) |
| `ANTHROPIC_API_KEY` | — | enables tier 2 on Anthropic (fallback when both are set); `ARIS_MODEL` overrides `claude-opus-4-8` |
| `ARIS_FAIL_MODE` | `closed` | `alert` turns tier-2 refusal/error/timeout into an alert instead of a block |
| `ARIS_TIER2_TIMEOUT_MS` | `20000` | per attempt |
| `ARIS_TIER2_DEADLINE_MS` | `45000` | whole provider chain |
| `ARIS_TIER2_CACHE_TTL_MS` | `600000` | verdict cache (real verdicts only, keyed by payload hash) |
| `ARIS_TIER2_CONCURRENCY` | `4` | concurrent tier-2 calls |
| `ARIS_TIER2_BUDGET_PER_MIN` | `30` | tier-2 calls per minute; past it → `alert`. `0` = unlimited |
| `ARIS_CLOUD_URL` + `ARIS_INGEST_KEY` | — | off-box incident reports (`agent/aris-cloud-endpoint.py` formats them for Telegram) |
| `ARIS_INCIDENTS` | `/var/log/aris-incidents.jsonl` | local incident log |
| `ARIS_VERBOSE=1` | — | log every allow too |

Install, deploy and de-branding: [agent/DEPLOY.md](agent/DEPLOY.md). Windows: [agent/win/WINDOWS.md](agent/win/WINDOWS.md). What leaves the box: [agent/DATA-HANDLING.md](agent/DATA-HANDLING.md). Langflow demo: [RUNBOOK.md](RUNBOOK.md).

## Honest limits

- **An agent told not to narrate is invisible to this.** Zero narration = zero signal. That is the design boundary, not a bug; tier 2 narrows it (it judges the concept, not keywords) but cannot close it. `test/loop/` is the stress test of a mutating attacker: 4/6 caught, the two "evasions" achieved nothing real.
- **Falco observes post-syscall.** The "stop before destruction" guarantee rests on the thesis that narration appears phases before impact — true of every agentic campaign observed so far.
- **Fail-closed means an adjudicator outage blocks the escalate band** in `--enforce`. That is deliberate for a security tool; `ARIS_FAIL_MODE=alert` is the knob if your risk posture differs.
- **v1 scores every exec.** Busy hosts should scope to sensitive sinks (next) and tune the tier-2 budget.
- Not built yet: sink scoping, session-level kill, a native Windows installer, Go packaging.

## Security

This is a defensive tool. Found a bypass or a bug that could hurt someone running it? See [SECURITY.md](SECURITY.md).
