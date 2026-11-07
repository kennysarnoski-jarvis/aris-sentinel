# Aris Sentinel

[![CI](https://github.com/kennysarnoski-jarvis/aris-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/kennysarnoski-jarvis/aris-sentinel/actions/workflows/ci.yml)

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
                               tier 2: LLM judge chain (local → Claude → openai → kimi)
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

Tier 2 is a **chain of judges**, each optional, first validated verdict wins: a **local** model on loopback (Ollama, vLLM, llama.cpp: nothing leaves the box), **Claude Opus 5.5**, any remote **OpenAI-compatible** endpoint, **Kimi K3**. Attack-shaped text is exactly what a hosted model's safety classifier declines, so the Claude leg asks for Anthropic's server-side fallbacks (a cyber-category decline is re-run on the model Anthropic recommends, inside the same call) and retries once with a de-fanged prompt. Legitimate security vendors can apply to Anthropic's [Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet) to lift the classifier on their key.

Tier 2 **fails closed**: when no judge produces a verdict (refusals, errors, timeouts), the payload is a `block`, never a pass. A refusal is not evidence of innocence. Set `ARIS_FAIL_MODE=alert` if you would rather page than kill on an outage.

## Layout — one detector, three entry points

- **[`agent/sentinel-core.mjs`](agent/sentinel-core.mjs)** — **the** detector. The only file that defines a pattern, a prompt or the decision policy: tier-1 features, decode stage, tier-2 judge chain (raw `fetch` on the Anthropic and OpenAI wires, per-attempt timeout + overall deadline, strict verdict validation, refusal handling), the tier-2 governor, and `decide()`. A unit test fails if any other file defines a pattern.
- **`detector/*.ts`** — thin typed re-exports of the core for the TypeScript test harnesses (`sentinel-core.d.mts` carries the types).
- **`agent/sentinel-agent.mjs`** — Linux agent: Falco exec stream → `decide()` → respond. Reads the script file for interpreter execs, resolved against the *process's* cwd. Protected-process allowlist, per-session dedup, `--selftest`.
- **`agent/win/sentinel-agent-win.mjs`** + `sensor.ps1` — Windows agent: PowerShell Script Block Logging (4104, auto-deobfuscated) → same `decide()` → `taskkill`.
- **`interposition/sentinel-langflow-demo.mjs`** — reverse proxy that blocks the CVE-2025-3248 payload at Langflow's exec sink. Imports the core.
- **`corpus/`** — 94 labeled samples: 28 narrated agentic attacks across languages and "voices" (ReAct transcripts, tool-call logs, markdown notes, thin narration), 40 verbose-but-benign files that lean on dual-use language (an agent framework's own source, churn ranking, a defender's checklist), 16 terse human one-liners, 10 PowerShell. Provenance, rules and the held-out results are in [corpus/README.md](corpus/README.md).

## Tests

| command | what it proves | key |
|---|---|---|
| `bun run test` | tier-1 corpus, 84 Linux files: **precision 1.00**, tier-1 recall 0.61, **pipeline-reachable recall 1.00** (no agentic sample is `clear`), 0 false positives; decode stage defeats base64 + exec-wrapping | no |
| `bun test` | **183 unit tests**: verdict validation, timeouts, provider-chain order, governor (cache / dedup / concurrency / budget), block/alert/allow policy, cwd resolution, inline-flag detection, alert + error incidents on both agents, corpus snapshot, single-source guard | no |
| `bun run windows` | 10/10: the same detector catches narrated **PowerShell** unchanged; benign admin + encoded cradles stay clear | no |
| `bun run pipeline:stub` | routing: only the escalate band reaches tier 2 | no |
| `bun run selftest` / `bun run win:mock` | agent smoke: block / allow / alert paths end to end, no root | no |
| `bun run typecheck` | `tsc --noEmit` over `detector/` + `test/` against the core's declaration file | no |
| `bun run test:all` | all of the above except typecheck | no |
| `bun run tier2` | tier 2 catches the 3 attacks tier 1 only escalates; benign + terse stay not-agentic | **yes** |
| `bun run pipeline` | end to end: attacks blocked, all 12 benign files allowed at tier 1 or tier 2 | **yes** |
| `bun run fpRate` | 12 benign-but-loud samples through both tiers: **0 false positives** | **yes** |
| `bun run matrix` | provider × prompt matrix on the samples Anthropic's input screen refused | **yes** |

Key-needed runs use whatever judges are configured (see Configuration) and write to `test/*-results.md` (gitignored). `test/corpus-snapshot.json` freezes every corpus verdict; a detector change that moves one fails `bun test` until you regenerate (`bun run corpus:snapshot`) and commit the diff — that diff is the review.

**The result that sells it:** on 62 held-out files scored before any pattern was touched, tier 1 convicted the loud half locally (12/23), escalated every other agentic sample and **missed none**, blocked **no** benign file, and cleared every terse one-liner. The escalate band on verbose code (13/39 benign files) is a *cost* (one cached LLM call), not a false positive, and it is where tier 2 earns its keep: thin agent narration and a Copilot comment both score 0.31 at tier 1.

## Configuration

| env | default | meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Claude judge. `ARIS_MODEL` overrides `claude-opus-5-5`; `ARIS_TIER2_EFFORT` sets `low`…`max`; `ARIS_TIER2_FALLBACKS=0` turns server-side fallbacks off |
| `OPENAI_BASE_URL` + `OPENAI_MODEL` | — | OpenAI-wire judge. A loopback URL (`http://127.0.0.1:11434/v1` for Ollama) is the **local** leg, first by default; anything else is the **openai** leg. `OPENAI_API_KEY` adds a bearer token (api.openai.com needs it, Ollama does not) |
| `KIMI_API_KEY` | — | Kimi K3 judge (`api.kimi.com/coding`, Anthropic wire; **not** `api.moonshot.ai`) |
| `ARIS_TIER2_ORDER` | `local,anthropic,openai,kimi` | chain order; unconfigured legs are skipped |
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
- **Fail-closed means an adjudicator outage blocks the escalate band** in `--enforce`. That is deliberate for a security tool; `ARIS_FAIL_MODE=alert` is the knob if your risk posture differs. A hosted judge's safety classifier can also decline benign security-flavoured code; fallbacks and the de-fanged retry reduce that, a local judge removes it.
- **Judge quality is measured, not assumed.** The tier-2 suites (`bun run matrix`, `bun run tier2`, `bun run fpRate`) exist to compare judges on the same cells; the 2026-07 numbers were on Kimi K3 and Claude Opus 4.8. Re-run them on whatever chain you deploy.
- **v1 scores every exec.** Busy hosts should scope to sensitive sinks (next) and tune the tier-2 budget.
- Not built yet: sink scoping, session-level kill, a native Windows installer, Go packaging.

## Security

This is a defensive tool. Found a bypass or a bug that could hurt someone running it? See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). Copyright 2026 Aris Tech LLC.
