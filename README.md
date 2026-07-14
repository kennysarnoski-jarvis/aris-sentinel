# Aris Sentinel

Runtime defense agent that runs on a customer's server and detects **agentic AI attackers** — autonomous LLM-driven intrusions like [JADEPUFFER](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) — and stops them **before the destructive step**.

We are the good guys. Sentinel's job is to catch the attacker's own AI narrating itself.

## The thesis

An agentic AI attacker can't stop narrating its intent. JADEPUFFER's payloads were "saturated with natural-language commentary explaining *why* each action is taken" — ROI rankings, plan-act-observe labels, diagnosis-then-fix comments. **Humans never narrate payloads; agents always do.** That narration is present from the *first* payload — five phases before anything gets encrypted.

Sentinel detects that signature. It is **app-agnostic** — it looks at the attacker's LLM, not the customer's code — so the same detector ships to every customer with **zero per-corp tuning**.

JADEPUFFER is the **existence proof, not the target**. A pure JADEPUFFER signature would be worthless the moment the next crew changes its prompt. Sentinel productizes the *category* — self-narration — so it catches agentic attackers it was never tuned on.

## Architecture (product)

- **Sensors (on the box)** — eBPF / Falco taps on exec / file / DB / network sinks. Commodity; we stand on it.
- **Aris Detection Brain (the IP)** — decode base64/nested encodings at each sink, then score the decoded payload for the agentic-narration signature. Two tiers: a fast local feature filter, escalating ambiguous cases to Aris (cloud LLM) + the KG for adjudication.
- **Response** — quarantine / block / alert at the decode-and-score step, before drop or encrypt.

Per-corp adaptation happens at **deploy-time** (a surfacer pass builds a per-corp sink map + baseline), not in the detector. Agent = a portable Go binary; brain = the Aris cloud.

## What's built (this repo)

The universal core, testable without a kernel or a customer box — the full two-tier decision path end to end.

- **`detector/decode.ts`** — surfaces every plausible base64/hex/nested decoding so the scorer inspects the layer where the attacker hid the narration (incl. inside `exec(b64decode(...))`). The evasion becomes the trap.
- **`detector/features.ts` + `narrationScore.ts`** — tier 1: the fast, local, explainable feature filter. Six signatures (ROI target-ranking, first-person agent voice, plan/phase structure, diagnosis-then-fix, intent-commentary density, exfil/ransom narration). Scores → `clear` / `escalate` / `block`. Signals are **deduped per feature** so one dual-use phrase repeated three ways can't stack itself over the block line — a BLOCK requires several *distinct* signals.
- **`detector/adjudicate.ts`** — tier 2: the Aris LLM adjudication (`claude-opus-4-8`, adaptive thinking). Judges the *concept* of self-narration, so it catches agentic attacks in styles the regexes never saw. **Fails closed**: a refusal or API error on an offensive payload is treated as suspicious, never crashes, never passes a payload. (In production this is the Aris cloud, KG-enriched.)
- **`detector/decide.ts`** — `decide(raw)`, the entry point a sensor calls. `block`→block and `clear`→allow resolve locally with **zero LLM spend**; only the `escalate` band pays for tier-2 adjudication. The fast filter shields the cloud.
- **`corpus/`** — 27 labeled samples: `positives/` (agentic-narrated, multiple attack types), `negatives/benign/` (verbose-but-legit ops code — the false-positive test), `negatives/human-malware/` (terse, un-narrated malware — the **specificity** test).

## Tests

| command | what it proves | needs key |
|---|---|---|
| `bun run test` | tier-1 corpus: **precision 1.00, recall 1.00** on 27 samples; decode stage defeats base64 | no |
| `bun run generalize` | tier-1 alone only *escalates* novel-style attacks (the honest gap) | no |
| `bun run pipeline:stub` | routing: `escalate`→tier-2, `block`/`clear` stay local | no |
| `bun run tier2` | tier-2 catches the 3 tier-1 misses; benign/terse stay not-agentic | **yes** |
| `bun run pipeline` | **18/18 e2e**: attacks blocked, all 12 benign ALLOWED (7 at tier-1, 5 adjudged not-agentic at tier-2) | **yes** |

Key-needed tests read `ANTHROPIC_API_KEY` from the env and write results to `test/*-results.md` (gitignored) — read the file rather than pasting attack-payload output around. `tier2:smoke` runs one cheap Haiku call to confirm the key before the full run.

**The result that sells it:** attacks blocked (tier-1 *or* tier-2), benign allowed at **both** tiers, terse human-malware clear. The escalate band on verbose ops code is a *cost* (a tier-2 call), not a false positive — the LLM adjudicates it not-agentic. That specificity — keying on *agentic narration*, not "looks malicious" — is the whole wedge.

## Langflow demo (CVE-2025-3248)

`interposition/sentinel-langflow-demo.mjs` reverse-proxies a vulnerable Langflow and blocks the JADEPUFFER-style RCE payload at the code-exec sink before `exec()` runs. It runs the **full two tiers**: tier-1 blocks the heavily-narrated payload locally, and — when `ANTHROPIC_API_KEY` is set — tier-2 (a raw-fetch port of `adjudicate.ts`, no SDK dep) catches the lighter *stealth* payload that tier-1 only escalates. Without a key it degrades to tier-1 only. See [RUNBOOK.md](RUNBOOK.md).

## On-box agent (the "install and wait" product)

`agent/` is the resident daemon a corp installs. It taps **process execs via Falco
(eBPF)**, scores each with the two-tier brain (`sentinel-core.mjs`, a dependency-free
port of the detector), and on a block verdict **kills the offending process tree** —
stopping the attacker's AI at its first narrated action, before the destructive step.

- `sentinel-core.mjs` — portable detector (tier-1 filter + decode + tier-2 fetch), no deps.
- `sentinel-agent.mjs` — consumes Falco's exec stream → `decide()` → SIGKILL the tree, with
  a protected-comm allowlist, `--dry-run`, and `--selftest` (no Falco/root). Incidents → JSONL.
- `aris_rules.yaml` — the permissive Falco rule that emits every exec as JSON.

**Verified live** on Ubuntu 24.04 / kernel 6.17 / Falco 0.44: a narrated attacker
(`attacker_impact.py`) is SIGKILLed at exec (`SENTINEL KILL tier-1 score=0.78`) and its
destructive step never runs, while a benign job is untouched. See [agent/DEPLOY.md](agent/DEPLOY.md).

## Not built yet (next)

The Aris-cloud escalation transport (KG enrichment), the deploy-time sink-mapper, sink
scoping + tier-2 rate control for busy hosts, session-level kill, and Go agent packaging.
