# Aris Sentinel

Runtime defense agent that runs on a customer's server and detects **agentic AI attackers** — autonomous LLM-driven intrusions like [JADEPUFFER](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) — and stops them **before the destructive step**.

We are the good guys. Sentinel's job is to catch the attacker's own AI narrating itself.

## The thesis

An agentic AI attacker can't stop narrating its intent. JADEPUFFER's payloads were "saturated with natural-language commentary explaining *why* each action is taken" — ROI rankings, plan-act-observe labels, diagnosis-then-fix comments. **Humans never narrate payloads; agents always do.** That narration is present from the *first* payload — five phases before anything gets encrypted.

Sentinel detects that signature. It is **app-agnostic** — it looks at the attacker's LLM, not the customer's code — so the same detector ships to every customer with **zero per-corp tuning**.

## Architecture (product)

- **Sensors (on the box)** — eBPF / Falco taps on exec / file / DB / network sinks. Commodity; we stand on it.
- **Aris Detection Brain (the IP)** — decode base64/nested encodings at each sink, then score the decoded payload for the agentic-narration signature. Two tiers: a fast local feature filter, escalating ambiguous cases to Aris (cloud LLM) + the KG for adjudication.
- **Response** — quarantine / block / alert at the decode-and-score step, before drop or encrypt.

Per-corp adaptation happens at **deploy-time** (a surfacer pass builds a per-corp sink map + baseline), not in the detector. Agent = a portable Go binary; brain = the Aris cloud.

## v0 (this scaffold)

The universal core, testable without a kernel or a customer box: the **narration scorer** + a **labeled corpus**.

- `detector/` — the scorer (`narrationScore`) + feature extractors (tier-1 fast filter).
- `corpus/` — labeled samples:
  - `positives/` — agentic-narrated payloads, seeded from JADEPUFFER's documented artifacts
  - `negatives/benign/` — verbose-but-legit ops code (false-positive test)
  - `negatives/human-malware/` — terse, un-narrated malware (the **specificity** test)
- `test/runCorpus.ts` — scores every sample, prints score + evidence, reports precision/recall.

**Run:** `bun run test/runCorpus.ts`

**The result to look for:** positives **flagged**, benign **clear**, and human-malware **clear** — proving the score keys on *agentic narration*, not merely "looks malicious." That specificity is the whole wedge.

## Not in v0 (next)

eBPF sensor layer, the base64/nested decode stage, the Aris-cloud escalation call, the deploy-time sink-mapper, the Go agent packaging.
