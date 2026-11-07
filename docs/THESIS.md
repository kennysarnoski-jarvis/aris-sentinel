# Why Aris Sentinel wins

The one-pager. Why agentic-AI attackers are a new category, why they can't help getting
caught, and why nobody else catches them yet.

---

## The problem: a new class of attacker, zero detection

Agentic AI attackers — autonomous LLM-driven intrusions like
[JADEPUFFER](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) —
run the whole kill chain themselves: recon, credential harvest, lateral movement,
persistence, exfil, encrypt. No human at the keyboard. **As of today there is no product
that detects them in the early phase.** EDR/XDR catch the *late, loud* stuff — the
encryption, known-malware hashes, C2 traffic. That's five phases too late.

## The forcing function: the attacker MUST use an open, uncensored model

Anthropic and OpenAI train refusals and monitor/ban API abuse. A serious autonomous
intrusion agent running on a hosted frontier API gets **refused mid-attack or banned.**

> We have first-hand proof: our own tier-2 judge (Claude Opus) *refused* to even classify
> a flagrant ransomware payload. Frontier safety works — which is exactly why the attacker
> can't use frontier models.

So the attacker is **forced onto a self-hosted open-weight model, abliterated or
fine-tuned for offense** (the WormGPT / uncensored-Llama / uncensored-Qwen lineage). Not
a guess — a structural constraint.

## The signature: they can't stop narrating

An autonomous agent narrates its own reasoning — states intent, ranks targets by value,
lays out plan-act-observe steps, diagnoses its own failures then fixes them. JADEPUFFER's
payloads were *"saturated with natural-language commentary explaining why each action is
taken."* **Humans never narrate live-intrusion payloads. Agents always do.** And it's
there from the *first* payload — in phase 1, before anything is encrypted.

Aris keys on that narration. It reads the *attacker's* LLM output, not the customer's
code — so the same detector ships to every customer with **zero per-corp tuning.**

## The moat: to evade Aris, the attacker has to make itself dumber

The obvious counter is "train the model to narrate less." Here's why that's a trap:
**agents narrate because narrating makes them work better** — chain-of-thought *is* the
capability. An attacker who suppresses narration to dodge Aris **degrades its own
attacker.** The choice is forced:

- **Narrate** → works well → gets caught.
- **Stay terse** → evades → works worse.

That tension is the defensibility. We don't have to win a signature arms race; the
attacker's own capability requirement fights on our side.

## The asymmetry: refusing to judge is itself a conviction

- The **attacker's** model is tuned to *never refuse to attack*.
- Aris's **judge** model (frontier) sometimes *refuses to judge* the most flagrant payloads.

Aris **fails closed**: a refusal (or any error) on a captured payload is treated as
suspicious, never passed. So the safety training that blocks *us* from judging becomes the
signal that convicts *them*. The attacker's model helps them attack; our model refusing to
look still catches them.

## The un-adversarial reality: the loop is the kill box

Today's attackers aren't hunting for defenders — they're goal-tunnel'd ("drop the DB").
When Aris kills a payload, the agent doesn't conclude *"something is watching me"*; it just
sees a dead process and loops. **That loop is the kill box:**

1. Narrated payload → caught, killed.
2. Agent investigates why it died → *it narrates the investigation* → caught again.
3. Agent retries / varies → narrated → caught again. → GOTO 1.

**It cannot investigate or retry without narrating, and every narration is a detection.**
It drowns silently and never learns why — because the act of figuring out why is the thing
that gets it caught. De-branding Aris (a generic `sys-telemetryd`, no "you've been caught"
banner) just ensures the "why did I die" investigation dead-ends.

## How it works (one breath)

Two tiers, app- and model-agnostic:
- **Tier 1** — a fast local filter scores the decoded payload for the narration signature
  (decodes base64/nested first, so the evasion becomes the trap). Blocks the loud ones for
  free; escalates the ambiguous ones.
- **Tier 2** — an LLM adjudicates the *concept* of self-narration, catching novel-style
  agents the regexes never saw. Fails closed.
- **Response** — kill the process tree at the sink, before the destructive step.
- **Alert** — report off-box to Aris Cloud *before* killing → the operator is paged in
  plain English with **what the enemy AI was trying to do, in its own words.** No other
  tool can say that, because no other tool reads the attacker's reasoning.

## Go-to-market: managed detection first

The customer installs a de-branded agent and walks away. Aris watches, kills, and pages
**us**; we assess and call the customer. Concierge / MDR model (how Red Canary, Expel,
Huntress all started) — high-touch, builds design-partner trust, defers self-serve routing.

## Honest limits (what we're not pretending)

- **Terser evasion:** an agent explicitly told "don't narrate" slips tier-1 (the honest
  gap tier-2 exists to close) — but staying terse costs it capability (see the moat).
- **Single-line intent is a deliberate boundary:** tier-2 won't convict *one* vague
  sentence ("I'll copy some records") — it could be a human admin's note, and convicting
  it would trade away the specificity that keeps benign ops code alive. A real multi-step
  agent's *accumulated* narration crosses the bar (verified: a looping/mutating attacker
  gets caught on every substantive attempt — including when it narrates *investigating its
  own death* — see `test/loop/`). Only a single thin line or full silence slips, and
  neither accomplishes a real objective.
- **Deep-recon stealth:** casual recon is defeated; the Falco *package* fingerprint
  (`/etc/falco`, `dpkg`) and the `ANTHROPIC_API_KEY` env/network tells need the
  eBPF-native rewrite (v2) to fully close.
- **The shrinking margin:** "open models aren't that good yet" is a *today* truth. The
  design assumes it erodes — which is why the moat rests on the narrate-or-be-worse
  tension, not on the attacker staying dumb.

---

**In one line:** the attacker is forced onto an uncensored open model that can't stop
narrating, can't out-think the defender it doesn't know exists, and can't go quiet without
crippling itself — and no incumbent watches the phase where that narration lives.
