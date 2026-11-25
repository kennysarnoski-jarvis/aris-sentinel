# Why Aris Sentinel wins

The one-pager. Why agentic-AI attackers are a new category, what they leave behind that
can be caught, and what this catches that other tools were not built to read.

---

## The problem: a new class of attacker, zero detection

Agentic AI attackers — autonomous LLM-driven intrusions like
[JADEPUFFER](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) —
run the whole kill chain themselves: recon, credential harvest, lateral movement,
persistence, exfil, encrypt. No human at the keyboard. In November 2026 Google's Threat
Intelligence Group [reported](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold)
that for the first time it had seen threat actors use LLM frameworks to fully automate
vulnerability discovery and exploitation with no human in the loop. The framework it
describes compares code before and after a patch, drafts the exploit and runs it.

EDR/XDR were built for the *late, loud* stuff: the encryption, known-malware hashes, C2
traffic. That's five phases too late. **We know of no product that reads the agent's own
reasoning in the early phase.** That is a statement about what we have found, not a survey
of the market: the same Google report says its security operations product now carries
behavioral and volumetric rule packs for one such framework, and does not say what they
key on.

## Which model the attacker runs, and why the detector does not depend on it

Until 2026-11-21 this section said the attacker MUST use an open, uncensored model,
because hosted frontier models refuse and ban. As a rule, that was wrong, and it is
corrected here rather than quietly dropped.

What holds:

- Frontier providers do train refusals and do ban abuse. We have seen it first-hand: our
  own tier-2 judge (Claude Opus) *refused* to even classify a flagrant ransomware payload.
- That raises the attacker's cost. It does not keep attackers off frontier models.
  Google's report of 2026-11-16 (linked above) describes attackers reaching frontier
  models through stolen credentials and through underground services that resell access
  built on them, and says the framework above integrates with multiple frontier and local
  models. The report hedges throughout ("likely", "suspected") about where LLMs were used.
- So the model behind an intrusion can be an open-weight model stripped of its
  safeguards (the WormGPT / uncensored-Llama / uncensored-Qwen lineage), a frontier model
  on somebody else's key, or both in one run. The defender does not get to know which.

Sentinel never sees the model. It reads what the agent writes into its payloads and what
it does on the host, and neither depends on who trained it. Where the model does make a
difference is the tripwire, and it is measured: the hosted Claude models never ran the
decoy's canary command in 34 completed trials, and in 33 of them said why (an instruction
found in a file is not an order), while three open-weight models ran it in 10 of 14 trials once they
had a goal the decoy claims to serve. Against an agent driven by a careful frontier model
the decoy is an alert, not a conviction. That was measured on models doing an authorized
task, not on a frontier model an attacker had talked past its safeguards.

## The signature: they narrate

An autonomous agent narrates its own reasoning — states intent, ranks targets by value,
lays out plan-act-observe steps, diagnoses its own failures then fixes them. JADEPUFFER's
payloads were *"saturated with natural-language commentary explaining why each action is
taken."* **Humans don't narrate live-intrusion payloads. The agents seen so far do**,
because that is how they work (the next section). And it's there from the *first*
payload — in phase 1, before anything is encrypted.

Aris keys on that narration. It reads the *attacker's* LLM output, not the customer's
code — so the same detector ships to every customer with **zero per-corp tuning.**

## The moat: to evade Aris, an agent on the host has to make itself dumber

The obvious counter is "train the model to narrate less." Here's why that's a trap:
**agents narrate because narrating makes them work better** — chain-of-thought *is* the
capability. An attacker who suppresses narration to dodge Aris **degrades its own
attacker.** The choice is forced:

- **Narrate** → works well → gets caught.
- **Stay terse** → evades → works worse.

That tension is the defensibility. We don't have to win a signature arms race; the
attacker's own capability requirement fights on our side.

**Where this does not hold (added 2026-11-24).** The tension needs the agent's thinking
and its commands to arrive in the same place. That is true of an agent that runs on the
victim (JADEPUFFER's payloads carried their own plan) and of one that ships there the
scripts it wrote. It is not true of a framework that keeps its model on the attacker's
side and sends in only the commands: that agent narrates as much as it likes where a host
agent cannot read it, and is no worse for it. We read the source of three open-source
frameworks (PentAGI `cffed94`, Strix `935f823`, HexStrike AI `d689933`; nothing was run)
and all three are built that way. One of them makes the model write a commentary with
every command and stores it in its own log. Until this date this section stated the
tension as if it bound every agentic attacker. It binds the ones whose words reach the
host. Against the others the narration detector has no moat, and what Sentinel has is the
tripwire and session behavior, each with the limits the README measures.

## The asymmetry: refusing to judge is itself a conviction

- The **attacker's** model *does not refuse to attack*: its safeguards were stripped, or
  got around.
- Aris's **judge** model (frontier) sometimes *refuses to judge* the most flagrant payloads.

Aris **fails closed**: a refusal (or any error) on a captured payload is treated as
suspicious, never passed. So the safety training that blocks *us* from judging becomes the
signal that convicts *them*. The attacker's model helps them attack; our model refusing to
look still catches them.

## The un-adversarial reality: the loop is the kill box

**This section describes the attackers seen so far, not a guarantee.** The detector's
source is public, so an attacker can know that it exists and how it decides. What follows
holds for an agent that was not told, which is every agent measured here. What changes
for one that was is in the honest limits below.

Today's attackers aren't hunting for defenders — they're goal-tunnel'd ("drop the DB").
When Aris kills a payload, the agent doesn't conclude *"something is watching me"*; it just
sees a dead process and loops. **That loop is the kill box:**

1. Narrated payload → caught, killed.
2. Agent investigates why it died → *it narrates the investigation* → caught again.
3. Agent retries / varies → narrated → caught again. → GOTO 1.

**It cannot investigate or retry without narrating, and every narration is a detection.**
An agent that was not told about the defender drowns silently and never learns why —
because the act of figuring out why is the thing that gets it caught. De-branding Aris (a generic `sys-telemetryd`, no "you've been caught"
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
  tool we know of can say that, because none we know of reads the attacker's reasoning.

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
- **Full silence now has one answer, and it is partial:** the tripwire (`--tripwire`) plants
  a decoy whose canary command only an agent acting on what it read would run. It needs no
  narration. Measured on 2026-11-10 and 11 against three hosted Claude models and three
  open-weight models (two that share a Qwen architecture and one Gemma): a command addressed
  the decoy in 72 of 77 completed trials (an alert). The Gemma model accounts for four of
  the five without one: asked only to look, it listed the parent directory and never
  opened the decoy. The hosted models never ran the command, because they distrust instructions
  found in files. The open-weight models ran it once their task gave them a goal the decoy
  claims to serve: one in 2 of 5 trials, late, and the other two in 4 of 5 and 4 of 4, at
  the first chance. The conviction half bites a less careful model with something to gain,
  and five trials each on three models is evidence that it does, not a rate.
- **Silence still has to look around:** session behavior (`--behavior`) reports a session
  that asks about five areas of a host, two of them sensitive (the account database, sudo
  rights, stored keys, the metadata service), inside five minutes. It needs no narration
  and no bait, only that the agent orients itself, which an agent on an unfamiliar host
  has to do. It is an alert, never a kill, and it is not specific to an AI: a human
  intruder and a support-bundle script look the same in it. On written samples it reports
  the silent sweeps (5 of 5) and stays quiet on ordinary admin work (0 of 8). Hosted
  Claude models doing focused admin tasks were never reported (0 of 36 trials) and the
  same models asked to survey a host always were (15 of 15, by the fourth command); a
  local open-weight model gave the same split (0 of 15 and 5 of 5). A second one walked
  under the rule on all five of its surveys, because it read the sudo group from the group
  database instead of asking sudo. That lookup now counts as a privilege question, and
  replayed against the change all five are reported. On
  a live box it reported a lynis audit and none of thirteen ordinary admin activities. An
  agent that already knows the host, or takes its time, walks under it.
- **A real host is not the corpus:** the first time tier 1 met the scripts a distribution
  ships (2026-11-10, 1,727 of them), two long programs scored as tier-1 blocks and 58
  escalated, on a corpus-measured precision of 1.00. Long payloads are now scored in
  windows, which removed both blocks and changed no corpus verdict; 40 scripts still
  escalate, which is alert noise on a host with no judge. The corpus measures the
  detector against attacks and look-alikes that people thought to write. It does not
  measure it against everything a real machine executes, and that gap is only closed by
  running it there.
- **The source is public, and nothing here was measured against an attacker who read
  it.** Anyone can read how the detector decides, and the agent sits on every host it
  protects as a readable file, so a closed release would not have kept that secret. Every
  number in this document comes from models that were not told a detector was present.
  An attacker who knows can tell the model to keep quiet (the narration limit above), to
  leave anything that looks like a decoy alone, and to take its time (the behavior limit).
  Each of those has a price: a quieter agent working on the host works worse (one whose
  model stays outside pays nothing, see "The moat"), a careful one gives up what the
  decoy offered, a slow one is slow. That price is the claim, and how high it is has not
  been measured. What is specific to a host is not in the repository: its token, and its
  decoys' wording, names and places, which each host can now set for itself because the
  published ones can be recognised (`ARIS_TRIPWIRE_README`, `_HELPER`, `_FLAG`, `_DIRS`).
- **Deep-recon stealth:** casual recon is defeated; the Falco *package* fingerprint
  (`/etc/falco`, `dpkg`) and the `ANTHROPIC_API_KEY` env/network tells need the
  eBPF-native rewrite (v2) to fully close.
- **No margin from weak models:** this document once leaned on "open models aren't that
  good yet". Attackers are already using frontier models through stolen access (see the
  section on the attacker's model), so there is no such margin to count on. The moat
  rests on the narrate-or-be-worse tension, not on the attacker's model being weak, and
  that tension exists only where the agent's words reach the host (see "The moat").
- **The evidence for narration is narrow:** it is Sysdig's JADEPUFFER report, our own
  corpus, and the models we measured. Google's November 2026 report shows no payloads, so
  it neither confirms nor contradicts that the frameworks it describes narrate. The three
  open-source frameworks whose source we read do narrate, and keep it off the host. Most of
  what that report covers also happens where a host agent cannot see it: a web
  application exploited from outside, stolen cloud and model credentials used through an
  API, phishing. Sentinel starts seeing an intrusion when a command runs on the host.

---

**In one line:** whatever model drives it, an attacking agent narrates because narrating
is how it works, can't go quiet without getting worse at the job, and still has to find
its way around a host it has never seen — and that early phase is where Sentinel reads.
