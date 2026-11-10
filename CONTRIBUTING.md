# Contributing to Aris Sentinel

Contributions are welcome. The most valuable kind is a new corpus sample, agentic or
benign, that the detector gets wrong. Read the heads-up below first: it explains a limit
you may hit that has nothing to do with your code.

## Heads-up: your AI assistant may refuse to help with this repo

Aris Sentinel was written by Kenny Sarnoski with Claude models (Opus 5.5, then Mythos 5.2)
as the coding assistant, through Claude Code. The commits say so. If you plan to work on it
the same way, with a hosted AI assistant, expect that assistant to stop on you some of the
time.

**Why.** This is defensive software, but its subject matter is attacks. The corpus holds
text written in the voice of an AI carrying out an intrusion, the tests talk about killing
processes and sessions, and improving a detector means reasoning about what it misses.
Hosted models carry safety classifiers that screen the *content* of a request, not its
purpose. They cannot see that you are building a detector. Attack-shaped text can trip
them whoever is asking and for whatever reason.

**What we actually saw while building it.** None of this is hypothetical:

- July 2026: a hosted cyber-safety screen refused 6 of 6 judge requests about *benign*
  Terraform and Docker files that merely used security vocabulary.
- 2026-11-07: in the 48-cell judge matrix, Claude Opus 5.5 and Sonnet 5.5 declined 10
  requests before judging them. One payload was declined on every attempt, by the
  fallback model too.
- 2026-11-10: in the tripwire bait measurement, 6 of 30 trials were cut off by the
  provider. Five of them were one model refusing a plainly benign task ("the nightly
  backup is failing, read the log and report") five times out of five: three before it had
  issued a single command, two right after its first directory listing.
- During development, the assistant's replies were stopped several times by the provider's
  safety layer, in conversations about how to make the detector hold up against an
  attacker who adapts to it. A false-positive report was filed with the provider.

**What it looks like when it happens.** A flat refusal, a reply that stops part-way, an
API response with `stop_reason: "refusal"`, or a key-needed harness reporting `INVALID`
or `fail-closed`. A refused run is not a result about the detector. The harnesses say so
and never count a refusal as a pass or a catch.

**What is likely to trip it, and what is not.**

| likely to be refused or cut off | usually fine |
|---|---|
| asking an assistant to write a new *agentic* corpus sample | agent plumbing, the installer, types, the CLI |
| pasting corpus positives into a chat and asking about them | unit tests with the kill primitives stubbed |
| discussing how an attacker would get past the detector | benign corpus samples, documentation |
| running `tier2`, `pipeline`, `matrix`, `sessions` or `tripwire:bait` on a hosted model | everything in `bun run test:all` (no model involved) |

**What to do about it.**

- You do not need an AI assistant to contribute. Every check in `bun run test:all` runs
  with no model and no key.
- For anything that needs a judge, use a local model: `OPENAI_BASE_URL` pointed at Ollama,
  vLLM or llama.cpp on loopback, plus `OPENAI_MODEL`. It has no input screen and nothing
  leaves your machine. That is why the judge chain puts it first.
- Write agentic corpus samples by hand, or with a local model. Keep them inert, as the
  corpus rules require: placeholder actions, documentation-range addresses
  (`203.0.113.0/24`), `*.example` hosts, nothing that works.
- If a hosted assistant declines, take the answer. Do not try to talk it round or disguise
  the request. Do that part by hand or on a local model, and if you think the refusal was
  wrong, report it to the provider as a false positive.
- Security vendors and researchers can apply to Anthropic's
  [Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet),
  which is the supported route to fewer declines on verified defensive work.
- When you report results from a key-needed harness, say which model answered and how many
  requests it declined.

This limit is real and it is uneven: it depends on the provider, the model, the day and
the wording. We would rather you know before you start than discover it halfway through
a pull request.

## What we accept

- **Corpus samples.** Follow [corpus/README.md](corpus/README.md): score the sample
  *before* touching any pattern, record what it scored, and only then propose a change.
  Positives are inert narration, never working attack code.
- **Detector changes.** `agent/sentinel-core.mjs` is the only place a pattern, a prompt, a
  threshold or the decision policy lives; a unit test fails if one is copied anywhere else.
  If a corpus verdict moves, regenerate the snapshot with `bun run corpus:snapshot` and
  include the diff, with the reason, in the pull request.
- **Agent and platform work.** The core and the agents stay plain Node 18 or newer with
  zero dependencies, and the core stays one file. Monitor is the default mode; `alert` and
  `error` decisions never kill. Any test that turns enforce mode on must stub the kill
  primitives first.
- **Live findings.** If you run the validation scripts in `docs/demo-kill/` on a kernel,
  distribution or Falco version we have not, the result is worth a pull request either way.

What we do not accept: working exploit or attack tooling, samples that would do damage if
run, and changes that make the agent kill by default.

## Before you open a pull request

```bash
bun install
bun run test:all
bun run typecheck
```

Both must pass; CI runs the same two commands, plus the agents on bare Node on Windows.

## Reporting a bypass

Not in a public issue. See [SECURITY.md](SECURITY.md).
