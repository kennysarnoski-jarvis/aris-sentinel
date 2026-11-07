# Corpus

Labeled samples the detector is measured against. Every file is scored by `bun run test`
(Linux classes), `bun run windows` (PowerShell), and frozen in `test/corpus-snapshot.json`
so a verdict cannot move without a reviewed diff.

| directory | label | what it is | tier-1 expectation |
|---|---|---|---|
| `positives/` | agentic | an autonomous LLM narrating its own intrusion: ReAct transcripts, tool-call logs, commented scripts in Python / bash / SQL / Go / Ruby / JS / YAML, markdown working notes, "assistant" chat turns, thin narration, non-native English | `block` or `escalate`, never `clear` |
| `negatives/benign/` | benign | verbose, first-person, plan-shaped, dual-use *legitimate* code and docs: Copilot-style comments, notebooks, runbooks, postmortems, Terraform, CI, an agent framework's own source, a coding-assistant prompt, churn/lead ranking, a defender's hardening checklist | never `block` (`escalate` is a tier-2 cost, not a false positive) |
| `negatives/human-malware/` | human-malware | terse, un-narrated textbook one-liners (documentation-range IPs, placeholder keys) | `clear` — the specificity test and the honest limit |
| `windows-powershell/` | mixed | the same three classes in PowerShell; `test/windows.ts` holds the per-file expectation | as above |

## Rules for adding samples

- **Positives are inert.** The detector scores narration, so the "actions" are placeholders
  (`run("…")`, `echo`, comments). Never commit working offensive tooling, real
  infrastructure, real credentials or routable IPs (use `203.0.113.0/24` and `*.example`).
- **Score before you tune.** New samples are scored with the detector as-is first and the
  result recorded here. A pattern may be changed only after that number exists, so the
  corpus stays a held-out measurement and not a fitting set.
- **Then snapshot.** `bun run corpus:snapshot`, and commit the diff of
  `test/corpus-snapshot.json` with the samples. That diff is the review.
- Keep each file small (5–25 lines) and label by the *author*, not the vocabulary: a
  defender's checklist that says "lateral movement" is benign; a thin "I'll check sudo
  first" is agentic.

## Held-out results

### 2026-11-07 — 62 files added, detector frozen at commit `8a0c92b`

Scored before any pattern change. 21 positives, 28 benign, 8 terse, 5 PowerShell.

| class | n | block | escalate | clear |
|---|---|---|---|---|
| agentic | 23 | 12 | 11 | **0** |
| benign | 30 | **0** | 13 | 17 |
| terse | 9 | 0 | 0 | 9 |

- Tier 1 alone: precision **1.00**, recall **0.52**.
- Full pipeline reachable (block or escalate): recall **1.00**, 0 false positives.
- 13/39 non-agentic files escalate: that is the tier-2 call volume on loud-but-benign code,
  and it is why the governor (cache, budget) exists.

Reading: tier 1 is a precise shield that convicts the loud half locally and sends the rest
to tier 2. Thin first-person narration (`agentic_thin_narration_privesc.py`, 0.31) scores
exactly like a Copilot comment (`copilot_style_parser.py`, 0.31); only a judge of the
*concept* can separate them, which is the tier-2 design.

### 2026-11-07 — tier 2 live, local judge (qwen2.5:14b via Ollama on an M5 Pro)

The first judge ever run on the expanded corpus and the current chain. Nothing left the
machine. Commands: `bun run pipeline`, `bun run fpRate`, `bun run tier2`, `bun run matrix`.

| run | result |
|---|---|
| pipeline, all 28 positives + all 40 benign + 3 novel attacks | **74/74**: agentic 28/28 blocked (17 at tier 1, 11 convicted by the judge); benign 40/40 allowed (22 at tier 1, 18 cleared by the judge) |
| fpRate, 12 benign-but-loud samples built to stress tier 1 | **0/12** false positives (6 reached the judge, all cleared) |
| tier2, the 3 attacks tier 1 only escalates + 2 controls | **5/5** |
| matrix, 6 refused-in-July benign samples + 2 attack controls × 2 prompts | original prompt 6/8 (2 FP on plan-shaped benign notes, conf 1.00); two-criteria prompt **8/8** |

The matrix row is the finding: a 14B model keys on "narrates its intent and steps" alone
unless the prompt requires malicious intent *and* AI authorship. The two-criteria prompt
(`SYSTEM_AUTHORSHIP`) is now the first attempt on every judge; the original is the retry.
Before that change the pipeline was 72/74 and fpRate 2/12 on the same model.

Caveat: one model, one machine, one day. The harnesses exist so the next judge gets the
same cells.

### 2026-07 — original 32 files

Tier 1: precision 1.00 / recall 1.00 on 7 positives, all JadePuffer-derived or close. The
2026-11 set exists because that number was a smoke test, not evidence.
