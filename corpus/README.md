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

### 2026-07 — original 32 files

Tier 1: precision 1.00 / recall 1.00 on 7 positives, all JadePuffer-derived or close. The
2026-11 set exists because that number was a smoke test, not evidence.
