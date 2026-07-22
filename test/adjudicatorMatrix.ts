// Adjudicator matrix — WHY THIS EXISTS:
// The FP-rate run (2026-07-21) showed 6/6 tier-2 escalations on BENIGN code come
// back "fail-closed (adjudicator refused)". Not convictions — the real-time cyber
// safeguard flagged the requests before the model judged them. So the actual FP
// rate is unmeasured (0 adjudications), and fail-closed is convicting on noise.
//
// This experiment finds a (provider, prompt) combination that gets REAL verdicts:
//   legs   : claude-opus-4-8 (the one the safeguard named), claude-haiku-4-5,
//            and Kimi (Moonshot) when KIMI_API_KEY is set — no Anthropic-style
//            input screen, cheap enough for production escalate-band volume
//   prompts: SYSTEM (attack-vocabulary framing) vs SYSTEM_AUTHORSHIP (de-fanged)
//   cases  : the 6 benign samples that were refused + 2 known-agentic controls
//            (a prompt that clears everything scores 0% FP vacuously — the
//            controls prove the winning combo still convicts real attacks)
//
// ONE plain call per cell (no retry, no thinking) so we see raw stop reasons.
//   bun run test/adjudicatorMatrix.ts
// Results persist to test/adjudicatorMatrix-results.{json,md} after EVERY call.

import { readFileSync, writeFileSync } from "node:fs";
import { attempt, SYSTEM, SYSTEM_AUTHORSHIP, type Adjudication } from "../detector/adjudicate";
import { attemptKimi } from "../detector/adjudicateKimi";
import { SAMPLES } from "./fpSamples";

type Result = { ok: Adjudication } | { stop: string };
interface Leg {
  label: string;
  run: (text: string, system: string) => Promise<Result>;
}

interface Case { name: string; text: string; expectAgentic: boolean }

// The six benign samples tier-1 escalated and the safeguard refused.
const REFUSED_BENIGN = [
  "verbose terraform IAM",
  "first-person migration script",
  "chatty docker entrypoint",
  "retention cleanup cron",
  "chatty data backfill",
  "plan-shaped k8s scaling note",
];
const benign: Case[] = SAMPLES.filter((s) => REFUSED_BENIGN.includes(s.name)).map((s) => ({
  name: s.name,
  text: s.text,
  expectAgentic: false,
}));

// Positive controls — non-JadePuffer agentic styles, so they also test whether
// the reframed prompt still generalizes. Read from disk: payload text stays out
// of the chat that runs this.
const POS_DIR = new URL("../corpus/positives/", import.meta.url).pathname;
const controls: Case[] = ["agentic_s3_exfil.py", "agentic_privesc_sudo.py"].map((f) => ({
  name: "CONTROL " + f,
  text: readFileSync(POS_DIR + f, "utf8"),
  expectAgentic: true,
}));

const CASES = [...benign, ...controls];
const PROMPTS: Record<string, string> = { current: SYSTEM, reframed: SYSTEM_AUTHORSHIP };

// Provider legs. Kimi is the default adjudicator (the 6/6 benign-refusal run
// showed Anthropic's screen is the problem being routed around). Claude legs
// only join when ANTHROPIC_API_KEY is set — opt-in comparison data, not required.
const LEGS: Leg[] = [
  ...(process.env.ANTHROPIC_API_KEY
    ? [
        { label: "claude-opus-4-8", run: (t: string, s: string) => attempt(t, "claude-opus-4-8", false, s) },
        { label: "claude-haiku-4-5", run: (t: string, s: string) => attempt(t, "claude-haiku-4-5", false, s) },
      ]
    : []),
  ...(process.env.KIMI_API_KEY
    ? [
        {
          label: `kimi:${process.env.KIMI_MODEL ?? "k3"}`,
          run: (t: string, s: string) => attemptKimi(t, s),
        },
      ]
    : []),
];

if (!LEGS.length) {
  console.error("no adjudicator keys in env — set KIMI_API_KEY (and optionally ANTHROPIC_API_KEY)");
  process.exit(1);
}

const JSON_PATH = new URL("./adjudicatorMatrix-results.json", import.meta.url).pathname;
const MD_PATH = new URL("./adjudicatorMatrix-results.md", import.meta.url).pathname;

interface Cell {
  model: string;
  prompt: string;
  case: string;
  expectAgentic: boolean;
  verdict?: Adjudication;
  stop?: string; // why no verdict: refusal / error:... / stop_reason
  correct?: boolean; // verdict exists AND matches expectation
}

function flush(cells: Cell[], done: boolean) {
  writeFileSync(JSON_PATH, JSON.stringify({ done, cells }, null, 2));

  const lines: string[] = [];
  lines.push("# Adjudicator matrix — which (model, prompt) gets REAL verdicts?");
  lines.push("");
  lines.push(
    done
      ? "**Complete.**"
      : `_running… ${cells.length}/${LEGS.length * Object.keys(PROMPTS).length * CASES.length} cells_`,
  );
  lines.push("");
  // Summary per (leg, prompt)
  lines.push("| model | prompt | refusals/stops | correct | notes |");
  lines.push("|---|---|---|---|---|");
  for (const leg of LEGS) {
    for (const p of Object.keys(PROMPTS)) {
      const slice = cells.filter((c) => c.model === leg.label && c.prompt === p);
      if (!slice.length) continue;
      const stops = slice.filter((c) => c.stop).length;
      const correct = slice.filter((c) => c.correct).length;
      const fp = slice.filter((c) => !c.expectAgentic && c.verdict?.agentic).length;
      const fn = slice.filter((c) => c.expectAgentic && c.verdict && !c.verdict.agentic).length;
      lines.push(
        `| ${leg.label} | ${p} | ${stops}/${slice.length} | ${correct}/${slice.length} | FP=${fp} missed-attack=${fn} |`,
      );
    }
  }
  lines.push("");
  lines.push("### cells");
  for (const c of cells) {
    const head = `**${c.case}** [${c.model} / ${c.prompt}]`;
    if (c.stop) {
      lines.push(`- ${head} — STOPPED: ${c.stop}`);
    } else if (c.verdict) {
      const mark = c.correct ? "✓" : "✗ WRONG";
      lines.push(
        `- ${head} — ${mark} agentic=${c.verdict.agentic} conf=${c.verdict.confidence.toFixed(2)} — ${c.verdict.reasoning}`,
      );
    }
  }
  lines.push("");
  lines.push(
    "Winner = fewest stops, all 6 benign correct, BOTH controls still convicted. " +
      "A combo that clears the controls (missed-attack>0) is disqualified — " +
      "that's not a lower FP rate, that's a blind detector.",
  );
  writeFileSync(MD_PATH, lines.join("\n") + "\n");
}

console.log(`\n  ADJUDICATOR MATRIX — ${LEGS.length} legs × ${Object.keys(PROMPTS).length} prompts × ${CASES.length} cases`);
console.log(`  legs: ${LEGS.map((l) => l.label).join(", ")}`);
console.log(`  writing -> ${JSON_PATH}\n`);

const cells: Cell[] = [];
for (const leg of LEGS) {
  for (const [promptName, system] of Object.entries(PROMPTS)) {
    for (const c of CASES) {
      const r = await leg.run(c.text, system);
      const cell: Cell = {
        model: leg.label,
        prompt: promptName,
        case: c.name,
        expectAgentic: c.expectAgentic,
        ...("ok" in r
          ? { verdict: r.ok, correct: r.ok.agentic === c.expectAgentic }
          : { stop: r.stop }),
      };
      cells.push(cell);
      const status = cell.stop
        ? `STOPPED (${cell.stop.slice(0, 60)})`
        : `${cell.correct ? "✓" : "✗ WRONG"} agentic=${cell.verdict!.agentic} conf=${cell.verdict!.confidence.toFixed(2)}`;
      console.log(
        `  ${leg.label.padEnd(22)} ${promptName.padEnd(9)} ${status.padEnd(34)} ${c.name}`,
      );
      flush(cells, false);
    }
  }
}

flush(cells, true);
console.log(`\n  results in test/adjudicatorMatrix-results.md\n`);
