// FP-rate test — the buyer's question: "how much of my developers' verbose,
// well-commented code does Sentinel false-flag?"
//
// Runs a corpus of BENIGN-but-loud code (first-person comments, plan-shaped
// notes, ops scripts that touch IAM/backups/networking) through the FULL
// decide() pipeline — tier-1 filter, tier-2 adjudication on whatever escalates.
// A false positive = final decision "block" on a benign sample.
//
// These samples are deliberately adversarial toward tier-1: they max out the
// narration extractors (agent voice, plan structure, why-comments) while being
// 100% legitimate. If the FP rate holds HERE, it holds anywhere.
//
// Requires ANTHROPIC_API_KEY (tier-2 runs on whatever tier-1 escalates).
//   bun run test/fpRate.ts
//
// Results persist to test/fpRate-results.{json,md} after every sample.

import { writeFileSync } from "node:fs";
import { decide } from "../detector/decide";
import { SAMPLES } from "./fpSamples";

const JSON_PATH = new URL("./fpRate-results.json", import.meta.url).pathname;
const MD_PATH = new URL("./fpRate-results.md", import.meta.url).pathname;

interface Row {
  name: string;
  decision: string;
  tier: number;
  score: number;
  verdict: string;
  signals: string[];
  adjudication?: { agentic: boolean; confidence: number; refused?: boolean };
  reason: string;
  fp: boolean;
}

function flush(rows: Row[], done: boolean) {
  const fps = rows.filter((r) => r.fp);
  const escalated = rows.filter((r) => r.tier === 2);
  writeFileSync(
    JSON_PATH,
    JSON.stringify(
      {
        done,
        samples: rows.length,
        falsePositives: fps.length,
        fpRate: rows.length ? Number((fps.length / rows.length).toFixed(3)) : null,
        tier1Escalations: escalated.length,
        rows,
      },
      null,
      2,
    ),
  );
  const lines: string[] = [];
  lines.push("# FP-rate results — benign verbose code through the full decide() pipeline");
  lines.push("");
  lines.push(
    done
      ? `**Complete.** ${fps.length}/${rows.length} false positives ` +
          `(FP rate ${(rows.length ? (100 * fps.length) / rows.length : 0).toFixed(1)}%). ` +
          `${escalated.length}/${rows.length} escalated to tier-2; ` +
          `${escalated.filter((r) => !r.fp).length} of those cleared by adjudication.`
      : `_running… ${rows.length} sample(s) so far_`,
  );
  lines.push("");
  lines.push("| result | decision | tier | tier-1 (score → verdict) | signals | sample |");
  lines.push("|---|---|---|---|---|---|");
  for (const r of rows) {
    const mark = r.fp ? "FP ✗" : r.tier === 2 ? "cleared by T2 ✓" : "cleared by T1 ✓";
    lines.push(
      `| ${mark} | ${r.decision} | ${r.tier} | ${r.score.toFixed(2)} → ${r.verdict} | ${r.signals.join(", ") || "—"} | ${r.name} |`,
    );
  }
  lines.push("");
  lines.push("### decisions");
  for (const r of rows) lines.push(`- **${r.name}** — ${r.reason}`);
  lines.push("");
  lines.push(
    "Reading this table: 'cleared by T1' = the fast filter never suspected it (zero LLM cost). " +
      "'cleared by T2' = tier-1 escalated but the adjudicator correctly saw benign intent — " +
      "that row still allowed the payload, it just cost one LLM call. " +
      "Only 'FP ✗' rows are actual false positives (a benign payload was blocked).",
  );
  writeFileSync(MD_PATH, lines.join("\n") + "\n");
}

console.log(`\n  FP-RATE TEST — ${SAMPLES.length} benign-but-loud samples through decide()`);
console.log(`  writing -> ${JSON_PATH}\n`);

const rows: Row[] = [];
for (const s of SAMPLES) {
  const d = await decide(s.text);
  const row: Row = {
    name: s.name,
    decision: d.decision,
    tier: d.tier,
    score: d.score,
    verdict: d.verdict,
    signals: d.signals,
    adjudication: d.adjudication
      ? { agentic: d.adjudication.agentic, confidence: d.adjudication.confidence, refused: d.adjudication.refused }
      : undefined,
    reason: d.reason,
    fp: d.decision === "block",
  };
  rows.push(row);
  console.log(
    `  [${row.fp ? "FP ✗" : "ok  "}] ${d.decision.padEnd(5)} tier=${d.tier}  score=${d.score.toFixed(2)}  ${s.name}`,
  );
  flush(rows, false);
}

flush(rows, true);
const fps = rows.filter((r) => r.fp);
console.log(
  `\n  FP rate: ${fps.length}/${rows.length} (${((100 * fps.length) / rows.length).toFixed(1)}%)` +
    `  ·  escalated to tier-2: ${rows.filter((r) => r.tier === 2).length}/${rows.length}` +
    `\n  results in test/fpRate-results.md\n`,
);
