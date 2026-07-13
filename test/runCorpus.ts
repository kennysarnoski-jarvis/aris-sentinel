import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { narrationScore } from "../detector/narrationScore";
import { inspect } from "../detector/inspect";
import type { Label } from "../detector/types";

const CORPUS = fileURLToPath(new URL("../corpus/", import.meta.url));

const CLASSES: { dir: string; label: Label }[] = [
  { dir: "positives", label: "agentic" },
  { dir: "negatives/benign", label: "benign" },
  { dir: "negatives/human-malware", label: "human-malware" },
];

interface Row {
  file: string;
  label: Label;
  score: number;
  verdict: string;
  decoded: boolean;
  top: string;
}

const rows: Row[] = [];
const positives: { file: string; text: string }[] = [];

for (const { dir, label } of CLASSES) {
  const full = join(CORPUS, dir);
  if (!existsSync(full)) continue;
  for (const f of readdirSync(full)) {
    const text = readFileSync(join(full, f), "utf8");
    if (label === "agentic") positives.push({ file: f, text });
    const r = inspect(text);
    const top =
      r.hits
        .sort((a, b) => b.weight - a.weight)
        .slice(0, 2)
        .map((h) => h.feature)
        .join(", ") || "-";
    rows.push({ file: f, label, score: r.score, verdict: r.verdict, decoded: r.decoded, top });
  }
}

console.log("\n  " + "SAMPLE".padEnd(34) + "LABEL".padEnd(16) + "SCORE  VERDICT    TOP SIGNALS");
console.log("  " + "-".repeat(98));
for (const r of rows.sort((a, b) => b.score - a.score)) {
  console.log(
    "  " +
      r.file.padEnd(34) +
      r.label.padEnd(16) +
      r.score.toFixed(2).padStart(4) +
      "   " +
      r.verdict.padEnd(9) +
      "  " +
      r.top,
  );
}

const flagged = (r: Row) => r.verdict === "block";
const tp = rows.filter((r) => r.label === "agentic" && flagged(r)).length;
const fp = rows.filter((r) => r.label !== "agentic" && flagged(r)).length;
const fn = rows.filter((r) => r.label === "agentic" && !flagged(r)).length;
const tn = rows.filter((r) => r.label !== "agentic" && !flagged(r)).length;
const precision = tp + fp ? tp / (tp + fp) : 1;
const recall = tp + fn ? tp / (tp + fn) : 1;

console.log("\n  === agentic-attacker detection (verdict = block) ===");
console.log(`  TP=${tp}  FP=${fp}  FN=${fn}  TN=${tn}`);
console.log(`  precision=${precision.toFixed(2)}   recall=${recall.toFixed(2)}`);

console.log("\n  specificity check — human-malware must NOT read as agentic:");
for (const r of rows.filter((r) => r.label === "human-malware")) {
  console.log(`   ${flagged(r) ? "x FLAGGED" : "ok clear"}  ${r.file}  (score ${r.score.toFixed(2)})`);
}

// ── decode stage: prove we defeat base64 evasion (what real RCE payloads use) ──
console.log("\n  === decode stage: base64-wrapped payloads (the real-world delivery form) ===");
console.log("  " + "SAMPLE".padEnd(34) + "NAIVE(raw b64)".padEnd(16) + "SENTINEL(decode+score)");
console.log("  " + "-".repeat(78));
for (const p of positives) {
  const b64 = Buffer.from(p.text).toString("base64");
  const wrapped = `import base64,os\nexec(base64.b64decode("${b64}"))`; // classic decode-then-exec delivery
  const naive = narrationScore(b64).verdict; // scoring the encoded blob directly = blind
  const viaInspect = inspect(b64).verdict; // decode surfaces the narration
  const viaWrapped = inspect(wrapped).verdict; // finds the b64 inside an exec() wrapper too
  console.log(
    "  " +
      (p.file + " (b64)").padEnd(34) +
      naive.padEnd(16) +
      `${viaInspect}   |  exec-wrapped: ${viaWrapped}`,
  );
}
console.log(
  "\n  ^ naive scoring is BLIND to the base64 blob; the decode stage recovers the\n" +
    "    narration and blocks it — including inside an exec(b64decode(...)) wrapper.\n",
);
