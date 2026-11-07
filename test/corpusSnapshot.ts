// Corpus verdict snapshot — every corpus file's tier-1 score, verdict and signals,
// frozen in test/corpus-snapshot.json. The unit test test/unit/corpus-snapshot.test.ts
// fails on ANY drift, so a refactor of the core can't silently change a verdict.
//
//   bun run corpus:snapshot      # regenerate after an INTENTIONAL detector change
//
// Review the diff of corpus-snapshot.json in that commit: it is the change log of what
// the detector decides.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect } from "../detector/inspect";
import { SAMPLES } from "./fpSamples";

export const SNAPSHOT_PATH = fileURLToPath(new URL("./corpus-snapshot.json", import.meta.url));
const CORPUS = fileURLToPath(new URL("../corpus/", import.meta.url));
const DIRS = ["positives", "negatives/benign", "negatives/human-malware", "windows-powershell"];

export interface Row {
  score: number;
  verdict: string;
  decoded: boolean;
  signals: string[];
}

function row(text: string): Row {
  const r = inspect(text);
  return { score: Number(r.score.toFixed(4)), verdict: r.verdict, decoded: r.decoded, signals: [...new Set(r.hits.map((h) => h.feature))].sort() };
}

/** Current verdicts, keyed by `corpus/<dir>/<file>` or `fpSamples/<name>`. */
export function collect(): Record<string, Row> {
  const out: Record<string, Row> = {};
  for (const d of DIRS) {
    for (const f of readdirSync(join(CORPUS, d)).sort()) out[`corpus/${d}/${f}`] = row(readFileSync(join(CORPUS, d, f), "utf8"));
  }
  for (const s of SAMPLES) out[`fpSamples/${s.name}`] = row(s.text);
  return out;
}

export function load(): Record<string, Row> {
  return JSON.parse(readFileSync(SNAPSHOT_PATH, "utf8"));
}

if (process.argv.includes("--update")) {
  const rows = collect();
  writeFileSync(SNAPSHOT_PATH, JSON.stringify(rows, null, 1) + "\n");
  console.log(`wrote ${Object.keys(rows).length} rows -> ${SNAPSHOT_PATH}`);
}
