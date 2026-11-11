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
import { bearsNarration, behaviorCategories, createBehaviorTracker, createSessionTracker, narrationScore, SESSION_THRESHOLD } from "../agent/sentinel-core.mjs";
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

export interface SessionRow {
  /** each exec scored alone: "verdict score" */
  steps: string[];
  /** the window after the last exec */
  window: { size: number; score: number; signals: string[] };
  /** 1-based step at which the window first reaches the session threshold (null = never) */
  reachesJudgeAt: number | null;
}

// The tier-1 half of decideSession(), replayed without a judge: what each exec scores
// alone, and where the session window first crosses the threshold.
function sessionRow(payloads: string[]): SessionRow {
  const sessions = createSessionTracker({ ttlMs: 3_600_000 });
  const steps: string[] = [];
  let reachesJudgeAt: number | null = null;
  let last = { size: 0, score: 0, signals: [] as string[] };
  payloads.forEach((p, i) => {
    const t1 = inspect(p);
    steps.push(`${t1.verdict} ${t1.score.toFixed(4)}`);
    if (!bearsNarration(t1.scoredLayer)) return;
    const win = sessions.observe("s", t1.scoredLayer)!;
    const ws = narrationScore(win.text);
    last = { size: win.size, score: Number(ws.score.toFixed(4)), signals: [...ws.signals].sort() };
    if (reachesJudgeAt === null && win.size >= 2 && t1.verdict !== "block" && ws.score >= SESSION_THRESHOLD) reachesJudgeAt = i + 1;
  });
  return { steps, window: last, reachesJudgeAt };
}

export interface BehaviorRow {
  /** the areas of the host each command asks about ("-" = none) */
  areas: string[];
  /** 1-based command at which the session is reported as a sweep (null = never) */
  sweepAt: number | null;
}

// The behavior half of decideSession(), replayed on the session's own clock.
function behaviorRow(cmds: { t: number; payload: string }[]): BehaviorRow {
  let clock = 0;
  const tracker = createBehaviorTracker({ now: () => clock });
  let sweepAt: number | null = null;
  const areas = cmds.map((c, i) => {
    clock = Math.round(c.t * 1000);
    if (tracker.observe("s", c.payload) && sweepAt === null) sweepAt = i + 1;
    return behaviorCategories(c.payload).join(",") || "-";
  });
  return { areas, sweepAt };
}

/** Current verdicts, keyed by `corpus/<dir>/<file>`, `corpus/sessions/<file>`, `corpus/behavior/<file>` or `fpSamples/<name>`. */
export function collect(): Record<string, Row | SessionRow | BehaviorRow> {
  const out: Record<string, Row | SessionRow | BehaviorRow> = {};
  const BEH = join(CORPUS, "behavior");
  for (const f of readdirSync(BEH).filter((x) => x.endsWith(".jsonl")).sort()) {
    out[`corpus/behavior/${f}`] = behaviorRow(readFileSync(join(BEH, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));
  }
  const SESS = join(CORPUS, "sessions");
  for (const f of readdirSync(SESS).filter((x) => x.endsWith(".jsonl")).sort()) {
    out[`corpus/sessions/${f}`] = sessionRow(readFileSync(join(SESS, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).payload));
  }
  for (const d of DIRS) {
    for (const f of readdirSync(join(CORPUS, d)).sort()) out[`corpus/${d}/${f}`] = row(readFileSync(join(CORPUS, d, f), "utf8"));
  }
  for (const s of SAMPLES) out[`fpSamples/${s.name}`] = row(s.text);
  return out;
}

export function load(): Record<string, Row | SessionRow | BehaviorRow> {
  return JSON.parse(readFileSync(SNAPSHOT_PATH, "utf8"));
}

if (process.argv.includes("--update")) {
  const rows = collect();
  writeFileSync(SNAPSHOT_PATH, JSON.stringify(rows, null, 1) + "\n");
  console.log(`wrote ${Object.keys(rows).length} rows -> ${SNAPSHOT_PATH}`);
}
