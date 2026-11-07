#!/usr/bin/env node
// Aris Sentinel — score a file (or stdin) the way the agent would. No key, no root.
//
//   bun run score corpus/positives/jadepuffer_retry_fk_bypass.py
//   node agent/score.mjs path/to/script.py other.sh        # several files
//   cat something.sh | node agent/score.mjs                # stdin
//   node agent/score.mjs --json file                       # machine-readable
//   node agent/score.mjs --decide file                     # run tier 2 too (needs a judge)
//
// Prints the tier-1 verdict, score, the signals that fired and the evidence snippet
// for each one — the same explanation an incident carries. With --decide it runs the
// full decide() policy (block / alert / allow) through whatever judges are configured.
//
// Exit code: 0 = clear/allow, 1 = escalate/alert, 2 = block. Usable as a gate.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { inspect, decide, hasTier2, providers } from "./sentinel-core.mjs";

const RANK = { clear: 0, allow: 0, escalate: 1, alert: 1, block: 2 };

export function explain(text, { decideResult } = {}) {
  const r = inspect(text);
  const strongest = new Map();
  for (const h of r.hits) if (!strongest.has(h.feature) || strongest.get(h.feature).weight < h.weight) strongest.set(h.feature, h);
  return {
    verdict: r.verdict,
    score: Number(r.score.toFixed(2)),
    decoded: r.decoded,
    layers: r.layers,
    signals: [...strongest.values()].map((h) => ({ feature: h.feature, weight: h.weight, evidence: h.evidence })),
    ...(decideResult ? { decision: decideResult.decision, tier: decideResult.tier, reason: decideResult.reason, adjudication: decideResult.adjudication ?? null } : {}),
  };
}

export function format(name, e) {
  const head = (e.decision ?? e.verdict).toUpperCase().padEnd(8);
  const lines = [`${name}: ${head} score ${e.score.toFixed(2)}${e.decoded ? "  (narration found in a decoded layer)" : ""}${e.tier ? `  tier ${e.tier}` : ""}`];
  if (e.reason) lines.push(`  ${e.reason}`);
  if (e.adjudication?.reasoning) lines.push(`  judge: ${e.adjudication.reasoning}${e.adjudication.model ? `  [${e.adjudication.model}]` : ""}`);
  if (e.signals.length) {
    lines.push(`  signals: ${e.signals.map((s) => s.feature).join(", ")}`);
    for (const s of e.signals) lines.push(`    [${s.feature} +${s.weight}] "${s.evidence}"`);
  } else lines.push("  signals: none — no narration signature");
  return lines.join("\n");
}

async function main(argv) {
  const json = argv.includes("--json");
  const full = argv.includes("--decide");
  const files = argv.filter((a) => !a.startsWith("--"));
  const inputs = files.length ? files.map((f) => [f, readFileSync(f, "utf8")]) : [["<stdin>", readFileSync(0, "utf8")]];
  if (full && !hasTier2()) console.error("note: --decide with no judge configured; escalate-band inputs will be ALERT (set ANTHROPIC_API_KEY or OPENAI_BASE_URL+OPENAI_MODEL)");
  else if (full) console.error(`judges: ${providers().map((p) => `${p.name}:${p.model}`).join(" -> ")}`);
  let worst = 0;
  const out = [];
  for (const [name, text] of inputs) {
    const e = explain(text, full ? { decideResult: await decide(text) } : {});
    worst = Math.max(worst, RANK[e.decision ?? e.verdict] ?? 0);
    if (json) out.push({ file: name, ...e });
    else console.log(format(name, e) + "\n");
  }
  if (json) console.log(JSON.stringify(files.length === 1 || !files.length ? out[0] : out, null, 2));
  process.exitCode = worst;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) main(process.argv.slice(2));
