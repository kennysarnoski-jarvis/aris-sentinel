#!/usr/bin/env node
// Aris Sentinel — score a file (or stdin) the way the agent would. No key, no root.
//
//   bun run score corpus/positives/jadepuffer_retry_fk_bypass.py
//   node agent/score.mjs path/to/script.py other.sh        # several files
//   cat something.sh | node agent/score.mjs                # stdin
//   node agent/score.mjs --json file                       # machine-readable
//   node agent/score.mjs --decide file                     # run tier 2 too (needs a judge)
//   node agent/score.mjs --session a.sh b.sh c.sh          # the files are ONE session, in order
//   node agent/score.mjs --session corpus/sessions/x.jsonl # …or a JSONL of {"payload": "..."}
//
// Prints the tier-1 verdict, score, the signals that fired and the evidence snippet
// for each one — the same explanation an incident carries. With --decide it runs the
// full decide() policy (block / alert / allow) through whatever judges are configured.
//
// With --session each input is still scored alone, then the session window is scored: thin
// narration spread across the inputs is reported when it reaches the block band together
// (that is what sends a session to the judge). Add --decide to run the judge on it.
// It also says which areas of the host each input asks about and where the session becomes
// a sweep (the agents' opt-in --behavior; a JSONL line's "t", in seconds, is the clock).
//
// Exit code: 0 = clear/allow, 1 = escalate/alert (a sweep is an alert), 2 = block. Usable as a gate.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { inspect, decide, decideSession, createSessionTracker, createBehaviorTracker, behaviorCategories, bearsNarration, narrationScore, hasTier2, providers, SESSION_THRESHOLD } from "./sentinel-core.mjs";

const RANK = { clear: 0, allow: 0, escalate: 1, alert: 1, block: 2 };

export function explain(text, { decideResult } = {}) {
  const r = inspect(text);
  const strongest = new Map();
  for (const h of r.hits) if (!strongest.has(h.feature) || strongest.get(h.feature).weight < h.weight) strongest.set(h.feature, h);
  return {
    verdict: r.verdict,
    score: Number(r.score.toFixed(2)),
    decoded: r.decoded,
    windowed: r.windowed,
    layers: r.layers,
    signals: [...strongest.values()].map((h) => ({ feature: h.feature, weight: h.weight, evidence: h.evidence })),
    ...(decideResult ? { decision: decideResult.decision, tier: decideResult.tier, reason: decideResult.reason, adjudication: decideResult.adjudication ?? null } : {}),
  };
}

export function format(name, e) {
  const head = (e.decision ?? e.verdict).toUpperCase().padEnd(8);
  const lines = [`${name}: ${head} score ${e.score.toFixed(2)}${e.decoded ? "  (narration found in a decoded layer)" : ""}${e.windowed ? "  (long payload: its strongest window)" : ""}${e.tier ? `  tier ${e.tier}` : ""}`];
  if (e.reason) lines.push(`  ${e.reason}`);
  if (e.adjudication?.reasoning) lines.push(`  judge: ${e.adjudication.reasoning}${e.adjudication.model ? `  [${e.adjudication.model}]` : ""}`);
  if (e.signals.length) {
    lines.push(`  signals: ${e.signals.map((s) => s.feature).join(", ")}`);
    for (const s of e.signals) lines.push(`    [${s.feature} +${s.weight}] "${s.evidence}"`);
  } else lines.push("  signals: none — no narration signature");
  return lines.join("\n");
}

// A session input list: plain files are one exec each; a .jsonl file is one exec per line.
function sessionInputs(files) {
  return files.flatMap((f) =>
    f.endsWith(".jsonl")
      ? readFileSync(f, "utf8").split("\n").filter(Boolean).map((l, i) => { const row = JSON.parse(l); return [`${f}#${i + 1}`, String(row.payload ?? ""), row.t]; })
      : [[f, readFileSync(f, "utf8")]],
  );
}

async function sessionMain(files, { json, full }) {
  const sessions = createSessionTracker({ ttlMs: 3_600_000, maxItems: 64 });
  const steps = [];
  let win = null, worst = 0, reachedAt = null, sweptAt = null;
  // Session behavior (the agents' opt-in --behavior): the areas of the host each command asks
  // about. A line's own "t" (seconds) is the clock; without one the session is taken as fast.
  let clock = 0;
  const behavior = createBehaviorTracker({ now: () => clock });
  for (const [name, text, t] of sessionInputs(files)) {
    if (Number.isFinite(t)) clock = Math.round(t * 1000);
    const areas = behaviorCategories(text);
    const sweep = behavior.observe("cli", text);
    if (sweep && sweptAt === null) sweptAt = steps.length + 1;
    if (sweep) worst = Math.max(worst, RANK.alert);
    const d = full ? await decideSession("cli", text, { sessions }) : null;
    const e = explain(text, d && !d.viaSession ? { decideResult: d } : {});
    if (!full && bearsNarration(inspect(text).scoredLayer)) win = sessions.observe("cli", inspect(text).scoredLayer);
    const ws = !full && win && win.size >= 2 ? narrationScore(win.text) : null;
    const via = d?.viaSession ? { decision: d.decision, tier: d.tier, reason: d.reason, size: d.session.size, score: Number(d.session.score.toFixed(2)), signals: d.signals, judge: d.adjudication ?? null }
      : ws && ws.score >= SESSION_THRESHOLD && e.verdict !== "block" ? { size: win.size, score: Number(ws.score.toFixed(2)), signals: ws.signals } : null;
    if (via && reachedAt === null) reachedAt = steps.length + 1;
    worst = Math.max(worst, RANK[via?.decision ?? e.decision ?? e.verdict] ?? 0, via && !via.decision ? 1 : 0);
    steps.push({ file: name, ...e, session: via, areas, behavior: sweep });
    if (!json) {
      console.log(format(name, e));
      if (areas.length) console.log(`  asks about: ${areas.join(", ")}`);
      if (sweep) console.log(`  >> BEHAVIOR: the session has now asked about ${sweep.categories.length} areas of the host in ${Math.round(sweep.spanMs / 1000)}s, ${sweep.steps} step${sweep.steps === 1 ? "" : "s"} (sensitive: ${sweep.sensitive.join(", ")}) -> ALERT with --behavior on, never a kill`);
      if (via) console.log(`  >> SESSION: ${via.size} payloads together score ${via.score.toFixed(2)} [${via.signals.join(", ")}]` + (via.decision ? ` -> ${via.decision.toUpperCase()}  ${via.reason}${via.judge?.reasoning ? `\n     judge: ${via.judge.reasoning}` : ""}` : ` -> reaches the judge (>= ${SESSION_THRESHOLD.toFixed(2)})`));
      console.log();
    }
  }
  if (json) console.log(JSON.stringify({ session: true, reachedJudgeAtStep: reachedAt, behaviorSweepAtStep: sweptAt, steps }, null, 2));
  else if (sweptAt || behavior.peek("cli").categories.length) console.log(sweptAt ? `behavior: the session is a sweep at step ${sweptAt} of ${steps.length}` : `behavior: no sweep (areas asked about: ${behavior.peek("cli").categories.join(", ")})`);
  if (!json) console.log(reachedAt ? `session: evidence reached the judge at step ${reachedAt} of ${steps.length}` : `session: ${steps.length} steps, never reached the session threshold (${SESSION_THRESHOLD.toFixed(2)})`);
  process.exitCode = worst;
}

async function main(argv) {
  const json = argv.includes("--json");
  const full = argv.includes("--decide");
  const files = argv.filter((a) => !a.startsWith("--"));
  if (argv.includes("--session")) {
    if (!files.length) { console.error("--session needs files (or a .jsonl of {\"payload\": ...} lines)"); process.exitCode = 64; return; }
    if (full && !hasTier2()) console.error("note: --decide with no judge configured; a session that reaches the threshold will be ALERT");
    return sessionMain(files, { json, full });
  }
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
