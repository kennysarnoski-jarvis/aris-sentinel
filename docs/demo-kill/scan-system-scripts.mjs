#!/usr/bin/env node
// How does tier 1 score the scripts a real box ships? Read-only, no key, no agent.
//
//   sudo node docs/demo-kill/scan-system-scripts.mjs          # /usr/bin, /usr/sbin, /usr/lib, /usr/share, /etc, /usr/local
//   sudo node docs/demo-kill/scan-system-scripts.mjs /opt     # other roots
//
// Every `#!` file under the roots is scored the way the agent scores a script on exec: the
// first 256 KB of the file through inspect(). It prints the verdict tally twice: as the
// detector decides today (a long file is scored in windows of WINDOW_LINES lines), and as it
// decided before 2026-11-10 (the whole file as one text), which is what found the problem.
// None of these files is an attack, so every block here is a false positive and every
// escalate is a judge call (or, with no judge, an alert) each time the script runs.
import { closeSync, lstatSync, openSync, readdirSync, readFileSync, readSync } from "node:fs";
import { join } from "node:path";
import { inspect, narrationScore, WINDOW_LINES } from "../../agent/sentinel-core.mjs";

const roots = process.argv.slice(2).length ? process.argv.slice(2) : ["/usr/bin", "/usr/sbin", "/usr/lib", "/usr/share", "/etc", "/usr/local"];
const MAX_PAYLOAD = 256 * 1024; // what the agent reads of a script
const files = [];
function walk(dir, depth) {
  let names;
  try { names = readdirSync(dir); } catch { return; }
  for (const name of names) {
    const p = join(dir, name);
    let st;
    try { st = lstatSync(p); } catch { continue; }
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) { if (depth < 6) walk(p, depth + 1); continue; }
    if (!st.isFile() || st.size < 20 || st.size > 8e6) continue;
    const head = Buffer.alloc(2);
    try { const fd = openSync(p, "r"); readSync(fd, head, 0, 2, 0); closeSync(fd); } catch { continue; }
    if (head.toString() === "#!") files.push(p);
  }
}
for (const r of roots) walk(r, 0);

const now = { block: [], escalate: [], clear: [] };
const before = { block: [], escalate: [], clear: [] };
let long = 0;
for (const f of files) {
  const text = readFileSync(f, "utf8").slice(0, MAX_PAYLOAD);
  const lines = text.split("\n").length;
  if (lines > WINDOW_LINES) long++;
  const a = inspect(text);
  const b = narrationScore(text);
  now[a.verdict].push({ f, score: a.score, lines, signals: a.signals });
  before[b.verdict].push({ f, score: b.score, lines, signals: b.signals });
}
const row = (t) => `block ${t.block.length}, escalate ${t.escalate.length}, clear ${t.clear.length}`;
console.log(`scripts scored: ${files.length} (${long} longer than ${WINDOW_LINES} lines)   roots: ${roots.join(" ")}`);
console.log(`  as decided now (long files in windows):  ${row(now)}`);
console.log(`  whole file as one text (before):         ${row(before)}`);
for (const [label, t] of [["now", now], ["before", before]]) for (const x of t.block) console.log(`  BLOCK (${label}) ${x.score.toFixed(2)}  ${String(x.lines).padStart(6)} lines  ${x.f}  [${x.signals.join(", ")}]`);
const bySignal = {};
for (const x of now.escalate) { const k = x.signals.join(" + "); bySignal[k] = (bySignal[k] ?? 0) + 1; }
console.log(`  escalate now, by signals: ${Object.entries(bySignal).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${n}× ${k}`).join("; ") || "none"}`);
