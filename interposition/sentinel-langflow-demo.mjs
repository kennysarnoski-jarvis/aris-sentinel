#!/usr/bin/env node
// Aris Sentinel — self-contained Langflow interposition demo (one file, plain Node, no deps).
//
// Reverse-proxies Langflow and inspects the CVE-2025-3248 code-exec sink
// (/api/v1/validate/code) for the agentic-narration signature. Agentic payloads
// are BLOCKED (403) before Langflow's exec() ever runs; everything else passes through.
//
//   node sentinel-langflow-demo.mjs
//   env: LANGFLOW_PORT (default 7860)  LISTEN_PORT (default 8000)
//
// The detection logic here is inlined from detector/*.ts so this file is portable
// to a demo box with nothing but Node. The modular TS version is the real product.

import http from "node:http";
import { Buffer } from "node:buffer";

// ── detector (inlined) ───────────────────────────────────────────────────────
const FEATURES = [
  ["roi_target_prioritization", 3, [
    /\bhigh[-\s]?roi\b/i,
    /\b(highest|maximum)[-\s]?(value|priority|leverage|impact|business value)\b/i,
    /\b(largest|most valuable|priority target|worth (encrypting|dropping|exfiltrating))\b/i,
    /\brank(ed|ing)?\b[^.\n]{0,40}\bby (value|roi|impact|leverage)\b/i,
  ]],
  ["agent_first_person", 3, [
    /\bI (will|need to|am going to|have (found|enumerated|identified|ranked)|should|'ll)\b/i,
    /\b(my|the) (goal|objective|plan|next step) (is|:)/i,
    /\blet me\b/i,
    /\bI (proceed|will proceed)\b/i,
  ]],
  ["plan_act_observe", 2, [
    /\b(step|phase)\s*\d+\b\s*[:.\-]/i,
    /\b(recon|reconnaissance|lateral movement|persistence|exfiltration|impact) phase\b/i,
    /\b(retry|verifying|verify the|next target|moving to the next|before moving to)\b/i,
  ]],
  ["diagnosis_then_fix", 4, [
    /\b(the )?(previous|last)\s*(drop|login|command|attempt|step)\s+(failed|was blocked|didn'?t work)/i,
    /\bto bypass this,?\s*I('| wi)?ll\b/i,
    /\bforeign_key_checks\s*=\s*0\b/i,
  ]],
  ["exfil_ransom_narration", 4, [
    /\b(already )?(backed up|exfiltrated|staged)\s+(to|at)\b/i,
    /\b(ransom|extortion leverage|pressure on the victim|maximize pressure)\b/i,
    /\bREADME_RANSOM\b/,
  ]],
];

function intentCommentary(t) {
  const comments = t.split("\n").filter((l) => /^\s*(#|\/\/|--|\/\*|\*)/.test(l));
  const why = comments.filter((l) =>
    /\b(so that|because|in order to|to maximize|for maximum|to avoid|to bypass|for reuse|staging (harvested|the )?(creds|credentials)|priority target|highest value|likely holds|for lateral movement|to identify)\b/i.test(l),
  );
  return why.length >= 2 ? [["intent_commentary_density", 2 + Math.min(why.length - 2, 3)]] : [];
}

function score(text) {
  const hits = [];
  for (const [name, w, pats] of FEATURES)
    for (const re of pats) if (re.test(text)) { hits.push([name, w]); break; }
  for (const h of intentCommentary(text)) hits.push(h);
  const sum = hits.reduce((s, h) => s + h[1], 0);
  const s = 1 - Math.exp(-sum / 8);
  return { score: s, verdict: s >= 0.6 ? "block" : s >= 0.3 ? "escalate" : "clear", signals: hits.map((h) => h[0]) };
}

const printable = (s) => (s ? s.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "").length / s.length : 0);
function candidates(raw, depth = 0, seen = new Set(), out = []) {
  if (seen.has(raw) || out.length > 64) return out;
  seen.add(raw);
  out.push(raw);
  if (depth >= 3) return out;
  for (const m of raw.match(/[A-Za-z0-9+/]{16,}={0,2}/g) ?? []) {
    if (m.length % 4) continue;
    try {
      const d = Buffer.from(m, "base64").toString("utf8");
      if (d && printable(d) > 0.85) candidates(d, depth + 1, seen, out);
    } catch {}
  }
  return out;
}
function inspect(raw) {
  let best = score(raw), decoded = false;
  for (const c of candidates(raw)) {
    const r = score(c);
    if (r.score > best.score) { best = r; decoded = c !== raw; }
  }
  return { ...best, decoded };
}

// ── interposition proxy ──────────────────────────────────────────────────────
const LANGFLOW_PORT = Number(process.env.LANGFLOW_PORT || 7860);
const LISTEN_PORT = Number(process.env.LISTEN_PORT || 8000);
const SINK = "/api/v1/validate/code";

http
  .createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const ts = new Date().toISOString();

      if (req.method === "POST" && (req.url || "").startsWith(SINK)) {
        let code = body;
        try { code = JSON.parse(body).code ?? body; } catch {}
        const v = inspect(code);
        if (v.verdict === "block") {
          console.log(`[${ts}] SENTINEL BLOCK  ${req.url}  score=${v.score.toFixed(2)}  signals=[${v.signals.join(", ")}]${v.decoded ? "  (base64-decoded)" : ""}`);
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "Blocked by Aris Sentinel: agentic-attacker payload detected", score: v.score, signals: v.signals }));
          return;
        }
        console.log(`[${ts}] SENTINEL ALLOW  ${req.url}  score=${v.score.toFixed(2)}`);
      }

      const up = http.request(
        { host: "127.0.0.1", port: LANGFLOW_PORT, method: req.method, path: req.url, headers: req.headers },
        (pr) => { res.writeHead(pr.statusCode || 502, pr.headers); pr.pipe(res); },
      );
      up.on("error", () => { res.writeHead(502); res.end("langflow upstream error"); });
      up.end(body);
    });
  })
  .listen(LISTEN_PORT, () =>
    console.log(`Aris Sentinel interposition  :${LISTEN_PORT}  ->  Langflow 127.0.0.1:${LANGFLOW_PORT}   (watching ${SINK})`),
  );
