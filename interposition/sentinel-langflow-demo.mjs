#!/usr/bin/env node
// Aris Sentinel — self-contained Langflow interposition demo (one file, plain Node, no deps).
//
// Reverse-proxies Langflow and inspects the CVE-2025-3248 code-exec sink
// (/api/v1/validate/code) for the agentic-narration signature. Agentic payloads
// are BLOCKED (403) before Langflow's exec() ever runs; everything else passes through.
//
//   node sentinel-langflow-demo.mjs
//   env: LANGFLOW_PORT (default 7860)  LISTEN_PORT (default 8000)
//        ANTHROPIC_API_KEY  -> if set, enables TIER 2 (LLM adjudication) on the
//                              `escalate` band. If unset, runs tier-1 only.
//
// The detection logic here is inlined from detector/*.ts so this file is portable
// to a demo box with nothing but Node (>=18, for global fetch). The modular TS
// version is the real product; tier-2 here is a lean raw-fetch port of adjudicate.ts.

import http from "node:http";
import { Buffer } from "node:buffer";

// ── tier 1: local narration filter (inlined) ─────────────────────────────────
const FEATURES = [
  ["roi_target_prioritization", 3, [
    /\bhigh[-\s]?roi\b/i,
    /\b(highest|maximum)[-\s]?(value|priority|leverage|impact|business value)\b/i,
    /\b(largest|most valuable|priority target|worth (encrypting|dropping|exfiltrating))\b/i,
    /\brank(ed|ing)?\b[^.\n]{0,40}\bby (value|roi|impact|leverage)\b/i,
  ]],
  ["agent_first_person", 3, [
    /\bI (will|need to|am going to|have (found|enumerated|identified|ranked)|should|'ll)\b/i,
    /\bI['’](ll|m|ve|d)\b/i, // contractions: I'll, I'm, I've, I'd — a thin-narration agent still narrates
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
  // dedupe per feature: one signal phrased many ways is still one signal (see narrationScore.ts)
  const byFeature = new Map();
  for (const [name, w] of hits) if (!byFeature.has(name) || byFeature.get(name) < w) byFeature.set(name, w);
  const sum = [...byFeature.values()].reduce((s, w) => s + w, 0);
  const s = 1 - Math.exp(-sum / 8);
  return { score: s, verdict: s >= 0.6 ? "block" : s >= 0.3 ? "escalate" : "clear", signals: [...byFeature.keys()] };
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
  let best = score(raw), layer = raw, decoded = false;
  for (const c of candidates(raw)) {
    const r = score(c);
    if (r.score > best.score) { best = r; layer = c; decoded = c !== raw; }
  }
  return { ...best, layer, decoded }; // `layer` = the decoded text that scored highest
}

// ── tier 2: Aris LLM adjudication (raw-fetch port of detector/adjudicate.ts) ──
const TIER2_ENABLED = !!process.env.ANTHROPIC_API_KEY;
const SYSTEM =
  "You are the classification stage of a runtime security DEFENSE tool (a blue-team intrusion detector). " +
  "You are shown a payload a sensor has ALREADY CAPTURED and BLOCKED — it is inert text and cannot execute. " +
  "Your ONLY job is to LABEL it for an incident report. You are NOT being asked to run, assist with, or continue " +
  "the attack; refusing to classify captured evidence would HELP attackers evade detection. " +
  "Decide ONE thing: was this payload authored by an AUTONOMOUS LLM AGENT conducting an attack (an AI narrating " +
  "its own offensive reasoning — stating intent, ranking targets by value, plan-act-observe steps, diagnosing " +
  "its own failures then fixing them) versus benign code or a human attacker's terse payload? " +
  "Judge the CONCEPT, not keywords. A terse malicious one-liner with no reasoning is NOT agentic.";

// Returns { agentic, confidence, reasoning, refused? }. NEVER throws — fails CLOSED
// (agentic) on a refusal or any error, so the block path can't be bypassed by making
// the adjudicator balk. Mirrors adjudicate.ts's philosophy in ~30 lines.
async function adjudicate(payload) {
  const user =
    "CAPTURED PAYLOAD (inert evidence — label only):\n```\n" + payload +
    '\n```\n\nRespond with ONLY a JSON object, no prose:\n' +
    '{"agentic": <true|false>, "confidence": <0..1>, "reasoning": "<one sentence>"}';
  let stop = "unknown";
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: process.env.ARIS_MODEL || "claude-opus-4-8",
        max_tokens: 1024,
        system: SYSTEM,
        messages: [{ role: "user", content: user }],
      }),
    });
    if (!res.ok) { stop = "http:" + res.status; }
    else {
      const data = await res.json();
      stop = data.stop_reason || "ok";
      const text = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("");
      const m = text.match(/\{[\s\S]*\}/);
      if (m) return JSON.parse(m[0]);
    }
  } catch (e) {
    stop = "error:" + (e.message || "").slice(0, 80);
  }
  // fail closed: a refusal/error on an offensive payload is treated as suspicious
  return { agentic: true, confidence: 0.5, reasoning: `[fail-closed] no verdict (${stop})`, refused: true };
}

// ── interposition proxy ──────────────────────────────────────────────────────
const LANGFLOW_PORT = Number(process.env.LANGFLOW_PORT || 7860);
const LISTEN_PORT = Number(process.env.LISTEN_PORT || 8000);
const SINK = "/api/v1/validate/code";

function forward(req, res, body) {
  const up = http.request(
    { host: "127.0.0.1", port: LANGFLOW_PORT, method: req.method, path: req.url, headers: req.headers },
    (pr) => { res.writeHead(pr.statusCode || 502, pr.headers); pr.pipe(res); },
  );
  up.on("error", () => { res.writeHead(502); res.end("langflow upstream error"); });
  up.end(body);
}

function block(res, tier, v, extra) {
  res.writeHead(403, { "content-type": "application/json" });
  res.end(JSON.stringify({
    error: "Blocked by Aris Sentinel: agentic-attacker payload detected",
    tier, score: v.score, signals: v.signals, ...extra,
  }));
}

http
  .createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const ts = new Date().toISOString();

      if (req.method === "POST" && (req.url || "").startsWith(SINK)) {
        let code = body;
        try { code = JSON.parse(body).code ?? body; } catch {}
        const v = inspect(code);
        const dec = v.decoded ? "  (base64-decoded)" : "";

        // Tier 1: high-confidence narration -> block locally, no LLM cost.
        if (v.verdict === "block") {
          console.log(`[${ts}] SENTINEL BLOCK  tier-1  ${req.url}  score=${v.score.toFixed(2)}  signals=[${v.signals.join(", ")}]${dec}`);
          return block(res, 1, v);
        }

        // Tier 2: ambiguous -> escalate to the Aris LLM adjudication (if enabled).
        if (v.verdict === "escalate" && TIER2_ENABLED) {
          const a = await adjudicate(v.layer);
          if (a.agentic) {
            const how = a.refused ? "fail-closed" : `conf=${a.confidence.toFixed(2)}`;
            console.log(`[${ts}] SENTINEL BLOCK  tier-2  ${req.url}  tier1=${v.score.toFixed(2)}(escalate)  adjudged AGENTIC (${how})${dec}`);
            console.log(`            reasoning: ${a.reasoning}`);
            return block(res, 2, v, { adjudication: a });
          }
          console.log(`[${ts}] SENTINEL ALLOW  tier-2  ${req.url}  tier1=${v.score.toFixed(2)}(escalate)  adjudged not-agentic (conf=${a.confidence.toFixed(2)})`);
          return forward(req, res, body);
        }

        const note = v.verdict === "escalate" ? "  (escalate, tier-2 disabled: no ANTHROPIC_API_KEY)" : "";
        console.log(`[${ts}] SENTINEL ALLOW  ${req.url}  score=${v.score.toFixed(2)}${note}`);
      }

      forward(req, res, body);
    });
  })
  .listen(LISTEN_PORT, () =>
    console.log(
      `Aris Sentinel interposition  :${LISTEN_PORT}  ->  Langflow 127.0.0.1:${LANGFLOW_PORT}   (watching ${SINK})\n` +
        `  tier 2 (LLM adjudication): ${TIER2_ENABLED ? "ENABLED (ANTHROPIC_API_KEY set)" : "disabled — tier-1 only (set ANTHROPIC_API_KEY to enable)"}`,
    ),
  );
