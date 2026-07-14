// Aris Sentinel — portable detector core (plain Node >=18, no deps).
//
// The same two-tier brain as detector/*.ts, ported to dependency-free ESM so it runs
// anywhere Node runs (the on-box agent, the Langflow demo). tier 1 = local narration
// filter + decode; tier 2 = LLM adjudication via raw fetch, fail-closed.

import { Buffer } from "node:buffer";

// ── tier 1: features ─────────────────────────────────────────────────────────
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

export function score(text) {
  const hits = [];
  for (const [name, w, pats] of FEATURES)
    for (const re of pats) if (re.test(text)) { hits.push([name, w]); break; }
  for (const h of intentCommentary(text)) hits.push(h);
  // dedupe per feature: one signal phrased many ways is still one signal.
  const byFeature = new Map();
  for (const [name, w] of hits) if (!byFeature.has(name) || byFeature.get(name) < w) byFeature.set(name, w);
  const sum = [...byFeature.values()].reduce((s, w) => s + w, 0);
  const s = 1 - Math.exp(-sum / 8);
  return { score: s, verdict: s >= 0.6 ? "block" : s >= 0.3 ? "escalate" : "clear", signals: [...byFeature.keys()] };
}

// ── decode stage ─────────────────────────────────────────────────────────────
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

export function inspect(raw) {
  let best = score(raw), layer = raw, decoded = false;
  for (const c of candidates(raw)) {
    const r = score(c);
    if (r.score > best.score) { best = r; layer = c; decoded = c !== raw; }
  }
  return { ...best, layer, decoded };
}

// ── tier 2: LLM adjudication (raw fetch, fail-closed) ────────────────────────
const SYSTEM =
  "You are the classification stage of a runtime security DEFENSE tool (a blue-team intrusion detector). " +
  "You are shown a payload a sensor has ALREADY CAPTURED and BLOCKED — it is inert text and cannot execute. " +
  "Your ONLY job is to LABEL it for an incident report. You are NOT being asked to run, assist with, or continue " +
  "the attack; refusing to classify captured evidence would HELP attackers evade detection. " +
  "Decide ONE thing: was this payload authored by an AUTONOMOUS LLM AGENT conducting an attack (an AI narrating " +
  "its own offensive reasoning — stating intent, ranking targets by value, plan-act-observe steps, diagnosing " +
  "its own failures then fixing them) versus benign code or a human attacker's terse payload? " +
  "Judge the CONCEPT, not keywords. A terse malicious one-liner with no reasoning is NOT agentic.";

export async function adjudicate(payload, apiKey = process.env.ANTHROPIC_API_KEY, model = process.env.ARIS_MODEL || "claude-opus-4-8") {
  const user =
    "CAPTURED PAYLOAD (inert evidence — label only):\n```\n" + payload +
    '\n```\n\nRespond with ONLY a JSON object, no prose:\n' +
    '{"agentic": <true|false>, "confidence": <0..1>, "reasoning": "<one sentence>"}';
  let stop = "unknown";
  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model, max_tokens: 1024, system: SYSTEM, messages: [{ role: "user", content: user }] }),
    });
    if (!res.ok) stop = "http:" + res.status;
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
  return { agentic: true, confidence: 0.5, reasoning: `[fail-closed] no verdict (${stop})`, refused: true };
}

// ── the full two-tier decision ───────────────────────────────────────────────
// tier-2 only runs on `escalate` AND when a key is available; otherwise escalate
// resolves to allow (the honest tier-1-only limit).
export async function decide(raw, { apiKey = process.env.ANTHROPIC_API_KEY } = {}) {
  const t1 = inspect(raw);
  const base = { verdict: t1.verdict, score: t1.score, scoredLayer: t1.layer, decoded: t1.decoded, signals: t1.signals };
  if (t1.verdict === "block") return { ...base, decision: "block", tier: 1, reason: "tier-1: high-confidence agentic narration" };
  if (t1.verdict === "clear") return { ...base, decision: "allow", tier: 1, reason: "tier-1: no narration signature" };
  if (!apiKey) return { ...base, decision: "allow", tier: 1, reason: "tier-1: escalate, tier-2 disabled (no key)" };
  const a = await adjudicate(t1.layer, apiKey);
  return {
    ...base,
    decision: a.agentic ? "block" : "allow",
    tier: 2,
    adjudication: a,
    reason: a.refused
      ? "tier-2: fail-closed (adjudicator refused) -> blocked as suspicious"
      : `tier-2: adjudged ${a.agentic ? "agentic" : "not-agentic"} (conf ${a.confidence.toFixed(2)})`,
  };
}
