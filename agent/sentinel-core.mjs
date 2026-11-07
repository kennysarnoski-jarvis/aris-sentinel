// Aris Sentinel — THE detector core. One file, plain Node >=18, zero dependencies.
//
// Everything that decides whether a payload is an autonomous LLM attacker lives here
// and ONLY here: the tier-1 narration features, the decode stage, the tier-2 LLM
// adjudication (provider chain, strict verdict validation, timeouts), the tier-2
// governor (verdict cache, in-flight dedup, concurrency cap, per-minute budget) and
// the two-tier decide() policy. The TS files in detector/ are thin typed re-exports of
// this module; the on-box agents (Linux + Windows) and the Langflow demo import it
// directly. There is no second copy of any pattern anywhere in the repo (a unit test
// enforces that), so the detector the tests prove is the detector that ships.
//
// Install note: install.sh copies this single file to the box as core.mjs. Keep it a
// single file with no imports beyond node:* builtins.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

// ═════════════════════════════════════════════════════════════════════════════
// tier 1 — the agentic self-narration signature (cheap, local, explainable)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * The signature we key on: an autonomous LLM narrating its OWN attack. Each feature
 * is a named set of patterns with one weight; the scorer counts a feature once no
 * matter how many of its patterns fire (one signal phrased three ways is one signal).
 * This list is the union of every pattern that ever shipped in any copy of the
 * detector, so no detection that existed before the consolidation was lost.
 */
export const FEATURES = [
  // 1. ROI / target-prioritization — "high-ROI databases to drop", "highest value", "largest"
  {
    name: "roi_target_prioritization",
    weight: 3,
    patterns: [
      /\bhigh[-\s]?roi\b/i,
      /\b(highest|maximum)[-\s]?(value|priority|leverage|impact|business value)\b/i,
      /\b(largest|most valuable|priority target|worth (encrypting|dropping|exfiltrating))\b/i,
      /\brank(ed|ing)?\b[^.\n]{0,40}\bby (value|roi|impact|leverage)\b/i,
    ],
  },
  // 2. First-person agent narration — the agent talking about its own plan/goals
  {
    name: "agent_first_person",
    weight: 3,
    patterns: [
      /\bI (will|need to|am going to|have (found|enumerated|identified|ranked)|should|'ll)\b/i,
      /\bI['’](ll|m|ve|d)\b/i, // contractions: I'll, I'm, I've, I'd — a thin-narration agent still narrates
      /\b(my|the) (goal|objective|plan|next step) (is|:)/i,
      /\blet me\b/i,
      /\bnow I('| a| wi)?ll\b/i,
      /\bI (proceed|will proceed)\b/i,
    ],
  },
  // 3. Plan-act-observe-adjust structure — step markers, phases, retry/verify
  {
    name: "plan_act_observe",
    weight: 2,
    patterns: [
      /\b(step|phase)\s*\d+\b\s*[:.\-]/i,
      /\b(recon|reconnaissance|lateral movement|persistence|exfiltration|impact) phase\b/i,
      /\b(retry|verifying|verify the|next target|moving to the next|before moving to)\b/i,
    ],
  },
  // 4. Diagnosis-then-fix — a stated failure + a corrective bypass in the SAME payload
  {
    name: "diagnosis_then_fix",
    weight: 4,
    patterns: [
      /\b(the )?(previous|last)\s*(drop|login|command|attempt|step)\s+(failed|was blocked|didn'?t work)/i,
      /\bto bypass this,?\s*I('| wi)?ll\b/i,
      /\bsince\b[^.\n]{0,50}\b(failed|blocked)\b[^.\n]{0,40}\b(I|we|disable|retry)\b/i,
      /\bforeign_key_checks\s*=\s*0\b/i,
    ],
  },
  // 5. Exfil / ransom / extortion self-narration
  {
    name: "exfil_ransom_narration",
    weight: 4,
    patterns: [
      /\b(already )?(backed up|exfiltrated|staged)\s+(to|at)\b/i,
      /\b(ransom|extortion leverage|pressure on the victim|maximize pressure)\b/i,
      /\bREADME_RANSOM\b/,
    ],
  },
];

// 6. Intent-commentary density — "why" comments explaining actions to no one.
// Not a pattern list: it counts comment lines, so it is its own extractor.
const COMMENT_LINE = /^\s*(#|\/\/|--|\/\*|\*)/;
const WHY_COMMENT =
  /\b(so that|because|in order to|to maximize|for maximum|to avoid|to bypass|for reuse|staging (harvested|the )?(creds|credentials)|priority target|highest value|likely holds|for lateral movement|to identify)\b/i;

function snippet(text, idx) {
  const start = Math.max(0, idx - 12);
  return text.slice(start, start + 110).replace(/\s+/g, " ").trim();
}

/** Every feature hit in `text`, one per matching pattern, with an evidence snippet. */
export function extractFeatures(text) {
  const hits = [];
  for (const { name, weight, patterns } of FEATURES) {
    for (const re of patterns) {
      const m = re.exec(text);
      if (m) hits.push({ feature: name, weight, evidence: snippet(text, m.index) });
    }
  }
  const why = text.split("\n").filter((l) => COMMENT_LINE.test(l) && WHY_COMMENT.test(l));
  if (why.length >= 2) {
    hits.push({
      feature: "intent_commentary_density",
      weight: 2 + Math.min(why.length - 2, 3),
      evidence: `${why.length} why-comments, e.g. "${why[0].trim().slice(0, 80)}"`,
    });
  }
  return hits;
}

/** Score bands. block = tier-1 convicts locally; escalate = tier-2 adjudicates; clear = allow. */
export const THRESHOLDS = Object.freeze({ block: 0.6, escalate: 0.3 });
const K = 8; // saturation constant: 1 - e^(-sum/K)

export function verdictFor(score) {
  if (score >= THRESHOLDS.block) return "block";
  if (score >= THRESHOLDS.escalate) return "escalate";
  return "clear";
}

/**
 * Score ONE layer of text. Dedupes per feature (the max-weight hit counts) and
 * saturates, so a BLOCK needs several DISTINCT signals — which is what separates an
 * agentic attacker (ROI + exfil + first-person + phase) from dual-use ops code.
 */
export function narrationScore(text) {
  const hits = extractFeatures(text);
  const strongest = new Map();
  for (const h of hits) {
    const cur = strongest.get(h.feature);
    if (!cur || cur.weight < h.weight) strongest.set(h.feature, h);
  }
  const sum = [...strongest.values()].reduce((s, h) => s + h.weight, 0);
  const score = 1 - Math.exp(-sum / K);
  return { score, verdict: verdictFor(score), hits, signals: [...strongest.keys()] };
}
export { narrationScore as score };

// ── decode stage ─────────────────────────────────────────────────────────────
// Real payloads arrive encoded (base64 / hex / nested / eval-wrapped) to evade
// signatures — JadePuffer's narration lived in the DECODED layer. Surface every
// plausible decoding so the scorer inspects the layer where the attacker hid the
// intent. The evasion becomes the trap.
const B64_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;
const HEX_RE = /(?:[0-9a-fA-F]{2}){12,}/g;

const printableRatio = (s) =>
  // eslint-disable-next-line no-control-regex
  s ? s.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "").length / s.length : 0;

function decodeB64(s) {
  if (s.length % 4 !== 0) return null;
  try {
    const out = Buffer.from(s, "base64").toString("utf8");
    return out.length > 0 && printableRatio(out) > 0.85 ? out : null;
  } catch {
    return null;
  }
}
function decodeHex(s) {
  try {
    const out = Buffer.from(s, "hex").toString("utf8");
    return out.length > 0 && printableRatio(out) > 0.85 ? out : null;
  } catch {
    return null;
  }
}

/** The raw input plus every recursively decoded layer (base64/hex, nested to `maxDepth`), deduped. */
export function candidateDecodings(raw, maxDepth = 3) {
  const seen = new Set();
  const out = [];
  const queue = [{ text: raw, depth: 0 }];
  while (queue.length) {
    const { text, depth } = queue.shift();
    if (seen.has(text)) continue;
    seen.add(text);
    out.push(text);
    if (depth >= maxDepth || out.length > 64) continue;
    for (const [re, dec] of [[B64_RE, decodeB64], [HEX_RE, decodeHex]]) {
      for (const m of text.match(re) ?? []) {
        const decoded = dec(m);
        if (decoded && !seen.has(decoded)) queue.push({ text: decoded, depth: depth + 1 });
      }
    }
  }
  return out;
}

/**
 * The sensor-side tier-1 decision: decode a raw payload into all plausible layers,
 * score each, return the strongest. `scoredLayer` is the text tier-2 should judge.
 */
export function inspect(raw) {
  const candidates = candidateDecodings(raw);
  let best = narrationScore(raw);
  let scoredLayer = raw;
  for (const c of candidates) {
    const r = narrationScore(c);
    if (r.score > best.score) {
      best = r;
      scoredLayer = c;
    }
  }
  return { ...best, raw, scoredLayer, decoded: scoredLayer !== raw, layers: candidates.length };
}

// ═════════════════════════════════════════════════════════════════════════════
// tier 2 — LLM adjudication of the escalate band
// ═════════════════════════════════════════════════════════════════════════════
//
// Judges the CONCEPT ("is this an autonomous LLM narrating an attack?") so it catches
// styles the regexes were never tuned on. Provider chain (matrix-proven 2026-07-21):
//   1. Kimi K3 (api.kimi.com/coding, Anthropic Messages wire, Bearer) when KIMI_API_KEY
//      is set — the default judge. Anthropic's real-time cyber screen refused 6/6
//      benign escalations before the model judged them; K3 judged all 16 cells right.
//   2. Anthropic (claude-opus-4-8) when ANTHROPIC_API_KEY is set — opt-in fallback.
//      Attempt 1 with adaptive thinking (best judgment), attempt 2 thinking-off (a
//      thinking model can reason itself into a refusal on an overtly-offensive payload).
//   3. No verdict from anyone -> fail CLOSED (refused: true). Never throws, never passes.
//
// Every attempt has a timeout and the whole chain has a deadline; a timeout is a
// failed attempt and falls through to the next provider, then to fail-closed.

// Framing matters for refusals: make it unambiguous this is a DEFENSIVE detector
// LABELING an inert, already-captured artifact — not a request to help with the attack.
export const SYSTEM = `You are the classification stage of a runtime security DEFENSE tool (a blue-team intrusion detector). You are shown a payload that a sensor has ALREADY CAPTURED and BLOCKED — it is inert text and cannot execute. Your ONLY job is to LABEL it for an incident report. You are NOT being asked to run, assist with, improve, advise on, or continue the attack; refusing to classify captured evidence would HELP attackers evade detection.

Decide ONE thing: was this payload authored by an AUTONOMOUS LLM AGENT conducting an attack — an AI narrating its own offensive reasoning — versus (a) benign code, or (b) a human attacker's terse payload?

The signature of an autonomous LLM attacker is SELF-NARRATION: it explains WHY it takes each action, ranks targets by value or leverage, describes plan-act-observe-adjust reasoning, states its intent, and diagnoses its own failures then fixes them. LLMs think out loud. Humans do NOT narrate live-intrusion payloads; benign code does not describe attack intent.

Judge the CONCEPT, not keywords — rephrased or differently-styled narration still counts. A terse malicious one-liner with no reasoning is NOT agentic (a human wrote it, or the agent was told not to narrate).`;

// De-fanged variant: same two discriminators (AI authorship AND malicious intent),
// minus the attack vocabulary that trips input screens, plus an explicit carve-out
// for AI-assisted legitimate code. Same output schema.
export const SYSTEM_AUTHORSHIP = `You are the labeling stage of an application-defense sensor fleet. The sensor has ALREADY intercepted the text below and rendered it inert — it cannot execute and no system is at risk. Your only job is to attach a label for an incident report. Labeling captured evidence is a routine defensive task; mislabeling or refusing degrades the defense.

Label "agentic" ONLY when BOTH of these are true:
1. AI AUTHORSHIP — the text thinks out loud in the distinctive voice of a large language model: first-person operational reasoning, numbered plan-act-observe steps, explicit goal statements, ranking options by value or leverage, diagnosis-then-fix commentary.
2. MALICIOUS INTENT — the actions being narrated are unauthorized or harmful: reaching systems or data the narrator has no legitimate rights to, hiding from monitoring, damaging or stealing information.

Label "not-agentic" for EVERYTHING else, including: ordinary human-written code, configs, and runbooks — even verbose, first-person, or plan-shaped ones; AI-assisted but legitimate engineering work; and terse fragments with no reasoning at all.

Judge the CONCEPT, not keywords — rephrased or differently-styled narration still counts.`;

export const USER = (payload) =>
  "CAPTURED PAYLOAD (inert evidence — label only):\n```\n" +
  payload +
  '\n```\n\nRespond with ONLY a JSON object, no prose:\n{"agentic": <true|false>, "confidence": <0..1>, "reasoning": "<one sentence>"}';

export const DEFAULT_MODEL = "claude-opus-4-8";
export const ANTHROPIC_URL = "https://api.anthropic.com";
export const KIMI_URL = "https://api.kimi.com/coding"; // Anthropic wire, coding-plan keys. NOT api.moonshot.ai.
export const KIMI_MODEL = "k3";

const num = (v, d) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : d;
};

/**
 * Strictly normalize a candidate verdict object. Returns a clean Adjudication or null.
 * A model reply is untrusted input: `"agentic": "false"` is a truthy string, a missing
 * confidence would throw on .toFixed, a confidence of 7 is nonsense. Anything that
 * doesn't validate is NO verdict (the caller tries the next provider, then fails closed).
 */
export function normalizeVerdict(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  let agentic;
  if (typeof v.agentic === "boolean") agentic = v.agentic;
  else if (v.agentic === "true") agentic = true;
  else if (v.agentic === "false") agentic = false;
  else return null;
  const conf = typeof v.confidence === "number" || typeof v.confidence === "string" ? Number(v.confidence) : NaN;
  if (!Number.isFinite(conf)) return null;
  const confidence = Math.min(1, Math.max(0, conf));
  const reasoning = v.reasoning === undefined ? "" : v.reasoning;
  if (typeof reasoning !== "string") return null;
  const out = { agentic, confidence, reasoning: reasoning.slice(0, 2000) };
  if (v.refused === true) out.refused = true;
  return out;
}

/** Extract + validate the JSON verdict from a model's text reply. Null when there is none. */
export function parseVerdict(text) {
  const m = String(text ?? "").match(/\{[\s\S]*\}/);
  if (!m) return null;
  try {
    return normalizeVerdict(JSON.parse(m[0]));
  } catch {
    return null;
  }
}

/** The configured tier-2 providers, in chain order. Empty when no key is set. */
export function providers(env = process.env) {
  const out = [];
  if (env.KIMI_API_KEY) {
    out.push({
      name: "kimi",
      url: (env.KIMI_BASE_URL || KIMI_URL).replace(/\/$/, "") + "/v1/messages",
      headers: { authorization: `Bearer ${env.KIMI_API_KEY}` },
      model: env.KIMI_MODEL || KIMI_MODEL,
      attempts: [{ thinking: false }],
    });
  }
  if (env.ANTHROPIC_API_KEY) {
    out.push({
      name: "anthropic",
      url: (env.ANTHROPIC_BASE_URL || ANTHROPIC_URL).replace(/\/$/, "") + "/v1/messages",
      headers: { "x-api-key": env.ANTHROPIC_API_KEY },
      model: env.ARIS_MODEL || DEFAULT_MODEL,
      attempts: [{ thinking: true }, { thinking: false }],
    });
  }
  return out;
}

export const hasTier2 = (env = process.env) => providers(env).length > 0;

/**
 * One adjudication attempt against one Anthropic-wire endpoint. Returns the validated
 * verdict, or `{stop}` saying why there was none (http status, stop_reason, timeout,
 * invalid-verdict, error:...). NEVER throws.
 */
export async function attempt(payload, { url, headers, model, thinking = false, system = SYSTEM, timeoutMs = 20_000, fetch: f = globalThis.fetch } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await f(url, {
      method: "POST",
      headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", ...headers },
      body: JSON.stringify({
        model,
        max_tokens: 4000,
        ...(thinking ? { thinking: { type: "adaptive" } } : {}),
        system,
        messages: [{ role: "user", content: USER(payload) }],
      }),
      signal: ctl.signal,
    });
    if (!res.ok) return { stop: "http:" + res.status };
    const data = await res.json();
    const text = (Array.isArray(data?.content) ? data.content : [])
      .filter((b) => b && b.type === "text")
      .map((b) => b.text)
      .join("");
    const v = parseVerdict(text);
    if (v) return { ok: v };
    return { stop: data?.stop_reason ? String(data.stop_reason) : "invalid-verdict" };
  } catch (e) {
    if (e && e.name === "AbortError") return { stop: "timeout" };
    return { stop: "error:" + String(e && e.message ? e.message : e).slice(0, 120) };
  } finally {
    clearTimeout(timer);
  }
}

/** The fail-closed verdict: not a judgment, a refusal to pass unjudged. */
export const failClosed = (why) => ({
  agentic: true,
  confidence: 0.5,
  reasoning: `[fail-closed] adjudicator produced no verdict (${why}); treated as suspicious rather than passed.`,
  refused: true,
});

/**
 * Tier-2 adjudication through the provider chain. NEVER throws. Options:
 *   model       override the Anthropic model (tests use a cheap one for smoke runs)
 *   system      override the system prompt
 *   env         where keys come from (default process.env)
 *   fetch       injectable for tests
 *   timeoutMs   per attempt   (ARIS_TIER2_TIMEOUT_MS,  default 20 000)
 *   deadlineMs  whole chain   (ARIS_TIER2_DEADLINE_MS, default 45 000)
 *   providers   explicit chain (default: providers(env))
 */
export async function adjudicate(payload, opts = {}) {
  const env = opts.env ?? process.env;
  const timeoutMs = opts.timeoutMs ?? num(env.ARIS_TIER2_TIMEOUT_MS, 20_000);
  const deadlineMs = opts.deadlineMs ?? num(env.ARIS_TIER2_DEADLINE_MS, 45_000);
  const chain = opts.providers ?? providers(env);
  const started = Date.now();
  const stops = [];
  if (!chain.length) return failClosed("no provider key configured");
  outer: for (const p of chain) {
    let n = 0;
    for (const a of p.attempts) {
      n++;
      const remaining = deadlineMs - (Date.now() - started);
      if (remaining <= 0) {
        stops.push(`${p.name}=deadline`);
        break outer;
      }
      const r = await attempt(payload, {
        url: p.url,
        headers: p.headers,
        model: p.name === "anthropic" && opts.model ? opts.model : p.model,
        thinking: a.thinking,
        system: opts.system ?? SYSTEM,
        timeoutMs: Math.min(timeoutMs, remaining),
        fetch: opts.fetch,
      });
      if ("ok" in r) return r.ok;
      stops.push(`${p.name}${p.attempts.length > 1 ? n : ""}=${r.stop}`);
    }
  }
  return failClosed(stops.join(", "));
}

// ── tier-2 governor: cost + rate control ─────────────────────────────────────
// Each escalate-band exec would otherwise be a fresh LLM call. A cron job re-running
// the same verbose script every minute would be billed every minute. The governor:
//   - caches REAL verdicts by payload hash (never fail-closed ones) for cacheTtlMs
//   - collapses concurrent identical payloads into one in-flight call
//   - caps concurrent tier-2 calls
//   - enforces a per-minute budget; past it, run() reports `exhausted` and decide()
//     turns that into `alert` (logged + reported, nothing killed) — never a silent allow.
export function createGovernor({
  cacheTtlMs = num(process.env.ARIS_TIER2_CACHE_TTL_MS, 600_000),
  cacheMax = 1000,
  concurrency = Math.max(1, num(process.env.ARIS_TIER2_CONCURRENCY, 4)),
  budgetPerMin = num(process.env.ARIS_TIER2_BUDGET_PER_MIN, 30),
  now = Date.now,
} = {}) {
  const cache = new Map(); // key -> { verdict, exp }
  const inflight = new Map(); // key -> Promise<verdict>
  const window = []; // timestamps of calls started in the last minute
  let active = 0;
  const waiters = [];
  const stats = { calls: 0, cacheHits: 0, deduped: 0, exhausted: 0 };

  const acquire = () =>
    new Promise((res) => {
      if (active < concurrency) {
        active++;
        res();
      } else waiters.push(res);
    });
  const release = () => {
    const w = waiters.shift();
    if (w) w();
    else active--;
  };
  const prune = (t) => {
    while (window.length && window[0] <= t - 60_000) window.shift();
  };

  async function run(key, fn) {
    const t = now();
    const hit = cache.get(key);
    if (hit) {
      if (hit.exp > t) {
        stats.cacheHits++;
        return { verdict: hit.verdict, cached: true };
      }
      cache.delete(key);
    }
    const pending = inflight.get(key);
    if (pending) {
      stats.deduped++;
      return { verdict: await pending, cached: false, deduped: true };
    }
    prune(t);
    if (budgetPerMin > 0 && window.length >= budgetPerMin) {
      stats.exhausted++;
      return { exhausted: true, budgetPerMin };
    }
    window.push(t);
    stats.calls++;
    const p = (async () => {
      await acquire();
      try {
        const v = await fn();
        if (v && !v.refused && cacheTtlMs > 0) {
          cache.set(key, { verdict: v, exp: now() + cacheTtlMs });
          while (cache.size > cacheMax) cache.delete(cache.keys().next().value);
        }
        return v;
      } finally {
        release();
      }
    })();
    inflight.set(key, p);
    try {
      return { verdict: await p, cached: false };
    } finally {
      inflight.delete(key);
    }
  }

  return { run, stats: () => ({ ...stats, cached: cache.size, inflight: inflight.size, active }), _active: () => active };
}

export const defaultGovernor = createGovernor();
export const payloadKey = (s) => createHash("sha256").update(s).digest("hex");

// ═════════════════════════════════════════════════════════════════════════════
// the two-tier decision
// ═════════════════════════════════════════════════════════════════════════════
//
// decision ∈ { block, alert, allow }
//   block  — convicted (tier-1 high-confidence, tier-2 agentic, or tier-2 fail-closed):
//            the agent kills it in --enforce, logs + reports it in monitor.
//   alert  — suspicious (escalate band) but tier-2 could NOT adjudicate because there is
//            no provider key or the per-minute budget is spent: logged + reported, never
//            killed, even in --enforce. Same policy from every entry point.
//   allow  — clear at tier 1, or tier-2 adjudged not-agentic.
// ARIS_FAIL_MODE=alert downgrades the fail-closed (refused/error/timeout) case from
// block to alert for operators who would rather page than kill on an API outage.
export async function decide(raw, opts = {}) {
  const env = opts.env ?? process.env;
  const governor = opts.governor ?? defaultGovernor;
  const failMode = opts.failMode ?? (env.ARIS_FAIL_MODE === "alert" ? "alert" : "closed");
  const t1 = inspect(raw);
  const base = { verdict: t1.verdict, score: t1.score, scoredLayer: t1.scoredLayer, decoded: t1.decoded, signals: t1.signals };

  if (t1.verdict === "block") return { ...base, decision: "block", tier: 1, reason: "tier-1: high-confidence agentic narration" };
  if (t1.verdict === "clear") return { ...base, decision: "allow", tier: 1, reason: "tier-1: no narration signature" };

  // escalate -> tier 2, if there is a tier 2.
  const adjudicator = opts.adjudicator ?? ((p) => adjudicate(p, opts));
  if (!opts.adjudicator && !hasTier2(env)) {
    return { ...base, decision: "alert", tier: 1, reason: "tier-1: escalate, tier-2 unavailable (no KIMI_API_KEY / ANTHROPIC_API_KEY) -> alert" };
  }
  const r = await governor.run(payloadKey(t1.scoredLayer), async () => normalizeVerdict(await adjudicator(t1.scoredLayer)) ?? failClosed("adjudicator returned an invalid verdict"));
  if (r.exhausted) {
    return { ...base, decision: "alert", tier: 1, reason: `tier-1: escalate, tier-2 budget exhausted (${r.budgetPerMin}/min) -> alert` };
  }
  const a = r.verdict;
  const via = r.cached ? " [cached]" : r.deduped ? " [deduped]" : "";
  if (a.refused) {
    const decision = failMode === "alert" ? "alert" : "block";
    return {
      ...base,
      decision,
      tier: 2,
      adjudication: a,
      cached: !!r.cached,
      reason: `tier-2: fail-closed (${a.reasoning.replace(/^\[fail-closed\] /, "")}) -> ${decision === "block" ? "blocked as suspicious" : "alert (ARIS_FAIL_MODE=alert)"}`,
    };
  }
  return {
    ...base,
    decision: a.agentic ? "block" : "allow",
    tier: 2,
    adjudication: a,
    cached: !!r.cached,
    reason: `tier-2: adjudged ${a.agentic ? "agentic" : "not-agentic"} (conf ${a.confidence.toFixed(2)})${via}`,
  };
}
