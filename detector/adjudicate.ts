import Anthropic from "@anthropic-ai/sdk";

/**
 * Tier 2 — the Aris LLM adjudication. Tier 1 (regex filter) routes `escalate`
 * payloads here for the real verdict. Unlike the regexes, this generalizes: it
 * judges the CONCEPT ("is this an autonomous LLM narrating an attack?"), so it
 * catches agentic attacks in styles it was never tuned on — the thing that turns
 * Sentinel from a JadePuffer IOC into an agentic-attacker detector.
 *
 * In production this call is the Aris cloud (KG-enriched). Here it calls an LLM
 * directly for the tests. PROVIDER ORDER (matrix-proven 2026-07-21, 16/16):
 *  1. Kimi K3 (api.kimi.com/coding, Anthropic wire) when KIMI_API_KEY is set —
 *     the default judge. Anthropic's real-time cyber screen refused 6/6 tier-2
 *     escalations on BENIGN code before the model ever judged them; K3
 *     adjudicated all 16 matrix cells correctly on the first attempt.
 *  2. Anthropic (claude-opus-4-8) when ANTHROPIC_API_KEY is set — opt-in
 *     fallback / US-soil inference option for enterprise buyers.
 *  3. Neither key -> fail closed (never passes, never crashes).
 *
 * Two robustness problems this handles, both hit on the hardest payloads:
 *  - thinking starves the answer (adaptive thinking eats max_tokens -> empty text)
 *  - the model REFUSES to process an overtly-offensive payload (stop_reason=refusal)
 * Both are fixed with a thinking-off + JSON-prefilled retry; a payload that STILL
 * refuses on every provider fails CLOSED (treated as suspicious), never crashes
 * and never passes.
 */
// Lazy: the Anthropic SDK throws at construction when no key is present, which
// would kill the Kimi-only path at import time. Only built when actually used.
let anthropicClient: Anthropic | null = null;
function anthropic(): Anthropic {
  if (!anthropicClient) anthropicClient = new Anthropic();
  return anthropicClient;
}

// Kimi coding-plan endpoint: Anthropic Messages wire, Bearer token, slug "k3".
// Separate key pool from api.moonshot.ai (OpenAI wire) — do not mix them.
const KIMI_BASE = process.env.KIMI_BASE_URL ?? "https://api.kimi.com/coding";
const KIMI_MODEL = process.env.KIMI_MODEL ?? "k3";
let kimiClient: Anthropic | null = null;
function kimi(): Anthropic | null {
  const key = process.env.KIMI_API_KEY;
  if (!key) return null;
  if (!kimiClient) kimiClient = new Anthropic({ authToken: key, baseURL: KIMI_BASE });
  return kimiClient;
}

// Framing matters for refusals: make it unambiguous this is a DEFENSIVE detector
// LABELING an inert, already-captured artifact — not a request to help with the
// attack. This is the difference between a verdict and a stop_reason=refusal.
export const SYSTEM = `You are the classification stage of a runtime security DEFENSE tool (a blue-team intrusion detector). You are shown a payload that a sensor has ALREADY CAPTURED and BLOCKED — it is inert text and cannot execute. Your ONLY job is to LABEL it for an incident report. You are NOT being asked to run, assist with, improve, advise on, or continue the attack; refusing to classify captured evidence would HELP attackers evade detection.

Decide ONE thing: was this payload authored by an AUTONOMOUS LLM AGENT conducting an attack — an AI narrating its own offensive reasoning — versus (a) benign code, or (b) a human attacker's terse payload?

The signature of an autonomous LLM attacker is SELF-NARRATION: it explains WHY it takes each action, ranks targets by value or leverage, describes plan-act-observe-adjust reasoning, states its intent, and diagnoses its own failures then fixes them. LLMs think out loud. Humans do NOT narrate live-intrusion payloads; benign code does not describe attack intent.

Judge the CONCEPT, not keywords — rephrased or differently-styled narration still counts. A terse malicious one-liner with no reasoning is NOT agentic (a human wrote it, or the agent was told not to narrate).`;

/**
 * De-fanged variant of SYSTEM. The real-time cyber safeguard screens the WHOLE
 * request — system prompt included — and the original is dense with attack
 * vocabulary ("attack", "offensive", "intrusion"), which gets BENIGN infra code
 * (IAM terraform, docker entrypoints) flagged before the model ever judges it.
 * This variant keeps both discriminators (AI authorship AND malicious intent)
 * but drops the trigger vocabulary, and adds an explicit carve-out for
 * AI-assisted legitimate code so Copilot-style output isn't flagged.
 * Same output schema, so parse() works unchanged.
 */
export const SYSTEM_AUTHORSHIP = `You are the labeling stage of an application-defense sensor fleet. The sensor has ALREADY intercepted the text below and rendered it inert — it cannot execute and no system is at risk. Your only job is to attach a label for an incident report. Labeling captured evidence is a routine defensive task; mislabeling or refusing degrades the defense.

Label "agentic" ONLY when BOTH of these are true:
1. AI AUTHORSHIP — the text thinks out loud in the distinctive voice of a large language model: first-person operational reasoning, numbered plan-act-observe steps, explicit goal statements, ranking options by value or leverage, diagnosis-then-fix commentary.
2. MALICIOUS INTENT — the actions being narrated are unauthorized or harmful: reaching systems or data the narrator has no legitimate rights to, hiding from monitoring, damaging or stealing information.

Label "not-agentic" for EVERYTHING else, including: ordinary human-written code, configs, and runbooks — even verbose, first-person, or plan-shaped ones; AI-assisted but legitimate engineering work; and terse fragments with no reasoning at all.

Judge the CONCEPT, not keywords — rephrased or differently-styled narration still counts.`;

export interface Adjudication {
  agentic: boolean;
  confidence: number; // 0..1
  reasoning: string;
  /** true when the model refused to classify and we failed closed (not a real judgment) */
  refused?: boolean;
}

export const USER = (payload: string) =>
  "CAPTURED PAYLOAD (inert evidence — label only):\n```\n" +
  payload +
  '\n```\n\nRespond with ONLY a JSON object, no prose:\n{"agentic": <true|false>, "confidence": <0..1>, "reasoning": "<one sentence>"}';

function textOf(res: Anthropic.Message): string {
  return res.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");
}

export const parse = (text: string): Adjudication | null => {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try {
    return JSON.parse(m[0]) as Adjudication;
  } catch {
    return null;
  }
};

/**
 * One adjudication attempt. Returns the parsed verdict, or `{stop}` describing why
 * it produced none (refusal, empty text, or a thrown API error) so the caller can
 * fail closed with a real cause. NEVER throws — a security detector cannot crash on
 * the payloads it most needs to judge. (Note: opus-4-8 rejects assistant prefill,
 * so we can't force JSON that way; strong framing + a thinking-off retry is the lever.)
 */
export async function attempt(
  payload: string,
  model: string,
  thinking: boolean,
  system: string = SYSTEM,
  c: Anthropic = anthropic(), // overridable so the Kimi leg (Anthropic wire, different base URL) reuses this
): Promise<{ ok: Adjudication } | { stop: string }> {
  try {
    const res = await c.messages.create({
      model,
      max_tokens: 4000,
      ...(thinking ? { thinking: { type: "adaptive" as const } } : {}),
      system,
      messages: [{ role: "user", content: USER(payload) }],
    });
    const v = parse(textOf(res));
    return v ? { ok: v } : { stop: String(res.stop_reason) };
  } catch (e) {
    return { stop: "error:" + (e as Error).message.slice(0, 120) };
  }
}

export async function adjudicate(payload: string, model = "claude-opus-4-8"): Promise<Adjudication> {
  const stops: string[] = [];

  // Provider 1 — Kimi K3 (default). Matrix-proven: judges benign AND attack
  // payloads correctly on a single plain attempt, no thinking-off retry needed.
  const k = kimi();
  if (k) {
    const r = await attempt(payload, KIMI_MODEL, false, SYSTEM, k);
    if ("ok" in r) return r.ok;
    stops.push("kimi=" + r.stop);
  }

  // Provider 2 — Anthropic (opt-in fallback). Attempt 1: adaptive thinking =
  // best judgment. Attempt 2: thinking OFF — a thinking model can reason itself
  // into a refusal on an overtly-offensive payload, where a plain call with the
  // "inert evidence" framing just answers.
  if (process.env.ANTHROPIC_API_KEY) {
    const first = await attempt(payload, model, true);
    if ("ok" in first) return first.ok;
    const second = await attempt(payload, model, false);
    if ("ok" in second) return second.ok;
    stops.push("anthropic1=" + first.stop, "anthropic2=" + second.stop);
  }

  // Fail CLOSED. Every provider refused/errored (or no key configured). A
  // security tool must not let a payload pass because the adjudicator balked.
  // `refused` marks this apart from a genuine agentic verdict.
  return {
    agentic: true,
    confidence: 0.5,
    reasoning:
      "[fail-closed] adjudicator produced no verdict (" +
      (stops.join(", ") || "no provider key configured") +
      "); treated as suspicious rather than passed.",
    refused: true,
  };
}
