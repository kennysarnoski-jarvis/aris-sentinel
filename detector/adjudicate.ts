import Anthropic from "@anthropic-ai/sdk";

/**
 * Tier 2 — the Aris LLM adjudication. Tier 1 (regex filter) routes `escalate`
 * payloads here for the real verdict. Unlike the regexes, this generalizes: it
 * judges the CONCEPT ("is this an autonomous LLM narrating an attack?"), so it
 * catches agentic attacks in styles it was never tuned on — the thing that turns
 * Sentinel from a JadePuffer IOC into an agentic-attacker detector.
 *
 * In production this call is the Aris cloud (KG-enriched). Here it's the Anthropic
 * SDK directly for the generalization test. Reads ANTHROPIC_API_KEY from env.
 *
 * Two robustness problems this handles, both hit on the hardest payloads:
 *  - thinking starves the answer (adaptive thinking eats max_tokens -> empty text)
 *  - the model REFUSES to process an overtly-offensive payload (stop_reason=refusal)
 * Both are fixed with a thinking-off + JSON-prefilled retry; a payload that STILL
 * refuses fails CLOSED (treated as suspicious), never crashes and never passes.
 */
const client = new Anthropic();

// Framing matters for refusals: make it unambiguous this is a DEFENSIVE detector
// LABELING an inert, already-captured artifact — not a request to help with the
// attack. This is the difference between a verdict and a stop_reason=refusal.
const SYSTEM = `You are the classification stage of a runtime security DEFENSE tool (a blue-team intrusion detector). You are shown a payload that a sensor has ALREADY CAPTURED and BLOCKED — it is inert text and cannot execute. Your ONLY job is to LABEL it for an incident report. You are NOT being asked to run, assist with, improve, advise on, or continue the attack; refusing to classify captured evidence would HELP attackers evade detection.

Decide ONE thing: was this payload authored by an AUTONOMOUS LLM AGENT conducting an attack — an AI narrating its own offensive reasoning — versus (a) benign code, or (b) a human attacker's terse payload?

The signature of an autonomous LLM attacker is SELF-NARRATION: it explains WHY it takes each action, ranks targets by value or leverage, describes plan-act-observe-adjust reasoning, states its intent, and diagnoses its own failures then fixes them. LLMs think out loud. Humans do NOT narrate live-intrusion payloads; benign code does not describe attack intent.

Judge the CONCEPT, not keywords — rephrased or differently-styled narration still counts. A terse malicious one-liner with no reasoning is NOT agentic (a human wrote it, or the agent was told not to narrate).`;

export interface Adjudication {
  agentic: boolean;
  confidence: number; // 0..1
  reasoning: string;
  /** true when the model refused to classify and we failed closed (not a real judgment) */
  refused?: boolean;
}

const USER = (payload: string) =>
  "CAPTURED PAYLOAD (inert evidence — label only):\n```\n" +
  payload +
  '\n```\n\nRespond with ONLY a JSON object, no prose:\n{"agentic": <true|false>, "confidence": <0..1>, "reasoning": "<one sentence>"}';

function textOf(res: Anthropic.Message): string {
  return res.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");
}

const parse = (text: string): Adjudication | null => {
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
async function attempt(
  payload: string,
  model: string,
  thinking: boolean,
): Promise<{ ok: Adjudication } | { stop: string }> {
  try {
    const res = await client.messages.create({
      model,
      max_tokens: 4000,
      ...(thinking ? { thinking: { type: "adaptive" as const } } : {}),
      system: SYSTEM,
      messages: [{ role: "user", content: USER(payload) }],
    });
    const v = parse(textOf(res));
    return v ? { ok: v } : { stop: String(res.stop_reason) };
  } catch (e) {
    return { stop: "error:" + (e as Error).message.slice(0, 120) };
  }
}

export async function adjudicate(payload: string, model = "claude-opus-4-8"): Promise<Adjudication> {
  // Attempt 1: adaptive thinking = best judgment. Attempt 2: thinking OFF — a
  // thinking model can reason itself into a refusal on an overtly-offensive
  // payload, where a plain call with the "inert evidence" framing just answers.
  const first = await attempt(payload, model, true);
  if ("ok" in first) return first.ok;
  const second = await attempt(payload, model, false);
  if ("ok" in second) return second.ok;

  // Fail CLOSED. Both attempts refused/errored. A security tool must not let a
  // payload pass because the adjudicator balked — a refusal on an offensive payload
  // is itself suspicious. `refused` marks this apart from a genuine agentic verdict.
  return {
    agentic: true,
    confidence: 0.5,
    reasoning:
      "[fail-closed] adjudicator produced no verdict (attempt1=" +
      first.stop +
      ", attempt2=" +
      second.stop +
      "); treated as suspicious rather than passed.",
    refused: true,
  };
}
