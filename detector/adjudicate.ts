/**
 * Tier 2 — the LLM adjudication, typed wrapper over the canonical core
 * (agent/sentinel-core.mjs). Judges the CONCEPT ("is this an autonomous LLM narrating
 * an attack?") so it catches agentic attacks in styles the regexes never saw.
 *
 * Provider chain (ARIS_TIER2_ORDER, default local → anthropic → openai → kimi; each
 * leg joins only when configured):
 *  local      OpenAI-compatible endpoint on loopback (Ollama / vLLM): nothing leaves the box
 *  anthropic  Claude Opus 5.5 with server-side fallbacks + a de-fanged-prompt retry
 *  openai     api.openai.com or any remote OpenAI-compatible endpoint
 *  kimi       Kimi K3 on the Anthropic wire
 *  nobody answers -> fail CLOSED (refused: true). Never throws, never passes.
 *
 * Raw fetch (no SDK), per-attempt timeout + chain deadline, every reply strictly
 * validated, classifier refusals surfaced as `refusal:<category>` stops.
 */
import {
  attempt as coreAttempt,
  adjudicate as coreAdjudicate,
  providers,
  providerWarnings,
  fallbackCapable,
  SYSTEM,
  SYSTEM_AUTHORSHIP,
  USER,
  parseVerdict,
  DEFAULT_MODEL,
  ANTHROPIC_URL,
} from "../agent/sentinel-core.mjs";
import type { Adjudication, AttemptResult, Provider } from "../agent/sentinel-core.mjs";

export { SYSTEM, SYSTEM_AUTHORSHIP, USER, providers, providerWarnings, fallbackCapable, DEFAULT_MODEL };
export type { Adjudication, AttemptResult, Provider };

/** Parse + strictly validate a model's text reply. Null when there is no usable verdict. */
export const parse = parseVerdict;

/**
 * One adjudication attempt. Defaults to the Anthropic endpoint (ANTHROPIC_API_KEY) with
 * server-side fallbacks when the model supports them; pass `provider` to aim it at
 * another configured leg (see adjudicateKimi.ts, or `providers()` for the local one).
 * Returns the parsed verdict, or `{stop}` describing why it produced none. NEVER throws.
 */
export function attempt(
  payload: string,
  model: string = DEFAULT_MODEL,
  thinking = true,
  system: string = SYSTEM,
  provider?: Pick<Provider, "url" | "headers" | "wire"> & Partial<Pick<Provider, "effort" | "fallbacks">>,
): Promise<AttemptResult> {
  const p = provider ?? {
    url: (process.env.ANTHROPIC_BASE_URL || ANTHROPIC_URL).replace(/\/$/, "") + "/v1/messages",
    headers: { "x-api-key": process.env.ANTHROPIC_API_KEY ?? "" },
    wire: "anthropic" as const,
    fallbacks: process.env.ARIS_TIER2_FALLBACKS !== "0" && fallbackCapable(model),
  };
  return coreAttempt(payload, { url: p.url, headers: p.headers, wire: p.wire, model, thinking, system, effort: p.effort, fallbacks: !!p.fallbacks });
}

/** Run the provider chain. `model` overrides the Anthropic leg's model (smoke tests use a cheap one). */
export function adjudicate(payload: string, model?: string): Promise<Adjudication> {
  return coreAdjudicate(payload, model ? { model } : {});
}
