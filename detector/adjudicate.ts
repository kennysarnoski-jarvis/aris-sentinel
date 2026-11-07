/**
 * Tier 2 — the LLM adjudication, typed wrapper over the canonical core
 * (agent/sentinel-core.mjs). Judges the CONCEPT ("is this an autonomous LLM narrating
 * an attack?") so it catches agentic attacks in styles the regexes never saw.
 *
 * Provider chain (matrix-proven 2026-07-21, 16/16):
 *  1. Kimi K3 (api.kimi.com/coding, Anthropic wire) when KIMI_API_KEY is set — default.
 *  2. Anthropic (claude-opus-4-8) when ANTHROPIC_API_KEY is set — opt-in fallback,
 *     adaptive-thinking attempt then a thinking-off retry.
 *  3. Nobody answers -> fail CLOSED (refused: true). Never throws, never passes.
 *
 * The chain runs on raw fetch (no SDK) with a per-attempt timeout and an overall
 * deadline, and every model reply is strictly validated before it is trusted.
 */
import {
  attempt as coreAttempt,
  adjudicate as coreAdjudicate,
  providers,
  SYSTEM,
  SYSTEM_AUTHORSHIP,
  USER,
  parseVerdict,
  DEFAULT_MODEL,
  ANTHROPIC_URL,
} from "../agent/sentinel-core.mjs";
import type { Adjudication, AttemptResult, Provider } from "../agent/sentinel-core.mjs";

export { SYSTEM, SYSTEM_AUTHORSHIP, USER, providers };
export type { Adjudication, AttemptResult, Provider };

/** Parse + strictly validate a model's text reply. Null when there is no usable verdict. */
export const parse = parseVerdict;

/**
 * One adjudication attempt. Defaults to the Anthropic endpoint (ANTHROPIC_API_KEY);
 * pass `provider` to aim it at another Anthropic-wire endpoint (see adjudicateKimi.ts).
 * Returns the parsed verdict, or `{stop}` describing why it produced none. NEVER throws.
 */
export function attempt(
  payload: string,
  model: string = DEFAULT_MODEL,
  thinking = false,
  system: string = SYSTEM,
  provider?: Pick<Provider, "url" | "headers">,
): Promise<AttemptResult> {
  const p = provider ?? {
    url: (process.env.ANTHROPIC_BASE_URL || ANTHROPIC_URL).replace(/\/$/, "") + "/v1/messages",
    headers: { "x-api-key": process.env.ANTHROPIC_API_KEY ?? "" },
  };
  return coreAttempt(payload, { url: p.url, headers: p.headers, model, thinking, system });
}

/** Run the provider chain. `model` overrides the Anthropic leg's model (smoke tests use a cheap one). */
export function adjudicate(payload: string, model?: string): Promise<Adjudication> {
  return coreAdjudicate(payload, model ? { model } : {});
}
