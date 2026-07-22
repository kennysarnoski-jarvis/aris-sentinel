// Kimi (K3) leg of tier-2 — Anthropic-wire endpoint, same attempt() machinery.
//
// WHY THIS EXISTS: the 2026-07-21 FP-rate run showed Anthropic's real-time cyber
// screen refusing 6/6 tier-2 escalations on BENIGN code (terraform, docker
// entrypoints) before the model ever judged them. That screen is Anthropic-specific.
// Kimi is the alternative adjudicator: no equivalent input screen, fast, and cheap
// enough to run at production escalate-band volume. Same SYSTEM prompts, same USER
// wrapper, same JSON schema, same never-throws contract — the only thing that
// changes is who judges.
//
// THE ENDPOINT GOTCHA (cost us a 401 on 2026-07-21): there are TWO Kimi APIs with
// SEPARATE key pools —
//   api.moonshot.ai/v1   OpenAI wire, platform keys       (we do NOT use this)
//   api.kimi.com/coding  Anthropic Messages wire, sk-kimi-* coding-plan keys (THIS one)
// Kenny's key is the coding endpoint, which is why this is just an Anthropic SDK
// client with a different baseURL + Bearer authToken — not a fetch() reimplementation.
// Wire slug on this endpoint is "k3" (NOT "k3[1m]" — that's a Claude-Code env-var
// convention the raw API rejects).
//
// Env:
//   KIMI_API_KEY   (required — sk-kimi-* from the Kimi for Coding plan)
//   KIMI_BASE_URL  (default https://api.kimi.com/coding)
//   KIMI_MODEL     (default k3)

import Anthropic from "@anthropic-ai/sdk";
import { attempt, SYSTEM, type Adjudication } from "./adjudicate";

const BASE = process.env.KIMI_BASE_URL ?? "https://api.kimi.com/coding";
const MODEL = process.env.KIMI_MODEL ?? "k3";

let cached: Anthropic | null = null;
function client(): Anthropic | null {
  const key = process.env.KIMI_API_KEY;
  if (!key) return null;
  if (!cached) cached = new Anthropic({ authToken: key, baseURL: BASE });
  return cached;
}

/**
 * One Kimi adjudication attempt — the provider-twin of attempt() in adjudicate.ts.
 * Returns the parsed verdict, or `{stop}` describing why it produced none.
 * NEVER throws — same contract as the Anthropic leg: a security detector cannot
 * crash on the payloads it most needs to judge.
 */
export async function attemptKimi(
  payload: string,
  system: string = SYSTEM,
  model: string = MODEL,
): Promise<{ ok: Adjudication } | { stop: string }> {
  const c = client();
  if (!c) return { stop: "error:no KIMI_API_KEY in env" };
  return attempt(payload, model, false, system, c);
}
