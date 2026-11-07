// Kimi (K3) leg of tier-2 — the same core attempt() aimed at the Kimi endpoint.
//
// WHY THIS EXISTS: the 2026-07-21 FP-rate run showed Anthropic's real-time cyber
// screen refusing 6/6 tier-2 escalations on BENIGN code (terraform, docker
// entrypoints) before the model ever judged them. That screen is Anthropic-specific.
// Kimi is the default adjudicator: no equivalent input screen, fast, and cheap enough
// to run at production escalate-band volume. Same prompts, same JSON schema, same
// never-throws contract — only the judge changes.
//
// THE ENDPOINT GOTCHA (cost us a 401 on 2026-07-21): there are TWO Kimi APIs with
// SEPARATE key pools —
//   api.moonshot.ai/v1   OpenAI wire, platform keys       (we do NOT use this)
//   api.kimi.com/coding  Anthropic Messages wire, sk-kimi-* coding-plan keys (THIS one)
// Wire slug on this endpoint is "k3" (NOT "k3[1m]" — a Claude-Code env convention).
//
// Env:
//   KIMI_API_KEY   (required — sk-kimi-* from the Kimi for Coding plan)
//   KIMI_BASE_URL  (default https://api.kimi.com/coding)
//   KIMI_MODEL     (default k3)

import { attempt, SYSTEM } from "./adjudicate";
import { providers } from "../agent/sentinel-core.mjs";
import type { AttemptResult } from "../agent/sentinel-core.mjs";

/** One Kimi adjudication attempt. `{stop}` (never a throw) when no key or no verdict. */
export function attemptKimi(payload: string, system: string = SYSTEM, model?: string): Promise<AttemptResult> {
  const kimi = providers(process.env).find((p) => p.name === "kimi");
  if (!kimi) return Promise.resolve({ stop: "error:no KIMI_API_KEY in env" });
  return attempt(payload, model ?? kimi.model, false, system, kimi);
}
