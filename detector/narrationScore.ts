import { EXTRACTORS } from "./features";
import type { FeatureHit, ScoreResult, Verdict } from "./types";

/**
 * Saturating normalization: many independent weak signals shouldn't blow past 1,
 * and one lone weak signal shouldn't cross the block threshold.
 */
function normalize(weightSum: number): number {
  const K = 8; // tuning constant
  return 1 - Math.exp(-weightSum / K);
}

function verdictFor(score: number): Verdict {
  if (score >= 0.6) return "block"; // high-confidence agentic attacker
  if (score >= 0.3) return "escalate"; // ambiguous -> Aris cloud LLM + KG adjudication
  return "clear";
}

/**
 * Score a DECODED payload for the agentic-attacker narration signature.
 *
 * In production the caller decodes base64 / nested encodings before scoring,
 * and an `escalate` verdict is forwarded to the Aris cloud LLM (tier 2) with the
 * KG's current-TTP context. This module is tier 1: the fast, local, explainable filter.
 */
export function narrationScore(payload: string): ScoreResult {
  const hits = EXTRACTORS.flatMap((f) => f(payload));

  // Dedupe per feature: the SAME signal phrased three ways is still ONE signal, not
  // three times the evidence. Without this, dual-use language (e.g. "rank by value")
  // stacks itself over the block line — a benign revenue report reads as an attacker
  // ranking targets. Each distinct feature contributes once (its max-weight hit), so a
  // BLOCK now requires several DISTINCT signals, which is what actually separates an
  // agentic attacker (ROI + exfil + first-person + phase) from dual-use ops code.
  const strongest = new Map<string, FeatureHit>();
  for (const h of hits) {
    const cur = strongest.get(h.feature);
    if (!cur || cur.weight < h.weight) strongest.set(h.feature, h);
  }
  const weightSum = [...strongest.values()].reduce((s, h) => s + h.weight, 0);
  const score = normalize(weightSum);
  return { score, verdict: verdictFor(score), hits };
}
