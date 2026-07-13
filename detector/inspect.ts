import { candidateDecodings } from "./decode";
import { narrationScore } from "./narrationScore";
import type { ScoreResult } from "./types";

export interface InspectResult extends ScoreResult {
  /** the raw sink input */
  raw: string;
  /** the decoded layer that scored highest (=== raw when no decoding helped) */
  scoredLayer: string;
  /** whether the verdict came from a decoded layer, not the raw input */
  decoded: boolean;
  /** how many candidate layers were surfaced */
  layers: number;
}

/**
 * The sensor-side decision: decode a raw payload into all plausible layers,
 * score each for the agentic-narration signature, and return the strongest.
 * This is what an eBPF/app-sink interposition calls before allowing execution.
 * An `escalate` verdict is forwarded to the Aris cloud LLM (tier 2).
 */
export function inspect(raw: string): InspectResult {
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

  return {
    ...best,
    raw,
    scoredLayer,
    decoded: scoredLayer !== raw,
    layers: candidates.length,
  };
}
