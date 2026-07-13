import { inspect, type InspectResult } from "./inspect";
import { adjudicate, type Adjudication } from "./adjudicate";

/**
 * The full two-tier decision — what a sensor/interposition actually calls before
 * allowing a payload to reach its sink. This is the wire that was missing: tier 1
 * (fast local filter) alone only BLOCKS high-confidence narration and lets
 * `escalate` (ambiguous) payloads through. Here `escalate` is forwarded to tier 2
 * (the Aris LLM adjudication), which is the only stage that catches novel-style
 * agentic attacks the regexes were never tuned on.
 *
 * Cost discipline: tier 1 resolves `block`/`clear` locally with zero LLM spend;
 * only the `escalate` band pays for adjudication. The fast filter shields the cloud.
 */

export type Decision = "block" | "allow";

export interface DecisionResult {
  decision: Decision;
  /** which tier made the final call */
  tier: 1 | 2;
  /** tier-1 verdict that routed the decision */
  verdict: InspectResult["verdict"];
  score: number;
  /** the decoded layer tier-1 scored highest (=== raw when nothing decoded) */
  scoredLayer: string;
  decoded: boolean;
  signals: string[];
  /** present iff tier 2 ran */
  adjudication?: Adjudication;
  reason: string;
}

/** Injectable so `decide` is unit-testable with a stub and runs real with a key. */
export type Adjudicator = (payload: string) => Promise<Adjudication>;

export async function decide(raw: string, adjudicator: Adjudicator = adjudicate): Promise<DecisionResult> {
  const t1 = inspect(raw);
  const base = {
    verdict: t1.verdict,
    score: t1.score,
    scoredLayer: t1.scoredLayer,
    decoded: t1.decoded,
    signals: t1.hits.map((h) => h.feature),
  };

  // Fast paths — resolved locally, no LLM cost.
  if (t1.verdict === "block") {
    return { ...base, decision: "block", tier: 1, reason: "tier-1: high-confidence agentic narration" };
  }
  if (t1.verdict === "clear") {
    return { ...base, decision: "allow", tier: 1, reason: "tier-1: no narration signature" };
  }

  // escalate -> tier 2 adjudicates the layer where the narration actually lived.
  const a = await adjudicator(t1.scoredLayer);
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
