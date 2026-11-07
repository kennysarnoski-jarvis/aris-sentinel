/**
 * The full two-tier decision — typed wrapper over the canonical core
 * (agent/sentinel-core.mjs). This is what a sensor / interposition calls before
 * allowing a payload to reach its sink.
 *
 *   block  → tier-1 high-confidence narration, tier-2 agentic, or tier-2 fail-closed
 *   alert  → escalate band that tier 2 could NOT adjudicate (no key / budget spent):
 *            logged + reported, never killed. Same policy from every entry point.
 *   allow  → tier-1 clear, or tier-2 not-agentic
 *
 * Cost discipline: tier 1 resolves block/clear locally with zero LLM spend; only the
 * escalate band pays for adjudication, and the core's governor caches verdicts,
 * dedupes in-flight calls, caps concurrency and enforces a per-minute budget.
 */
import { decide as coreDecide } from "../agent/sentinel-core.mjs";
import type { Adjudicator, DecideOptions, DecisionResult, Decision } from "../agent/sentinel-core.mjs";

export type { Adjudicator, DecisionResult, Decision };

/** `adjudicator` is injectable so decide() is unit-testable with a stub and runs real with a key. */
export function decide(raw: string, adjudicator?: Adjudicator, opts: DecideOptions = {}): Promise<DecisionResult> {
  return coreDecide(raw, adjudicator ? { ...opts, adjudicator } : opts);
}
