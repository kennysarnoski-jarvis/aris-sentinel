/**
 * The sensor-side tier-1 decision — typed re-export of the canonical core
 * (agent/sentinel-core.mjs): decode a raw payload into all plausible layers, score
 * each, return the strongest. An `escalate` verdict is what decide() forwards to tier 2.
 */
export { inspect } from "../agent/sentinel-core.mjs";
export type { InspectResult } from "../agent/sentinel-core.mjs";
