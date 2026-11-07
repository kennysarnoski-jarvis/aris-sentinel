/**
 * Tier-1 scorer — typed re-export of the canonical core (agent/sentinel-core.mjs).
 * Dedupes per feature and saturates, so a BLOCK needs several DISTINCT signals.
 */
export { narrationScore, verdictFor, THRESHOLDS } from "../agent/sentinel-core.mjs";
