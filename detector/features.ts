/**
 * Tier-1 features — typed re-export of the canonical core.
 *
 * The patterns live in ONE place: agent/sentinel-core.mjs. This file used to hold a
 * hand-copied set that drifted from the one deployed on customer boxes; now the tests
 * prove the exact detector that ships. Edit the core, not this file.
 */
export { FEATURES, extractFeatures } from "../agent/sentinel-core.mjs";
export type { Feature, FeatureHit } from "../agent/sentinel-core.mjs";
