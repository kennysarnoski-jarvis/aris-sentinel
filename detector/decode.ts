/**
 * Decode stage — typed re-export of the canonical core (agent/sentinel-core.mjs).
 * Surfaces every plausible base64 / hex / nested decoding so the scorer inspects the
 * layer where the attacker actually hid the narration. The evasion becomes the trap.
 */
export { candidateDecodings } from "../agent/sentinel-core.mjs";
