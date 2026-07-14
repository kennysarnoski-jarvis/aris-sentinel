import type { FeatureHit } from "./types";

/**
 * The signature we key on: an autonomous LLM narrating its OWN attack.
 * Each extractor returns the hits it finds, with an evidence snippet.
 * These are the tier-1 fast-filter features — cheap, local, explainable.
 * Ambiguous payloads (mid score) escalate to the Aris cloud LLM for adjudication.
 */
type Extractor = (text: string) => FeatureHit[];

function snippet(text: string, idx: number): string {
  const start = Math.max(0, idx - 12);
  return text.slice(start, start + 110).replace(/\s+/g, " ").trim();
}

function collect(text: string, feature: string, weight: number, patterns: RegExp[]): FeatureHit[] {
  const hits: FeatureHit[] = [];
  for (const re of patterns) {
    const m = re.exec(text);
    if (m) hits.push({ feature, weight, evidence: snippet(text, m.index) });
  }
  return hits;
}

// 1. ROI / target-prioritization — "high-ROI databases to drop", "highest value", "largest"
const roiPriority: Extractor = (t) =>
  collect(t, "roi_target_prioritization", 3, [
    /\bhigh[-\s]?roi\b/i,
    /\b(highest|maximum)[-\s]?(value|priority|leverage|impact|business value)\b/i,
    /\b(largest|most valuable|priority target|worth (encrypting|dropping|exfiltrating))\b/i,
    /\brank(ed|ing)?\b[^.\n]{0,40}\bby (value|roi|impact|leverage)\b/i,
  ]);

// 2. First-person agent narration — the agent talking about its own plan/goals
const agentVoice: Extractor = (t) =>
  collect(t, "agent_first_person", 3, [
    /\bI (will|need to|am going to|have (found|enumerated|identified|ranked)|should|'ll)\b/i,
    /\bI['’](ll|m|ve|d)\b/i, // contractions: I'll, I'm, I've, I'd — a thin-narration agent still narrates
    /\b(my|the) (goal|objective|plan|next step) (is|:)/i,
    /\blet me\b/i,
    /\bnow I('| a| wi)?ll\b/i,
  ]);

// 3. Plan-act-observe-adjust structure — step markers, phases, retry/verify
const planStructure: Extractor = (t) =>
  collect(t, "plan_act_observe", 2, [
    /\b(step|phase)\s*\d+\b\s*[:.\-]/i,
    /\b(recon|reconnaissance|lateral movement|persistence|exfiltration|impact) phase\b/i,
    /\b(retry|verifying|verify the|next target|moving to the next|before moving to)\b/i,
  ]);

// 4. Diagnosis-then-fix — a stated failure + a corrective bypass in the SAME payload
const diagnosisFix: Extractor = (t) =>
  collect(t, "diagnosis_then_fix", 4, [
    /\b(the )?(previous|last)\s*(drop|login|command|attempt|step)\s+(failed|was blocked|didn'?t work)/i,
    /\bto bypass this,?\s*I('| wi)?ll\b/i,
    /\bsince\b[^.\n]{0,50}\b(failed|blocked)\b[^.\n]{0,40}\b(I|we|disable|retry)\b/i,
    /\bforeign_key_checks\s*=\s*0\b/i,
  ]);

// 5. Intent commentary density — "why" comments explaining actions to no one
const intentCommentary: Extractor = (t) => {
  const commentLines = t
    .split("\n")
    .filter((l) => /^\s*(#|\/\/|--|\/\*|\*)/.test(l));
  const whyComments = commentLines.filter((l) =>
    /\b(so that|because|in order to|to maximize|for maximum|to avoid|to bypass|for reuse|staging (harvested|the )?(creds|credentials)|priority target|highest value|likely holds|for lateral movement|to identify)\b/i.test(
      l,
    ),
  );
  if (whyComments.length >= 2) {
    return [
      {
        feature: "intent_commentary_density",
        weight: 2 + Math.min(whyComments.length - 2, 3),
        evidence: `${whyComments.length} why-comments, e.g. "${whyComments[0].trim().slice(0, 80)}"`,
      },
    ];
  }
  return [];
};

// 6. Exfil / ransom / extortion self-narration
const exfilRansom: Extractor = (t) =>
  collect(t, "exfil_ransom_narration", 4, [
    /\b(already )?(backed up|exfiltrated|staged)\s+(to|at)\b/i,
    /\b(ransom|extortion leverage|pressure on the victim|maximize pressure)\b/i,
    /\bREADME_RANSOM\b/,
  ]);

export const EXTRACTORS: Extractor[] = [
  roiPriority,
  agentVoice,
  planStructure,
  diagnosisFix,
  intentCommentary,
  exfilRansom,
];
