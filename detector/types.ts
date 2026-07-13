export type Label = "agentic" | "benign" | "human-malware";

export interface FeatureHit {
  /** which signature fired */
  feature: string;
  /** contribution to the raw weight sum */
  weight: number;
  /** the text that tripped it (for explainability + analyst review) */
  evidence: string;
}

export type Verdict = "block" | "escalate" | "clear";

export interface ScoreResult {
  /** 0..1 confidence that this payload was authored by an autonomous LLM attacker */
  score: number;
  verdict: Verdict;
  hits: FeatureHit[];
}
