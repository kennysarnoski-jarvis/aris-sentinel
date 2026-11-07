// Shared detector types. The structural types come from the core's declaration file
// so the TS side and the deployed JS can never disagree about shapes.
export type Label = "agentic" | "benign" | "human-malware";
export type {
  FeatureHit,
  Verdict,
  Decision,
  ScoreResult,
  InspectResult,
  Adjudication,
  DecisionResult,
} from "../agent/sentinel-core.mjs";
