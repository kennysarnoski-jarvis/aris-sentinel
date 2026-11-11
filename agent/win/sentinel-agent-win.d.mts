// Types for the Windows agent's exported seams (used by test/unit/agent-win.test.ts).
import type { DecisionResult, Tripwire, TripwireHit } from "../sentinel-core.mjs";

export interface SensorEvent {
  source?: string;
  pid: number | string;
  user?: string;
  comm?: string;
  payload: string;
}

export interface Incident {
  host: string;
  ts: string;
  decision: "block" | "alert" | "error";
  tier: 1 | 2 | null;
  action: string;
  pid: number;
  user?: string;
  exe: string;
  cmdline: string;
  score: number | null;
  signals: string[];
  reason: string;
  error?: string;
  conf: number | null;
  reasoning: string | null;
  narration: string;
  via_session?: boolean;
  session?: import("../sentinel-core.mjs").SessionSummary | null;
  /** what the tripwire saw (never the token itself), or null */
  tripwire?: TripwireHit | null;
  /** the sweep the session's behavior amounted to (area names only), or null */
  behavior?: import("../sentinel-core.mjs").BehaviorHit | null;
}

export const deps: {
  decide: (payload: string, sessionKey?: string | null) => Promise<DecisionResult>;
  /** this host's tripwire once main() armed it (--tripwire); tests set their own */
  tripwire: Tripwire | null;
  /** the session-behavior tracker once main() turned it on (--behavior); tests set their own */
  behavior: import("../sentinel-core.mjs").BehaviorTracker | null;
};
/** Resolves to the DecisionResult on allow, the written Incident otherwise. */
export function handleEvent(ev: SensorEvent): Promise<DecisionResult | Incident | undefined>;
