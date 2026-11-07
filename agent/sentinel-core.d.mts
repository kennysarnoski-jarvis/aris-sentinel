// Type declarations for sentinel-core.mjs — the one canonical detector module.
// The .mjs stays plain JavaScript so it runs on a bare Node box; this file gives the
// TypeScript side (detector/*.ts, test/*.ts) types for it.

export interface FeatureHit {
  feature: string;
  weight: number;
  evidence: string;
}
export interface Feature {
  name: string;
  weight: number;
  patterns: RegExp[];
}
export type Verdict = "block" | "escalate" | "clear";
export type Decision = "block" | "alert" | "allow";

export interface ScoreResult {
  score: number;
  verdict: Verdict;
  hits: FeatureHit[];
  signals: string[];
}
export interface InspectResult extends ScoreResult {
  raw: string;
  scoredLayer: string;
  decoded: boolean;
  layers: number;
}

export interface Adjudication {
  agentic: boolean;
  confidence: number;
  reasoning: string;
  refused?: boolean;
}
export type AttemptResult = { ok: Adjudication } | { stop: string };

export interface Provider {
  name: string;
  url: string;
  headers: Record<string, string>;
  model: string;
  attempts: { thinking: boolean }[];
}
export interface AttemptOptions {
  url: string;
  headers?: Record<string, string>;
  model: string;
  thinking?: boolean;
  system?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}
export interface AdjudicateOptions {
  model?: string;
  system?: string;
  env?: Record<string, string | undefined>;
  fetch?: typeof fetch;
  timeoutMs?: number;
  deadlineMs?: number;
  providers?: Provider[];
}

export type GovernorResult =
  | { verdict: Adjudication; cached: boolean; deduped?: boolean }
  | { exhausted: true; budgetPerMin: number };
export interface Governor {
  run(key: string, fn: () => Promise<Adjudication>): Promise<GovernorResult>;
  stats(): { calls: number; cacheHits: number; deduped: number; exhausted: number; cached: number; inflight: number; active: number };
}
export interface GovernorOptions {
  cacheTtlMs?: number;
  cacheMax?: number;
  concurrency?: number;
  budgetPerMin?: number;
  now?: () => number;
}

export type Adjudicator = (payload: string) => Promise<Adjudication>;
export interface DecideOptions extends AdjudicateOptions {
  adjudicator?: Adjudicator;
  governor?: Governor;
  failMode?: "closed" | "alert";
}
export interface DecisionResult {
  decision: Decision;
  tier: 1 | 2;
  verdict: Verdict;
  score: number;
  scoredLayer: string;
  decoded: boolean;
  signals: string[];
  adjudication?: Adjudication;
  cached?: boolean;
  reason: string;
}

export const FEATURES: Feature[];
export const THRESHOLDS: { readonly block: number; readonly escalate: number };
export function verdictFor(score: number): Verdict;
export function extractFeatures(text: string): FeatureHit[];
export function narrationScore(text: string): ScoreResult;
export { narrationScore as score };
export function candidateDecodings(raw: string, maxDepth?: number): string[];
export function inspect(raw: string): InspectResult;

export const SYSTEM: string;
export const SYSTEM_AUTHORSHIP: string;
export const USER: (payload: string) => string;
export const DEFAULT_MODEL: string;
export const ANTHROPIC_URL: string;
export const KIMI_URL: string;
export const KIMI_MODEL: string;
export function normalizeVerdict(v: unknown): Adjudication | null;
export function parseVerdict(text: string): Adjudication | null;
export function providers(env?: Record<string, string | undefined>): Provider[];
export function hasTier2(env?: Record<string, string | undefined>): boolean;
export function attempt(payload: string, opts: AttemptOptions): Promise<AttemptResult>;
export function failClosed(why: string): Adjudication;
export function adjudicate(payload: string, opts?: AdjudicateOptions): Promise<Adjudication>;

export function createGovernor(opts?: GovernorOptions): Governor;
export const defaultGovernor: Governor;
export function payloadKey(s: string): string;

export function decide(raw: string, opts?: DecideOptions): Promise<DecisionResult>;
