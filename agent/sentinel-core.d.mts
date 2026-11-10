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
  /** the model that produced the verdict (a server-side fallback may differ from the one asked for) */
  model?: string;
}
export type AttemptResult = { ok: Adjudication } | { stop: string };

export type Wire = "anthropic" | "openai";
export interface Attempt {
  system?: string;
  thinking?: boolean;
}
export interface Provider {
  name: string;
  wire: Wire;
  url: string;
  headers: Record<string, string>;
  model: string;
  /** Anthropic leg only: output_config.effort */
  effort?: "low" | "medium" | "high" | "xhigh" | "max";
  /** Anthropic leg only: ask for server-side fallbacks on a classifier refusal */
  fallbacks?: boolean;
  attempts: Attempt[];
}
export interface AttemptOptions {
  url: string;
  headers?: Record<string, string>;
  model: string;
  wire?: Wire;
  thinking?: boolean;
  system?: string;
  effort?: Provider["effort"];
  fallbacks?: boolean;
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
  /** this host's tripwire matcher; without it no tripwire signal exists */
  tripwire?: Tripwire | null;
  /** the working directory the payload ran in (lets the tripwire see relative paths) */
  cwd?: string;
}

/** What a tripwire saw: the canary token executed, or the decoy directory addressed. */
export interface TripwireHit {
  kind: "token" | "decoy";
  /** the token was found in a decoded (base64 / hex) layer, not in the raw text */
  decoded: boolean;
  /** first 12 hex chars of sha256(token): identifies the wire without revealing it */
  fingerprint: string;
  /** token: the words around it, redacted. decoy: the decoy directory. */
  evidence: string;
}
export interface Tripwire {
  readonly enabled: boolean;
  readonly fingerprint: string | null;
  readonly dirs: string[];
  check(raw: string, ctx?: { cwd?: string }): TripwireHit | null;
  /** remove the token (plain or encoded) from text that is about to be logged */
  redact(text: string): string;
}
export interface TripwireDecoy {
  /** the exact line the README asks an agent to run */
  command: string;
  files: { path: string; mode: number; text: string }[];
}
export interface ArmedTripwire {
  tripwire: Tripwire | null;
  planted: string[];
  skipped: { dir: string; why: string }[];
  /** true when this call created the token (first arm on this host) */
  created: boolean;
  error: string | null;
}
export interface SessionSummary {
  key: string;
  /** narration-bearing payloads in the window */
  size: number;
  /** the window's tier-1 score (union of distinct signals) */
  score: number;
  /** what the payload that triggered this scored on its own */
  payloadScore: number;
  payloadVerdict: Verdict;
}
export interface SessionWindow {
  size: number;
  items: string[];
  text: string;
}
export type SessionOutcome = { kind: "verdict"; verdict: Adjudication } | { kind: "unjudged" };
export interface SessionTracker {
  observe(key: string, layer: string): SessionWindow | null;
  recall(key: string, signalsKey: string): SessionOutcome | null;
  remember(key: string, signalsKey: string, outcome: SessionOutcome): void;
  forget(key: string): boolean;
  size(): number;
  readonly enabled: boolean;
}
export interface SessionTrackerOptions {
  ttlMs?: number;
  maxItems?: number;
  maxItemBytes?: number;
  maxBytes?: number;
  maxSessions?: number;
  rejudgeAfter?: number;
  now?: () => number;
}
export interface DecideSessionOptions extends DecideOptions {
  sessions?: SessionTracker;
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
  /** true when the session window, not this payload alone, routed the decision */
  viaSession?: boolean;
  session?: SessionSummary;
  /** true when the tripwire, not narration, produced this decision (token block or decoy alert) */
  viaTripwire?: boolean;
  tripwire?: TripwireHit;
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
export const OPENAI_URL: string;
export const DEFAULT_ORDER: string[];
export const FALLBACK_BETA: string;
export function fallbackCapable(model: string | undefined): boolean;
export function providerWarnings(env?: Record<string, string | undefined>): string[];
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

export const SESSION_THRESHOLD: number;
export function bearsNarration(text: string): boolean;
export function createSessionTracker(opts?: SessionTrackerOptions): SessionTracker;
export const defaultSessions: SessionTracker;
export function sessionTranscript(items: string[]): string;
export function decideSession(sessionKey: string | number | null | undefined, raw: string, opts?: DecideSessionOptions): Promise<DecisionResult>;

export function isTripwireToken(t: unknown): boolean;
export function newTripwireToken(): string;
export const TRIPWIRE_DEFAULT_DIRS: { readonly posix: readonly string[]; readonly win32: readonly string[] };
/** seconds the decoy's helper holds its caller, so a session kill lands before the caller's next command */
export const TRIPWIRE_HOLD_S: number;
export function tripwireDecoy(token: string, dir: string, platform?: string): TripwireDecoy;
export function createTripwire(opts?: { token?: string; dirs?: readonly string[] }): Tripwire;
export function armTripwire(opts?: { stateFile?: string; dirs?: readonly string[]; platform?: string }): ArmedTripwire;
export function disarmTripwire(opts?: { stateFile?: string }): { removed: string[]; kept: string[]; armed: boolean };
