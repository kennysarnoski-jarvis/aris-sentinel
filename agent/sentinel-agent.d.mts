// Types for the Linux agent's exported seams (used by test/unit/agent.test.ts).
import type { BehaviorOriginFacts, BehaviorTracker, DecisionResult, Tripwire } from "./sentinel-core.mjs";

export interface FalcoFields {
  "proc.pid": number | string;
  "proc.ppid"?: number | string;
  "proc.sid"?: number | string;
  "proc.exe"?: string;
  "proc.pname"?: string;
  "proc.cwd"?: string;
  "proc.cmdline"?: string;
  "user.name"?: string;
  [k: string]: unknown;
}

export const deps: {
  decide: (payload: string, sessionKey?: string | null, ctx?: { cwd?: string; command?: string; origin?: BehaviorOriginFacts | null }) => Promise<DecisionResult>;
  /** this host's tripwire once main() armed it (--tripwire); tests set their own */
  tripwire: Tripwire | null;
  /** the session-behavior tracker once main() turned it on (--behavior); tests set their own */
  behavior: BehaviorTracker | null;
  /** what the process was started with; tests flip these with the kill primitives stubbed */
  mode: { enforce: boolean; killSession: boolean };
  killTree: (pid: number) => number[];
  sessionPids: (sid: number) => number[];
  /** [pid, parent, grandparent, …]: a session kill takes the offender's ancestors first, outermost first */
  ancestorsOf: (pid: number) => number[];
  procName: (pid: number) => string;
  /** a process's parent pid, or null when it is gone: an ancestor chain is whole only if its top is a child of pid 1 */
  procParent: (pid: number) => number | null;
  /** the account that logged in (the kernel's loginuid: it survives sudo), or null when there was no login */
  loginUid: (pid: number) => number | null;
  noLogin: (pid: number) => boolean | null;
  /** the SSH client's address from the process's SSH_CONNECTION, or null */
  sshClient: (pid: number) => string | null;
  /** uid -> account name, read from /etc/passwd as a file */
  userName: (uid: number) => string;
  killPid: (pid: number) => void;
  /** session ids the agent lives in (its own + its ancestors'): never session-killed */
  ownSids: Set<number>;
  now: () => number;
};
export function parseStatSid(stat: string): number | null;
export function sessionKeyOf(f: FalcoFields): string | null;
/** where the event's session came from (facts for the core's origin rule), found once per session; null when no chain reaches init */
export function originOf(f: FalcoFields): BehaviorOriginFacts | null;
/** names of the processes above an exec, nearest first, from the event's own fields */
export function lineageOf(f: Record<string, unknown>): string[];
/** originOf plus the event's lineage and login fact: what the core's origin and service rules read */
export function behaviorFacts(f: FalcoFields): BehaviorOriginFacts | null;
export function hasInlineCode(exe: string, args: string[]): boolean;
export function interpreterOf(exe: string): "python" | "shell" | "node" | "perl" | "ruby" | "php" | null;
/** the first positional argument (the script), or null for a module run, stdin, or no positional */
export function scriptToken(exe: string, args: string[]): string | null;
export function resolveScript(tok: string, ctx?: { cwd?: string; pid?: number }): string | null;
export function extractPayload(f: FalcoFields): string;
/** Resolves to the DecisionResult on allow, undefined on block/alert/error (those go to the incident log). */
export function handleEvent(f: FalcoFields): Promise<DecisionResult | undefined>;
