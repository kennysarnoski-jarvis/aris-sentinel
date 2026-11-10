// Types for the Linux agent's exported seams (used by test/unit/agent.test.ts).
import type { DecisionResult } from "./sentinel-core.mjs";

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

export const deps: { decide: (payload: string, sessionKey?: string | null) => Promise<DecisionResult> };
export function sessionKeyOf(f: FalcoFields): string | null;
export function hasInlineCode(exe: string, args: string[]): boolean;
export function resolveScript(tok: string, ctx?: { cwd?: string; pid?: number }): string | null;
export function extractPayload(f: FalcoFields): string;
/** Resolves to the DecisionResult on allow, undefined on block/alert/error (those go to the incident log). */
export function handleEvent(f: FalcoFields): Promise<DecisionResult | undefined>;
