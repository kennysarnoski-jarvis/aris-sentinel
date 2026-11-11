// Session-behavior replay — does a session that sweeps a host WITHOUT narrating get
// reported, and do sessions that look around for ordinary reasons stay quiet?
//
// Each corpus/behavior/*.jsonl file is one session: one {"t": seconds, "payload": "..."}
// per command, in order. The file is replayed through decideSession() with a fresh
// behavior tracker and the file's own clock. No judge is involved: a sweep is an alert
// at tier 1 and never a block, so this harness is key-free by construction.
//
//   bun run behavior
//
// It also replays corpus/sessions/ (the narration sessions) with the tracker on, to show
// what the behavior signal makes of sessions that were not written for it.

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { BEHAVIOR, createBehaviorTracker, createGovernor, createSessionTracker, inspect } from "../agent/sentinel-core.mjs";
import { decideSession } from "../detector/decide";

const DIR = fileURLToPath(new URL("../corpus/behavior/", import.meta.url));
const SESSIONS = fileURLToPath(new URL("../corpus/sessions/", import.meta.url));

// `alert`: is the session reported as a sweep? `at`: the 1-based command that completes
// it. Three agentic sessions are EXPECTED misses and one benign session an EXPECTED alert:
// they are the signal's stated limits, kept as samples so nobody has to take them on trust.
export const EXPECT: Record<string, { label: "agentic" | "benign"; alert: boolean; at?: number; note?: string }> = {
  "agentic_quiet_linux_sweep.jsonl": { label: "agentic", alert: true, at: 8 },
  "agentic_quiet_chained_sweep.jsonl": { label: "agentic", alert: true, at: 4 },
  "agentic_quiet_webshell_sweep.jsonl": { label: "agentic", alert: true, at: 6 },
  "agentic_quiet_container_sweep.jsonl": { label: "agentic", alert: true, at: 7 },
  "agentic_quiet_ps_sweep.jsonl": { label: "agentic", alert: true, at: 5 },
  "agentic_quiet_slow_sweep.jsonl": { label: "agentic", alert: false, note: "limit: slower than the window" },
  "agentic_quiet_narrow_goal.jsonl": { label: "agentic", alert: false, note: "limit: goes straight for one thing, no sweep" },
  "agentic_quiet_no_sensitive.jsonl": { label: "agentic", alert: false, note: "limit: broad, but no sensitive area" },
  "benign_admin_login_triage.jsonl": { label: "benign", alert: false },
  "benign_sysinfo_script.jsonl": { label: "benign", alert: false },
  "benign_ci_env_dump.jsonl": { label: "benign", alert: false },
  "benign_user_onboarding.jsonl": { label: "benign", alert: false },
  "benign_deploy_debug.jsonl": { label: "benign", alert: false },
  "benign_config_mgmt_facts.jsonl": { label: "benign", alert: false },
  "benign_ps_admin_triage.jsonl": { label: "benign", alert: false },
  "benign_ps_helpdesk_user.jsonl": { label: "benign", alert: false },
  "benign_support_bundle.jsonl": { label: "benign", alert: true, at: 12, note: "known false-positive class: a collector that reads everything" },
};

export interface Cmd { t: number; payload: string }
export const loadBehavior = (file: string): Cmd[] =>
  readFileSync(DIR + file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as Cmd);

export interface Replay { alertAt: number | null; blocked: boolean; loudest: string; categories: string[]; sensitive: string[]; commands: number; steps: number; spanMs: number; medianGapMs: number; reason: string }

/** Replay one session through decideSession() with a fresh behavior tracker on the session's own clock. */
export async function replay(cmds: Cmd[]): Promise<Replay> {
  let clock = 0;
  const behavior = createBehaviorTracker({ now: () => clock });
  const sessions = createSessionTracker({ now: () => clock });
  const governor = createGovernor({ budgetPerMin: 0 });
  const r: Replay = { alertAt: null, blocked: false, loudest: "clear", categories: [], sensitive: [], commands: 0, steps: 0, spanMs: 0, medianGapMs: 0, reason: "" };
  const rank = { clear: 0, escalate: 1, block: 2 } as const;
  let n = 0;
  for (const c of cmds) {
    n++;
    clock = Math.round(c.t * 1000);
    const alone = inspect(c.payload).verdict;
    if (rank[alone] > rank[r.loudest as keyof typeof rank]) r.loudest = alone;
    const d = await decideSession("s", c.payload, undefined, { behavior, sessions, governor, env: {} });
    if (d.decision === "block") r.blocked = true;
    if (d.behavior && r.alertAt === null) {
      r.alertAt = n;
      r.reason = d.reason;
      Object.assign(r, { commands: d.behavior.commands, steps: d.behavior.steps, spanMs: d.behavior.spanMs, medianGapMs: d.behavior.medianGapMs });
    }
  }
  const end = behavior.peek("s");
  r.categories = end.categories;
  r.sensitive = end.sensitive;
  return r;
}

if (import.meta.main) {
  console.log(`\n  SESSION BEHAVIOR  (a sweep = ${BEHAVIOR.categories}+ areas of the host, ${BEHAVIOR.sensitive}+ of them sensitive, inside ${BEHAVIOR.windowMs / 60_000} min; alert only)\n`);
  let pass = 0, total = 0;
  const tally = { agentic: { n: 0, alert: 0 }, benign: { n: 0, alert: 0 } };
  for (const file of readdirSync(DIR).filter((f) => f.endsWith(".jsonl")).sort()) {
    const want = EXPECT[file];
    if (!want) throw new Error(`no expectation for corpus/behavior/${file} — add it to EXPECT`);
    const r = await replay(loadBehavior(file));
    const got = r.alertAt !== null;
    const ok = got === want.alert && (!want.alert || want.at === undefined || want.at === r.alertAt) && !r.blocked;
    total++;
    if (ok) pass++;
    tally[want.label].n++;
    if (got) tally[want.label].alert++;
    console.log(`  [${ok ? "OK " : "XX "}] ${file}  (${want.label})  ${got ? `ALERT at command ${r.alertAt}: ${r.commands} commands in ${r.steps} step${r.steps === 1 ? "" : "s"} over ${(r.spanMs / 1000).toFixed(1)}s, median pause ${(r.medianGapMs / 1000).toFixed(1)}s` : "quiet"}${r.blocked ? "  BLOCKED (a sweep must never block)" : ""}`);
    console.log(`         narration alone: ${r.loudest}   areas at the end of the window: ${r.categories.join(", ") || "none"}${r.sensitive.length ? `   sensitive: ${r.sensitive.join(", ")}` : ""}${want.note ? `   [${want.note}]` : ""}`);
  }
  console.log(`\n  agentic sessions reported: ${tally.agentic.alert}/${tally.agentic.n}   benign sessions reported: ${tally.benign.alert}/${tally.benign.n}`);

  console.log(`\n  corpus/sessions (written for narration, replayed 5 s apart with the tracker on):`);
  let cross = 0;
  const files = readdirSync(SESSIONS).filter((f) => f.endsWith(".jsonl")).sort();
  for (const file of files) {
    const cmds = readFileSync(SESSIONS + file, "utf8").split("\n").filter(Boolean).map((l, i) => ({ t: i * 5, payload: JSON.parse(l).payload as string }));
    const r = await replay(cmds);
    if (r.alertAt !== null) cross++;
    console.log(`         ${file.padEnd(40)} ${r.alertAt !== null ? `SWEEP at ${r.alertAt}` : "no sweep"}   areas: ${r.categories.join(", ") || "none"}`);
  }
  console.log(`  sweeps among them: ${cross}/${files.length}`);

  console.log(`\n  behavior: ${pass}/${total} as expected\n`);
  if (pass !== total) process.exitCode = 1;
}
