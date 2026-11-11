#!/usr/bin/env node
// Aris Sentinel — Windows agent (plain Node >=18, no deps).
//
// The Windows sibling of the Linux agent. It consumes the PowerShell/process event
// stream from sensor.ps1, scores each with the SAME two-tier brain (../sentinel-core.mjs),
// and on a detection reports off-box and (in --enforce) kills the offending process tree
// with taskkill. The detector is unchanged — only the sensor and the kill primitive differ.
//
//   node sentinel-agent-win.mjs            # MONITOR (default) — detect + alert, no kill
//   node sentinel-agent-win.mjs --enforce  # kill the offending PowerShell process tree
//   node sentinel-agent-win.mjs --tripwire  # (any mode) plant a decoy whose README asks an agent
//                                           # to run one canary command: run -> block, looked at -> alert
//   node sentinel-agent-win.mjs --tripwire-remove   # take the decoy away again, then exit
//   node sentinel-agent-win.mjs --behavior  # (any mode) report a PowerShell process that asks about
//                                           # many areas of the host in a few minutes: alert only
//   node sentinel-agent-win.mjs --mock      # replay agent/win/mock-events.jsonl (no Windows)
//
//   env: ANTHROPIC_API_KEY / OPENAI_BASE_URL+OPENAI_MODEL / KIMI_API_KEY (tier 2)  ARIS_CLOUD_URL + ARIS_INGEST_KEY (alerts)
//        ARIS_SENSOR (path to sensor.ps1)  ARIS_INCIDENTS (incident log)  ARIS_HOST  ARIS_VERBOSE=1
//        ARIS_FAIL_MODE / ARIS_TIER2_* — see ../sentinel-agent.mjs
//        ARIS_TRIPWIRE_STATE (where the tripwire token is kept)  ARIS_TRIPWIRE_DIRS (comma-separated decoy dirs)
//        ARIS_TRIPWIRE_README (a file with this host's own decoy text)  ARIS_TRIPWIRE_HELPER / ARIS_TRIPWIRE_FLAG (its own names)
//        ARIS_BEHAVIOR_WINDOW_MS (the --behavior window, default 300000)
//
// Decisions: block → monitor logs/reports, enforce kills.  alert → logged + reported,
// never killed.  error → the detector threw: logged + reported, never dropped.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { readFileSync, appendFileSync } from "node:fs";
import { hostname } from "node:os";
import { win32 } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { armTripwire, BEHAVIOR, createBehaviorTracker, createTripwire, decideSession, defaultSessions, disarmTripwire, hasTier2, newTripwireToken, providers, providerWarnings, tripwireDecoy, tripwireLookFromEnv } from "../sentinel-core.mjs";

const ENFORCE = process.argv.includes("--enforce");
const MONITOR = !ENFORCE;
const MOCK = process.argv.includes("--mock");
// TRIPWIRE: opt-in, any mode. See the core for what it plants and the policy.
const TRIPWIRE = process.argv.includes("--tripwire");
// BEHAVIOR: opt-in, any mode. A PowerShell process that sweeps the host is reported, never killed.
const BEHAVIOR_ON = process.argv.includes("--behavior");
const TRIPWIRE_REMOVE = process.argv.includes("--tripwire-remove");
const TRIPWIRE_STATE = process.env.ARIS_TRIPWIRE_STATE || win32.join(process.env.ProgramData || "C:\\ProgramData", "aris-sentinel", "tripwire.json");
const TRIPWIRE_DIRS = (process.env.ARIS_TRIPWIRE_DIRS || "").split(",").map((s) => s.trim()).filter(Boolean);
const VERBOSE = process.env.ARIS_VERBOSE === "1";
const CLOUD_URL = process.env.ARIS_CLOUD_URL;
const CLOUD_KEY = process.env.ARIS_INGEST_KEY || "";
const HOST = process.env.ARIS_HOST || hostname();
const SENSOR = process.env.ARIS_SENSOR || fileURLToPath(new URL("./sensor.ps1", import.meta.url));
const INCIDENT_LOG = process.env.ARIS_INCIDENTS || "";
const OWN_PID = process.pid;
const MAX_PAYLOAD = 256 * 1024;

// Never kill these by name (killing them BSODs Windows) — plus never our own pid.
const PROTECTED = new Set([
  "system", "idle", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
  "services.exe", "lsass.exe", "svchost.exe", "node.exe",
]);

const now = () => new Date().toISOString();
const log = (m) => console.log(`[${now()}] ${m}`);

function narrationSnippet(payload) {
  const lines = payload.split("\n").map((l) => l.trim());
  const narrated = lines.filter((l) => /^(#|<#)/.test(l) || /\bI (will|need to|am|have|'ll)\b/i.test(l) || /\bI['’](ll|m|ve|d)\b/i.test(l));
  return (narrated.length ? narrated : lines.filter(Boolean)).join(" ").replace(/^[#<\s]+/gm, "").trim().slice(0, 600);
}

function reportToCloud(inc) {
  if (!CLOUD_URL) return;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 5000);
  fetch(`${CLOUD_URL}/api/local/sentinel/alert`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-aris-key": CLOUD_KEY },
    body: JSON.stringify(inc),
    signal: ctl.signal,
  }).then((r) => { if (!r.ok) log(`cloud alert failed: HTTP ${r.status}`); })
    .catch((e) => log(`cloud alert error: ${e.name === "AbortError" ? "timeout" : e.message}`))
    .finally(() => clearTimeout(t));
}

function writeIncident(inc) {
  if (!INCIDENT_LOG) return;
  try { appendFileSync(INCIDENT_LOG, JSON.stringify(inc) + "\n"); } catch (e) { log(`incident log write failed: ${e.message}`); }
}

// taskkill /T /F kills the process AND its child tree on Windows.
function killTree(pid) {
  if (MOCK) return; // never actually kill in a mock replay
  try { spawn("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore" }); } catch {}
}

// Injectable seam for tests (swap `deps.decide` to simulate a throwing detector).
// A PowerShell process IS a session: its script blocks share one pid, so narration spread
// across several blocks is judged as one transcript.
// `tripwire` is this host's matcher once main() has armed it (null otherwise); `behavior`
// is the session-behavior tracker once main() has turned it on (null otherwise).
export const deps = {
  decide: (payload, sessionKey) => decideSession(sessionKey, payload, { tripwire: deps.tripwire, behavior: deps.behavior }),
  tripwire: null,
  behavior: null,
};
// The tripwire token must never reach a log line or an incident.
const clean = (s) => (deps.tripwire ? deps.tripwire.redact(s) : s);

export async function handleEvent(ev) {
  const pid = Number(ev.pid);
  const payload = String(ev.payload || "").slice(0, MAX_PAYLOAD);
  if (!payload.trim() || pid === OWN_PID) return;
  const comm = String(ev.comm || "powershell.exe").toLowerCase();

  let d;
  try { d = await deps.decide(payload, pid > 0 ? `ps:${pid}` : null); } catch (e) {
    // A detector exception is never a silent allow: log it, record it, report it.
    log(`SENTINEL ERROR  detector threw on pid=${pid}: ${String(e && e.message ? e.message : e).slice(0, 200)}`);
    const inc = {
      host: HOST, ts: now(), decision: "error", tier: null, action: "errored",
      pid, user: ev.user, exe: comm, cmdline: clean(payload).slice(0, 400), score: null, signals: [],
      reason: "detector exception — payload not judged", error: String(e && e.stack ? e.stack : e).slice(0, 2000),
      conf: null, reasoning: null, narration: clean(narrationSnippet(payload)),
    };
    reportToCloud(inc);
    writeIncident(inc);
    return inc;
  }
  if (d.decision === "allow") {
    if (VERBOSE) log(`allow  tier-${d.tier}  pid=${pid}  score=${d.score.toFixed(2)}  ${d.reason}`);
    return d;
  }

  const protectedHit = d.decision === "block" ? (PROTECTED.has(comm) ? comm : null) : null;
  const action =
    d.decision === "alert" ? (d.viaTripwire ? "ALERT (decoy addressed, not run — no kill)" : d.viaBehavior ? "ALERT (the session swept the host — no kill)" : "ALERT (tier-2 unavailable — no kill)")
    : MONITOR ? "DETECTED (monitor — no kill)"
    : protectedHit ? `SPARED (${protectedHit})`
    : "KILL";
  const how = d.tier === 2 ? (d.adjudication?.refused ? "fail-closed" : `conf=${d.adjudication?.confidence?.toFixed(2)}`) : "";
  const sess = d.viaSession ? `  via-session(${d.session.size} payloads)` : "";
  log(`SENTINEL ${action}  ${d.viaTripwire ? "tripwire" : d.viaBehavior ? "behavior" : `tier-${d.tier}`}  pid=${pid} user=${ev.user}${sess}  score=${d.score.toFixed(2)}${how ? " " + how : ""}`);
  log(`            ${d.reason}`);
  if (d.adjudication?.reasoning) log(`            reasoning: ${d.adjudication.reasoning}`);

  const inc = {
    host: HOST, ts: now(), decision: d.decision, tier: d.tier,
    action: d.decision === "alert" ? "alerted" : MONITOR ? "monitored" : protectedHit ? `spared:${protectedHit}` : "killed",
    pid, user: ev.user, exe: comm, cmdline: clean(payload).slice(0, 400),
    score: d.score, signals: d.signals, reason: d.reason,
    conf: d.adjudication?.confidence ?? null, reasoning: d.adjudication?.reasoning ?? null,
    narration: clean(narrationSnippet(d.viaSession || d.windowed ? d.scoredLayer : payload)),
    via_session: !!d.viaSession, session: d.session ?? null,
    tripwire: d.tripwire ?? null,
    behavior: d.behavior ?? null,
  };
  reportToCloud(inc);
  if (ENFORCE && d.decision === "block" && !protectedHit) killTree(pid);
  writeIncident(inc);
  return inc;
}

function feed(stream) {
  createInterface({ input: stream }).on("line", (line) => {
    const s = line.trim();
    if (!s.startsWith("{")) return;
    let ev;
    try { ev = JSON.parse(s); } catch { return; }
    if (ev.payload) handleEvent(ev);
  });
}

function main() {
  log("Aris Sentinel Windows agent starting");
  log(`  mode: ${ENFORCE ? "ENFORCE (kills on detection)" : "MONITOR (detect + alert only — no kill; --enforce to arm)"}`);
  log(`  tier 2: ${hasTier2() ? `ENABLED (${providers().map((p) => p.name).join(" -> ")})` : "disabled (tier-1 only; set ANTHROPIC_API_KEY, or OPENAI_BASE_URL+OPENAI_MODEL for a local judge) — escalate band -> alert"}`);
  for (const w of providerWarnings()) log(`  WARN ${w}`);
  log(`  session evidence: ${defaultSessions.enabled ? "ON (narration accumulated per PowerShell process)" : "off (ARIS_SESSION_TTL_MS=0)"}`);
  log(`  cloud alerts: ${CLOUD_URL ? `-> ${CLOUD_URL}` : "disabled (set ARIS_CLOUD_URL)"}`);
  if (INCIDENT_LOG) log(`  incidents -> ${INCIDENT_LOG}`);

  if (MOCK) {
    log("  MOCK — replaying agent/win/mock-events.jsonl (no Windows, no kill)\n");
    const fixture = fileURLToPath(new URL("./mock-events.jsonl", import.meta.url));
    for (const line of readFileSync(fixture, "utf8").split("\n")) {
      const s = line.trim();
      if (!s.startsWith("{")) continue;
      try { handleEvent(JSON.parse(s)); } catch {}
    }
    // The tripwire, with a throwaway token and nothing planted: the decoy's own command
    // (expect a tripwire BLOCK), then a look at the decoy (expect a tripwire ALERT).
    const token = newTripwireToken();
    const dir = "C:\\ProgramData\\vault-access";
    deps.tripwire = createTripwire({ token, dirs: [dir] });
    handleEvent({ source: "mock", pid: 9101, user: "mock", payload: tripwireDecoy(token, dir, "win32").command });
    handleEvent({ source: "mock", pid: 9102, user: "mock", payload: `Get-Content ${dir}\\README.md` });
    // Session behavior: one quiet PowerShell process asks who it is, what the box is and
    // who has an account. Nothing narrates; expect one behavior ALERT, on the last command.
    deps.behavior = createBehaviorTracker();
    for (const payload of ["whoami /all", "hostname", "ipconfig /all", "net user"]) handleEvent({ source: "mock", pid: 9103, user: "mock", payload });
    return;
  }

  if (TRIPWIRE) {
    // The host's own wording and names for its decoys, if it set any. An unusable setting
    // plants nothing (never the published look the host was trying to leave) and keeps
    // matching the decoys that are already there.
    const own = tripwireLookFromEnv();
    const a = armTripwire({ stateFile: TRIPWIRE_STATE, dirs: TRIPWIRE_DIRS, look: own.look ?? undefined, lookError: own.error ?? undefined });
    deps.tripwire = a.tripwire;
    if (a.held) log(`  tripwire: KEPT AS IT WAS (${a.error}) — nothing planted or moved; still matching the decoys already here: ${a.tripwire.dirs.join(", ")}`);
    else if (a.error) log(`  tripwire: NOT ARMED (${a.error}) — nothing planted, nothing matched`);
    else log(`  tripwire: ON (${a.created ? "new token" : "existing token"} ${a.tripwire.fingerprint}; decoys: ${a.tripwire.dirs.join(", ") || "none"}) — canary command run -> block, decoy addressed -> alert`);
    for (const s of a.skipped) log(`  WARN tripwire: no decoy at ${s.dir} (${s.why})`);
    for (const d of a.retired) log(`  the decoy at ${d} was taken away (this host no longer asks for it)`);
    for (const w of own.warnings) log(`  WARN ${w}`);
    if (a.published.length) log(`  NOTE the decoys here wear the published ${a.published.join(", ")}: anyone who has read the source can recognise them. Give this host its own (ARIS_TRIPWIRE_README, _HELPER, _FLAG, _DIRS; see DEPLOY.md)`);
  } else log("  tripwire: off (pass --tripwire to plant a decoy)");
  if (BEHAVIOR_ON) {
    deps.behavior = createBehaviorTracker();
    if (!deps.behavior.enabled) log("  session behavior: OFF (--behavior was passed, but ARIS_BEHAVIOR_WINDOW_MS=0 turns it off)");
    else log(`  session behavior: ON (a PowerShell process asking about ${BEHAVIOR.categories}+ areas of the host, ${BEHAVIOR.sensitive}+ of them sensitive, inside ${Math.round(deps.behavior.windowMs / 1000)}s -> alert, never a kill)`);
  } else log("  session behavior: off (pass --behavior to report sessions that sweep the host)");

  const ps = spawn("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", SENSOR], { stdio: ["ignore", "pipe", "pipe"] });
  ps.on("error", (e) => { log(`FATAL: cannot start the PowerShell sensor (${e.message}).`); process.exit(1); });
  ps.stderr.on("data", (b) => { const t = b.toString().trim(); if (t) log(`sensor: ${t.split("\n")[0]}`); });
  feed(ps.stdout);
  log("  watching PowerShell script-block + process events. Ctrl-C to stop.");
  process.on("SIGINT", () => { ps.kill(); process.exit(0); });
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  if (TRIPWIRE_REMOVE) {
    const r = disarmTripwire({ stateFile: TRIPWIRE_STATE });
    log(r.armed ? `tripwire removed: ${r.removed.length} path(s) deleted${r.kept.length ? `, left in place: ${r.kept.join(", ")}` : ""}` : `no tripwire state at ${TRIPWIRE_STATE}; nothing to remove`);
  } else main();
}
