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
//   node sentinel-agent-win.mjs --mock      # replay agent/win/mock-events.jsonl (no Windows)
//
//   env: ANTHROPIC_API_KEY / OPENAI_BASE_URL+OPENAI_MODEL / KIMI_API_KEY (tier 2)  ARIS_CLOUD_URL + ARIS_INGEST_KEY (alerts)
//        ARIS_SENSOR (path to sensor.ps1)  ARIS_INCIDENTS (incident log)  ARIS_HOST  ARIS_VERBOSE=1
//        ARIS_FAIL_MODE / ARIS_TIER2_* — see ../sentinel-agent.mjs
//
// Decisions: block → monitor logs/reports, enforce kills.  alert → logged + reported,
// never killed.  error → the detector threw: logged + reported, never dropped.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { readFileSync, appendFileSync } from "node:fs";
import { hostname } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { decide, hasTier2, providers, providerWarnings } from "../sentinel-core.mjs";

const ENFORCE = process.argv.includes("--enforce");
const MONITOR = !ENFORCE;
const MOCK = process.argv.includes("--mock");
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
export const deps = { decide };

export async function handleEvent(ev) {
  const pid = Number(ev.pid);
  const payload = String(ev.payload || "").slice(0, MAX_PAYLOAD);
  if (!payload.trim() || pid === OWN_PID) return;
  const comm = String(ev.comm || "powershell.exe").toLowerCase();

  let d;
  try { d = await deps.decide(payload); } catch (e) {
    // A detector exception is never a silent allow: log it, record it, report it.
    log(`SENTINEL ERROR  detector threw on pid=${pid}: ${String(e && e.message ? e.message : e).slice(0, 200)}`);
    const inc = {
      host: HOST, ts: now(), decision: "error", tier: null, action: "errored",
      pid, user: ev.user, exe: comm, cmdline: payload.slice(0, 400), score: null, signals: [],
      reason: "detector exception — payload not judged", error: String(e && e.stack ? e.stack : e).slice(0, 2000),
      conf: null, reasoning: null, narration: narrationSnippet(payload),
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
    d.decision === "alert" ? "ALERT (tier-2 unavailable — no kill)"
    : MONITOR ? "DETECTED (monitor — no kill)"
    : protectedHit ? `SPARED (${protectedHit})`
    : "KILL";
  const how = d.tier === 2 ? (d.adjudication?.refused ? "fail-closed" : `conf=${d.adjudication?.confidence?.toFixed(2)}`) : "";
  log(`SENTINEL ${action}  tier-${d.tier}  pid=${pid} user=${ev.user}  score=${d.score.toFixed(2)}${how ? " " + how : ""}`);
  log(`            ${d.reason}`);
  if (d.adjudication?.reasoning) log(`            reasoning: ${d.adjudication.reasoning}`);

  const inc = {
    host: HOST, ts: now(), decision: d.decision, tier: d.tier,
    action: d.decision === "alert" ? "alerted" : MONITOR ? "monitored" : protectedHit ? `spared:${protectedHit}` : "killed",
    pid, user: ev.user, exe: comm, cmdline: payload.slice(0, 400),
    score: d.score, signals: d.signals, reason: d.reason,
    conf: d.adjudication?.confidence ?? null, reasoning: d.adjudication?.reasoning ?? null,
    narration: narrationSnippet(payload),
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
    return;
  }

  const ps = spawn("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", SENSOR], { stdio: ["ignore", "pipe", "pipe"] });
  ps.on("error", (e) => { log(`FATAL: cannot start the PowerShell sensor (${e.message}).`); process.exit(1); });
  ps.stderr.on("data", (b) => { const t = b.toString().trim(); if (t) log(`sensor: ${t.split("\n")[0]}`); });
  feed(ps.stdout);
  log("  watching PowerShell script-block + process events. Ctrl-C to stop.");
  process.on("SIGINT", () => { ps.kill(); process.exit(0); });
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) main();
