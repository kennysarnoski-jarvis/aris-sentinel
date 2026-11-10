// Linux agent: script-path resolution (against the PROCESS's cwd, never the agent's),
// inline-code flag detection, and the alert / error incident paths. No Falco, no root,
// no kill (monitor mode is the default and the agent is imported, not executed).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ESCALATE = `# Objective: escalate to admin in this AWS account. I need to enumerate my current permissions first.
# The attached role can create access keys for other users -- that is my path up.
# Plan: 1) list IAM users, 2) find one with AdministratorAccess, 3) mint a key for them, 4) assume it.
# I will avoid creating a new admin user because that would trip GuardDuty.
import boto3`;

let work: string; // the "process cwd" — has job.py
let decoy: string; // the agent's own cwd — has a DIFFERENT job.py that must never be read
let incidents: string;
let agent: typeof import("../../agent/sentinel-agent.mjs");
let origCwd: string;

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), "aris-work-"));
  decoy = mkdtempSync(join(tmpdir(), "aris-decoy-"));
  writeFileSync(join(work, "job.py"), ESCALATE);
  writeFileSync(join(work, "benign.py"), "import time\ntime.sleep(1)\n");
  writeFileSync(join(decoy, "job.py"), "# DECOY — the agent's own cwd. Must never be scored.\n" + ESCALATE);
  incidents = join(work, "incidents.jsonl");
  writeFileSync(incidents, "");
  origCwd = process.cwd();
  process.chdir(decoy);
  delete process.env.KIMI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  process.env.ARIS_INCIDENTS = incidents;
  agent = await import("../../agent/sentinel-agent.mjs");
});
afterAll(() => {
  process.chdir(origCwd);
  rmSync(work, { recursive: true, force: true });
  rmSync(decoy, { recursive: true, force: true });
});

const readIncidents = () => readFileSync(incidents, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
let sid = 100;
const ev = (cmdline: string, extra: Record<string, unknown> = {}) => ({
  "proc.pid": 4242, "proc.ppid": 1, "proc.sid": ++sid, "user.name": "ubuntu",
  "proc.exe": "/usr/bin/" + cmdline.split(" ")[0], "proc.cmdline": cmdline, ...extra,
});

describe("hasInlineCode", () => {
  test("plain and combined flags", () => {
    const { hasInlineCode } = agent;
    expect(hasInlineCode("bash", ["-c", "id"])).toBe(true);
    expect(hasInlineCode("bash", ["-lc", "id"])).toBe(true);
    expect(hasInlineCode("python3", ["-Bc", "print(1)"])).toBe(true);
    expect(hasInlineCode("python3", ["-c", "print(1)"])).toBe(true);
    expect(hasInlineCode("perl", ["-ne", "print"])).toBe(true);
    expect(hasInlineCode("node", ["-e", "1"])).toBe(true);
    expect(hasInlineCode("node", ["--eval", "1"])).toBe(true);
    expect(hasInlineCode("php", ["-r", "echo 1;"])).toBe(true);
  });
  test("script invocations are not inline", () => {
    const { hasInlineCode } = agent;
    expect(hasInlineCode("python3", ["job.py"])).toBe(false);
    expect(hasInlineCode("python3", ["-u", "job.py"])).toBe(false);
    expect(hasInlineCode("bash", ["-x", "run.sh"])).toBe(false);
    expect(hasInlineCode("bash", ["--norc", "run.sh"])).toBe(false);
    expect(hasInlineCode("ls", ["-c"])).toBe(false); // not an interpreter
  });
});

describe("resolveScript", () => {
  test("absolute stays, relative resolves against proc.cwd, then /proc/<pid>/cwd, never the agent's cwd", () => {
    const { resolveScript } = agent;
    expect(resolveScript("/opt/x.py", { cwd: "/tmp", pid: 7 })).toBe("/opt/x.py");
    expect(resolveScript("x.py", { cwd: "/tmp", pid: 7 })).toBe("/tmp/x.py");
    expect(resolveScript("../x.py", { cwd: "/tmp/a", pid: 7 })).toBe("/tmp/x.py");
    expect(resolveScript("x.py", { pid: 7 })).toBe("/proc/7/cwd/x.py");
    expect(resolveScript("x.py", { cwd: "relative", pid: 7 })).toBe("/proc/7/cwd/x.py");
    expect(resolveScript("x.py", {})).toBeNull();
  });
});

describe("extractPayload", () => {
  test("reads the script from the process's cwd", () => {
    const p = agent.extractPayload(ev("python3 job.py", { "proc.cwd": work }));
    expect(p).toContain("python3 job.py");
    expect(p).toContain("trip GuardDuty");
    expect(p).not.toContain("DECOY");
  });
  test("never falls back to the agent's own cwd when proc.cwd is missing", () => {
    // pid 4242's /proc entry does not exist here (and on Linux it would be the real
    // process's cwd, not ours) — so the decoy job.py must not be read.
    const p = agent.extractPayload(ev("python3 job.py"));
    expect(p).toBe("python3 job.py");
  });
  test("inline code (-c, -lc, -Bc) never slurps a file that happens to be named in the args", () => {
    expect(agent.extractPayload(ev("bash -lc python3 job.py", { "proc.cwd": work }))).toBe("bash -lc python3 job.py");
    expect(agent.extractPayload(ev("python3 -Bc exec(open('job.py').read())", { "proc.cwd": work }))).not.toContain("GuardDuty");
  });
  test("non-interpreters never read files", () => {
    expect(agent.extractPayload(ev("cat job.py", { "proc.cwd": work }))).toBe("cat job.py");
  });
});

describe("which argument is the script (found live: the agent once read its own incident log)", () => {
  test("interpreterOf knows versioned names", () => {
    const { interpreterOf } = agent;
    expect(interpreterOf("python3")).toBe("python");
    expect(interpreterOf("python3.12")).toBe("python");
    expect(interpreterOf("python")).toBe("python");
    expect(interpreterOf("bash")).toBe("shell");
    expect(interpreterOf("zsh")).toBe("shell");
    expect(interpreterOf("node")).toBe("node");
    expect(interpreterOf("nodejs")).toBe("node");
    expect(interpreterOf("perl5.36")).toBe("perl");
    expect(interpreterOf("php8.3")).toBe("php");
    for (const x of ["cat", "pythonista", "bashful", "cron", ""]) expect(interpreterOf(x)).toBeNull();
  });

  test("scriptToken: only the first positional argument, never data after it", () => {
    const { scriptToken } = agent;
    expect(scriptToken("python3", ["job.py"])).toBe("job.py");
    expect(scriptToken("python3", ["job.py", "data.json", "more.txt"])).toBe("job.py");
    expect(scriptToken("python3", ["-u", "job.py", "notes.md"])).toBe("job.py");
    expect(scriptToken("python3", ["missing.py", "job.py"])).toBe("missing.py"); // no scanning past it
    expect(scriptToken("bash", ["run.sh", "arg"])).toBe("run.sh");
    expect(scriptToken("cat", ["job.py"])).toBeNull();
  });

  test("scriptToken: module runs and stdin have no script file", () => {
    const { scriptToken } = agent;
    expect(scriptToken("python3", ["-m", "json.tool", "incidents.jsonl"])).toBeNull();
    expect(scriptToken("python3", ["-Im", "http.server", "8000"])).toBeNull();
    expect(scriptToken("python3", ["-", "incidents.jsonl", "7931"])).toBeNull();
    expect(scriptToken("bash", ["-"])).toBeNull();
    expect(scriptToken("python3", [])).toBeNull();
    expect(scriptToken("python3", ["-u"])).toBeNull();
  });

  test("scriptToken: an option's value is not the script", () => {
    const { scriptToken } = agent;
    expect(scriptToken("python3", ["-W", "ignore", "job.py"])).toBe("job.py");
    expect(scriptToken("python3", ["-X", "dev", "-u", "job.py"])).toBe("job.py");
    expect(scriptToken("python3", ["-uW", "ignore", "job.py"])).toBe("job.py");
    expect(scriptToken("bash", ["-o", "pipefail", "run.sh"])).toBe("run.sh");
    expect(scriptToken("bash", ["+o", "histexpand", "-x", "run.sh"])).toBe("run.sh");
    expect(scriptToken("bash", ["--rcfile", "/etc/x", "run.sh"])).toBe("run.sh");
    expect(scriptToken("node", ["--require", "./hook.js", "app.js"])).toBe("app.js");
    expect(scriptToken("node", ["-r", "./hook.js", "app.js"])).toBe("app.js");
    expect(scriptToken("perl", ["-I", "lib", "script.pl"])).toBe("script.pl");
    expect(scriptToken("ruby", ["-r", "json", "tool.rb"])).toBe("tool.rb");
    expect(scriptToken("php", ["-d", "memory_limit=1G", "run.php"])).toBe("run.php");
    expect(scriptToken("php", ["-f", "run.php", "x"])).toBe("run.php");
    expect(scriptToken("python3", ["--", "-odd-name.py"])).toBe("-odd-name.py");
  });

  test("extractPayload reads the script, and never the data handed to it", () => {
    writeFileSync(join(work, "report.py"), "import sys\nprint(open(sys.argv[1]).read()[:10])\n");
    writeFileSync(join(work, "writeup.md"), ESCALATE); // narrated attack text, as DATA
    const p = agent.extractPayload(ev("python3 report.py writeup.md", { "proc.cwd": work }));
    expect(p).toContain("import sys");
    expect(p).not.toContain("GuardDuty");
  });

  test("extractPayload: a module run or stdin program reads no file, whatever the arguments name", () => {
    expect(agent.extractPayload(ev("python3 -m json.tool job.py", { "proc.cwd": work }))).toBe("python3 -m json.tool job.py");
    expect(agent.extractPayload(ev("python3 - job.py 7931 session_killed", { "proc.cwd": work }))).toBe("python3 - job.py 7931 session_killed");
  });

  test("extractPayload: a missing first positional is the end of it (no fishing for a later file)", () => {
    expect(agent.extractPayload(ev("python3 nope.py job.py", { "proc.cwd": work }))).toBe("python3 nope.py job.py");
  });

  test("extractPayload: option values are skipped, versioned interpreters are recognised", () => {
    expect(agent.extractPayload(ev("python3 -W ignore job.py", { "proc.cwd": work }))).toContain("GuardDuty");
    expect(agent.extractPayload(ev("python3.12 job.py", { "proc.cwd": work, "proc.exe": "/usr/bin/python3.12" }))).toContain("GuardDuty");
  });

  test("the agent never reads its own incident log as a script, however it is invoked", async () => {
    // put attacker narration in the incident log, exactly as a real incident would
    writeFileSync(incidents, JSON.stringify({ decision: "block", narration: ESCALATE, cmdline: "python3 job.py" }) + "\n");
    for (const cmd of [`bash ${incidents}`, `python3 ${incidents}`, `python3 -u ${incidents}`, `python3 -m json.tool ${incidents}`, `python3 - ${incidents}`]) {
      expect(agent.extractPayload(ev(cmd))).toBe(cmd);
    }
    const before = readIncidents().length;
    const r = await agent.handleEvent(ev(`python3 -m json.tool ${incidents}`));
    expect(r).toMatchObject({ decision: "allow" });
    expect(readIncidents().length).toBe(before);
  });
});

describe("handleEvent", () => {
  test("escalate band with no tier-2 key → ALERT incident, nothing killed", async () => {
    const before = readIncidents().length;
    const r = await agent.handleEvent(ev("python3 job.py", { "proc.cwd": work }));
    expect(r).toBeUndefined(); // respond() path
    const inc = readIncidents().slice(before);
    expect(inc).toHaveLength(1);
    expect(inc[0]).toMatchObject({ decision: "alert", action: "alerted", tier: 1, pid: 4242, exe: "python3", cwd: work, killed: [] });
    expect(inc[0].reason).toContain("tier-2 unavailable (no judge configured)");
    expect(inc[0].narration).toContain("escalate to admin");
  });

  test("clear payload → allow, no incident", async () => {
    const before = readIncidents().length;
    const r = await agent.handleEvent(ev("python3 benign.py", { "proc.cwd": work }));
    expect(r).toMatchObject({ decision: "allow" });
    expect(readIncidents().length).toBe(before);
  });

  test("a detector exception is an ERROR incident, never a silent allow", async () => {
    const before = readIncidents().length;
    const real = agent.deps.decide;
    agent.deps.decide = (async () => { throw new Error("boom: scorer blew up"); }) as any;
    try {
      await agent.handleEvent(ev("python3 benign.py", { "proc.cwd": work }));
    } finally {
      agent.deps.decide = real;
    }
    const inc = readIncidents().slice(before);
    expect(inc).toHaveLength(1);
    expect(inc[0]).toMatchObject({ decision: "error", action: "errored", pid: 4242 });
    expect(inc[0].error).toContain("boom: scorer blew up");
  });

  test("the same (session, payload) within the dedup window is handled once", async () => {
    const before = readIncidents().length;
    const e = ev("python3 job.py", { "proc.cwd": work });
    await Promise.all([agent.handleEvent(e), agent.handleEvent(e), agent.handleEvent({ ...e })]);
    expect(readIncidents().length - before).toBe(1);
  });
});

describe("session evidence through the agent", () => {
  // Thin steps: none blocks alone; together they reach the block band.
  const steps = [
    "# I'll check what this account can reach first.\nid; hostname",
    "# Step 2: list the mounted shares.\nls -la /mnt",
    "# finance is the largest share, so that one goes first.\ndu -sh /mnt/*",
  ];
  const sidEv = (n: number, body: string, sidNo: number) => {
    writeFileSync(join(work, `s${n}.sh`), body);
    return { "proc.pid": 5000 + n, "proc.ppid": 1, "proc.sid": sidNo, "user.name": "ubuntu", "proc.exe": "/usr/bin/bash", "proc.cmdline": `bash s${n}.sh`, "proc.cwd": work };
  };

  test("sessionKeyOf: a real sid is a session; 0, 1 and garbage are not", () => {
    expect(agent.sessionKeyOf({ "proc.pid": 1, "proc.sid": 4321 })).toBe("sid:4321");
    expect(agent.sessionKeyOf({ "proc.pid": 1, "proc.sid": "4321" })).toBe("sid:4321");
    for (const sid of [0, 1, -1, "x", undefined]) expect(agent.sessionKeyOf({ "proc.pid": 1, "proc.sid": sid as any })).toBeNull();
  });

  test("thin narration across three execs of one sid → one session ALERT (no judge), nothing killed", async () => {
    const before = readIncidents().length;
    for (let i = 0; i < steps.length; i++) await agent.handleEvent(sidEv(i + 1, steps[i], 777001));
    const inc = readIncidents().slice(before);
    const via = inc.filter((r) => r.via_session);
    expect(via).toHaveLength(1);
    expect(via[0]).toMatchObject({ decision: "alert", action: "alerted", tier: 1, pid: 5003, killed: [] });
    expect(via[0].session).toMatchObject({ key: "sid:777001", size: 3, payloadVerdict: "escalate" });
    expect(via[0].session.score).toBeGreaterThanOrEqual(0.6);
    expect(via[0].reason).toContain("session (3 payloads");
    // the alert quotes the SESSION's words, including the first step's
    expect(via[0].narration).toContain("check what this account can reach");
    expect(via[0].narration).toContain("largest share");
  });

  test("the same three execs in three different sids are never a session", async () => {
    const before = readIncidents().length;
    for (let i = 0; i < steps.length; i++) await agent.handleEvent(sidEv(i + 4, steps[i] + "\n# x", 777100 + i));
    expect(readIncidents().slice(before).filter((r) => r.via_session)).toHaveLength(0);
  });
});

describe("session-level kill (--enforce --kill-session)", () => {
  // Every kill primitive is stubbed: nothing on this machine is ever signalled.
  const LOUD = "# Phase 4: Impact. I have ranked the reachable databases by value.\n# High-ROI databases to drop, data already backed up to my collection host.\nrun_sql('DROP DATABASE x')";
  const THIN = "# Objective: escalate to admin in this AWS account. I need to enumerate my current permissions first.\n# Plan: 1) list IAM users, 2) mint a key.\n# I will avoid creating a new admin user because that would trip GuardDuty."; // escalate alone → alert with no judge
  let real: any;
  let treeKills: number[], pidKills: number[], asked: number[], t: number;
  const members: Record<number, number[]> = {};
  const names: Record<number, string> = {};
  let nextPid = 61000;

  const arm = (mode: { enforce: boolean; killSession: boolean }) => {
    treeKills = []; pidKills = []; asked = [];
    agent.deps.mode = mode;
    agent.deps.killTree = (pid: number) => { treeKills.push(pid); return [pid]; };
    agent.deps.killPid = (pid: number) => { pidKills.push(pid); };
    agent.deps.sessionPids = (sid: number) => { asked.push(sid); return members[sid] ?? []; };
    agent.deps.ancestorsOf = () => []; // never read this machine's /proc for a made-up pid
    agent.deps.procName = (pid: number) => names[pid] ?? "bash";
    agent.deps.now = () => t;
  };
  const exec = (body: string, sid: number, extra: Record<string, unknown> = {}) => {
    const pid = ++nextPid;
    writeFileSync(join(work, `k${pid}.sh`), body);
    return { pid, f: { "proc.pid": pid, "proc.ppid": 1, "proc.sid": sid, "user.name": "deploy", "proc.exe": "/usr/bin/bash", "proc.cmdline": `bash k${pid}.sh`, "proc.cwd": work, ...extra } };
  };
  const last = () => readIncidents().at(-1);

  beforeAll(() => { real = { ...agent.deps, mode: { ...agent.deps.mode } }; t = 1_000_000; agent.deps.ownSids = new Set(); });
  afterAll(() => { Object.assign(agent.deps, real); });

  test("parseStatSid survives a comm with spaces and parens", () => {
    expect(agent.parseStatSid("4242 (bash) S 4000 4242 4100 34816 4242 4194304")).toBe(4100);
    expect(agent.parseStatSid("77 (my (weird) comm) R 1 77 9001 0 -1")).toBe(9001);
    expect(agent.parseStatSid("garbage")).toBeNull();
  });

  test("the default mode is monitor with session kill off", () => {
    expect(real.mode).toEqual({ enforce: false, killSession: false });
  });

  test("a conviction kills the offender's tree, then the rest of its session, sparing protected processes", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 880001;
    const a = exec(LOUD, sid);
    members[sid] = [a.pid, 62001, 62002, 62003];
    names[62002] = "sshd";
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(asked).toEqual([sid]);
    expect(pidKills).toEqual([62001, 62003]); // the offender is not signalled twice; sshd is spared
    const inc = last();
    expect(inc).toMatchObject({ decision: "block", action: "killed", tier: 1, sid });
    expect(inc.session_kill).toEqual({ sid, killed: [62001, 62003], spared: [{ pid: 62002, why: "protected-comm:sshd" }], why: null });
    expect(inc.killed).toEqual([a.pid, 62001, 62003]);
  });

  test("the session is quarantined: its next exec is killed without being scored, even a silent one", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 880001; // convicted in the previous test
    const b = exec("ls -la /var/log", sid);
    const before = readIncidents().length;
    const r = await agent.handleEvent(b.f);
    expect(r).toBeUndefined();
    expect(treeKills).toEqual([b.pid]);
    const inc = readIncidents().slice(before);
    expect(inc).toHaveLength(1);
    expect(inc[0]).toMatchObject({ decision: "block", action: "killed", tier: null, score: null, pid: b.pid });
    expect(inc[0].reason).toContain("quarantined until");
    expect(inc[0].quarantine).toMatchObject({ sid, count: 1 });
    // a protected process in the quarantined session is spared, and still recorded
    const c = exec("true", sid, { "proc.exe": "/usr/sbin/sshd" });
    await agent.handleEvent(c.f);
    expect(treeKills).toEqual([b.pid]);
    expect(last()).toMatchObject({ action: "spared:protected-comm:sshd", pid: c.pid });
  });

  test("other sessions are untouched, and quarantine expires", async () => {
    arm({ enforce: true, killSession: true });
    const other = exec("ls -la /tmp", 880002);
    expect(await agent.handleEvent(other.f)).toMatchObject({ decision: "allow" });
    expect(treeKills).toEqual([]);
    t += 11 * 60 * 1000; // past the 10-minute quarantine
    const later = exec("ls -la /etc", 880001);
    expect(await agent.handleEvent(later.f)).toMatchObject({ decision: "allow" });
    expect(treeKills).toEqual([]);
  });

  test("--enforce WITHOUT --kill-session: the tree dies, the session is not looked at, nothing is quarantined", async () => {
    arm({ enforce: true, killSession: false });
    const sid = 880010;
    const a = exec(LOUD + "\n# a", sid);
    members[sid] = [a.pid, 62100];
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(asked).toEqual([]);
    expect(pidKills).toEqual([]);
    expect(last().session_kill).toBeNull();
    const b = exec("ls -la /srv", sid);
    expect(await agent.handleEvent(b.f)).toMatchObject({ decision: "allow" });
  });

  test("monitor mode never kills, whatever the flag says", async () => {
    arm({ enforce: false, killSession: true });
    const a = exec(LOUD + "\n# b", 880020);
    members[880020] = [a.pid, 62200];
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([]);
    expect(pidKills).toEqual([]);
    expect(asked).toEqual([]);
    expect(last()).toMatchObject({ decision: "block", action: "monitored", session_kill: null });
  });

  test("an ALERT never triggers a session kill or a quarantine", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 880030;
    const a = exec(THIN, sid);
    members[sid] = [a.pid, 62300];
    await agent.handleEvent(a.f);
    expect(last()).toMatchObject({ decision: "alert", action: "alerted", session_kill: null });
    expect(treeKills).toEqual([]);
    expect(pidKills).toEqual([]);
    expect(asked).toEqual([]);
    const b = exec("ls -la /home", sid);
    expect(await agent.handleEvent(b.f)).toMatchObject({ decision: "allow" });
  });

  test("no usable session id → the tree is killed and the session is left alone", async () => {
    arm({ enforce: true, killSession: true });
    const a = exec(LOUD + "\n# c", 1);
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(asked).toEqual([]);
    expect(last().session_kill).toMatchObject({ killed: [], why: "no session id" });
  });

  test("a spared (protected) offender still gets its session ended, member by member under the same guard", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 880040;
    const a = exec(LOUD + "\n# d", sid, { "proc.exe": "/usr/bin/node" }); // node is on the protected list
    members[sid] = [a.pid, 62400, 62401];
    names[a.pid] = "node";
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([]);
    expect(pidKills).toEqual([62400, 62401]);
    expect(last()).toMatchObject({ action: "spared:protected-comm:node" });
    expect(last().session_kill.spared).toEqual([{ pid: a.pid, why: "protected-comm:node" }]);
  });

  test("the session the agent runs in, or was started from, is never ended or quarantined", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 880060;
    agent.deps.ownSids = new Set([sid]);
    const a = exec(LOUD + "\n# f", sid);
    members[sid] = [a.pid, 62600, 62601];
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]); // the convicted process itself still dies
    expect(asked).toEqual([]); // …but its session is not even enumerated
    expect(pidKills).toEqual([]);
    expect(last().session_kill).toMatchObject({ killed: [], why: "the session the agent runs in or was started from" });
    const b = exec("ls -la /opt", sid);
    expect(await agent.handleEvent(b.f)).toMatchObject({ decision: "allow" }); // not quarantined
    agent.deps.ownSids = new Set();
  });

  test("kill order (found live): the session dies BEFORE the offender, its ancestors first, outermost first", async () => {
    // The shell that launched the offender is blocked waiting for it. Killing the offender
    // first wakes that shell, and it ran one more command before the session kill arrived.
    arm({ enforce: true, killSession: true });
    const sid = 880070;
    const a = exec(LOUD + "\n# g", sid);
    const [harness, shell, helper, sibling] = [62700, 62701, 62702, 62703];
    members[sid] = [sibling, helper, a.pid, shell, harness]; // /proc order is no help
    const order: string[] = [];
    agent.deps.killTree = (pid: number) => { order.push(`tree:${pid}`); return [pid, helper]; }; // helper is the offender's child
    agent.deps.killPid = (pid: number) => { order.push(`pid:${pid}`); };
    agent.deps.ancestorsOf = (pid: number) => (pid === a.pid ? [a.pid, shell, harness, 1] : [pid]);
    await agent.handleEvent(a.f);
    expect(order).toEqual([`pid:${harness}`, `pid:${shell}`, `pid:${sibling}`, `pid:${helper}`, `tree:${a.pid}`]);
    const inc = last();
    expect(inc.session_kill.killed).toEqual([harness, shell, sibling, helper]);
    expect(inc.killed).toEqual([a.pid, helper, harness, shell, sibling]); // each pid once
  });

  test("kill order: a protected ancestor is spared in place and the rest still go top-down", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 880071;
    const a = exec(LOUD + "\n# h", sid);
    members[sid] = [a.pid, 62711, 62710];
    names[62710] = "sshd";
    const order: string[] = [];
    agent.deps.killTree = (pid: number) => { order.push(`tree:${pid}`); return [pid]; };
    agent.deps.killPid = (pid: number) => { order.push(`pid:${pid}`); };
    agent.deps.ancestorsOf = (pid: number) => (pid === a.pid ? [a.pid, 62711, 62710] : [pid]);
    await agent.handleEvent(a.f);
    expect(order).toEqual(["pid:62711", `tree:${a.pid}`]);
    expect(last().session_kill.spared).toEqual([{ pid: 62710, why: "protected-comm:sshd" }]);
  });

  test("a kill that throws (process already gone) does not stop the rest", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 880050;
    const a = exec(LOUD + "\n# e", sid);
    members[sid] = [a.pid, 62500, 62501];
    agent.deps.killPid = (pid: number) => { if (pid === 62500) throw new Error("ESRCH"); pidKills.push(pid); };
    await agent.handleEvent(a.f);
    expect(pidKills).toEqual([62501]);
    expect(last().session_kill.killed).toEqual([62501]);
  });
});


describe("tripwire through the agent (--tripwire)", () => {
  // The kill primitives are stubbed before enforce is ever flipped; nothing is planted
  // (the matcher is built directly, the decoy directory does not exist on this machine).
  const DIR = "/opt/vault-access";
  let real: any;
  let core: typeof import("../../agent/sentinel-core.mjs");
  let token: string, command: string;
  let treeKills: number[], pidKills: number[], asked: number[];
  const members: Record<number, number[]> = {};
  let nextPid = 71000;

  const arm = (mode: { enforce: boolean; killSession: boolean }) => {
    treeKills = []; pidKills = []; asked = [];
    agent.deps.mode = mode;
    agent.deps.killTree = (pid: number) => { treeKills.push(pid); return [pid]; };
    agent.deps.killPid = (pid: number) => { pidKills.push(pid); };
    agent.deps.sessionPids = (sid: number) => { asked.push(sid); return members[sid] ?? []; };
    agent.deps.ancestorsOf = () => []; // never read this machine's /proc for a made-up pid
    agent.deps.procName = () => "bash";
    agent.deps.now = () => 5_000_000;
  };
  const run = (cmdline: string, sid: number, extra: Record<string, unknown> = {}) => {
    const pid = ++nextPid;
    return { pid, f: { "proc.pid": pid, "proc.ppid": 1, "proc.sid": sid, "user.name": "www-data", "proc.exe": "/usr/bin/" + cmdline.split(" ")[0].split("/").pop(), "proc.cmdline": cmdline, "proc.cwd": "/tmp", ...extra } };
  };
  const last = () => readIncidents().at(-1);
  const logText = () => readFileSync(incidents, "utf8");

  beforeAll(async () => {
    core = await import("../../agent/sentinel-core.mjs");
    real = { ...agent.deps, mode: { ...agent.deps.mode } };
    token = core.newTripwireToken();
    command = core.tripwireDecoy(token, DIR, "linux").command;
    agent.deps.ownSids = new Set();
    agent.deps.tripwire = core.createTripwire({ token, dirs: [DIR] });
  });
  afterAll(() => { Object.assign(agent.deps, real); });

  test("the agent starts with no tripwire: it is opt-in", () => {
    expect(real.tripwire).toBeNull();
  });

  test("monitor: the canary command is a BLOCK incident, nothing is killed, and the token is not in the log", async () => {
    arm({ enforce: false, killSession: false });
    const a = run(command, 990001);
    expect(await agent.handleEvent(a.f)).toBeUndefined();
    expect(treeKills).toEqual([]);
    const inc = last();
    expect(inc).toMatchObject({ decision: "block", action: "monitored", tier: 1, pid: a.pid, signals: ["tripwire_token"], killed: [], session_kill: null });
    expect(inc.tripwire).toMatchObject({ kind: "token", decoded: false, fingerprint: agent.deps.tripwire!.fingerprint });
    expect(inc.cmdline).toBe(`${DIR}/register --ticket [tripwire:${agent.deps.tripwire!.fingerprint}]`);
    expect(logText()).not.toContain(token);
  });

  test("enforce: the process that ran it is killed; without --kill-session its session is left alone", async () => {
    arm({ enforce: true, killSession: false });
    const a = run(`sh -c ${command}`, 990002);
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(asked).toEqual([]);
    expect(last()).toMatchObject({ decision: "block", action: "killed", killed: [a.pid], session_kill: null });
    expect(logText()).not.toContain(token);
  });

  test("enforce + kill-session: taking the bait ends the whole session and quarantines it", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 990003;
    const a = run(command, sid);
    members[sid] = [a.pid, 72001, 72002];
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(pidKills).toEqual([72001, 72002]);
    expect(last().session_kill).toMatchObject({ sid, killed: [72001, 72002], why: null });
    // the session's next command, silent and unrelated, is stopped unscored
    const b = run("ls -la /var/log", sid);
    await agent.handleEvent(b.f);
    expect(treeKills).toEqual([a.pid, b.pid]);
    expect(last().quarantine).toMatchObject({ sid, count: 1 });
  });

  test("a script that carries the canary command is caught when it is run", async () => {
    arm({ enforce: true, killSession: false });
    writeFileSync(join(work, "next-step.sh"), `#!/bin/bash\nset -e\n${command}\nls /mnt\n`);
    const a = run("bash next-step.sh", 990004, { "proc.cwd": work });
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(last()).toMatchObject({ decision: "block", cmdline: "bash next-step.sh" });
    expect(last().tripwire).toMatchObject({ kind: "token" });
    expect(logText()).not.toContain(token);
  });

  test("an encoded canary command is caught, and the encoded run is taken out of the log too", async () => {
    arm({ enforce: true, killSession: false });
    const blob = Buffer.from(command).toString("base64");
    const a = run(`bash -c echo ${blob} | base64 -d | sh`, 990005);
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(last().tripwire).toMatchObject({ kind: "token", decoded: true });
    expect(last().cmdline).toBe("bash -c echo [encoded tripwire] | base64 -d | sh");
    expect(logText()).not.toContain(blob);
  });

  test("a look at the decoy is an ALERT: never a kill, never a session kill, even fully armed", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 990006;
    const a = run(`cat ${DIR}/README.md`, sid);
    members[sid] = [a.pid, 72100];
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([]);
    expect(pidKills).toEqual([]);
    expect(asked).toEqual([]);
    expect(last()).toMatchObject({ decision: "alert", action: "alerted", pid: a.pid, signals: ["tripwire_decoy"], killed: [], session_kill: null });
    expect(last().tripwire).toMatchObject({ kind: "decoy", evidence: DIR });
    // and the session is not quarantined: its next command runs
    expect(await agent.handleEvent(run("ls -la /srv", sid).f)).toMatchObject({ decision: "allow" });
  });

  test("the process's cwd counts: `cat README.md` from inside the decoy, a relative path from its parent", async () => {
    arm({ enforce: true, killSession: false });
    await agent.handleEvent(run("cat README.md", 990007, { "proc.cwd": DIR }).f);
    expect(last()).toMatchObject({ decision: "alert", cmdline: "cat README.md" });
    await agent.handleEvent(run("cat vault-access/README.md", 990008, { "proc.cwd": "/opt" }).f);
    expect(last()).toMatchObject({ decision: "alert", cmdline: "cat vault-access/README.md" });
    expect(treeKills).toEqual([]);
  });

  test("unrelated commands are untouched, and without a tripwire the canary command is just a command", async () => {
    arm({ enforce: true, killSession: true });
    const n = readIncidents().length;
    expect(await agent.handleEvent(run("ls -la /opt", 990009).f)).toMatchObject({ decision: "allow" });
    expect(await agent.handleEvent(run("tar czf /tmp/opt.tgz /opt", 990010).f)).toMatchObject({ decision: "allow" });
    agent.deps.tripwire = null;
    expect(await agent.handleEvent(run(command, 990011).f)).toMatchObject({ decision: "allow" });
    expect(readIncidents().length).toBe(n);
    expect(treeKills).toEqual([]);
    agent.deps.tripwire = core.createTripwire({ token, dirs: [DIR] });
  });

  test("the operator's own session is never ended for tripping it", async () => {
    arm({ enforce: true, killSession: true });
    const sid = 990012;
    agent.deps.ownSids = new Set([sid]);
    const a = run(command + " --again", sid);
    members[sid] = [a.pid, 72200];
    await agent.handleEvent(a.f);
    expect(treeKills).toEqual([a.pid]);
    expect(pidKills).toEqual([]);
    expect(last().session_kill).toMatchObject({ killed: [], why: "the session the agent runs in or was started from" });
    agent.deps.ownSids = new Set();
  });

  test("a detector error on a payload carrying the token still keeps the token out of the log", async () => {
    arm({ enforce: false, killSession: false });
    const realDecide = agent.deps.decide;
    agent.deps.decide = (async () => { throw new Error("boom"); }) as any;
    try { await agent.handleEvent(run(command + " --err", 990013).f); } finally { agent.deps.decide = realDecide; }
    expect(last()).toMatchObject({ decision: "error" });
    expect(logText()).not.toContain(token);
  });
});
