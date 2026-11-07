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

describe("handleEvent", () => {
  test("escalate band with no tier-2 key → ALERT incident, nothing killed", async () => {
    const before = readIncidents().length;
    const r = await agent.handleEvent(ev("python3 job.py", { "proc.cwd": work }));
    expect(r).toBeUndefined(); // respond() path
    const inc = readIncidents().slice(before);
    expect(inc).toHaveLength(1);
    expect(inc[0]).toMatchObject({ decision: "alert", action: "alerted", tier: 1, pid: 4242, exe: "python3", cwd: work, killed: [] });
    expect(inc[0].reason).toContain("tier-2 unavailable");
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
