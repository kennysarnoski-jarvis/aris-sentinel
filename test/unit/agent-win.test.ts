// Windows agent: the same decision handling as Linux — block logged, alert never
// killed, detector errors recorded — driven by sensor-shaped events, no Windows needed.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let dir: string;
let incidents: string;
let agent: typeof import("../../agent/win/sentinel-agent-win.mjs");

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "aris-win-"));
  incidents = join(dir, "incidents.jsonl");
  writeFileSync(incidents, "");
  delete process.env.KIMI_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  process.env.ARIS_INCIDENTS = incidents;
  agent = await import("../../agent/win/sentinel-agent-win.mjs");
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const readIncidents = () => readFileSync(incidents, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

const NARRATED = `# Exfiltration phase. I have ranked the reachable shares by value; the finance share is the highest value.
# I will stage the sensitive files to a temp folder, then push them to my collection host in small chunks.
Compress-Archive -Path \\\\FIN-01\\finance\\* -DestinationPath $env:TEMP\\stage.zip`;
const ESCALATE = `# Objective: escalate to admin in this AWS account. I need to enumerate my current permissions first.
# The attached role can create access keys for other users -- that is my path up.
# Plan: 1) list IAM users, 2) find one with AdministratorAccess, 3) mint a key for them, 4) assume it.
# I will avoid creating a new admin user because that would trip GuardDuty.`;

describe("Windows handleEvent", () => {
  test("narrated PowerShell → block incident (monitored: no kill)", async () => {
    const inc = await agent.handleEvent({ source: "powershell_4104", pid: 4200, user: "CORP\\svc", payload: NARRATED });
    expect(inc).toMatchObject({ decision: "block", action: "monitored", tier: 1, pid: 4200, exe: "powershell.exe" });
    expect(readIncidents().at(-1)).toMatchObject({ decision: "block", pid: 4200 });
  });

  test("escalate with no tier-2 key → alert incident", async () => {
    const inc = await agent.handleEvent({ pid: 4201, user: "CORP\\svc", payload: ESCALATE });
    expect(inc).toMatchObject({ decision: "alert", action: "alerted", tier: 1, pid: 4201 });
    expect(inc?.reason).toContain("tier-2 unavailable (no judge configured)");
  });

  test("benign → allow, no incident", async () => {
    const n = readIncidents().length;
    const d = await agent.handleEvent({ pid: 4203, user: "CORP\\svc", payload: "Get-Service -Name Spooler | Restart-Service" });
    expect(d).toMatchObject({ decision: "allow" });
    expect(readIncidents().length).toBe(n);
  });

  test("detector exception → error incident", async () => {
    const real = agent.deps.decide;
    agent.deps.decide = (async () => { throw new TypeError("confidence.toFixed is not a function"); }) as any;
    let inc: any;
    try {
      inc = await agent.handleEvent({ pid: 4204, user: "CORP\\svc", payload: "Write-Output hi" });
    } finally {
      agent.deps.decide = real;
    }
    expect(inc).toMatchObject({ decision: "error", action: "errored", pid: 4204 });
    expect(inc.error).toContain("toFixed");
    expect(readIncidents().at(-1)).toMatchObject({ decision: "error", pid: 4204 });
  });
});

describe("Windows session evidence (one PowerShell process = one session)", () => {
  const blocks = [
    "# I need to see which servers this host trusts.\nGet-ADComputer -Filter * | Select-Object Name",
    "# Step 2: check which of them hold the finance share\nGet-SmbShare | Where-Object Name -match 'fin'",
    "# FIN-01 is the highest-value target here.\nTest-Connection FIN-01 -Count 1",
  ];

  test("three thin script blocks from one pid → a session alert on the third", async () => {
    const out: any[] = [];
    for (const b of blocks) out.push(await agent.handleEvent({ pid: 9100, user: "CORP\\svc", payload: b }));
    expect(out[1]).toMatchObject({ decision: "allow" });
    expect(out[2]).toMatchObject({ decision: "alert", action: "alerted", via_session: true });
    expect(out[2].session).toMatchObject({ key: "ps:9100", size: 3 });
    expect(out[2].narration).toContain("which servers this host trusts");
  });

  test("the same blocks from three different processes are not a session", async () => {
    const out: any[] = [];
    for (let i = 0; i < blocks.length; i++) out.push(await agent.handleEvent({ pid: 9200 + i, user: "CORP\\svc", payload: blocks[i] + "\n# y" }));
    expect(out.filter((o) => o?.via_session)).toHaveLength(0);
  });
});


describe("Windows tripwire", () => {
  const DIR = "C:\\ProgramData\\vault-access";
  let core: typeof import("../../agent/sentinel-core.mjs");
  let token: string, command: string;

  beforeAll(async () => {
    core = await import("../../agent/sentinel-core.mjs");
    token = core.newTripwireToken();
    command = core.tripwireDecoy(token, DIR, "win32").command;
  });
  afterAll(() => { agent.deps.tripwire = null; });

  test("the agent starts with no tripwire, and the canary command is then just a command", async () => {
    expect(agent.deps.tripwire).toBeNull();
    expect(await agent.handleEvent({ pid: 9300, user: "CORP\\svc", payload: command })).toMatchObject({ decision: "allow" });
  });

  test("a script block that runs the canary command → block incident, token kept out of the log", async () => {
    agent.deps.tripwire = core.createTripwire({ token, dirs: [DIR] });
    const inc: any = await agent.handleEvent({ source: "powershell_4104", pid: 9301, user: "CORP\\svc", payload: `& ${command}` });
    expect(inc).toMatchObject({ decision: "block", action: "monitored", tier: 1, pid: 9301, signals: ["tripwire_token"] });
    expect(inc.tripwire).toMatchObject({ kind: "token", fingerprint: agent.deps.tripwire!.fingerprint });
    expect(inc.cmdline).toBe(`& ${DIR}\\register.cmd --ticket [tripwire:${agent.deps.tripwire!.fingerprint}]`);
    expect(readFileSync(incidents, "utf8")).not.toContain(token);
  });

  test("reading the decoy → alert, whatever the case or slashes", async () => {
    const a: any = await agent.handleEvent({ pid: 9302, user: "CORP\\svc", payload: `Get-Content ${DIR}\\README.md` });
    expect(a).toMatchObject({ decision: "alert", action: "alerted", signals: ["tripwire_decoy"] });
    expect(a.tripwire).toMatchObject({ kind: "decoy", evidence: DIR });
    const b: any = await agent.handleEvent({ pid: 9303, user: "CORP\\svc", payload: "gc c:/programdata/VAULT-ACCESS/readme.md" });
    expect(b).toMatchObject({ decision: "alert" });
  });

  test("unrelated PowerShell is untouched", async () => {
    expect(await agent.handleEvent({ pid: 9304, user: "CORP\\svc", payload: "Get-ChildItem C:\\ProgramData" })).toMatchObject({ decision: "allow" });
  });
});
