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
    expect(inc?.reason).toContain("tier-2 unavailable");
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
