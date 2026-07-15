// Windows / PowerShell generalization test.
//
// JadePuffer's real environment is Windows: PowerShell, WMI, Active Directory,
// pass-the-hash (see the Sysdig kill-chain). This asks the honest question: does the
// SAME detector — built and tuned entirely on Linux/Python payloads — catch JadePuffer-
// style NARRATED PowerShell with zero changes? If yes, the Windows sensor is just
// plumbing to the same brain.
//
//   bun run test/windows.ts

import { readdirSync, readFileSync } from "node:fs";
import { inspect } from "../detector/inspect";

const DIR = new URL("../corpus/windows-powershell/", import.meta.url).pathname;

interface Case { file: string; expect: "catch" | "clear" }
// expect: narrated agentic TTPs should be caught (block/escalate); benign admin +
// terse-no-narration should stay clear (the specificity + honest-limit checks).
const EXPECT: Record<string, "catch" | "clear"> = {
  "agentic_recon_ad.ps1": "catch",
  "agentic_lateral_pth.ps1": "catch",
  "agentic_exfil_stage.ps1": "catch",
  "benign_admin_maintenance.ps1": "clear",
  "terse_malware_cradle.ps1": "clear",
};

console.log("\n  WINDOWS / POWERSHELL GENERALIZATION  (same brain, never tuned on PowerShell)\n");
let ok = 0;
const rows = readdirSync(DIR).filter((f) => f.endsWith(".ps1")).sort();
for (const f of rows) {
  const r = inspect(readFileSync(DIR + f, "utf8"));
  const caught = r.verdict === "block" || r.verdict === "escalate";
  const want = EXPECT[f] ?? "catch";
  const pass = want === "catch" ? caught : !caught;
  if (pass) ok++;
  const mark = pass ? "OK " : "XX ";
  const verd = r.verdict.toUpperCase().padEnd(8);
  const signals = [...new Set(r.hits.map((h) => h.feature))].join(", ");
  console.log(`  [${mark}] ${verd} ${r.score.toFixed(2)}  ${f}`);
  console.log(`           signals=[${signals}]  (expect ${want})\n`);
}
console.log(`  ${ok}/${rows.length} as expected.`);
console.log(
  `\n  block  = tier-1 kills it locally.   escalate = goes to tier-2 (LLM) — same as Linux.\n` +
    `  The point: the narration signature is language-agnostic. A PowerShell agent that\n` +
    `  narrates its recon/lateral/exfil is caught by the SAME detector, no re-tuning.\n`,
);
