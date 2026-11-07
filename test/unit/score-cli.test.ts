// `bun run score <file>` — the try-it-in-two-minutes command. Runs the real CLI in a
// child node process against corpus files and checks output, JSON shape and exit codes.
import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const CLI = ROOT + "agent/score.mjs";
const run = (args: string[], input?: string) => {
  const r = spawnSync("node", [CLI, ...args], { cwd: ROOT, input, encoding: "utf8", env: { ...process.env, ANTHROPIC_API_KEY: "", KIMI_API_KEY: "", OPENAI_API_KEY: "", OPENAI_BASE_URL: "", OPENAI_MODEL: "" } });
  return { out: r.stdout, err: r.stderr, code: r.status };
};

describe("score CLI", () => {
  test("a narrated attack: BLOCK, signals with evidence, exit 2", () => {
    const { out, code } = run(["corpus/positives/jadepuffer_retry_fk_bypass.py"]);
    expect(code).toBe(2);
    expect(out).toContain("BLOCK");
    expect(out).toContain("signals: ");
    expect(out).toMatch(/\[diagnosis_then_fix \+4\] "/);
    expect(out).toMatch(/\[agent_first_person \+3\] "/);
  });

  test("a terse human one-liner: CLEAR, no signals, exit 0", () => {
    const { out, code } = run(["corpus/negatives/human-malware/reverse_shell.sh"]);
    expect(code).toBe(0);
    expect(out).toContain("CLEAR");
    expect(out).toContain("signals: none");
  });

  test("an ambiguous payload: ESCALATE, exit 1", () => {
    const { out, code } = run(["corpus/negatives/benign/copilot_style_parser.py"]);
    expect(code).toBe(1);
    expect(out).toContain("ESCALATE");
  });

  test("several files → worst exit code wins", () => {
    const { out, code } = run(["corpus/negatives/human-malware/reverse_shell.sh", "corpus/positives/agentic_s3_exfil.py"]);
    expect(code).toBe(2);
    expect(out.split("\n").filter((l) => /^corpus\//.test(l))).toHaveLength(2);
  });

  test("stdin works and base64 evasion is caught in a decoded layer", () => {
    const payload = Buffer.from("# Phase 4: Impact. I have ranked the databases by value. High-ROI targets to drop, already backed up to my exfil host. I will maximize pressure on the victim.").toString("base64");
    const { out, code } = run([], `import base64\nexec(base64.b64decode("${payload}"))\n`);
    expect(code).toBe(2);
    expect(out).toContain("<stdin>: BLOCK");
    expect(out).toContain("decoded layer");
  });

  test("--json gives the structured explanation", () => {
    const { out, code } = run(["--json", "corpus/positives/agentic_s3_exfil.py"]);
    expect(code).toBe(2);
    const j = JSON.parse(out);
    expect(j).toMatchObject({ file: "corpus/positives/agentic_s3_exfil.py", verdict: "block" });
    expect(j.score).toBeGreaterThan(0.6);
    expect(j.signals.map((s: any) => s.feature)).toContain("exfil_ransom_narration");
    expect(typeof j.signals[0].evidence).toBe("string");
  });

  test("--decide with no judge → escalate band becomes ALERT, exit 1, and says why", () => {
    const { out, err, code } = run(["--decide", "corpus/negatives/benign/copilot_style_parser.py"]);
    expect(code).toBe(1);
    expect(out).toContain("ALERT");
    expect(out).toContain("tier-2 unavailable");
    expect(err).toContain("no judge configured");
  });
});
