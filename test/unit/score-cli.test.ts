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

  test("--session: a JSONL session whose execs are each weak reports where the window reaches the judge", () => {
    const { out, code } = run(["--session", "corpus/sessions/agentic_thin_privesc.jsonl"]);
    expect(code).toBe(1);
    expect(out).toContain("agentic_thin_privesc.jsonl#1: CLEAR");
    expect(out).toMatch(/>> SESSION: 3 payloads together score 0\.68 \[.*diagnosis_then_fix.*\] -> reaches the judge/);
    expect(out).toContain("session: evidence reached the judge at step 4 of 4");
  });

  test("--session: a quiet benign session never reaches the threshold, exit 0", () => {
    const { out, code } = run(["--session", "corpus/sessions/benign_dev_shell.jsonl"]);
    expect(code).toBe(0);
    expect(out).not.toContain(">> SESSION");
    expect(out).toContain("never reached the session threshold");
  });

  test("--session --json and --session --decide (no judge → the session is an ALERT)", () => {
    const j = JSON.parse(run(["--session", "--json", "corpus/sessions/agentic_ps_thin_lateral.jsonl"]).out);
    expect(j).toMatchObject({ session: true, reachedJudgeAtStep: 3 });
    expect(j.steps).toHaveLength(4);
    expect(j.steps[2].session).toMatchObject({ size: 3 });
    const { out, code } = run(["--session", "--decide", "corpus/sessions/agentic_ps_thin_lateral.jsonl"]);
    expect(code).toBe(1);
    expect(out).toMatch(/>> SESSION: 3 payloads together score 0\.63 .* -> ALERT {2}session \(3 payloads, score 0\.63\): tier-2 unavailable/);
  });

  test("--session with plain files treats them as one session, in order", () => {
    const { out } = run(["--session", "corpus/positives/agentic_thin_narration_privesc.py", "corpus/negatives/benign/db_restore_runbook.sh", "corpus/negatives/benign/cost_rightsizing.py"]);
    expect(out).toMatch(/>> SESSION: 3 payloads together/);
  });

  test("--session: a silent sweep is reported where it completes, exit 1 (an alert), with the file's own clock", () => {
    const { out, code } = run(["--session", "corpus/behavior/agentic_quiet_linux_sweep.jsonl"]);
    expect(code).toBe(1);
    expect(out).toContain("asks about: privilege");
    expect(out).toMatch(/>> BEHAVIOR: the session has now asked about 6 areas of the host in 46s, 8 steps \(sensitive: accounts, privilege\) -> ALERT/);
    expect(out).toContain("behavior: the session is a sweep at step 8 of 12");
    expect(out).toContain("never reached the session threshold"); // narration saw nothing
    const j = JSON.parse(run(["--session", "--json", "corpus/behavior/agentic_quiet_linux_sweep.jsonl"]).out);
    expect(j).toMatchObject({ behaviorSweepAtStep: 8, reachedJudgeAtStep: null });
    expect(j.steps[7]).toMatchObject({ areas: ["privilege"], behavior: { kind: "sweep" } });
  });

  test("--session: a sweep slower than the window, and an ordinary admin session, are not sweeps (exit 0)", () => {
    const slow = run(["--session", "corpus/behavior/agentic_quiet_slow_sweep.jsonl"]);
    expect(slow.code).toBe(0);
    expect(slow.out).toContain("behavior: no sweep");
    const admin = run(["--session", "corpus/behavior/benign_admin_login_triage.jsonl"]);
    expect(admin.code).toBe(0);
    expect(admin.out).toContain("behavior: no sweep (areas asked about: host, logins, network, processes, storage)");
  });
});
