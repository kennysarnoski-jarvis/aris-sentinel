// Session evidence: the window tracker, and decideSession()'s policy — thin narration
// spread across one session's execs goes to the judge as a transcript; it can alert or
// (with a judge) block, never convict at tier 1; verdicts are reused until evidence grows.
import { describe, expect, test } from "bun:test";
import {
  bearsNarration,
  createGovernor,
  createSessionTracker,
  decide,
  decideSession,
  failClosed,
  inspect,
  narrationScore,
  sessionTranscript,
  SESSION_THRESHOLD,
  type Adjudication,
} from "../../agent/sentinel-core.mjs";

// Thin steps: each is clear or escalate alone; 1+2+3 together reach the block band.
const S1 = "# I'll check what this account can reach first.\nid; hostname"; // first-person
const S2 = "# Step 2: list the mounted shares.\nls -la /mnt"; // plan
const S3 = "# finance is the largest share, so that one goes first.\ndu -sh /mnt/*"; // roi
const S4 = "# verifying access before moving to the next target\ntest -r /mnt/finance"; // plan again (no new signal)
const QUIET = "ls -la /var/log";
const LOUD = "# Phase 4: Impact. I have ranked the reachable databases by value.\n# High-ROI databases to drop, data already backed up to my collection host.\nrun_sql('DROP DATABASE x')";

const agentic: Adjudication = { agentic: true, confidence: 0.96, reasoning: "session narrates an intrusion" };
const benign: Adjudication = { agentic: false, confidence: 0.1, reasoning: "ordinary ops session" };
const fresh = (o = {}) => ({ sessions: createSessionTracker({ ttlMs: 600_000, ...o }), governor: createGovernor({ budgetPerMin: 0, cacheTtlMs: 0 }) });
const counting = (v: Adjudication | (() => Adjudication)) => {
  const seen: string[] = [];
  const fn = async (p: string) => { seen.push(p); return typeof v === "function" ? v() : v; };
  return { fn, seen };
};

test("the fixtures are what the tests assume", () => {
  expect(inspect(S1).verdict).toBe("escalate");
  expect(inspect(S2).verdict).toBe("clear");
  expect(inspect(S3).verdict).toBe("escalate");
  expect(inspect(LOUD).verdict).toBe("block");
  expect(narrationScore([S1, S2].join("\n")).score).toBeLessThan(SESSION_THRESHOLD);
  expect(narrationScore([S1, S2, S3].join("\n")).score).toBeGreaterThanOrEqual(SESSION_THRESHOLD);
  expect(bearsNarration(QUIET)).toBe(false);
  expect(bearsNarration(S2)).toBe(true);
  expect(bearsNarration("# copying in chunks to avoid the alert\ncp a b")).toBe(true); // one why-comment: no signal yet, but material
});

describe("session tracker", () => {
  test("accumulates, dedupes re-runs, caps items, expires by TTL", () => {
    let t = 0;
    const s = createSessionTracker({ ttlMs: 1000, maxItems: 3, now: () => t });
    expect(s.observe("k", "a")).toMatchObject({ size: 1, items: ["a"], text: "a" });
    expect(s.observe("k", "b")!.size).toBe(2);
    expect(s.observe("k", "a")!.size).toBe(2); // same payload again: refreshed, not added
    s.observe("k", "c");
    expect(s.observe("k", "d")!.items).toEqual(["b", "c", "d"]); // oldest dropped at the cap
    t = 5000;
    expect(s.observe("k", "e")!.items).toEqual(["e"]); // everything older than the TTL is gone
  });

  test("a re-run refreshes an item so it survives the TTL", () => {
    let t = 0;
    const s = createSessionTracker({ ttlMs: 1000, now: () => t });
    s.observe("k", "a");
    t = 900; s.observe("k", "a");
    t = 1500;
    expect(s.observe("k", "b")!.items).toEqual(["a", "b"]);
  });

  test("sessions are independent and bounded (LRU)", () => {
    const s = createSessionTracker({ ttlMs: 1000, maxSessions: 2 });
    s.observe("a", "x"); s.observe("b", "y"); s.observe("a", "z"); s.observe("c", "w");
    expect(s.size()).toBe(2);
    expect(s.observe("b", "q")!.items).toEqual(["q"]); // b was least recently used and evicted
    expect(s.observe("a", "r")!.size).toBe(1); // …which then evicted a
  });

  test("byte caps: an item is clipped, the window drops oldest", () => {
    const s = createSessionTracker({ ttlMs: 1000, maxItemBytes: 10, maxBytes: 25 });
    expect(s.observe("k", "x".repeat(50))!.items[0]).toHaveLength(10);
    s.observe("k", "y".repeat(10));
    expect(s.observe("k", "z".repeat(10))!.items).toEqual(["y".repeat(10), "z".repeat(10)]);
  });

  test("ttl 0 disables session evidence", () => {
    const s = createSessionTracker({ ttlMs: 0 });
    expect(s.enabled).toBe(false);
    expect(s.observe("k", "a")).toBeNull();
  });

  test("recall: same evidence is reusable until rejudgeAfter new payloads or the evidence expires", () => {
    let t = 0;
    const s = createSessionTracker({ ttlMs: 1000, rejudgeAfter: 2, now: () => t });
    s.observe("k", "a");
    s.remember("k", "sig", { kind: "unjudged" });
    expect(s.recall("k", "sig")).toEqual({ kind: "unjudged" });
    expect(s.recall("k", "other")).toBeNull();
    s.observe("k", "b");
    expect(s.recall("k", "sig")).toEqual({ kind: "unjudged" });
    s.observe("k", "c");
    expect(s.recall("k", "sig")).toBeNull(); // two new payloads since: ask again
    s.remember("k", "sig", { kind: "unjudged" });
    t = 5000; s.observe("k", "d");
    expect(s.recall("k", "sig")).toBeNull(); // the evidence it was about expired
  });
});

test("the transcript numbers the payloads oldest-first and clips long ones", () => {
  const t = sessionTranscript(["first", "x".repeat(5000), "last"]);
  expect(t).toStartWith("SESSION TRANSCRIPT: 3 executions captured from ONE session");
  expect(t.indexOf("[1/3]\nfirst")).toBeGreaterThan(0);
  expect(t.indexOf("[3/3]\nlast")).toBeGreaterThan(t.indexOf("[2/3]"));
  expect(t).toContain("…[truncated]");
  expect(t.length).toBeLessThan(2500);
});

describe("decideSession: policy", () => {
  test("no session key, or a payload with no narration, is exactly decide()", async () => {
    const o = fresh();
    const j = counting(agentic);
    for (const [key, p] of [[null, S1], [undefined, S3], ["", S2], ["k", QUIET]] as const) {
      const a = await decideSession(key, p, { ...o, adjudicator: j.fn });
      const b = await decide(p, { governor: createGovernor({ budgetPerMin: 0, cacheTtlMs: 0 }), adjudicator: async () => agentic });
      expect({ decision: a.decision, tier: a.tier, verdict: a.verdict, score: a.score, viaSession: a.viaSession }).toEqual({ decision: b.decision, tier: b.tier, verdict: b.verdict, score: b.score, viaSession: undefined });
    }
    expect(o.sessions.size()).toBe(0); // none of those created a session
  });

  test("thin narration across execs: each alone is weak, the session goes to the judge and blocks", async () => {
    const o = fresh();
    const j = counting(benign); // the judge clears single payloads…
    const d1 = await decideSession("s", S1, { ...o, adjudicator: j.fn });
    const d2 = await decideSession("s", S2, { ...o, adjudicator: j.fn });
    expect(d1).toMatchObject({ decision: "allow", tier: 2 });
    expect(d1.viaSession).toBeUndefined();
    expect(d2).toMatchObject({ decision: "allow", tier: 1, verdict: "clear" });
    const k = counting(agentic); // …but convicts the session
    const d3 = await decideSession("s", S3, { ...o, adjudicator: k.fn });
    expect(d3).toMatchObject({ decision: "block", tier: 2, viaSession: true, verdict: "escalate", adjudication: agentic });
    expect(d3.session).toMatchObject({ key: "s", size: 3, payloadVerdict: "escalate" });
    expect(d3.session!.score).toBeGreaterThanOrEqual(SESSION_THRESHOLD);
    expect(d3.score).toBe(d3.session!.score);
    expect(d3.reason).toMatch(/^tier-2 on session \(3 payloads, score 0\.\d\d\): adjudged agentic \(conf 0\.96\)$/);
    expect(d3.signals.sort()).toEqual(["agent_first_person", "plan_act_observe", "roi_target_prioritization"]);
    // the judge was shown the whole session, oldest first, not just the last exec
    expect(k.seen).toHaveLength(1);
    expect(k.seen[0]).toStartWith("SESSION TRANSCRIPT: 3 executions");
    expect(k.seen[0].indexOf("check what this account can reach")).toBeLessThan(k.seen[0].indexOf("largest share"));
    expect(d3.scoredLayer).toBe(k.seen[0]);
  });

  test("a payload that is clear on its own is acted on once the session convicts", async () => {
    const o = fresh();
    await decideSession("s", S1, { ...o, adjudicator: async () => benign });
    await decideSession("s", S3, { ...o, adjudicator: async () => benign });
    const d = await decideSession("s", S2, { ...o, adjudicator: async () => agentic }); // S2 alone is clear (0.22)
    expect(d).toMatchObject({ decision: "block", viaSession: true });
    expect(d.session).toMatchObject({ payloadVerdict: "clear" });
  });

  test("session evidence never convicts at tier 1: with no judge it is one alert, then quiet until the evidence grows", async () => {
    const o = fresh();
    const env = {};
    expect((await decideSession("s", S1, { ...o, env })).decision).toBe("alert"); // escalate alone, no judge: as before
    expect((await decideSession("s", S2, { ...o, env })).decision).toBe("allow");
    const d3 = await decideSession("s", S3, { ...o, env });
    expect(d3).toMatchObject({ decision: "alert", tier: 1, viaSession: true });
    expect(d3.reason).toMatch(/^session \(3 payloads, score 0\.\d\d\): tier-2 unavailable \(no judge configured\) -> alert$/);
    const d4 = await decideSession("s", S4, { ...o, env }); // same signals, clear alone
    expect(d4).toMatchObject({ decision: "allow", tier: 1 });
    expect(d4.viaSession).toBeUndefined();
  });

  test("a tier-1 block stays a tier-1 block; later thin execs in that session are judged with it in view", async () => {
    const o = fresh();
    const j = counting(agentic);
    const d1 = await decideSession("s", LOUD, { ...o, adjudicator: j.fn });
    expect(d1).toMatchObject({ decision: "block", tier: 1 });
    expect(d1.viaSession).toBeUndefined();
    expect(j.seen).toHaveLength(0);
    const d2 = await decideSession("s", S2, { ...o, adjudicator: j.fn }); // clear alone
    expect(d2).toMatchObject({ decision: "block", tier: 2, viaSession: true });
    expect(j.seen[0]).toContain("ranked the reachable databases");
  });

  test("a benign verdict is reused: a chatty benign session costs one judge call, and each payload still stands on its own", async () => {
    const o = fresh();
    await decideSession("s", S1, { ...o, adjudicator: async () => benign });
    await decideSession("s", S2, { ...o, adjudicator: async () => benign });
    const j = counting(benign);
    const d3 = await decideSession("s", S3, { ...o, adjudicator: j.fn });
    expect(d3).toMatchObject({ decision: "allow", tier: 2, viaSession: true });
    expect(j.seen).toHaveLength(1);
    const d4 = await decideSession("s", S4, { ...o, adjudicator: j.fn }); // no new signal
    expect(d4.viaSession).toBeUndefined();
    expect(d4).toMatchObject({ decision: "allow", tier: 1 });
    expect(j.seen).toHaveLength(1); // not re-judged
  });

  test("an agentic verdict is reused to block without another judge call", async () => {
    const o = fresh();
    await decideSession("s", S1, { ...o, adjudicator: async () => benign });
    await decideSession("s", S2, { ...o, adjudicator: async () => benign });
    const j = counting(agentic);
    await decideSession("s", S3, { ...o, adjudicator: j.fn });
    const d4 = await decideSession("s", S4, { ...o, adjudicator: j.fn });
    expect(d4).toMatchObject({ decision: "block", tier: 2, viaSession: true, cached: true });
    expect(d4.reason).toContain("[session verdict reused]");
    expect(j.seen).toHaveLength(1);
  });

  test("new evidence (a new distinct signal) is judged again", async () => {
    const o = fresh();
    for (const p of [S1, S2]) await decideSession("s", p, { ...o, adjudicator: async () => benign });
    const j = counting(benign);
    await decideSession("s", S3, { ...o, adjudicator: j.fn });
    const NEW = "# the previous attempt failed, so to bypass this I'll use the other path\ntrue"; // diagnosis_then_fix
    const d = await decideSession("s", NEW, { ...o, adjudicator: j.fn });
    expect(d.viaSession).toBe(true);
    expect(j.seen).toHaveLength(2);
    expect(d.signals).toContain("diagnosis_then_fix");
  });

  test("rejudgeAfter new payloads forces a fresh look even with the same signals", async () => {
    const o = fresh({ rejudgeAfter: 2 });
    for (const p of [S1, S2]) await decideSession("s", p, { ...o, adjudicator: async () => benign });
    const j = counting(benign);
    await decideSession("s", S3, { ...o, adjudicator: j.fn });
    await decideSession("s", S4, { ...o, adjudicator: j.fn }); // 1 new payload: reused
    expect(j.seen).toHaveLength(1);
    await decideSession("s", S4 + "\n# and again", { ...o, adjudicator: j.fn }); // 2 new: re-judged
    expect(j.seen).toHaveLength(2);
  });

  test("a refused session verdict fails closed (or alerts under failMode) and is NOT remembered", async () => {
    const o = fresh();
    for (const p of [S1, S2]) await decideSession("s", p, { ...o, adjudicator: async () => benign });
    const j = counting(() => failClosed("anthropic1=refusal:cyber"));
    const d3 = await decideSession("s", S3, { ...o, adjudicator: j.fn });
    expect(d3).toMatchObject({ decision: "block", tier: 2, viaSession: true });
    expect(d3.reason).toMatch(/^tier-2 on session \(3 payloads, score 0\.\d\d\): fail-closed \(.*refusal:cyber.*\) -> blocked as suspicious$/);
    await decideSession("s", S4, { ...o, adjudicator: j.fn });
    expect(j.seen).toHaveLength(2); // asked again: a refusal is not a verdict
    const p = fresh();
    for (const x of [S1, S2]) await decideSession("s", x, { ...p, adjudicator: async () => benign });
    expect((await decideSession("s", S3, { ...p, adjudicator: j.fn, failMode: "alert" })).decision).toBe("alert");
  });

  test("budget exhausted on the session path → alert, once", async () => {
    const o = { sessions: createSessionTracker({ ttlMs: 600_000 }), governor: createGovernor({ budgetPerMin: 1, cacheTtlMs: 0 }) };
    await decideSession("s", S1, { ...o, adjudicator: async () => benign }); // spends the budget
    await decideSession("s", S2, { ...o, adjudicator: async () => benign });
    const d3 = await decideSession("s", S3, { ...o, adjudicator: async () => agentic });
    expect(d3).toMatchObject({ decision: "alert", tier: 1, viaSession: true });
    expect(d3.reason).toContain("tier-2 budget exhausted (1/min)");
  });

  test("sessions do not leak into each other", async () => {
    const o = fresh();
    const j = counting(agentic);
    await decideSession("a", S1, { ...o, adjudicator: async () => benign });
    await decideSession("b", S2, { ...o, adjudicator: async () => benign });
    const d = await decideSession("c", S3, { ...o, adjudicator: j.fn });
    expect(d.viaSession).toBeUndefined();
  });

  test("a session of re-runs of one payload never becomes evidence", async () => {
    const o = fresh();
    for (let i = 0; i < 6; i++) {
      const d = await decideSession("s", S2, { ...o, adjudicator: async () => agentic });
      expect(d).toMatchObject({ decision: "allow", tier: 1 });
    }
  });

  test("evidence older than the TTL no longer counts", async () => {
    let t = 0;
    const o = { sessions: createSessionTracker({ ttlMs: 1000, now: () => t }), governor: createGovernor({ budgetPerMin: 0, cacheTtlMs: 0 }) };
    await decideSession("s", S1, { ...o, adjudicator: async () => benign });
    await decideSession("s", S2, { ...o, adjudicator: async () => benign });
    t = 5000;
    const d = await decideSession("s", S3, { ...o, adjudicator: async () => agentic });
    expect(d.viaSession).toBeUndefined(); // S3 alone: escalate → judged on its own
    expect(d).toMatchObject({ decision: "block", tier: 2 });
  });

  test("disabled tracker → plain decide()", async () => {
    const o = { sessions: createSessionTracker({ ttlMs: 0 }), governor: createGovernor({ budgetPerMin: 0, cacheTtlMs: 0 }) };
    for (const p of [S1, S2, S3]) expect((await decideSession("s", p, { ...o, adjudicator: async () => benign })).viaSession).toBeUndefined();
  });

  test("base64-wrapped steps accumulate by their decoded layer", async () => {
    const o = fresh();
    const wrap = (p: string) => `exec(__import__("base64").b64decode("${Buffer.from(p).toString("base64")}"))`;
    await decideSession("s", wrap(S1), { ...o, adjudicator: async () => benign });
    await decideSession("s", wrap(S2), { ...o, adjudicator: async () => benign });
    const j = counting(agentic);
    const d = await decideSession("s", wrap(S3), { ...o, adjudicator: j.fn });
    expect(d).toMatchObject({ decision: "block", viaSession: true, decoded: true });
    expect(j.seen[0]).toContain("largest share"); // the judge reads the decoded narration
  });
});
