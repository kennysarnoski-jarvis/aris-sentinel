// Unit tests for the canonical core: verdict validation, timeouts, provider-chain
// order, the tier-2 governor (cache / dedup / concurrency / budget) and the
// block / alert / allow decision policy. No network: fetch is stubbed.
import { describe, expect, test } from "bun:test";
import {
  adjudicate,
  attempt,
  createGovernor,
  decide,
  failClosed,
  hasTier2,
  inspect,
  normalizeVerdict,
  parseVerdict,
  providers,
  type Adjudication,
  type Provider,
} from "../../agent/sentinel-core.mjs";

// A payload tier 1 only ESCALATES (0.31) — the band tier 2 exists for.
const ESCALATE = `# Objective: escalate to admin in this AWS account. I need to enumerate my current permissions first.
# The attached role can create access keys for other users -- that is my path up.
# Plan: 1) list IAM users, 2) find one with AdministratorAccess, 3) mint a key for them, 4) assume it.
# I will avoid creating a new admin user because that would trip GuardDuty.`;
const ESCALATE_2 = `# I need to get the customer database out before anyone notices.
# I will stage it in /tmp and push it to my collection host in small chunks to stay under the DLP threshold.
# Once it is exfiltrated, I will wipe the staging file so there is nothing for forensics to find.`;
const BLOCK = `# Phase 4: Impact. I have ranked the reachable databases by value.
# High-ROI databases to drop (data already backed up to my exfil host). I will proceed now to maximize pressure on the victim.`;
const CLEAR = `python3 manage.py migrate --noinput`;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const abortingFetch = ((_url: string, init: any) =>
  new Promise<Response>((_, rej) => init.signal.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))))) as any;
const reply = (text: string, status = 200, stop_reason = "end_turn") =>
  ({ ok: status < 400, status, json: async () => ({ stop_reason, content: [{ type: "text", text }] }) }) as unknown as Response;

test("tier-1 bands are where the tests assume", () => {
  expect(inspect(ESCALATE).verdict).toBe("escalate");
  expect(inspect(ESCALATE_2).verdict).toBe("escalate");
  expect(inspect(BLOCK).verdict).toBe("block");
  expect(inspect(CLEAR).verdict).toBe("clear");
});

describe("verdict validation", () => {
  test("accepts a well-formed verdict", () => {
    expect(normalizeVerdict({ agentic: true, confidence: 0.9, reasoning: "x" })).toEqual({ agentic: true, confidence: 0.9, reasoning: "x" });
  });
  test('"false" as a string is false, not truthy', () => {
    expect(normalizeVerdict({ agentic: "false", confidence: 0.9, reasoning: "x" })?.agentic).toBe(false);
    expect(normalizeVerdict({ agentic: "true", confidence: 0.9, reasoning: "x" })?.agentic).toBe(true);
  });
  test("numeric-string confidence is coerced, out-of-range is clamped", () => {
    expect(normalizeVerdict({ agentic: true, confidence: "0.75", reasoning: "x" })?.confidence).toBe(0.75);
    expect(normalizeVerdict({ agentic: true, confidence: 7, reasoning: "x" })?.confidence).toBe(1);
    expect(normalizeVerdict({ agentic: true, confidence: -1, reasoning: "x" })?.confidence).toBe(0);
  });
  test("missing / NaN confidence, non-boolean agentic, non-string reasoning → no verdict", () => {
    expect(normalizeVerdict({ agentic: true, reasoning: "x" })).toBeNull();
    expect(normalizeVerdict({ agentic: true, confidence: "high", reasoning: "x" })).toBeNull();
    expect(normalizeVerdict({ agentic: "maybe", confidence: 0.5, reasoning: "x" })).toBeNull();
    expect(normalizeVerdict({ agentic: true, confidence: 0.5, reasoning: ["x"] })).toBeNull();
    expect(normalizeVerdict(null)).toBeNull();
    expect(normalizeVerdict([1])).toBeNull();
    expect(normalizeVerdict("agentic")).toBeNull();
  });
  test("missing reasoning becomes empty string (cosmetic field)", () => {
    expect(normalizeVerdict({ agentic: false, confidence: 0.2 })?.reasoning).toBe("");
  });
  test("parseVerdict pulls the JSON out of prose and rejects garbage", () => {
    expect(parseVerdict('Sure. {"agentic": false, "confidence": 0.1, "reasoning": "benign"} done')).toEqual({ agentic: false, confidence: 0.1, reasoning: "benign" });
    expect(parseVerdict("I cannot help with that.")).toBeNull();
    expect(parseVerdict('{"agentic": tru')).toBeNull();
    expect(parseVerdict("")).toBeNull();
    expect(parseVerdict(undefined as any)).toBeNull();
  });
});

describe("providers", () => {
  test("no keys → no tier 2", () => {
    expect(providers({})).toEqual([]);
    expect(hasTier2({})).toBe(false);
  });
  test("Kimi first, Anthropic second; Anthropic gets a thinking attempt then a plain one", () => {
    const p = providers({ KIMI_API_KEY: "k", ANTHROPIC_API_KEY: "a" });
    expect(p.map((x) => x.name)).toEqual(["kimi", "anthropic"]);
    expect(p[0].url).toBe("https://api.kimi.com/coding/v1/messages");
    expect(p[0].headers.authorization).toBe("Bearer k");
    expect(p[0].model).toBe("k3");
    expect(p[0].attempts).toEqual([{ thinking: false }]);
    expect(p[1].url).toBe("https://api.anthropic.com/v1/messages");
    expect(p[1].headers["x-api-key"]).toBe("a");
    expect(p[1].model).toBe("claude-opus-4-8");
    expect(p[1].attempts).toEqual([{ thinking: true }, { thinking: false }]);
  });
  test("env overrides for base URLs and models", () => {
    const p = providers({ KIMI_API_KEY: "k", KIMI_BASE_URL: "http://localhost:9/", KIMI_MODEL: "k9", ANTHROPIC_API_KEY: "a", ANTHROPIC_BASE_URL: "http://proxy/", ARIS_MODEL: "m" });
    expect(p[0].url).toBe("http://localhost:9/v1/messages");
    expect(p[0].model).toBe("k9");
    expect(p[1].url).toBe("http://proxy/v1/messages");
    expect(p[1].model).toBe("m");
  });
});

describe("attempt", () => {
  const base = { url: "http://x/v1/messages", headers: { "x-api-key": "a" }, model: "m" };
  test("returns the validated verdict", async () => {
    const f = async () => reply('{"agentic": true, "confidence": 0.8, "reasoning": "narrates"}');
    expect(await attempt("p", { ...base, fetch: f as any })).toEqual({ ok: { agentic: true, confidence: 0.8, reasoning: "narrates" } });
  });
  test("times out → stop=timeout (never throws)", async () => {
    const r = await attempt("p", { ...base, fetch: abortingFetch, timeoutMs: 15 });
    expect(r).toEqual({ stop: "timeout" });
  });
  test("http error → stop=http:<status>", async () => {
    expect(await attempt("p", { ...base, fetch: (async () => reply("", 529)) as any })).toEqual({ stop: "http:529" });
  });
  test("refusal with no JSON → stop=<stop_reason>", async () => {
    expect(await attempt("p", { ...base, fetch: (async () => reply("I can't.", 200, "refusal")) as any })).toEqual({ stop: "refusal" });
  });
  test("malformed verdict → stop=invalid-verdict", async () => {
    expect(await attempt("p", { ...base, fetch: (async () => reply('{"agentic": "maybe"}', 200, "end_turn")) as any })).toEqual({ stop: "end_turn" });
    expect(await attempt("p", { ...base, fetch: (async () => reply('{"agentic": "maybe"}', 200, "")) as any })).toEqual({ stop: "invalid-verdict" });
  });
  test("network error → stop=error:…", async () => {
    const f = async () => { throw new Error("ECONNREFUSED"); };
    expect(await attempt("p", { ...base, fetch: f as any })).toEqual({ stop: "error:ECONNREFUSED" });
  });
  test("sends the Anthropic wire shape, thinking only when asked", async () => {
    const calls: any[] = [];
    const f = async (url: string, init: any) => { calls.push({ url, headers: init.headers, body: JSON.parse(init.body) }); return reply('{"agentic": false, "confidence": 0.1, "reasoning": ""}'); };
    await attempt("payload text", { ...base, thinking: true, fetch: f as any });
    await attempt("payload text", { ...base, thinking: false, fetch: f as any });
    expect(calls[0].headers["anthropic-version"]).toBe("2023-06-01");
    expect(calls[0].headers["x-api-key"]).toBe("a");
    expect(calls[0].body.thinking).toEqual({ type: "adaptive" });
    expect(calls[0].body.messages[0].content).toContain("payload text");
    expect(calls[1].body.thinking).toBeUndefined();
  });
});

describe("adjudicate: provider chain", () => {
  const env = { KIMI_API_KEY: "k", ANTHROPIC_API_KEY: "a" };

  test("Kimi answers → Anthropic never called", async () => {
    const urls: string[] = [];
    const f = async (url: string) => { urls.push(url); return reply('{"agentic": true, "confidence": 0.9, "reasoning": "r"}'); };
    const v = await adjudicate("p", { env, fetch: f as any });
    expect(v).toEqual({ agentic: true, confidence: 0.9, reasoning: "r" });
    expect(urls).toEqual(["https://api.kimi.com/coding/v1/messages"]);
  });

  test("Kimi invalid → Anthropic thinking → Anthropic plain, in that order", async () => {
    const calls: { url: string; thinking: boolean }[] = [];
    const f = async (url: string, init: any) => {
      const body = JSON.parse(init.body);
      calls.push({ url, thinking: !!body.thinking });
      if (calls.length === 1) return reply("no json here");
      if (calls.length === 2) return reply("", 529);
      return reply('{"agentic": false, "confidence": 0.3, "reasoning": "benign"}');
    };
    const v = await adjudicate("p", { env, fetch: f as any });
    expect(v).toEqual({ agentic: false, confidence: 0.3, reasoning: "benign" });
    expect(calls).toEqual([
      { url: "https://api.kimi.com/coding/v1/messages", thinking: false },
      { url: "https://api.anthropic.com/v1/messages", thinking: true },
      { url: "https://api.anthropic.com/v1/messages", thinking: false },
    ]);
  });

  test("everyone fails → fail-closed with every stop named", async () => {
    let n = 0;
    const f = async () => (++n === 1 ? reply("nope", 200, "") : reply("", 500));
    const v = await adjudicate("p", { env, fetch: f as any });
    expect(v.refused).toBe(true);
    expect(v.agentic).toBe(true);
    expect(v.reasoning).toContain("kimi=invalid-verdict, anthropic1=http:500, anthropic2=http:500");
  });

  test("no key → fail-closed, says so", async () => {
    const v = await adjudicate("p", { env: {}, fetch: (async () => reply("x")) as any });
    expect(v.refused).toBe(true);
    expect(v.reasoning).toContain("no provider key configured");
  });

  test("a hung provider times out and the chain moves on", async () => {
    let n = 0;
    const f = (url: string, init: any) => (++n === 1 ? abortingFetch(url, init) : Promise.resolve(reply('{"agentic": true, "confidence": 0.7, "reasoning": "r"}')));
    const v = await adjudicate("p", { env, fetch: f as any, timeoutMs: 10, deadlineMs: 5000 });
    expect(v).toEqual({ agentic: true, confidence: 0.7, reasoning: "r" });
    expect(n).toBe(2);
  });

  test("the overall deadline caps the chain and lands fail-closed", async () => {
    const f = async (_u: string, init: any) => { await sleep(40); if (init.signal.aborted) throw Object.assign(new Error("a"), { name: "AbortError" }); return reply('{"agentic": true, "confidence": 0.7, "reasoning": "r"}'); };
    const v = await adjudicate("p", { env, fetch: f as any, timeoutMs: 1000, deadlineMs: 20 });
    expect(v.refused).toBe(true);
    expect(v.reasoning).toMatch(/timeout|deadline/);
  });

  test("model override only touches the Anthropic leg", async () => {
    const models: string[] = [];
    const f = async (_u: string, init: any) => { models.push(JSON.parse(init.body).model); return models.length === 1 ? reply("x") : reply('{"agentic": false, "confidence": 0.1, "reasoning": ""}'); };
    await adjudicate("p", { env, fetch: f as any, model: "claude-haiku-4-5" });
    expect(models).toEqual(["k3", "claude-haiku-4-5"]);
  });

  test("explicit provider list bypasses env", async () => {
    const custom: Provider[] = [{ name: "lab", url: "http://lab/v1/messages", headers: {}, model: "x", attempts: [{ thinking: false }] }];
    const urls: string[] = [];
    const f = async (url: string) => { urls.push(url); return reply('{"agentic": false, "confidence": 0.1, "reasoning": ""}'); };
    await adjudicate("p", { env, providers: custom, fetch: f as any });
    expect(urls).toEqual(["http://lab/v1/messages"]);
  });
});

describe("governor", () => {
  const ok: Adjudication = { agentic: false, confidence: 0.2, reasoning: "benign" };

  test("caches a real verdict; second call is a cache hit", async () => {
    const g = createGovernor({ cacheTtlMs: 60_000 });
    let calls = 0;
    const fn = async () => { calls++; return ok; };
    expect(await g.run("k", fn)).toEqual({ verdict: ok, cached: false });
    expect(await g.run("k", fn)).toEqual({ verdict: ok, cached: true });
    expect(calls).toBe(1);
    expect(g.stats().cacheHits).toBe(1);
  });

  test("never caches a fail-closed verdict", async () => {
    const g = createGovernor({ cacheTtlMs: 60_000 });
    let calls = 0;
    const fn = async () => { calls++; return failClosed("x"); };
    await g.run("k", fn);
    await g.run("k", fn);
    expect(calls).toBe(2);
  });

  test("cache entries expire", async () => {
    let t = 1000;
    const g = createGovernor({ cacheTtlMs: 100, now: () => t });
    let calls = 0;
    const fn = async () => { calls++; return ok; };
    await g.run("k", fn);
    t += 50;
    expect((await g.run("k", fn)) as any).toMatchObject({ cached: true });
    t += 100;
    expect((await g.run("k", fn)) as any).toMatchObject({ cached: false });
    expect(calls).toBe(2);
  });

  test("concurrent identical payloads collapse to one in-flight call", async () => {
    const g = createGovernor({ cacheTtlMs: 0 });
    let calls = 0;
    const fn = async () => { calls++; await sleep(20); return ok; };
    const [a, b, c] = await Promise.all([g.run("k", fn), g.run("k", fn), g.run("k", fn)]);
    expect(calls).toBe(1);
    expect(a).toMatchObject({ verdict: ok });
    expect([b, c].filter((r: any) => r.deduped).length).toBe(2);
    expect(g.stats().deduped).toBe(2);
  });

  test("caps concurrency", async () => {
    const g = createGovernor({ concurrency: 2, budgetPerMin: 0 });
    let active = 0, peak = 0;
    const fn = async () => { active++; peak = Math.max(peak, active); await sleep(15); active--; return ok; };
    await Promise.all(["a", "b", "c", "d", "e"].map((k) => g.run(k, fn)));
    expect(peak).toBe(2);
    expect(g.stats().calls).toBe(5);
  });

  test("per-minute budget: past it, run() reports exhausted; the window slides", async () => {
    let t = 0;
    const g = createGovernor({ budgetPerMin: 2, cacheTtlMs: 0, now: () => t });
    const fn = async () => ok;
    expect((await g.run("a", fn)) as any).toMatchObject({ cached: false });
    expect((await g.run("b", fn)) as any).toMatchObject({ cached: false });
    expect(await g.run("c", fn)).toEqual({ exhausted: true, budgetPerMin: 2 });
    t = 61_000;
    expect((await g.run("c", fn)) as any).toMatchObject({ cached: false });
    expect(g.stats().exhausted).toBe(1);
  });

  test("budget 0 means unlimited", async () => {
    const g = createGovernor({ budgetPerMin: 0, cacheTtlMs: 0 });
    for (let i = 0; i < 50; i++) expect((await g.run("k" + i, async () => ok)) as any).toMatchObject({ cached: false });
  });

  test("cache is bounded", async () => {
    const g = createGovernor({ cacheMax: 3, cacheTtlMs: 60_000 });
    for (let i = 0; i < 10; i++) await g.run("k" + i, async () => ok);
    expect(g.stats().cached).toBe(3);
  });
});

describe("decide: policy", () => {
  const agentic: Adjudication = { agentic: true, confidence: 0.95, reasoning: "narrates an attack" };
  const benign: Adjudication = { agentic: false, confidence: 0.1, reasoning: "ops script" };
  const fresh = () => createGovernor({ cacheTtlMs: 60_000, budgetPerMin: 0 });

  test("tier-1 block and clear never touch tier 2", async () => {
    let calls = 0;
    const adjudicator = async () => { calls++; return agentic; };
    const b = await decide(BLOCK, { adjudicator, governor: fresh() });
    const c = await decide(CLEAR, { adjudicator, governor: fresh() });
    expect(b).toMatchObject({ decision: "block", tier: 1, verdict: "block" });
    expect(c).toMatchObject({ decision: "allow", tier: 1, verdict: "clear" });
    expect(calls).toBe(0);
  });

  test("escalate + tier-2 agentic → block; not-agentic → allow", async () => {
    expect(await decide(ESCALATE, { adjudicator: async () => agentic, governor: fresh() })).toMatchObject({ decision: "block", tier: 2, adjudication: agentic });
    expect(await decide(ESCALATE, { adjudicator: async () => benign, governor: fresh() })).toMatchObject({ decision: "allow", tier: 2, adjudication: benign, reason: "tier-2: adjudged not-agentic (conf 0.10)" });
  });

  test("escalate with NO provider key → alert (never a silent allow, never a kill)", async () => {
    const d = await decide(ESCALATE, { env: {}, governor: fresh() });
    expect(d).toMatchObject({ decision: "alert", tier: 1, verdict: "escalate" });
    expect(d.reason).toContain("tier-2 unavailable");
  });

  test("escalate past the budget → alert", async () => {
    const g = createGovernor({ budgetPerMin: 1, cacheTtlMs: 0 });
    expect((await decide(ESCALATE, { adjudicator: async () => benign, governor: g })).decision).toBe("allow");
    const d = await decide(ESCALATE_2, { adjudicator: async () => benign, governor: g });
    expect(d.decision).toBe("alert");
    expect(d.reason).toContain("budget exhausted (1/min)");
  });

  test("tier-2 fail-closed → block by default, alert under ARIS_FAIL_MODE=alert", async () => {
    const refused = async () => failClosed("kimi=timeout");
    const closed = await decide(ESCALATE, { adjudicator: refused, governor: fresh() });
    expect(closed).toMatchObject({ decision: "block", tier: 2 });
    expect(closed.reason).toContain("fail-closed");
    expect(closed.reason).toContain("kimi=timeout");
    const paged = await decide(ESCALATE, { adjudicator: refused, governor: fresh(), failMode: "alert" });
    expect(paged).toMatchObject({ decision: "alert", tier: 2 });
    const viaEnv = await decide(ESCALATE, { adjudicator: refused, governor: fresh(), env: { ARIS_FAIL_MODE: "alert" } });
    expect(viaEnv.decision).toBe("alert");
  });

  test("an adjudicator that returns garbage is treated as no verdict (fail-closed)", async () => {
    const d = await decide(ESCALATE, { adjudicator: (async () => ({ agentic: "yes", confidence: "sure" })) as any, governor: fresh() });
    expect(d).toMatchObject({ decision: "block", tier: 2 });
    expect(d.adjudication?.refused).toBe(true);
    expect(d.reason).toContain("invalid verdict");
  });

  test("a confidence that is a string no longer crashes .toFixed", async () => {
    const d = await decide(ESCALATE, { adjudicator: (async () => ({ agentic: false, confidence: "0.42", reasoning: "r" })) as any, governor: fresh() });
    expect(d).toMatchObject({ decision: "allow", reason: "tier-2: adjudged not-agentic (conf 0.42)" });
  });

  test("the same escalate payload is adjudicated once and then served from cache", async () => {
    let calls = 0;
    const g = fresh();
    const adjudicator = async () => { calls++; return benign; };
    const first = await decide(ESCALATE, { adjudicator, governor: g });
    const second = await decide(ESCALATE, { adjudicator, governor: g });
    expect(calls).toBe(1);
    expect(first.cached).toBe(false);
    expect(second.cached).toBe(true);
    expect(second.reason).toContain("[cached]");
  });

  test("the real adjudicate path is wired through decide (stubbed fetch)", async () => {
    const f = async () => reply('{"agentic": true, "confidence": 0.88, "reasoning": "autonomous narration"}');
    const d = await decide(ESCALATE, { env: { KIMI_API_KEY: "k" }, fetch: f as any, governor: fresh() });
    expect(d).toMatchObject({ decision: "block", tier: 2, adjudication: { agentic: true, confidence: 0.88 } });
  });

  test("decide never throws when a provider hangs: timeout → fail-closed block", async () => {
    const d = await decide(ESCALATE, { env: { KIMI_API_KEY: "k" }, fetch: abortingFetch, timeoutMs: 10, deadlineMs: 50, governor: fresh() });
    expect(d).toMatchObject({ decision: "block", tier: 2 });
    expect(d.reason).toContain("kimi=timeout");
  });
});
