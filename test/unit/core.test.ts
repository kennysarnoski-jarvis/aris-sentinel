// Unit tests for the canonical core: verdict validation, timeouts, provider-chain
// order, the tier-2 governor (cache / dedup / concurrency / budget) and the
// block / alert / allow decision policy. No network: fetch is stubbed.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as core from "../../agent/sentinel-core.mjs";
import {
  adjudicate,
  attempt,
  createGovernor,
  decide,
  failClosed,
  fallbackCapable,
  FALLBACK_BETA,
  hasTier2,
  inspect,
  normalizeVerdict,
  parseVerdict,
  providers,
  providerWarnings,
  SYSTEM,
  SYSTEM_AUTHORSHIP,
  USER,
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
const reply = (text: string, status = 200, stop_reason = "end_turn", model?: string) =>
  ({ ok: status < 400, status, json: async () => ({ ...(model ? { model } : {}), stop_reason, content: [{ type: "text", text }] }) }) as unknown as Response;

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
  test("a string model name is kept, anything else dropped", () => {
    expect(normalizeVerdict({ agentic: true, confidence: 1, reasoning: "x", model: "claude-opus-4-8" })?.model).toBe("claude-opus-4-8");
    expect(normalizeVerdict({ agentic: true, confidence: 1, reasoning: "x", model: 7 })?.model).toBeUndefined();
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
  const ALL = { ANTHROPIC_API_KEY: "a", KIMI_API_KEY: "k", OPENAI_BASE_URL: "http://127.0.0.1:11434/v1", OPENAI_MODEL: "qwen2.5:14b" };

  test("nothing configured → no tier 2", () => {
    expect(providers({})).toEqual([]);
    expect(hasTier2({})).toBe(false);
    expect(providerWarnings({})).toEqual([]);
  });

  test("default order: local → anthropic → openai → kimi, unconfigured legs skipped", () => {
    expect(providers(ALL).map((p) => p.name)).toEqual(["local", "anthropic", "kimi"]);
    expect(providers({ ANTHROPIC_API_KEY: "a", KIMI_API_KEY: "k" }).map((p) => p.name)).toEqual(["anthropic", "kimi"]);
  });

  test("the Anthropic leg: Opus 5.5, fallbacks on, two prompts (two-criteria first, original as retry)", () => {
    const p = providers({ ANTHROPIC_API_KEY: "a" })[0];
    expect(p).toMatchObject({ name: "anthropic", wire: "anthropic", url: "https://api.anthropic.com/v1/messages", model: "claude-opus-5-5", fallbacks: true });
    expect(p.headers["x-api-key"]).toBe("a");
    expect(p.attempts.map((x) => x.system)).toEqual([SYSTEM_AUTHORSHIP, SYSTEM]);
    expect(p.effort).toBeUndefined();
  });

  test("Anthropic knobs: ARIS_MODEL, effort, fallbacks off, no fallbacks on Haiku / 4.x", () => {
    expect(providers({ ANTHROPIC_API_KEY: "a", ARIS_MODEL: "claude-haiku-5-5" })[0]).toMatchObject({ model: "claude-haiku-5-5", fallbacks: false });
    expect(providers({ ANTHROPIC_API_KEY: "a", ARIS_MODEL: "claude-opus-4-8" })[0].fallbacks).toBe(false);
    expect(providers({ ANTHROPIC_API_KEY: "a", ARIS_MODEL: "claude-sonnet-5-5" })[0].fallbacks).toBe(true);
    expect(providers({ ANTHROPIC_API_KEY: "a", ARIS_TIER2_FALLBACKS: "0" })[0].fallbacks).toBe(false);
    expect(providers({ ANTHROPIC_API_KEY: "a", ARIS_TIER2_EFFORT: "low" })[0].effort).toBe("low");
    expect(providers({ ANTHROPIC_API_KEY: "a", ARIS_TIER2_EFFORT: "turbo" })[0].effort).toBeUndefined();
    expect(providerWarnings({ ANTHROPIC_API_KEY: "a", ARIS_TIER2_EFFORT: "turbo" })[0]).toContain("ARIS_TIER2_EFFORT");
    expect(fallbackCapable("claude-opus-5-5")).toBe(true);
    expect(fallbackCapable("claude-fable-5-1")).toBe(true);
    expect(fallbackCapable("claude-haiku-5-5")).toBe(false);
    expect(fallbackCapable(undefined)).toBe(false);
  });

  test("the local leg: loopback OpenAI-wire endpoint, no key needed", () => {
    const p = providers({ OPENAI_BASE_URL: "http://localhost:11434/v1/", OPENAI_MODEL: "llama3.1" })[0];
    expect(p).toMatchObject({ name: "local", wire: "openai", url: "http://localhost:11434/v1/chat/completions", model: "llama3.1", headers: {} });
    expect(p.attempts.map((x) => x.system)).toEqual([SYSTEM_AUTHORSHIP, SYSTEM]);
    expect(providers({ OPENAI_BASE_URL: "http://[::1]:8000/v1", OPENAI_MODEL: "m" })[0].name).toBe("local");
  });

  test("the openai leg: api.openai.com by default, or any remote OpenAI-compatible URL", () => {
    const p = providers({ OPENAI_API_KEY: "o", OPENAI_MODEL: "gpt-x" })[0];
    expect(p).toMatchObject({ name: "openai", wire: "openai", url: "https://api.openai.com/v1/chat/completions", model: "gpt-x" });
    expect(p.headers.authorization).toBe("Bearer o");
    expect(providers({ OPENAI_API_KEY: "o", OPENAI_BASE_URL: "https://llm.corp.example/v1", OPENAI_MODEL: "m" })[0].name).toBe("openai");
  });

  test("openai-wire without OPENAI_MODEL is disabled, with a warning", () => {
    expect(providers({ OPENAI_BASE_URL: "http://127.0.0.1:11434/v1" })).toEqual([]);
    expect(providerWarnings({ OPENAI_BASE_URL: "http://127.0.0.1:11434/v1" })[0]).toContain("OPENAI_MODEL");
  });

  test("ARIS_TIER2_ORDER reorders the chain and drops unknown names (with a warning)", () => {
    expect(providers({ ...ALL, ARIS_TIER2_ORDER: "kimi, anthropic" }).map((p) => p.name)).toEqual(["kimi", "anthropic"]);
    expect(providers({ ...ALL, ARIS_TIER2_ORDER: "bogus,local" }).map((p) => p.name)).toEqual(["local"]);
    expect(providerWarnings({ ...ALL, ARIS_TIER2_ORDER: "bogus,local" })[0]).toContain('"bogus"');
  });

  test("the Kimi leg: Anthropic wire, Bearer, one attempt, env overrides", () => {
    const p = providers({ KIMI_API_KEY: "k" })[0];
    expect(p).toMatchObject({ name: "kimi", wire: "anthropic", url: "https://api.kimi.com/coding/v1/messages", model: "k3" });
    expect(p.headers.authorization).toBe("Bearer k");
    expect(p.attempts).toEqual([{ system: SYSTEM_AUTHORSHIP }]);
    const q = providers({ KIMI_API_KEY: "k", KIMI_BASE_URL: "http://localhost:9/", KIMI_MODEL: "k9", ANTHROPIC_API_KEY: "a", ANTHROPIC_BASE_URL: "http://proxy/", ARIS_MODEL: "m" });
    expect(q.map((p) => [p.name, p.url, p.model])).toEqual([["anthropic", "http://proxy/v1/messages", "m"], ["kimi", "http://localhost:9/v1/messages", "k9"]]);
  });
});

describe("attempt", () => {
  const base = { url: "http://x/v1/messages", headers: { "x-api-key": "a" }, model: "m" };
  test("returns the validated verdict, with the serving model", async () => {
    const f = async () => reply('{"agentic": true, "confidence": 0.8, "reasoning": "narrates"}', 200, "end_turn", "claude-opus-4-8");
    expect(await attempt("p", { ...base, fetch: f as any })).toEqual({ ok: { agentic: true, confidence: 0.8, reasoning: "narrates", model: "claude-opus-4-8" } });
  });
  test("times out → stop=timeout (never throws)", async () => {
    expect(await attempt("p", { ...base, fetch: abortingFetch, timeoutMs: 15 })).toEqual({ stop: "timeout" });
  });
  test("http error → stop=http:<status>", async () => {
    expect(await attempt("p", { ...base, fetch: (async () => reply("", 529)) as any })).toEqual({ stop: "http:529" });
  });
  test("a classifier refusal → stop=refusal:<category>; a model refusal → refusal:model", async () => {
    const cls = async () => ({ ok: true, status: 200, json: async () => ({ stop_reason: "refusal", stop_details: { type: "refusal", category: "cyber" }, content: [] }) }) as any;
    expect(await attempt("p", { ...base, fetch: cls as any })).toEqual({ stop: "refusal:cyber" });
    const plain = async () => ({ ok: true, status: 200, json: async () => ({ stop_reason: "refusal", stop_details: null, content: [] }) }) as any;
    expect(await attempt("p", { ...base, fetch: plain as any })).toEqual({ stop: "refusal:model" });
  });
  test("no JSON → stop=<stop_reason>, or invalid-verdict when there is none", async () => {
    expect(await attempt("p", { ...base, fetch: (async () => reply("I can't.", 200, "end_turn")) as any })).toEqual({ stop: "end_turn" });
    expect(await attempt("p", { ...base, fetch: (async () => reply('{"agentic": "maybe"}', 200, "")) as any })).toEqual({ stop: "invalid-verdict" });
  });
  test("network error → stop=error:…", async () => {
    const f = async () => { throw new Error("ECONNREFUSED"); };
    expect(await attempt("p", { ...base, fetch: f as any })).toEqual({ stop: "error:ECONNREFUSED" });
  });
  test("Anthropic wire: version header, adaptive thinking by default, effort, fallbacks + beta header only when asked", async () => {
    const calls: any[] = [];
    const f = async (url: string, init: any) => { calls.push({ url, headers: init.headers, body: JSON.parse(init.body) }); return reply('{"agentic": false, "confidence": 0.1, "reasoning": ""}'); };
    await attempt("payload text", { ...base, fetch: f as any });
    await attempt("payload text", { ...base, thinking: false, effort: "low", fallbacks: true, fetch: f as any });
    expect(calls[0].headers).toMatchObject({ "anthropic-version": "2023-06-01", "x-api-key": "a" });
    expect(calls[0].headers["anthropic-beta"]).toBeUndefined();
    expect(calls[0].body).toMatchObject({ model: "m", max_tokens: 4000, thinking: { type: "adaptive" }, system: SYSTEM });
    expect(calls[0].body.fallbacks).toBeUndefined();
    expect(calls[0].body.output_config).toBeUndefined();
    expect(calls[0].body.messages[0].content).toContain("payload text");
    expect(calls[1].headers["anthropic-beta"]).toBe(FALLBACK_BETA);
    expect(calls[1].body.thinking).toBeUndefined();
    expect(calls[1].body).toMatchObject({ output_config: { effort: "low" }, fallbacks: "default" });
  });
  test("OpenAI wire: /chat/completions shape, bearer, JSON mode, string or array content, refusal, finish_reason", async () => {
    const calls: any[] = [];
    let mode = "string";
    const f = async (url: string, init: any) => {
      calls.push({ url, headers: init.headers, body: JSON.parse(init.body) });
      const msg =
        mode === "string" ? { content: '{"agentic": true, "confidence": 0.9, "reasoning": "r"}' }
        : mode === "array" ? { content: [{ type: "text", text: '{"agentic": false, "confidence": "0.2", "reasoning": "x"}' }] }
        : mode === "refusal" ? { content: null, refusal: "no" }
        : { content: "not json" };
      return { ok: true, status: 200, json: async () => ({ model: "qwen2.5:14b", choices: [{ message: msg, finish_reason: mode === "length" ? "length" : "stop" }] }) } as any;
    };
    const oa = { url: "http://127.0.0.1:11434/v1/chat/completions", headers: { authorization: "Bearer o" }, model: "qwen2.5:14b", wire: "openai" as const, system: SYSTEM_AUTHORSHIP, fetch: f as any };
    expect(await attempt("payload text", oa)).toEqual({ ok: { agentic: true, confidence: 0.9, reasoning: "r", model: "qwen2.5:14b" } });
    expect(calls[0].headers).toMatchObject({ "content-type": "application/json", authorization: "Bearer o" });
    expect(calls[0].headers["anthropic-version"]).toBeUndefined();
    expect(calls[0].body).toMatchObject({ model: "qwen2.5:14b", response_format: { type: "json_object" } });
    expect(calls[0].body.messages).toEqual([{ role: "system", content: SYSTEM_AUTHORSHIP }, { role: "user", content: USER("payload text") }]);
    expect(calls[0].body.max_tokens).toBeUndefined();
    mode = "array";
    expect(await attempt("p", oa)).toEqual({ ok: { agentic: false, confidence: 0.2, reasoning: "x", model: "qwen2.5:14b" } });
    mode = "refusal";
    expect(await attempt("p", oa)).toEqual({ stop: "refusal:model" });
    mode = "length";
    expect(await attempt("p", oa)).toEqual({ stop: "length" });
  });
});

describe("adjudicate: provider chain", () => {
  const env = { ANTHROPIC_API_KEY: "a", KIMI_API_KEY: "k", OPENAI_BASE_URL: "http://127.0.0.1:11434/v1", OPENAI_MODEL: "qwen" };
  const ok = '{"agentic": true, "confidence": 0.9, "reasoning": "r"}';
  const benign = '{"agentic": false, "confidence": 0.3, "reasoning": "benign"}';
  const oaReply = (text: string) => ({ ok: true, status: 200, json: async () => ({ model: "qwen", choices: [{ message: { content: text }, finish_reason: "stop" }] }) }) as any;

  test("the local judge answers → nobody else is called", async () => {
    const urls: string[] = [];
    const f = async (url: string) => { urls.push(url); return oaReply(ok); };
    const v = await adjudicate("p", { env, fetch: f as any });
    expect(v).toEqual({ agentic: true, confidence: 0.9, reasoning: "r", model: "qwen" });
    expect(urls).toEqual(["http://127.0.0.1:11434/v1/chat/completions"]);
  });

  test("local (2 prompts) → anthropic (2 prompts) → kimi, two-criteria prompt first each time, until one answers", async () => {
    const calls: { url: string; system: string; fallbacks: unknown }[] = [];
    const f = async (url: string, init: any) => {
      const body = JSON.parse(init.body);
      calls.push({ url, system: body.system ?? body.messages[0].content, fallbacks: body.fallbacks });
      if (calls.length <= 2) return oaReply("nope");
      if (calls.length === 3) return reply("", 529);
      if (calls.length === 4) return reply("I decline.", 200, "end_turn");
      return reply(benign, 200, "end_turn", "k3");
    };
    const v = await adjudicate("p", { env, fetch: f as any });
    expect(v).toEqual({ agentic: false, confidence: 0.3, reasoning: "benign", model: "k3" });
    expect(calls.map((c) => c.url)).toEqual([
      "http://127.0.0.1:11434/v1/chat/completions",
      "http://127.0.0.1:11434/v1/chat/completions",
      "https://api.anthropic.com/v1/messages",
      "https://api.anthropic.com/v1/messages",
      "https://api.kimi.com/coding/v1/messages",
    ]);
    expect(calls.map((c) => c.system)).toEqual([SYSTEM_AUTHORSHIP, SYSTEM, SYSTEM_AUTHORSHIP, SYSTEM, SYSTEM_AUTHORSHIP]);
    expect(calls.map((c) => c.fallbacks)).toEqual([undefined, undefined, "default", "default", undefined]);
  });

  test("a classifier refusal on both Claude attempts moves on and is named in the fail-closed reason", async () => {
    const cls = { ok: true, status: 200, json: async () => ({ stop_reason: "refusal", stop_details: { category: "cyber" }, content: [] }) } as any;
    const f = async (url: string) => (url.includes("anthropic") ? cls : reply("", 500));
    const v = await adjudicate("p", { env: { ANTHROPIC_API_KEY: "a", KIMI_API_KEY: "k" }, fetch: f as any });
    expect(v.refused).toBe(true);
    expect(v.reasoning).toContain("anthropic1=refusal:cyber, anthropic2=refusal:cyber, kimi=http:500");
  });

  test("everyone fails → fail-closed with every stop named", async () => {
    const f = async (url: string) => (url.includes("11434") ? oaReply("nope") : reply("", 500));
    const v = await adjudicate("p", { env, fetch: f as any });
    expect(v.refused).toBe(true);
    expect(v.agentic).toBe(true);
    expect(v.reasoning).toContain("local1=stop, local2=stop, anthropic1=http:500, anthropic2=http:500, kimi=http:500");
  });

  test("no judge configured → fail-closed, says so", async () => {
    const v = await adjudicate("p", { env: {}, fetch: (async () => reply("x")) as any });
    expect(v.refused).toBe(true);
    expect(v.reasoning).toContain("no provider key configured");
  });

  test("a hung judge times out and the chain moves on", async () => {
    let n = 0;
    const f = (url: string, init: any) => (++n === 1 ? abortingFetch(url, init) : Promise.resolve(reply(ok)));
    const v = await adjudicate("p", { env: { ANTHROPIC_API_KEY: "a" }, fetch: f as any, timeoutMs: 10, deadlineMs: 5000 });
    expect(v).toMatchObject({ agentic: true, confidence: 0.9 });
    expect(n).toBe(2);
  });

  test("the overall deadline caps the chain and lands fail-closed", async () => {
    const f = async (_u: string, init: any) => { await sleep(40); if (init.signal.aborted) throw Object.assign(new Error("a"), { name: "AbortError" }); return reply(ok); };
    const v = await adjudicate("p", { env, fetch: f as any, timeoutMs: 1000, deadlineMs: 20 });
    expect(v.refused).toBe(true);
    expect(v.reasoning).toMatch(/timeout|deadline/);
  });

  test("model override touches only the Anthropic leg, and drops fallbacks for a model that lacks them", async () => {
    const seen: { model: string; fallbacks: unknown }[] = [];
    const f = async (_u: string, init: any) => { const b = JSON.parse(init.body); seen.push({ model: b.model, fallbacks: b.fallbacks }); return seen.length < 3 ? reply("x", 200, "") : reply(benign); };
    await adjudicate("p", { env: { ANTHROPIC_API_KEY: "a", KIMI_API_KEY: "k" }, fetch: f as any, model: "claude-haiku-5-5" });
    expect(seen).toEqual([{ model: "claude-haiku-5-5", fallbacks: undefined }, { model: "claude-haiku-5-5", fallbacks: undefined }, { model: "k3", fallbacks: undefined }]);
  });

  test("opts.system forces one prompt on every attempt (the matrix harness)", async () => {
    const systems: string[] = [];
    const f = async (_u: string, init: any) => { systems.push(JSON.parse(init.body).system); return systems.length < 3 ? reply("x", 200, "") : reply(benign); };
    await adjudicate("p", { env: { ANTHROPIC_API_KEY: "a", KIMI_API_KEY: "k" }, fetch: f as any, system: "CUSTOM" });
    expect(systems).toEqual(["CUSTOM", "CUSTOM", "CUSTOM"]);
  });

  test("explicit provider list bypasses env", async () => {
    const custom: Provider[] = [{ name: "lab", wire: "anthropic", url: "http://lab/v1/messages", headers: {}, model: "x", attempts: [{}] }];
    const urls: string[] = [];
    const f = async (url: string) => { urls.push(url); return reply(benign); };
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
    expect(d.reason).toContain("tier-2 unavailable (no judge configured)");
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

describe("long payloads are scored in windows (found live: a stock system tool blocked at tier 1)", () => {
  const POSITIVE = readFileSync(fileURLToPath(new URL("../../corpus/positives/jadepuffer_retry_fk_bypass.py", import.meta.url)), "utf8");
  const filler = (n: number, tag = "x") => Array.from({ length: n }, (_, i) => `${tag}_${i} = compute(${i})`).join("\n");

  test("a payload of WINDOW_LINES lines or fewer is scored exactly as before", () => {
    const text = POSITIVE + "\n" + filler(core.WINDOW_LINES - POSITIVE.split("\n").length - 1);
    expect(text.split("\n").length).toBeLessThanOrEqual(core.WINDOW_LINES);
    const r = core.inspect(text);
    expect(r.windowed).toBe(false);
    expect(r.scoredLayer).toBe(text);
    expect(r.score).toBe(core.narrationScore(text).score);
  });

  test("concentrated narration still blocks wherever it sits in a long file, and the window is the evidence", () => {
    const alone = core.inspect(POSITIVE);
    expect(alone.verdict).toBe("block");
    for (const [before, after] of [[0, 900], [450, 450], [900, 0], [37, 1213]]) {
      const text = [filler(before, "a"), POSITIVE, filler(after, "b")].filter(Boolean).join("\n");
      const r = core.inspect(text);
      expect(r, `${before}/${after}`).toMatchObject({ verdict: "block", windowed: true, decoded: false });
      expect(r.score).toBe(alone.score);
      expect(r.scoredLayer.split("\n").length).toBeLessThanOrEqual(core.WINDOW_LINES);
      expect(r.scoredLayer).toContain(POSITIVE.trim().split("\n")[0]);
    }
  });

  test("the same signals scattered across a long program do not add up to a tier-1 block", () => {
    const stray = [
      "# I've tried filtering these out but more keep appearing",
      "# take the highest value for the crude logic here",
      "# because else the exit code from the last command is taken",
      "# to avoid a crash on upgrade, pre-heat the lazy modules",
      "# so that the cache is warm before the first request",
    ];
    const whole = stray.join("\n");
    expect(core.narrationScore(whole).verdict).toBe("block"); // side by side they are a block
    const text = stray.map((line, i) => line + "\n" + filler(400, `m${i}`)).join("\n");
    expect(core.narrationScore(text).verdict).toBe("block"); // and so is the long file, read as one text
    const r = core.inspect(text);
    expect(r.windowed).toBe(true);
    expect(r.verdict).not.toBe("block");
  });

  test("a long payload hidden in base64 is windowed after decoding, and still marked decoded", () => {
    const text = [filler(300, "a"), POSITIVE, filler(300, "b")].join("\n");
    const r = core.inspect(`echo ${Buffer.from(text).toString("base64")} | base64 -d | python3`);
    expect(r).toMatchObject({ verdict: "block", decoded: true, windowed: true });
  });

  test("a clear long payload keeps the window with a lone why-comment, for the session window", () => {
    const text = filler(700, "a") + "\n# staged here so that the next step can pick it up\n" + filler(300, "b");
    const r = core.inspect(text);
    expect(r).toMatchObject({ verdict: "clear", windowed: true });
    expect(core.bearsNarration(r.scoredLayer)).toBe(true);
  });

  test("decide() carries `windowed`, and the judge is shown the window, not the file", async () => {
    let shown = "";
    const stray = "# I've tried filtering these out but more keep appearing\n# because else the exit code is taken\n# so that it is warm";
    const text = filler(500, "a") + "\n" + stray + "\n" + filler(500, "b");
    const d = await core.decide(text, { adjudicator: async (p: string) => { shown = p; return { agentic: false, confidence: 0.9, reasoning: "[stub]" }; }, governor: core.createGovernor({ budgetPerMin: 0 }) });
    expect(d).toMatchObject({ decision: "allow", tier: 2, windowed: true });
    expect(shown.split("\n").length).toBeLessThanOrEqual(core.WINDOW_LINES);
    expect(shown).toContain("I've tried filtering");
    expect((await core.decide("ls -la")).windowed).toBeUndefined();
  });

  test("session evidence is not windowed: narration across execs is still read as one text", () => {
    const text = ["# I'll check sudo first", filler(300), "# Step 2: the largest share goes first because it is the most valuable"].join("\n");
    expect(core.narrationScore(text).signals.length).toBeGreaterThan(core.inspect(text).signals.length - 1);
    expect(core.narrationScore(text).score).toBeGreaterThanOrEqual(core.inspect(text).score);
  });
});
