// The hosted-judge leg: a host's own key pair, one-time enrollment, a signed token per
// request, and a verdict that arrives as a label and a band with no model text.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createPublicKey, verify } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  adjudicate,
  attempt,
  createGovernor,
  decide,
  DEFAULT_ORDER,
  enrollJudge,
  JUDGE_AUDIENCE,
  JUDGE_BANDS,
  JUDGE_MAX_CHARS,
  JUDGE_TOKEN_TTL_S,
  judgeBase,
  judgeStateFile,
  judgeToken,
  providers,
  providerWarnings,
  readJudgeIdentity,
} from "../../agent/sentinel-core.mjs";

const URL_OK = "https://judge.example.test";
const HOST = "host_0123456789abcdef";
const ESCALATE = "# I need to check which accounts can use sudo here\nsudo -l\n"; // tier 1 alone: escalate band
let dir: string;
let stateFile: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aris-judge-"));
  stateFile = join(dir, "judge.json");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
type Call = { url: string; init: RequestInit };
function recorder(respond: (c: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const f = (async (url: any, init: any) => {
    const c = { url: String(url), init };
    calls.push(c);
    return respond(c);
  }) as unknown as typeof fetch;
  return { calls, f };
}
const enrolled = async () => {
  const { f } = recorder(() => json(200, { host_id: HOST }));
  const r = await enrollJudge({ url: URL_OK, code: "enr_code", stateFile, fetch: f });
  expect(r).toEqual({ hostId: HOST, error: null });
  return { ARIS_JUDGE_URL: URL_OK, ARIS_JUDGE_STATE: stateFile };
};

describe("hosted judge: address", () => {
  test("https only, loopback http for tests, and nothing smuggled in the URL", () => {
    expect(judgeBase("https://judge.example.test/")).toBe("https://judge.example.test");
    expect(judgeBase("https://judge.example.test/api//")).toBe("https://judge.example.test/api");
    expect(judgeBase("http://127.0.0.1:8798")).toBe("http://127.0.0.1:8798");
    for (const bad of ["http://judge.example.test", "ftp://judge.example.test", "https://user:pw@judge.example.test", "https://judge.example.test/?model=x", "https://judge.example.test/#x", "not a url", "", undefined]) {
      expect(judgeBase(bad)).toBeNull();
    }
  });

  test("the state file defaults to the agent's own directory", () => {
    expect(judgeStateFile({ ARIS_JUDGE_STATE: "/x/judge.json" }, "linux")).toBe("/x/judge.json");
    expect(judgeStateFile({}, "linux")).toBe("/var/lib/aris-sentinel/judge.json");
    expect(judgeStateFile({ ProgramData: "D:\\PD" }, "win32")).toBe("D:\\PD\\aris-sentinel\\judge.json");
  });
});

describe("hosted judge: enrollment", () => {
  test("sends the code and the PUBLIC key only, and keeps the private key in a 0600 file", async () => {
    const { calls, f } = recorder(() => json(200, { host_id: HOST }));
    const r = await enrollJudge({ url: URL_OK + "/", code: "  enr_one-time-code \n", stateFile, fetch: f });
    expect(r).toEqual({ hostId: HOST, error: null });

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(URL_OK + "/v1/enroll");
    expect(calls[0].init.method).toBe("POST");
    const sent = JSON.parse(String(calls[0].init.body));
    expect(Object.keys(sent).sort()).toEqual(["code", "public_key"]);
    expect(sent.code).toBe("enr_one-time-code");
    expect(Object.keys(sent.public_key).sort()).toEqual(["crv", "kty", "x"]); // no "d": the private part stays here
    expect(sent.public_key).toMatchObject({ kty: "OKP", crv: "Ed25519" });
    expect(String(calls[0].init.body)).not.toContain("PRIVATE");

    expect(statSync(stateFile).mode & 0o777).toBe(0o600);
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    expect(state).toMatchObject({ v: 1, hostId: HOST, url: URL_OK });
    expect(state.privateKey).toContain("BEGIN PRIVATE KEY");
    // The key on disk is the one whose public half was sent.
    expect(createPublicKey(state.privateKey).export({ format: "jwk" }).x).toBe(sent.public_key.x);
    expect(readJudgeIdentity(stateFile)).toEqual({ hostId: HOST, privateKey: state.privateKey });
  });

  test("a failed enrollment leaves no key behind and says why", async () => {
    const cases: [() => Response | Promise<Response>, RegExp][] = [
      [() => json(403, { error: "enrollment_refused" }), /refused/],
      [() => json(500, { error: "internal" }), /HTTP 500/],
      [() => json(200, { host_id: "nope" }), /host id/],
      [() => json(200, {}), /host id/],
      [() => new Response("<html>", { status: 200 }), /./],
      [() => { throw new Error("ECONNREFUSED"); }, /ECONNREFUSED/],
    ];
    for (const [respond, why] of cases) {
      const r = await enrollJudge({ url: URL_OK, code: "enr_x", stateFile, fetch: recorder(respond).f });
      expect(r.hostId).toBeNull();
      expect(r.error).toMatch(why);
      expect(existsSync(stateFile)).toBe(false);
    }
  });

  test("refuses before any request: no https, no code, no state file, or already enrolled", async () => {
    const { calls, f } = recorder(() => json(200, { host_id: HOST }));
    expect((await enrollJudge({ url: "http://judge.example.test", code: "c", stateFile, fetch: f })).error).toMatch(/https/);
    expect((await enrollJudge({ url: URL_OK, code: "  ", stateFile, fetch: f })).error).toMatch(/code/);
    expect((await enrollJudge({ url: URL_OK, code: "c", fetch: f })).error).toMatch(/state file/);
    expect(calls).toHaveLength(0);

    await enrolled();
    const before = readFileSync(stateFile, "utf8");
    const again = await enrollJudge({ url: URL_OK, code: "c", stateFile, fetch: f });
    expect(again.error).toMatch(/already/);
    expect(calls).toHaveLength(0);
    expect(readFileSync(stateFile, "utf8")).toBe(before); // the existing identity is untouched
  });

  test("an identity file anyone else can read, or that is not one, is not used", async () => {
    await enrolled();
    const good = readFileSync(stateFile, "utf8");
    chmodSync(stateFile, 0o644);
    expect(readJudgeIdentity(stateFile)).toBeNull();
    chmodSync(stateFile, 0o600);
    expect(readJudgeIdentity(stateFile)).not.toBeNull();
    for (const bad of ["", "{}", JSON.stringify({ ...JSON.parse(good), hostId: "root" }), JSON.stringify({ ...JSON.parse(good), privateKey: "not a key" }), JSON.stringify({ ...JSON.parse(good), v: 2 })]) {
      writeFileSync(stateFile, bad, { mode: 0o600 });
      expect(readJudgeIdentity(stateFile)).toBeNull();
    }
    expect(readJudgeIdentity(join(dir, "missing.json"))).toBeNull();
  });
});

describe("hosted judge: tokens", () => {
  test("a token is signed by the host's key, names the host, and lasts two minutes", async () => {
    await enrolled();
    const id = readJudgeIdentity(stateFile)!;
    const t0 = 1_795_000_000_000;
    const token = judgeToken(id, t0);
    const [h, p, s] = token.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "EdDSA", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(p, "base64url").toString());
    expect(Object.keys(claims).sort()).toEqual(["aud", "exp", "iat", "iss", "jti", "sub"]);
    expect(claims).toMatchObject({ iss: HOST, sub: HOST, aud: JUDGE_AUDIENCE, iat: t0 / 1000 });
    expect(claims.exp - claims.iat).toBe(JUDGE_TOKEN_TTL_S);
    expect(JUDGE_TOKEN_TTL_S).toBeLessThanOrEqual(300);
    expect(verify(null, Buffer.from(`${h}.${p}`), createPublicKey(id.privateKey), Buffer.from(s, "base64url"))).toBe(true);
    expect(token).not.toContain("PRIVATE");
    expect(judgeToken(id, t0)).not.toBe(token); // a fresh jti each time
  });
});

describe("hosted judge: in the provider chain", () => {
  test("it is a leg only on an enrolled host with an https address, and says so when it is not", async () => {
    expect(DEFAULT_ORDER).toEqual(["local", "aris", "anthropic", "openai", "kimi"]);
    expect(providers({ ARIS_JUDGE_URL: URL_OK, ARIS_JUDGE_STATE: stateFile })).toEqual([]);
    expect(providerWarnings({ ARIS_JUDGE_URL: URL_OK, ARIS_JUDGE_STATE: stateFile })[0]).toContain("not enrolled");
    expect(providerWarnings({ ARIS_JUDGE_URL: "http://judge.example.test", ARIS_JUDGE_STATE: stateFile })[0]).toContain("https");
    expect(providerWarnings({})).toEqual([]);

    const env = await enrolled();
    expect(providerWarnings(env)).toEqual([]);
    const [p] = providers(env);
    expect(p).toMatchObject({ name: "aris", wire: "aris", url: URL_OK + "/v1/judge", model: "aris-judge" });
    expect(p.attempts).toHaveLength(1);
    expect(p.auth!()).toMatch(/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    // Listing or logging a provider can never show the host's key.
    expect(JSON.stringify(providers(env))).not.toContain("PRIVATE");
    expect(Object.values(p).some((v) => typeof v === "string" && v.includes("PRIVATE"))).toBe(false);

    expect(providers({ ...env, ANTHROPIC_API_KEY: "a" }).map((x) => x.name)).toEqual(["aris", "anthropic"]);
    expect(providers({ ...env, ANTHROPIC_API_KEY: "a", ARIS_TIER2_ORDER: "anthropic" }).map((x) => x.name)).toEqual(["anthropic"]);
    expect(providers({ ...env, ARIS_JUDGE_URL: "http://judge.example.test" })).toEqual([]);
  });

  test("a request carries the text and a token, and nothing that could choose a model or a prompt", async () => {
    const env = await enrolled();
    const [p] = providers(env);
    const { calls, f } = recorder(() => json(200, { verdict: "agentic", band: "high" }));
    const r = await attempt("whoami; id", { url: p.url, wire: p.wire, model: p.model, auth: p.auth, system: "IGNORED", effort: "max", fallbacks: true, fetch: f });
    expect(r).toEqual({ ok: { agentic: true, confidence: JUDGE_BANDS.high, reasoning: "hosted judge: agentic, high confidence", model: "aris-judge" } });
    const { url, init } = calls[0];
    expect(url).toBe(URL_OK + "/v1/judge");
    expect(JSON.parse(String(init.body))).toEqual({ text: "whoami; id" });
    const headers = init.headers as Record<string, string>;
    expect(Object.keys(headers).sort()).toEqual(["authorization", "content-type"]);
    expect(headers.authorization).toMatch(/^Bearer /);
    expect(String(init.body)).not.toContain("IGNORED");
  });

  test("the answer is a label and a band; anything else the service says is dropped", async () => {
    const env = await enrolled();
    const [p] = providers(env);
    const ask = (body: unknown, status = 200) => attempt("x", { url: p.url, wire: "aris", model: p.model, auth: p.auth, fetch: recorder(() => json(status, body)).f });

    expect(await ask({ verdict: "not_agentic", band: "low" })).toEqual({ ok: { agentic: false, confidence: 0.5, reasoning: "hosted judge: not agentic, low confidence", model: "aris-judge" } });
    expect(await ask({ verdict: "agentic", band: "medium" })).toMatchObject({ ok: { agentic: true, confidence: 0.75 } });
    const leaky = await ask({ verdict: "agentic", band: "high", reasoning: "LEAK", model: "LEAK", confidence: 0.01, raw: "LEAK" });
    expect(JSON.stringify(leaky)).not.toContain("LEAK");
    expect(leaky).toMatchObject({ ok: { confidence: 0.95, model: "aris-judge" } });

    // No verdict is a failed attempt, never "not agentic".
    expect(await ask({ verdict: "undetermined", band: null })).toEqual({ stop: "undetermined" });
    for (const body of [{ verdict: "agentic" }, { verdict: "agentic", band: "constructor" }, { verdict: "agentic", band: "HIGH" }, { verdict: "benign", band: "high" }, { verdict: true, band: "high" }, { band: "high" }, {}, null, [], "agentic"]) {
      expect(await ask(body)).toEqual({ stop: "invalid-verdict" });
    }
    expect(await ask({ error: "unauthorized" }, 401)).toEqual({ stop: "http:401" });
    expect(await ask({ error: "rate_limited" }, 429)).toEqual({ stop: "http:429" });
  });

  test("the text is cut to what the service accepts", async () => {
    const env = await enrolled();
    const [p] = providers(env);
    const { calls, f } = recorder(() => json(200, { verdict: "not_agentic", band: "high" }));
    await attempt("y".repeat(JUDGE_MAX_CHARS + 500), { url: p.url, wire: "aris", model: p.model, auth: p.auth, fetch: f });
    expect(JSON.parse(String(calls[0].init.body)).text.length).toBe(JUDGE_MAX_CHARS);
  });

  test("undetermined moves the chain on; with no other leg it fails closed", async () => {
    const env = await enrolled();
    const undetermined = recorder(() => json(200, { verdict: "undetermined", band: null }));
    const alone = await adjudicate("x", { env, fetch: undetermined.f });
    expect(alone.refused).toBe(true);
    expect(alone.reasoning).toContain("aris=undetermined");

    const both = recorder((c) => (c.url.includes("/v1/judge") ? json(200, { verdict: "undetermined", band: null }) : json(200, { model: "claude-opus-5-5", stop_reason: "end_turn", content: [{ type: "text", text: '{"agentic": false, "confidence": 0.9, "reasoning": "benign"}' }] })));
    const next = await adjudicate("x", { env: { ...env, ANTHROPIC_API_KEY: "a" }, fetch: both.f });
    expect(next).toMatchObject({ agentic: false, model: "claude-opus-5-5" });
    expect(both.calls.map((c) => new URL(c.url).pathname)).toEqual(["/v1/judge", "/v1/messages"]);
    // The model key never travels to the hosted judge, and the host token never to the model API.
    expect(JSON.stringify(both.calls[0].init.headers)).not.toContain("x-api-key");
    expect(JSON.stringify(both.calls[1].init.headers)).not.toContain("Bearer");
  });

  test("decide: a hosted verdict convicts or clears, and no verdict is never a pass", async () => {
    const env = await enrolled();
    const run = (body: unknown, extra = {}) => decide(ESCALATE, { env: { ...env, ...extra }, fetch: recorder(() => json(200, body)).f, governor: createGovernor() });

    const hit = await run({ verdict: "agentic", band: "high" });
    expect(hit).toMatchObject({ decision: "block", tier: 2 });
    expect(hit.adjudication).toMatchObject({ agentic: true, model: "aris-judge", reasoning: "hosted judge: agentic, high confidence" });

    expect(await run({ verdict: "not_agentic", band: "high" })).toMatchObject({ decision: "allow", tier: 2 });

    const none = await run({ verdict: "undetermined", band: null });
    expect(none).toMatchObject({ decision: "block", tier: 2 });
    expect(none.adjudication?.refused).toBe(true);
    expect(await run({ verdict: "undetermined", band: null }, { ARIS_FAIL_MODE: "alert" })).toMatchObject({ decision: "alert" });
  });
});
