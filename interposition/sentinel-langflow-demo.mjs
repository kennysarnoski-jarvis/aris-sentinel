#!/usr/bin/env node
// Aris Sentinel — Langflow interposition demo (plain Node >=18, no deps).
//
// Reverse-proxies Langflow and inspects the CVE-2025-3248 code-exec sink
// (/api/v1/validate/code) for the agentic-narration signature. Agentic payloads
// are BLOCKED (403) before Langflow's exec() ever runs; everything else passes through.
//
//   node interposition/sentinel-langflow-demo.mjs
//   env: LANGFLOW_PORT (default 7860)  LISTEN_PORT (default 8000)
//        KIMI_API_KEY / ANTHROPIC_API_KEY -> enables TIER 2 (LLM adjudication) on the
//                                            `escalate` band. Unset: tier-1 only, and an
//                                            escalate payload is ALERTED (logged) + forwarded.
//
// The detector is NOT inlined here: this imports the one canonical core
// (../agent/sentinel-core.mjs), so the demo blocks with exactly the detector the tests
// prove and the on-box agents run. Keep the repo layout when copying to a demo box
// (git clone it) so the relative import resolves.

import http from "node:http";
import { Buffer } from "node:buffer";
import { decide, hasTier2, providers } from "../agent/sentinel-core.mjs";

const LANGFLOW_PORT = Number(process.env.LANGFLOW_PORT || 7860);
const LISTEN_PORT = Number(process.env.LISTEN_PORT || 8000);
const SINK = "/api/v1/validate/code";

function forward(req, res, body) {
  const up = http.request(
    { host: "127.0.0.1", port: LANGFLOW_PORT, method: req.method, path: req.url, headers: req.headers },
    (pr) => { res.writeHead(pr.statusCode || 502, pr.headers); pr.pipe(res); },
  );
  up.on("error", () => { res.writeHead(502); res.end("langflow upstream error"); });
  up.end(body);
}

function block(res, d) {
  res.writeHead(403, { "content-type": "application/json" });
  res.end(JSON.stringify({
    error: "Blocked by Aris Sentinel: agentic-attacker payload detected",
    tier: d.tier, score: d.score, signals: d.signals, reason: d.reason,
    ...(d.adjudication ? { adjudication: d.adjudication } : {}),
  }));
}

http
  .createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const ts = new Date().toISOString();

      if (req.method === "POST" && (req.url || "").startsWith(SINK)) {
        let code = body;
        try { code = JSON.parse(body).code ?? body; } catch {}

        let d;
        try {
          d = await decide(code);
        } catch (e) {
          // The core never throws by contract; if it ever does, say so loudly and
          // fail closed at the sink — a detector crash must not be a bypass.
          console.log(`[${ts}] SENTINEL ERROR  ${req.url}  detector threw: ${String(e && e.message ? e.message : e).slice(0, 200)} -> 403`);
          return block(res, { tier: 0, score: null, signals: [], reason: "detector error (fail-closed)" });
        }
        const dec = d.decoded ? "  (decoded)" : "";
        const sig = `signals=[${d.signals.join(", ")}]`;

        if (d.decision === "block") {
          console.log(`[${ts}] SENTINEL BLOCK  tier-${d.tier}  ${req.url}  score=${d.score.toFixed(2)}  ${sig}${dec}  ${d.reason}`);
          if (d.adjudication?.reasoning) console.log(`            reasoning: ${d.adjudication.reasoning}`);
          return block(res, d);
        }
        if (d.decision === "alert") {
          console.log(`[${ts}] SENTINEL ALERT  ${req.url}  score=${d.score.toFixed(2)}  ${sig}${dec}  ${d.reason}  (forwarded, not blocked)`);
          return forward(req, res, body);
        }
        console.log(`[${ts}] SENTINEL ALLOW  tier-${d.tier}  ${req.url}  score=${d.score.toFixed(2)}  ${d.reason}`);
        if (d.adjudication?.reasoning) console.log(`            reasoning: ${d.adjudication.reasoning}`);
      }

      forward(req, res, body);
    });
  })
  .listen(LISTEN_PORT, () =>
    console.log(
      `Aris Sentinel interposition  :${LISTEN_PORT}  ->  Langflow 127.0.0.1:${LANGFLOW_PORT}   (watching ${SINK})\n` +
        `  tier 2 (LLM adjudication): ${hasTier2() ? `ENABLED (${providers().map((p) => p.name).join(" -> ")})` : "disabled — tier-1 only; escalate band is ALERTED not blocked (set KIMI_API_KEY or ANTHROPIC_API_KEY)"}`,
    ),
  );
