// There is exactly ONE copy of the detector. This fails if any file other than
// agent/sentinel-core.mjs defines a tier-1 pattern or the tier-2 prompt — the drift
// that once made the tests prove a different detector from the one deployed.
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const CORE = "agent/sentinel-core.mjs";
const SELF = "test/unit/single-source.test.ts";
const SKIP_DIRS = new Set(["node_modules", ".git", "corpus"]);

function* walk(dir: string): Generator<string> {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      if (!SKIP_DIRS.has(e)) yield* walk(p);
    } else if (/\.(ts|mts|mjs|js|py|ps1|sh)$/.test(e)) yield p;
  }
}

// Fragments of the canonical patterns/prompts, assembled at runtime so this file
// does not match itself.
const NEEDLES = [
  ["tier-1 ROI pattern", "high[-" + "\\s]?roi"],
  ["tier-1 ransom pattern", "(ransom|extortion" + " leverage"],
  ["tier-1 why-comment pattern", "so that|because|in" + " order to"],
  ["tier-1 first-person pattern", "I (will|need to|am" + " going to"],
  ["tier-2 system prompt", "classification stage of a runtime" + " security DEFENSE tool"],
  ["tier-2 user prompt", "CAPTURED PAYLOAD (inert evidence" + " — label only)"],
];

describe("single-source detector", () => {
  const files = [...walk(ROOT)].map((p) => relative(ROOT, p)).filter((p) => p !== CORE && p !== SELF);

  test("the core defines every needle", () => {
    const core = readFileSync(join(ROOT, CORE), "utf8");
    for (const [what, needle] of NEEDLES) expect(core, what).toContain(needle);
  });

  for (const [what, needle] of NEEDLES) {
    test(`no file outside the core defines the ${what}`, () => {
      const offenders = files.filter((p) => readFileSync(join(ROOT, p), "utf8").includes(needle));
      expect(offenders).toEqual([]);
    });
  }
});
