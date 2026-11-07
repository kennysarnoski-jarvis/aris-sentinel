// The detector's decisions on the labeled corpus are frozen in test/corpus-snapshot.json.
// Any drift fails here. If the change is intentional, `bun run corpus:snapshot` and
// commit the diff — that diff IS the review of what the detector now decides.
import { describe, expect, test } from "bun:test";
import { collect, load } from "../corpusSnapshot";

describe("corpus snapshot", () => {
  const now = collect();
  const frozen = load();

  test("every snapshotted file still exists in the corpus", () => {
    for (const k of Object.keys(frozen)) expect(now, `missing: ${k}`).toHaveProperty([k]);
  });

  test("every corpus file is snapshotted (run `bun run corpus:snapshot` after adding one)", () => {
    for (const k of Object.keys(now)) expect(frozen, `not snapshotted: ${k}`).toHaveProperty([k]);
  });

  for (const [k, want] of Object.entries(frozen)) {
    test(`${k} → ${want.verdict} ${want.score}`, () => {
      expect(now[k]).toEqual(want);
    });
  }
});
