/**
 * Decode stage. Real payloads arrive encoded (base64/hex/nested/eval-wrapped) to
 * evade signatures — JadePuffer's narration lived in the DECODED layer. This
 * surfaces every plausible decoding so the scorer inspects the layer where the
 * attacker actually hid the intent. The evasion becomes the trap.
 */

const B64_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;
const HEX_RE = /(?:[0-9a-fA-F]{2}){12,}/g;

function printableRatio(s: string): number {
  if (!s) return 0;
  // eslint-disable-next-line no-control-regex
  return s.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "").length / s.length;
}

function decodeB64(s: string): string | null {
  if (s.length % 4 !== 0) return null;
  try {
    const out = Buffer.from(s, "base64").toString("utf8");
    return out.length > 0 && printableRatio(out) > 0.85 ? out : null;
  } catch {
    return null;
  }
}

function decodeHex(s: string): string | null {
  try {
    const out = Buffer.from(s, "hex").toString("utf8");
    return out.length > 0 && printableRatio(out) > 0.85 ? out : null;
  } catch {
    return null;
  }
}

/**
 * Returns the raw input plus every recursively-decoded layer (base64/hex,
 * nested up to `maxDepth`). Deduped. The scorer runs against all of them.
 */
export function candidateDecodings(raw: string, maxDepth = 3): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const queue: { text: string; depth: number }[] = [{ text: raw, depth: 0 }];

  while (queue.length) {
    const { text, depth } = queue.shift()!;
    if (seen.has(text)) continue;
    seen.add(text);
    out.push(text);
    if (depth >= maxDepth || out.length > 64) continue;

    for (const [re, dec] of [
      [B64_RE, decodeB64],
      [HEX_RE, decodeHex],
    ] as const) {
      for (const m of text.match(re) ?? []) {
        const decoded = dec(m);
        if (decoded && !seen.has(decoded)) queue.push({ text: decoded, depth: depth + 1 });
      }
    }
  }
  return out;
}
