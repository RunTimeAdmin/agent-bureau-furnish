import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/canonical.js";
import {
  parsePublicKey,
  parseSignedEventV1,
  verifyEventV1,
} from "../src/sign.js";
import { buildVectors } from "./vectors.js";

type Vectors = {
  keys: Record<string, { public_key: string }>;
  public_keys: { id: string; public_key: string; expect: "valid" | "invalid" }[];
  events: {
    id: string;
    event: Record<string, unknown>;
    verify_with: string;
    expect: {
      schema: "valid" | "invalid";
      signature: "valid" | "invalid" | null;
      signed_event_hash: string | null;
    };
  }[];
};

// The committed file; before it first exists, the built vectors, so the
// cases still run while the snapshot test writes it.
const FILE = new URL("../vectors/outcome-event-v1.json", import.meta.url);
const vectors = (
  existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : buildVectors()
) as Vectors;
const sha256 = (text: string) =>
  createHash("sha256").update(text, "utf8").digest("hex");

describe("shared outcome event v1 vectors", () => {
  it("are what test/vectors.ts builds (npm run vectors rebuilds them)", async () => {
    await expect(`${JSON.stringify(buildVectors(), null, 2)}\n`).toMatchFileSnapshot(
      "../vectors/outcome-event-v1.json"
    );
  });

  it.each(vectors.events.map(c => [c.id, c] as const))("event %s", (_id, c) => {
    const parsed = parseSignedEventV1(c.event);
    expect(parsed.ok).toBe(c.expect.schema === "valid");
    if (c.expect.schema !== "valid") return;
    const key = parsePublicKey(vectors.keys[c.verify_with].public_key);
    expect(verifyEventV1(c.event, key).ok).toBe(c.expect.signature === "valid");
    expect(sha256(canonicalize(c.event))).toBe(c.expect.signed_event_hash);
  });

  it.each(vectors.public_keys.map(k => [k.id, k] as const))("public key %s", (_id, k) => {
    if (k.expect === "valid") expect(() => parsePublicKey(k.public_key)).not.toThrow();
    else expect(() => parsePublicKey(k.public_key)).toThrow();
  });
});
