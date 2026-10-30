import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sign } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalize } from "../src/canonical.js";
import { runCli, safe, verifyCommand } from "../src/cli.js";
import { buildEvent, csvToEvents, parseCsv } from "../src/csv.js";
import {
  outcomeEventJsonSchema,
  outcomeEventV1JsonSchema,
  unsignedEventSchema,
  unsignedEventV1Schema,
  type UnsignedEvent,
  type UnsignedEventV1,
} from "../src/event.js";
import {
  generateFurnisherKey,
  parsePrivateKey,
  parsePublicKey,
  signEvent,
  signEventV1,
  verifyEvent,
  verifyEventV1,
} from "../src/sign.js";

const FURNISHER = "fur_test01";
const SCHEMA_FILE = fileURLToPath(
  new URL("../schema/outcome-event-v0.json", import.meta.url)
);
const SCHEMA_FILE_V1 = fileURLToPath(
  new URL("../schema/outcome-event-v1.json", import.meta.url)
);

const paid: UnsignedEvent = {
  schema_version: "0",
  furnisher_id: FURNISHER,
  event_id: "inv-1001",
  subject_ref: { chain: "base", registry: "erc8004", id: "1234" },
  occurred_at: "2026-10-20T14:03:00Z",
  outcome: "paid",
  amount: { value: "12.50", asset: "USDC", chain: "base" },
};

const paidV1: UnsignedEventV1 = {
  schema_version: "1",
  furnisher_id: FURNISHER,
  key_id: "key-2026-10",
  event_id: "inv-1001",
  subject_ref: { chain: "base", registry: "erc8004", id: "1234" },
  occurred_at: "2026-10-20T14:03:00Z",
  outcome: "paid",
  amount: { value: "12.50", asset: "USDC", chain: "base" },
};

function keys() {
  const { privateKeyPem, publicKey } = generateFurnisherKey();
  return { privateKey: parsePrivateKey(privateKeyPem), publicKey: parsePublicKey(publicKey) };
}

describe("canonicalize", () => {
  it("sorts keys at every depth, keeps array order and drops undefined", () => {
    expect(
      canonicalize({ b: 2, a: { d: [3, { z: 1, y: 2 }], c: "é\n", skip: undefined } })
    ).toBe('{"a":{"c":"é\\n","d":[3,{"y":2,"z":1}]},"b":2}');
  });

  it("refuses values JSON cannot represent instead of dropping them", () => {
    expect(() => canonicalize({ n: Number.NaN })).toThrow();
    expect(() => canonicalize({ f: () => 1 })).toThrow();
    expect(() => canonicalize(() => 1)).toThrow();
  });
});

describe("outcome event rules", () => {
  const parse = (patch: Record<string, unknown>) =>
    unsignedEventSchema.safeParse({ ...paid, ...patch }).success;

  it("accepts a paid event with an amount", () => {
    expect(parse({})).toBe(true);
  });

  it("requires an amount for payment outcomes", () => {
    expect(parse({ amount: undefined })).toBe(false);
    expect(parse({ outcome: "payment_failed", evidence: { tx_hash: "0xabc" } })).toBe(true);
    expect(parse({ outcome: "payment_failed", amount: undefined, evidence: { tx_hash: "0xabc" } })).toBe(false);
  });

  it("requires evidence with at least one pointer for negative outcomes", () => {
    expect(parse({ outcome: "policy_violation", amount: undefined })).toBe(false);
    expect(parse({ outcome: "policy_violation", amount: undefined, evidence: {} })).toBe(false);
    expect(parse({ outcome: "policy_violation", amount: undefined, evidence: { log_ref: "fw-2026-10-20#88" } })).toBe(true);
  });

  it("accepts delivered and disputed without amount or evidence", () => {
    expect(parse({ outcome: "delivered", amount: undefined })).toBe(true);
    expect(parse({ outcome: "disputed", amount: undefined })).toBe(true);
  });

  it("takes exactly one kind of subject reference", () => {
    expect(parse({ subject_ref: { wallet: `0x${"a".repeat(40)}` } })).toBe(true);
    expect(parse({ subject_ref: { did: "did:countersig:agent-9" } })).toBe(true);
    expect(parse({ subject_ref: { chain: "base", registry: "erc8004", id: "1", wallet: `0x${"a".repeat(40)}` } })).toBe(false);
    expect(parse({ subject_ref: { chain: "ethereum", registry: "erc8004", id: "1" } })).toBe(false);
  });

  it("rejects unknown fields, malformed ids and non-UTC times", () => {
    expect(parse({ note: "extra" })).toBe(false);
    expect(parse({ furnisher_id: "acme" })).toBe(false);
    expect(parse({ occurred_at: "2026-10-20T14:03:00+02:00" })).toBe(false);
    expect(parse({ occurred_at: "2026-10-20T14:03Z" })).toBe(false);
    expect(parse({ occurred_at: "2026-10-20T14:03:00.250Z" })).toBe(true);
    expect(parse({ amount: { value: "12,50", asset: "USDC", chain: "base" } })).toBe(false);
  });
});

describe("signing", () => {
  it("round-trips a signed event", () => {
    const { privateKey, publicKey } = keys();
    const signed = signEvent(paid, privateKey);
    expect(signed.signature).toMatch(/^ed25519:[A-Za-z0-9_-]{86}$/);
    expect(verifyEvent(signed, publicKey)).toEqual({ ok: true, event: signed });
  });

  it("does not depend on key order", () => {
    const { privateKey, publicKey } = keys();
    const signed = signEvent(paid, privateKey);
    const reordered = Object.fromEntries(Object.entries(signed).reverse());
    expect(verifyEvent(reordered, publicKey).ok).toBe(true);
  });

  it("rejects a changed event, another key, and a signature without the context", () => {
    const { privateKey, publicKey } = keys();
    const signed = signEvent(paid, privateKey);
    const changed = { ...signed, amount: { ...signed.amount, value: "1250.00" } };
    expect(verifyEvent(changed, publicKey)).toEqual({ ok: false, reason: "signature does not match" });
    expect(verifyEvent(signed, keys().publicKey).ok).toBe(false);

    const bare = sign(null, Buffer.from(canonicalize(paid)), privateKey).toString("base64url");
    expect(verifyEvent({ ...paid, signature: `ed25519:${bare}` }, publicKey).ok).toBe(false);
  });

  it("refuses to sign an invalid event", () => {
    expect(() => signEvent({ ...paid, amount: undefined } as never, keys().privateKey)).toThrow();
  });

  it("only accepts well-formed public keys", () => {
    expect(() => parsePublicKey("ed25519:short")).toThrow();
    expect(() => parsePublicKey(generateFurnisherKey().publicKey)).not.toThrow();
  });
});

describe("outcome event v1 (draft)", () => {
  const parseV1 = (patch: Record<string, unknown>) =>
    unsignedEventV1Schema.safeParse({ ...paidV1, ...patch }).success;

  it("carries over the v0 outcome rules", () => {
    expect(parseV1({})).toBe(true);
    expect(parseV1({ amount: undefined })).toBe(false);
    expect(
      parseV1({ outcome: "policy_violation", amount: undefined, evidence: { log_ref: "fw#1" } })
    ).toBe(true);
  });

  it("requires a key_id", () => {
    expect(parseV1({ key_id: undefined })).toBe(false);
    expect(parseV1({ key_id: "has space" })).toBe(false);
  });

  it("takes an optional, well-formed relation to another event", () => {
    expect(parseV1({ relation: { type: "corrects", target_event_id: "inv-0999" } })).toBe(true);
    expect(parseV1({ relation: { type: "withdraws", target_event_id: "inv-0999" } })).toBe(true);
    expect(parseV1({ relation: { type: "bogus", target_event_id: "inv-0999" } })).toBe(false);
    expect(parseV1({ relation: { type: "corrects", target_event_id: "" } })).toBe(false);
    expect(parseV1({ relation: { type: "corrects" } })).toBe(false);
    expect(
      parseV1({ relation: { type: "corrects", target_event_id: "inv-0999", note: "x" } })
    ).toBe(false);
  });

  it("rejects a relation that points at the event's own id", () => {
    expect(parseV1({ relation: { type: "supersedes", target_event_id: "inv-1001" } })).toBe(false);
  });

  it("round-trips a signed v1 event, with and without a relation", () => {
    const { privateKey, publicKey } = keys();
    const signed = signEventV1(paidV1, privateKey);
    expect(verifyEventV1(signed, publicKey)).toEqual({ ok: true, event: signed });

    const corrected = signEventV1(
      { ...paidV1, event_id: "inv-1002", relation: { type: "corrects", target_event_id: "inv-1001" } },
      privateKey
    );
    expect(verifyEventV1(corrected, publicKey).ok).toBe(true);
  });

  it("rejects a changed event, another key, and a signature without the v1 context", () => {
    const { privateKey, publicKey } = keys();
    const signed = signEventV1(paidV1, privateKey);
    const changed = { ...signed, key_id: "key-other" };
    expect(verifyEventV1(changed, publicKey).ok).toBe(false);
    expect(verifyEventV1(signed, keys().publicKey).ok).toBe(false);

    const bare = sign(null, Buffer.from(canonicalize(paidV1)), privateKey).toString("base64url");
    expect(verifyEventV1({ ...paidV1, signature: `ed25519:${bare}` }, publicKey).ok).toBe(false);
  });

  it("keeps v0 and v1 apart: neither verifies as the other", () => {
    const { privateKey, publicKey } = keys();
    expect(verifyEventV1(signEvent(paid, privateKey), publicKey).ok).toBe(false);
    expect(verifyEvent(signEventV1(paidV1, privateKey), publicKey).ok).toBe(false);
  });
});

describe("CSV import", () => {
  const header =
    "event_id,outcome,occurred_at,subject_chain,subject_registry,subject_id,subject_wallet,amount_value,amount_asset,amount_chain,evidence_log_ref";

  it("parses quoted fields, escaped quotes, CRLF and a byte order mark", () => {
    expect(parseCsv('﻿a,b\r\n"x, y","say ""hi"""\r\n')).toEqual([
      ["a", "b"],
      ["x, y", 'say "hi"'],
    ]);
    expect(() => parseCsv('a,"open')).toThrow();
  });

  it("turns rows into valid events", () => {
    const csv = [
      header,
      "inv-1,paid,2026-10-20T14:03:00Z,base,erc8004,1234,,12.50,USDC,base,",
      `blk-7,policy_violation,2026-10-21T09:00:00Z,,,,0x${"b".repeat(40)},,,,"gateway log 2026-10-21, line 88"`,
      ",,,,,,,,,,",
    ].join("\n");
    const { events, errors } = csvToEvents(csv, FURNISHER);
    expect(errors).toEqual([]);
    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({
      outcome: "policy_violation",
      subject_ref: { wallet: `0x${"b".repeat(40)}` },
      evidence: { log_ref: "gateway log 2026-10-21, line 88" },
    });
  });

  it("reports row problems by spreadsheet line", () => {
    const csv = [
      header,
      `a1,paid,2026-10-20T14:03:00Z,base,erc8004,1,0x${"c".repeat(40)},5,USDC,base,`,
      "a2,policy_violation,2026-10-20T14:03:00Z,base,erc8004,1,,,,,",
      "a3,paid,2026-10-20T14:03:00Z,base,erc8004,1,,5,USDC,base,",
      "a3,paid,2026-10-20T14:03:00Z,base,erc8004,1,,5,USDC,base,",
    ].join("\n");
    const { events, errors } = csvToEvents(csv, FURNISHER);
    expect(events).toHaveLength(1);
    expect(errors.map(error => error.line)).toEqual([2, 3, 5]);
    expect(errors[0].message).toContain("exactly one subject");
    expect(errors[1].message).toContain(
      "evidence is required for this outcome: give tx_hash, counteraudit_packet or log_ref"
    );
    expect(errors[2].message).toContain("more than once");
  });

  it("rejects unknown and missing columns up front", () => {
    expect(csvToEvents("event_id,outcome,amont_value\n", FURNISHER).errors[0]).toEqual({
      line: 1,
      message: "unknown columns: amont_value; missing columns: occurred_at",
    });
  });
});

describe("published JSON Schema", () => {
  it("matches the zod schema (run npm run schema after changing event.ts)", () => {
    expect(JSON.parse(readFileSync(SCHEMA_FILE, "utf8"))).toEqual(outcomeEventJsonSchema());
  });

  it("matches the v1 zod schema (run `node dist/cli.js schema --version 1`)", () => {
    expect(JSON.parse(readFileSync(SCHEMA_FILE_V1, "utf8"))).toEqual(outcomeEventV1JsonSchema());
  });
});

describe("verify --furnisher binding", () => {
  const logs: string[] = [];
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = 0;
    logs.length = 0;
  });

  // Signs two events with one key but different furnisher ids, then verifies.
  function signedFile(): { file: string; publicKey: string } {
    const { privateKeyPem, publicKey } = generateFurnisherKey();
    const key = parsePrivateKey(privateKeyPem);
    const lines = ["fur_acme01", "fur_victim01"].map((furnisher_id, i) =>
      JSON.stringify(
        signEvent({ ...paid, furnisher_id, event_id: `inv-${i}` }, key)
      )
    );
    const dir = mkdtempSync(path.join(tmpdir(), "furnish-"));
    const file = path.join(dir, "signed.jsonl");
    writeFileSync(file, lines.join("\n") + "\n");
    return { file, publicKey };
  }

  function run(args: string[]): { exitCode: number; errors: string } {
    const errors: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    vi.spyOn(console, "error").mockImplementation((...a) =>
      errors.push(a.join(" "))
    );
    process.exitCode = 0;
    verifyCommand(args);
    return { exitCode: Number(process.exitCode) || 0, errors: errors.join("\n") };
  }

  it("accepts both lines when no furnisher is required", () => {
    const { file, publicKey } = signedFile();
    const { exitCode } = run(["--public-key", publicKey, file]);
    expect(logs.join("\n")).toContain("2 valid, 0 invalid.");
    expect(exitCode).toBe(0);
  });

  it("rejects a line whose furnisher_id is not the expected one", () => {
    const { file, publicKey } = signedFile();
    const { exitCode, errors } = run([
      "--public-key",
      publicKey,
      "--furnisher",
      "fur_acme01",
      file,
    ]);
    expect(errors).toContain("fur_victim01 does not match --furnisher fur_acme01");
    expect(logs.join("\n")).toContain("1 valid, 1 invalid.");
    expect(exitCode).toBe(1);
  });

  it("rejects a malformed --furnisher", () => {
    const { file, publicKey } = signedFile();
    expect(() =>
      run(["--public-key", publicKey, "--furnisher", "acme", file])
    ).toThrow(/furnisher/);
  });
});

describe("hardening", () => {
  it("does not let JSON input override the tool-set furnisher_id", () => {
    const result = buildEvent("fur_real01", {
      event_id: "d-1",
      outcome: "delivered",
      occurred_at: "2026-10-20T14:03:00Z",
      subject_ref: { chain: "base", registry: "erc8004", id: "1234" },
      furnisher_id: "fur_evil01",
      schema_version: "9",
    });
    expect("event" in result && result.event.furnisher_id).toBe("fur_real01");
    expect("event" in result && result.event.schema_version).toBe("0");
  });

  it("rejects a CSV with a duplicate header instead of dropping data", () => {
    const csv = [
      "event_id,event_id,outcome,occurred_at,subject_wallet",
      "a,b,delivered,2026-10-20T14:03:00Z,0x" + "1".repeat(40),
    ].join("\n");
    const { events, errors } = csvToEvents(csv, "fur_acme01");
    expect(events).toHaveLength(0);
    expect(errors[0].message).toContain("duplicate columns: event_id");
  });

  it("strips control characters from echoed text", () => {
    expect(safe("ok\u001b[2Kfaked\u0007\u007f")).toBe("ok [2Kfaked  ");
  });

  it("does not dispatch inherited object properties as commands", () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...a) =>
      errors.push(a.join(" "))
    );
    for (const name of ["constructor", "__proto__", "toString"]) {
      process.exitCode = 0;
      runCli([name]);
      expect(process.exitCode).toBe(1);
      expect(errors.join("\n")).toContain(`Unknown command: ${name}`);
      errors.length = 0;
    }
    spy.mockRestore();
    process.exitCode = 0;
  });
});
