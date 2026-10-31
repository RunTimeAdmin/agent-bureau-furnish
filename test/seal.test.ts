import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { canonicalize } from "../src/canonical.js";
import { runCli } from "../src/cli.js";
import { apiBaseUrl, CONNECTOR_ID, signedEventHash } from "../src/seal.js";
import { generateFurnisherKey, parsePrivateKey, signEvent, signEventV1 } from "../src/sign.js";
import type { SignedEventV1, UnsignedEvent, UnsignedEventV1 } from "../src/event.js";

const KEY = "ca_live_test_ingest_key";
const { privateKeyPem } = generateFurnisherKey();
const privateKey = parsePrivateKey(privateKeyPem);

function event(id: string): UnsignedEventV1 {
  return {
    schema_version: "1",
    furnisher_id: "fur_acme01",
    key_id: "acme-2026-10",
    event_id: id,
    outcome: "delivered",
    occurred_at: "2026-10-20T14:03:00Z",
    subject_ref: { chain: "base", registry: "erc8004", id: "1234" },
  } as UnsignedEventV1;
}
const signed = (id: string) => signEventV1(event(id), privateKey);
const packet = (n: number) => `6a311b56-bf03-43cd-86b2-${String(n).padStart(12, "0")}`;

// What CounterAudit's receipt says about a furnished event sealed for the Bureau.
function receipt(n: number, raw: unknown, over: Record<string, unknown> = {}) {
  return {
    receipt_type: "counteraudit-receipt",
    packet_id: packet(n),
    connector_id: CONNECTOR_ID,
    public_proof: true,
    created_at: "2026-10-31T00:00:00.000Z",
    expires_at: "2028-10-31T00:00:00.000Z",
    outcome_claim: {
      asserted_by: "signature",
      signed_event_hash: createHash("sha256").update(canonicalize(raw), "utf8").digest("hex"),
    },
    ...over,
  };
}
const ok = (n: number, body: Record<string, unknown>, status = 201, over: Record<string, unknown> = {}): Answer => ({
  status,
  body: { packet_id: packet(n), entry_hash: "x", receipt: receipt(n, body.raw_event, over) },
});

type Answer = { status: number; body?: unknown; headers?: Record<string, string> };
let server: Server;
let base: string;
let received: { method?: string; url?: string; auth?: string; body: Record<string, unknown> }[] = [];
let answer: (body: Record<string, unknown>, n: number) => Answer = () => ({ status: 500 });

beforeAll(async () => {
  server = createServer((req: IncomingMessage, res) => {
    let raw = "";
    req.on("data", c => (raw += c));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : {};
      received.push({ method: req.method, url: req.url, auth: req.headers.authorization, body });
      const a = answer(body, received.length);
      res.writeHead(a.status, { "content-type": "application/json", ...a.headers });
      res.end(a.body === undefined ? "" : JSON.stringify(a.body));
    });
  });
  await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>(r => server.close(() => r())));

let dir: string;
let errors: string[];
let logs: string[];
beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), "furnish-seal-"));
  received = [];
  errors = [];
  logs = [];
  vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a.join(" ")));
  vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
  process.env.COUNTERAUDIT_INGEST_KEY = KEY;
  process.exitCode = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
  delete process.env.COUNTERAUDIT_INGEST_KEY;
  process.exitCode = 0;
});

function file(lines: unknown[]): string {
  const p = path.join(dir, "signed.jsonl");
  writeFileSync(p, lines.map(l => (typeof l === "string" ? l : JSON.stringify(l))).join("\n") + "\n");
  return p;
}
const out = () => path.join(dir, "sealed.jsonl");
const seal = (input: string, outPath = out()) => runCli(["seal", "--api-url", base, "--out", outPath, input]);
const said = () => [...errors, ...logs].join("\n");

describe("furnish seal", () => {
  it("seals each event with the ingest key and a public proof, and writes the lines the Bureau takes", async () => {
    const events = [signed("inv-1"), signed("inv-2")];
    // The second is one CounterAudit already holds.
    answer = (body, n) => ok(n, body, n === 1 ? 201 : 200);
    await seal(file(events));
    expect(process.exitCode).toBe(0);
    expect(received).toHaveLength(2);
    for (const [i, r] of received.entries()) {
      expect(r.method).toBe("POST");
      expect(r.url).toBe("/v1/audit/ingest");
      expect(r.auth).toBe(`Bearer ${KEY}`);
      expect(r.body).toEqual({ connector_id: CONNECTOR_ID, raw_event: events[i], public_proof: true });
    }
    const lines = readFileSync(out(), "utf8").trim().split("\n").map(l => JSON.parse(l));
    expect(lines).toEqual([
      { packet_id: packet(1), event: events[0] },
      { packet_id: packet(2), event: events[1] },
    ]);
    expect(logs[0]).toBe(`Sealing 2 event(s) at ${base}`);
    expect(said()).toContain("1 new, 1 already sealed");
    // The hash the receipt is checked against is CounterAudit's: SHA-256 of the canonical signed event.
    expect(signedEventHash(events[0] as SignedEventV1)).toBe(receipt(1, events[0]).outcome_claim.signed_event_hash);
  });

  it("checks every line before sending anything or creating the output", async () => {
    const v0 = signEvent(
      { schema_version: "0", furnisher_id: "fur_acme01", event_id: "old-1", outcome: "delivered",
        occurred_at: "2026-10-20T14:03:00Z", subject_ref: { wallet: "0x" + "ab".repeat(20) } } as UnsignedEvent,
      privateKey
    );
    const tampered = { ...signed("inv-3"), extra: true };
    await seal(file([signed("inv-1"), "{not json", v0, tampered, signed("inv-1")]));
    expect(received).toHaveLength(0);
    expect(process.exitCode).toBe(1);
    expect(said()).toContain("signed.jsonl:2: not valid JSON");
    expect(said()).toMatch(/signed\.jsonl:3: /);
    expect(said()).toMatch(/signed\.jsonl:4: /);
    expect(said()).toContain("signed.jsonl:5: duplicate event fur_acme01/inv-1");
    expect(said()).toContain("Nothing was sealed.");
    expect(existsSync(out())).toBe(false);
  });

  it("sends nothing without a usable key, to a plain-http host, or where the output cannot be created", async () => {
    const input = file([signed("inv-1")]);
    delete process.env.COUNTERAUDIT_INGEST_KEY;
    await seal(input);
    expect(said()).toContain("Set COUNTERAUDIT_INGEST_KEY");

    process.env.COUNTERAUDIT_INGEST_KEY = "ca_live_two\nlines";
    await seal(input);
    expect(said()).toContain("characters an API key cannot have");
    expect(said()).not.toContain("ca_live_two");

    process.env.COUNTERAUDIT_INGEST_KEY = KEY;
    await runCli(["seal", "--api-url", "http://counteraudit.example", "--out", out(), input]);
    expect(said()).toContain("--api-url must be an https URL");

    writeFileSync(out(), "kept\n");
    errors.length = 0;
    await seal(input);
    expect(said()).toContain("already exists; nothing was sealed");
    expect(readFileSync(out(), "utf8")).toBe("kept\n");

    errors.length = 0;
    await seal(input, path.join(dir, "missing", "sealed.jsonl"));
    expect(said()).toMatch(/cannot be created \(ENOENT\); nothing was sealed/);
    expect(said()).not.toContain("furnish: sign and verify");
    expect(received).toHaveLength(0);
    expect(process.exitCode).toBe(1);
  });

  it("reports an event CounterAudit refuses, carries on with the rest, and writes nothing", async () => {
    answer = (body, n) =>
      n === 2
        ? { status: 422, body: { error: "outcome_signature_invalid", message: "the signature does not verify\u001b[2K‮" } }
        : ok(n, body);
    await seal(file([signed("inv-1"), signed("inv-2"), signed("inv-3")]));
    expect(received).toHaveLength(3);
    expect(process.exitCode).toBe(1);
    expect(said()).toContain("signed.jsonl:2: CounterAudit refused it (422 outcome_signature_invalid: the signature does not verify");
    expect(said()).not.toMatch(/[\u001b‮]/);
    expect(said()).toContain("2 of 3 event(s) sealed the way the Bureau takes them. Nothing was written.");
    expect(existsSync(out())).toBe(false);
  });

  it("stops at a refused key, since every event would fail the same way, and never prints the key", async () => {
    answer = () => ({ status: 401, body: { error: "unauthorized" } });
    await seal(file([signed("inv-1"), signed("inv-2")]));
    expect(received).toHaveLength(1);
    expect(said()).toContain("Stopped");
    expect(said()).not.toContain(KEY);
    expect(process.exitCode).toBe(1);
  });

  it("waits out a rate limit and tries again, and stops at a spent quota", async () => {
    answer = (body, n) => (n === 1 ? { status: 429, headers: { "retry-after": "0" } } : ok(n, body));
    await seal(file([signed("inv-1")]));
    expect(received).toHaveLength(2);
    expect(said()).toContain("waiting 0s");
    expect(process.exitCode).toBe(0);
    expect(JSON.parse(readFileSync(out(), "utf8")).packet_id).toBe(packet(2));

    received = [];
    answer = () => ({ status: 429, body: { error: "quota_exceeded" } });
    await seal(file([signed("inv-1"), signed("inv-2")]), path.join(dir, "quota.jsonl"));
    expect(received).toHaveLength(1);
    expect(said()).toContain("quota is used up");
    expect(process.exitCode).toBe(1);
  });

  it("does not follow a redirect with the key, or take an answer without a packet id", async () => {
    answer = () => ({ status: 307, headers: { location: `${base}/elsewhere` } });
    await seal(file([signed("inv-1")]));
    expect(received.map(r => r.url)).toEqual(["/v1/audit/ingest"]);
    expect(said()).toContain("could not reach CounterAudit");
    expect(process.exitCode).toBe(1);

    for (const body of [{ packet_id: "not-a-packet" }, null]) {
      errors.length = 0;
      answer = () => ({ status: 201, body });
      await seal(file([signed("inv-1")]));
      expect(said()).toContain("no packet id");
    }
  });

  it("stops at a packet the Bureau would refuse, before the rest are sealed the same way", async () => {
    const cases: [Record<string, unknown>, RegExp][] = [
      [{ expires_at: undefined }, /no expiry date.*retention policy/],
      [{ expires_at: "2028-11-01T00:00:00.000Z" }, /more than 24 months after sealing/],
      [{ outcome_claim: { signed_event_hash: "0".repeat(64) } }, /not for this event/],
      [{ packet_id: packet(99) }, /for another packet/],
    ];
    for (const [over, message] of cases) {
      received = [];
      errors.length = 0;
      answer = (body, n) => ok(n, body, 201, over);
      await seal(file([signed("inv-1"), signed("inv-2")]));
      expect(received, String(message)).toHaveLength(1);
      expect(said()).toMatch(message);
      expect(existsSync(out())).toBe(false);
    }
  });

  it("refuses one event sealed earlier in a way the Bureau cannot use, and carries on", async () => {
    const cases: [Record<string, unknown> | null, RegExp][] = [
      [{ public_proof: false }, /without a public proof/],
      [{ connector_id: "generic-webhook" }, /under the connector generic-webhook/],
      [null, /without a receipt/],
    ];
    for (const [over, message] of cases) {
      received = [];
      errors.length = 0;
      answer = (body, n) => {
        if (n !== 1) return ok(n, body);
        return over === null
          ? { status: 200, body: { packet_id: packet(n), receipt: null } }
          : ok(n, body, 200, over);
      };
      await seal(file([signed("inv-1"), signed("inv-2")]));
      expect(received, String(message)).toHaveLength(2);
      expect(said()).toMatch(message);
      expect(process.exitCode).toBe(1);
      expect(existsSync(out())).toBe(false);
    }
  });
});

describe("apiBaseUrl", () => {
  it("takes https, or plain http to this machine only", () => {
    expect(apiBaseUrl("https://api.counteraudit.io/")).toBe("https://api.counteraudit.io");
    expect(apiBaseUrl("https://api.counteraudit.io/?")).toBe("https://api.counteraudit.io");
    expect(apiBaseUrl("http://localhost:3000")).toBe("http://localhost:3000");
    expect(apiBaseUrl("http://127.0.0.1:8080/")).toBe("http://127.0.0.1:8080");
    for (const bad of [
      "http://api.counteraudit.io",
      "http://localhost.evil",
      "ftp://api.counteraudit.io",
      "https://u:p@api.counteraudit.io",
      "https://api.counteraudit.io/?k=1",
      "api.counteraudit.io",
    ]) {
      expect(() => apiBaseUrl(bad), bad).toThrow(/--api-url/);
    }
  });
});
