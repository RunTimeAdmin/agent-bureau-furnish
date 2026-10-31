// Builds the shared test vectors for outcome event v1
// (vectors/outcome-event-v1.json). Every implementation that signs or checks
// v1 events (this tool, CounterAudit, The Agent Bureau) runs them and must
// reach the result each case states. Rebuild with `npm run vectors`; the test
// fails while the committed file differs from what this builds.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalize } from "../src/canonical.js";
import { encodePublicKey } from "../src/sign.js";

type Json = Record<string, unknown>;

const CONTEXT_V1 = "agent-bureau/outcome-event/v1\n";
const CONTEXT_V0 = "agent-bureau/outcome-event/v0\n";
const FURNISHER = "fur_vectors01";
const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Fixed keys, each derived from a public seed so anyone can rebuild the file.
// TEST ONLY: never register them anywhere real.
type TestKey = { name: string; seed: Buffer; privateKey: KeyObject; publicKey: string };
function testKey(name: string): TestKey {
  const seed = createHash("sha256")
    .update(`agent-bureau test vector key ${name}`)
    .digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]),
    format: "der",
    type: "pkcs8",
  });
  return {
    name,
    seed,
    privateKey,
    publicKey: encodePublicKey(createPublicKey(privateKey)),
  };
}
const A = testKey("a");
const A_OLD = testKey("a-old");
const B = testKey("b");

function signWith(unsigned: Json, key: TestKey, context = CONTEXT_V1): Json {
  const signature = sign(
    null,
    Buffer.from(context + canonicalize(unsigned), "utf8"),
    key.privateKey
  );
  return { ...unsigned, signature: `ed25519:${signature.toString("base64url")}` };
}

const hash = (event: Json) =>
  createHash("sha256").update(canonicalize(event), "utf8").digest("hex");

// A second base64url spelling of the same bytes. The last character of 32 or
// 64 encoded bytes carries spare bits; flipping the lowest changes the text,
// not the bytes.
function respell(text: string, length: number): string {
  const last = ALPHABET.indexOf(text.at(-1)!);
  const other = text.slice(0, -1) + ALPHABET[last ^ 1];
  const same = Buffer.from(other, "base64url").equals(Buffer.from(text, "base64url"));
  if (!same || Buffer.from(other, "base64url").length !== length) {
    throw new Error("respelling changed the bytes");
  }
  return other;
}

const paid: Json = {
  schema_version: "1",
  furnisher_id: FURNISHER,
  key_id: "vec-a-1",
  event_id: "vec-paid-1",
  subject_ref: { wallet: "0x090F6D72F49ABaBbD3FfD2ebA26D6B8A374b5b77" },
  occurred_at: "2026-10-31T12:00:00Z",
  outcome: "paid",
  amount: { value: "1.00", asset: "USDC", chain: "arc-testnet" },
  evidence: {
    tx_hash: "0xd6fbaf6ec24b0ae502b0dd4e3360619eb9052652ecbaf51ae5566d86ad6aafe5",
    log_ref: "levy charge 8-1",
  },
};

type Case = {
  id: string;
  description: string;
  event: Json;
  verify_with: string;
  expect: {
    schema: "valid" | "invalid";
    signature: "valid" | "invalid" | null;
    signed_event_hash: string | null;
    counteraudit:
      | "accepted"
      | "outcome_schema_invalid"
      | "outcome_signer_unknown"
      | "outcome_signature_invalid";
  };
};

function valid(id: string, description: string, unsigned: Json): Case {
  const event = signWith(unsigned, A);
  return {
    id,
    description,
    event,
    verify_with: "a",
    expect: {
      schema: "valid",
      signature: "valid",
      signed_event_hash: hash(event),
      counteraudit: "accepted",
    },
  };
}

function badSignature(id: string, description: string, event: Json): Case {
  return {
    id,
    description,
    event,
    verify_with: "a",
    expect: {
      schema: "valid",
      signature: "invalid",
      signed_event_hash: hash(event),
      counteraudit: "outcome_signature_invalid",
    },
  };
}

function badSchema(id: string, description: string, event: Json): Case {
  return {
    id,
    description,
    event,
    verify_with: "a",
    expect: {
      schema: "invalid",
      signature: null,
      signed_event_hash: null,
      counteraudit: "outcome_schema_invalid",
    },
  };
}

function cases(): Case[] {
  const signedPaid = signWith(paid, A);
  const { key_id: _keyId, ...noKeyId } = paid;
  const { amount: _amount, ...noAmount } = paid;
  const revoked = signWith({ ...paid, key_id: "vec-a-0", event_id: "vec-revoked-1" }, A_OLD);
  const unregistered = signWith({ ...paid, key_id: "vec-b-1", event_id: "vec-unregistered-1" }, B);
  // A key the signature does not cover, added after signing. JSON.parse keeps
  // "__proto__" as an own key, which schema libraries may silently drop.
  const withProto = JSON.parse(
    JSON.stringify(signedPaid).replace(/^\{/, '{"__proto__":{"admin":true},')
  ) as Json;
  return [
    valid("paid-full", "paid, wallet subject, amount and evidence", paid),
    valid("delivered-minimal", "delivered, DID subject, nothing optional", {
      schema_version: "1",
      furnisher_id: FURNISHER,
      key_id: "vec-a-1",
      event_id: "vec-delivered-1",
      subject_ref: {
        did: "did:sigvara:5042002:0xCc52Cd92963f8A86d04dB29a4810d1e01D193910",
      },
      occurred_at: "2026-10-31T12:05:00Z",
      outcome: "delivered",
    }),
    valid("payment-failed-corrects", "payment_failed correcting an earlier event", {
      ...paid,
      event_id: "vec-failed-1",
      outcome: "payment_failed",
      evidence: { log_ref: "levy dunning 3-2" },
      relation: { type: "corrects", target_event_id: "vec-paid-1" },
    }),
    valid("access-revoked-registry", "access_revoked, registry subject, packet evidence", {
      schema_version: "1",
      furnisher_id: FURNISHER,
      key_id: "vec-a-1",
      event_id: "vec-revoked-access-1",
      subject_ref: { chain: "arc", registry: "erc8004", id: "42" },
      occurred_at: "2026-10-31T12:10:00.250Z",
      outcome: "access_revoked",
      evidence: { counteraudit_packet: "6a311b56-bf03-43cd-86b2-9357f5685080" },
    }),
    valid("non-ascii-text", "non-ASCII, a quote and a backslash in a string", {
      schema_version: "1",
      furnisher_id: FURNISHER,
      key_id: "vec-a-1",
      event_id: "vec-unicode-1",
      subject_ref: { wallet: "0x451567A35648445143768d3D6e9072A50BB2d85F" },
      occurred_at: "2026-10-31T12:15:00Z",
      outcome: "delivered",
      evidence: { log_ref: 'Lieferschein "7" C:\\Zürich ✓ 配達済み' },
    }),
    badSignature("tampered-amount", "paid-full with its amount changed after signing", {
      ...signedPaid,
      amount: { value: "100.00", asset: "USDC", chain: "arc-testnet" },
    }),
    badSignature("wrong-key", "names key vec-a-1 but is signed with another key", {
      ...signWith(paid, B),
    }),
    badSignature("v0-context", "signed over the v0 signing context", signWith(paid, A, CONTEXT_V0)),
    badSignature("non-canonical-signature", "the right signature bytes in a second base64url spelling", {
      ...signedPaid,
      signature: `ed25519:${respell(String(signedPaid.signature).slice(8), 64)}`,
    }),
    {
      id: "revoked-key",
      description: "signed with key vec-a-0, which CounterAudit has revoked",
      event: revoked,
      verify_with: "a-old",
      expect: {
        schema: "valid",
        signature: "valid",
        signed_event_hash: hash(revoked),
        counteraudit: "outcome_signer_unknown",
      },
    },
    {
      id: "unregistered-key",
      description: "signed with key vec-b-1, which was never registered",
      event: unregistered,
      verify_with: "b",
      expect: {
        schema: "valid",
        signature: "valid",
        signed_event_hash: hash(unregistered),
        counteraudit: "outcome_signer_unknown",
      },
    },
    badSchema("unknown-field", "a field v1 does not define", signWith({ ...paid, note: "extra" }, A)),
    badSchema("proto-key-after-signing", "a __proto__ key added after signing", withProto),
    badSchema("missing-key-id", "no key_id", signWith(noKeyId, A)),
    badSchema("self-relation", "a relation to its own event_id", signWith({
      ...paid,
      relation: { type: "corrects", target_event_id: "vec-paid-1" },
    }, A)),
    badSchema("paid-without-amount", "paid with no amount", signWith(noAmount, A)),
    badSchema("negative-without-evidence", "not_delivered with no evidence", signWith({
      schema_version: "1",
      furnisher_id: FURNISHER,
      key_id: "vec-a-1",
      event_id: "vec-not-delivered-1",
      subject_ref: { wallet: "0x090F6D72F49ABaBbD3FfD2ebA26D6B8A374b5b77" },
      occurred_at: "2026-10-31T12:20:00Z",
      outcome: "not_delivered",
    }, A)),
    badSchema("non-utc-time", "occurred_at with an offset instead of Z", signWith({
      ...paid,
      occurred_at: "2026-10-31T14:00:00+02:00",
    }, A)),
  ];
}

// The Ed25519 points of small order, and the non-canonical encodings OpenSSL
// still loads for two of them (libsodium's ge25519_has_small_order list).
const SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

function publicKeys() {
  const x = A.publicKey.slice("ed25519:".length);
  // Every small-order entry, with the sign bit clear and set: Node loads all
  // of them as keys, so each implementation's list is what refuses them.
  const smallOrder = SMALL_ORDER.flatMap((hex, index) =>
    (["clear", "set"] as const).map(bit => {
      const bytes = Buffer.from(hex, "hex");
      bytes[31] = bit === "set" ? bytes[31] | 0x80 : bytes[31] & 0x7f;
      return {
        id: `small-order-${index}-sign-${bit}`,
        public_key: `ed25519:${bytes.toString("base64url")}`,
        expect: "invalid",
      };
    })
  );
  return [
    { id: "a", public_key: A.publicKey, expect: "valid" },
    ...smallOrder,
    { id: "non-canonical-spelling", public_key: `ed25519:${respell(x, 32)}`, expect: "invalid" },
    { id: "too-short", public_key: `ed25519:${x.slice(0, 42)}`, expect: "invalid" },
    { id: "missing-prefix", public_key: x, expect: "invalid" },
  ];
}

export function buildVectors(): Json {
  const proof = JSON.parse(
    readFileSync(new URL("./fixtures/counteraudit-proof.json", import.meta.url), "utf8")
  ) as Json;
  return {
    format: "agent-bureau/outcome-event-v1-vectors/1",
    about:
      "Shared test vectors for outcome event v1. agent-bureau-furnish, CounterAudit and The Agent Bureau each run every case and must reach the stated result. Built by test/vectors.ts in agent-bureau-furnish; copies elsewhere are pinned by SHA-256.",
    signing: {
      context: CONTEXT_V1,
      canonical_json: "RFC 8785",
      signature: "ed25519: and the canonical base64url of the 64-byte Ed25519 signature over context + canonical JSON of the event without signature",
      signed_event_hash: "SHA-256 (hex) of the canonical JSON of the signed event",
    },
    keys: Object.fromEntries(
      [A, A_OLD, B].map(key => [
        key.name,
        {
          public_key: key.publicKey,
          seed_hex: key.seed.toString("hex"),
          note: "TEST ONLY. The seed is published so anyone can rebuild these vectors; never register this key anywhere real.",
        },
      ])
    ),
    public_keys: publicKeys(),
    signers: [
      { furnisher_id: FURNISHER, key_id: "vec-a-1", key: "a", status: "active" },
      { furnisher_id: FURNISHER, key_id: "vec-a-0", key: "a-old", status: "revoked" },
    ],
    events: cases(),
    proofs: [
      {
        id: "counteraudit-production-2026-10-30",
        description: proof.note,
        org_id: proof.org_id,
        packet_id: proof.packet_id,
        event: proof.event,
        proof: proof.proof,
        jwks: proof.jwks,
        expect: "every check passes",
      },
    ],
  };
}
