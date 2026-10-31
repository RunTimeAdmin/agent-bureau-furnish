import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { z } from "zod";
import { canonicalize } from "./canonical.js";
import {
  signedEventSchema,
  signedEventV1Schema,
  unsignedEventSchema,
  unsignedEventV1Schema,
  type SignedEvent,
  type SignedEventV1,
  type UnsignedEvent,
  type UnsignedEventV1,
} from "./event.js";

const KEY_PREFIX = "ed25519:";

// Domain separation: a furnisher key that signs other things can never have
// one of those signatures accepted as an outcome event, or the reverse. Each
// schema version has its own context, so a v0 signature cannot be replayed as
// a v1 event or the reverse.
const SIGNING_CONTEXT = "agent-bureau/outcome-event/v0\n";
const SIGNING_CONTEXT_V1 = "agent-bureau/outcome-event/v1\n";

export function signingPayload(event: UnsignedEvent): Buffer {
  return Buffer.from(SIGNING_CONTEXT + canonicalize(event), "utf8");
}

export function signingPayloadV1(event: UnsignedEventV1): Buffer {
  return Buffer.from(SIGNING_CONTEXT_V1 + canonicalize(event), "utf8");
}

export function generateFurnisherKey(): {
  privateKeyPem: string;
  publicKey: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString(),
    publicKey: encodePublicKey(publicKey),
  };
}

export function encodePublicKey(key: KeyObject): string {
  const { x } = key.export({ format: "jwk" });
  if (!x) throw new Error("Not an Ed25519 public key");
  return KEY_PREFIX + x;
}

// The Ed25519 points of small order, and the non-canonical encodings OpenSSL
// still loads for two of them, as libsodium lists them
// (ge25519_has_small_order). Compared without the sign bit. Anyone can forge a
// signature that verifies under such a key, for any event. The same list
// CounterAudit and The Agent Bureau refuse.
const SMALL_ORDER_KEYS = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map(hex => Buffer.from(hex, "hex"));

function isSmallOrderKey(bytes: Buffer): boolean {
  const masked = Buffer.from(bytes);
  masked[31] &= 0x7f;
  return SMALL_ORDER_KEYS.some(key => key.equals(masked));
}

// Base64url text that decodes to `length` bytes and is the only spelling of
// them. The last character carries spare bits, so without this one key or
// signature has several spellings.
function decodeCanonicalBase64url(text: string, length: number): Buffer | null {
  const bytes = Buffer.from(text, "base64url");
  return bytes.length === length && bytes.toString("base64url") === text
    ? bytes
    : null;
}

export function parsePublicKey(text: string): KeyObject {
  const x = text.trim();
  const bytes = x.startsWith(KEY_PREFIX)
    ? decodeCanonicalBase64url(x.slice(KEY_PREFIX.length), 32)
    : null;
  if (!bytes) {
    throw new Error("Public key must look like ed25519:<43 base64url chars>");
  }
  if (isSmallOrderKey(bytes)) {
    throw new Error(
      "Public key is a small-order point, under which anyone could forge a signature"
    );
  }
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: x.slice(KEY_PREFIX.length) },
    format: "jwk",
  });
}

export function parsePrivateKey(pem: string): KeyObject {
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("Private key must be Ed25519");
  }
  return key;
}

export function signEvent(event: UnsignedEvent, privateKey: KeyObject): SignedEvent {
  const valid = unsignedEventSchema.parse(event);
  const signature = sign(null, signingPayload(valid), privateKey);
  return { ...valid, signature: KEY_PREFIX + signature.toString("base64url") };
}

export type VerifyResult =
  | { ok: true; event: SignedEvent }
  | { ok: false; reason: string };

export function verifyEvent(input: unknown, publicKey: KeyObject): VerifyResult {
  const parsed = signedEventSchema.safeParse(input);
  if (!parsed.success) return { ok: false, reason: z.prettifyError(parsed.error) };
  const { signature, ...unsigned } = parsed.data;
  const bytes = Buffer.from(signature.slice(KEY_PREFIX.length), "base64url");
  const valid = verify(
    null,
    signingPayload(unsigned as UnsignedEvent),
    publicKey,
    bytes
  );
  return valid ? { ok: true, event: parsed.data } : { ok: false, reason: "signature does not match" };
}

// v1 signing. Same scheme as v0 over the v1 context and schema.
export function signEventV1(
  event: UnsignedEventV1,
  privateKey: KeyObject
): SignedEventV1 {
  const valid = unsignedEventV1Schema.parse(event);
  const signature = sign(null, signingPayloadV1(valid), privateKey);
  return { ...valid, signature: KEY_PREFIX + signature.toString("base64url") };
}

export type VerifyResultV1 =
  | { ok: true; event: SignedEventV1 }
  | { ok: false; reason: string };

/**
 * Parses a signed v1 event against the schema. The pinned zod refuses an own
 * "__proto__" key itself; as a second guard, should a schema library ever drop
 * a key instead, an input whose canonical form differs from the parsed event's
 * is refused, so a signature is never checked over less than the event.
 * CounterAudit does the same.
 */
export function parseSignedEventV1(input: unknown): VerifyResultV1 {
  const parsed = signedEventV1Schema.safeParse(input);
  if (!parsed.success) return { ok: false, reason: z.prettifyError(parsed.error) };
  let same = false;
  try {
    same = canonicalize(input) === canonicalize(parsed.data);
  } catch {
    same = false;
  }
  if (!same) {
    return { ok: false, reason: "the event has keys the v1 schema does not allow" };
  }
  return { ok: true, event: parsed.data };
}

export function verifyEventV1(
  input: unknown,
  publicKey: KeyObject
): VerifyResultV1 {
  const parsed = parseSignedEventV1(input);
  if (!parsed.ok) return parsed;
  const { signature, ...unsigned } = parsed.event;
  // Only the canonical spelling, so one signature is one event to the hashes.
  const bytes = decodeCanonicalBase64url(signature.slice(KEY_PREFIX.length), 64);
  if (!bytes) return { ok: false, reason: "signature is not canonical base64url" };
  const valid = verify(
    null,
    signingPayloadV1(unsigned as UnsignedEventV1),
    publicKey,
    bytes
  );
  return valid ? { ok: true, event: parsed.event } : { ok: false, reason: "signature does not match" };
}
