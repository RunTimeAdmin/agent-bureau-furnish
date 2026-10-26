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
  unsignedEventSchema,
  type SignedEvent,
  type UnsignedEvent,
} from "./event.js";

const KEY_PREFIX = "ed25519:";

// Domain separation: a furnisher key that signs other things can never have
// one of those signatures accepted as an outcome event, or the reverse.
const SIGNING_CONTEXT = "agent-bureau/outcome-event/v0\n";

export function signingPayload(event: UnsignedEvent): Buffer {
  return Buffer.from(SIGNING_CONTEXT + canonicalize(event), "utf8");
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

export function parsePublicKey(text: string): KeyObject {
  const x = text.trim();
  if (!x.startsWith(KEY_PREFIX) || x.length !== KEY_PREFIX.length + 43) {
    throw new Error("Public key must look like ed25519:<43 base64url chars>");
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
