import { createHash } from "node:crypto";
import { canonicalize } from "./canonical.js";
import type { SignedEventV1 } from "./event.js";

// Sealing signed events in the furnisher's own CounterAudit organization, for the Bureau's
// cross-organization intake (docs/cross-org-intake.md in the-agent-bureau). CounterAudit checks
// the signature against the outcome signer registered in the organization, seals the whole event
// in the organization's chain and serves a public proof anyone can check without a key. The
// Bureau takes the packet id and the event, fetches that proof and checks it.

/** The connector CounterAudit seals furnished outcome events under. */
export const CONNECTOR_ID = "agent-bureau-outcome-v1";
export const DEFAULT_API_URL = "https://api.counteraudit.io";
const INGEST_PATH = "/v1/audit/ingest";
// A receipt is a few kilobytes. A server that sends more is not CounterAudit answering.
const MAX_RESPONSE_BYTES = 256 * 1024;
// CounterAudit counts ingest requests over 15 minutes, so a Retry-After can be that long.
const MAX_RETRY_AFTER_SECONDS = 900;
const DEFAULT_RETRY_AFTER_SECONDS = 5;
// The Bureau's retention rule: a packet must expire within 24 months of being sealed.
const RETENTION_MONTHS = 24;
const PACKET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * CounterAudit's base URL, without a trailing slash. https, or plain http to this machine only:
 * the request carries the organization's ingest key.
 */
export function apiBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`--api-url ${raw} is not a URL`);
  }
  const local = url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if ((url.protocol !== "https:" && !local) || url.username || url.password || url.search || url.hash) {
    throw new Error(
      "--api-url must be an https URL (or http to localhost) with no credentials, query or fragment"
    );
  }
  // Rebuilt from its parts, so an empty "?" or "#" cannot end up in front of the path.
  return `${url.origin}${url.pathname}`.replace(/\/+$/, "");
}

/** CounterAudit's signed_event_hash: SHA-256 of the signed event's RFC 8785 canonical JSON. */
export function signedEventHash(event: SignedEventV1): string {
  return createHash("sha256").update(canonicalize(event), "utf8").digest("hex");
}

export type SealResult =
  | { ok: true; packetId: string; created: boolean }
  // fatal: the rest of the file would fail the same way, or would be sealed in a way the Bureau
  // refuses, so it is not sent.
  | { ok: false; reason: string; fatal: boolean };

export interface SealOptions {
  apiUrl: string;
  apiKey: string;
  timeoutMs?: number;
  /** Tries after a 429 before giving up. */
  retries?: number;
  /** Told before each wait a 429 asks for. */
  onWait?: (seconds: number) => void;
}

async function readCapped(res: Response): Promise<string> {
  if (!res.body) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of res.body) {
    size += chunk.length;
    if (size > MAX_RESPONSE_BYTES) throw new Error(`the response is over ${MAX_RESPONSE_BYTES} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Whether CounterAudit's receipt says this event was sealed the way the Bureau takes it. A packet
 * CounterAudit already holds comes back as it was first sealed, and sealing again cannot change
 * it, so a packet the Bureau would refuse is caught here rather than there.
 */
function receiptProblem(event: SignedEventV1, packetId: string, receipt: unknown): SealResult | null {
  const refuse = (reason: string, fatal: boolean): SealResult => ({ ok: false, reason, fatal });
  if (!isObject(receipt)) {
    return refuse("CounterAudit returned the packet without a receipt (its content may have been erased)", false);
  }
  if (typeof receipt.packet_id !== "string" || receipt.packet_id.toLowerCase() !== packetId) {
    return refuse("CounterAudit's receipt is for another packet", true);
  }
  if (receipt.connector_id !== CONNECTOR_ID) {
    return refuse(
      `this event was sealed earlier under the connector ${String(receipt.connector_id).slice(0, 64)}, which the Bureau does not take`,
      false
    );
  }
  const claim = isObject(receipt.outcome_claim) ? receipt.outcome_claim : {};
  if (claim.signed_event_hash !== signedEventHash(event)) {
    return refuse("CounterAudit's receipt is not for this event", true);
  }
  if (receipt.public_proof !== true) {
    return refuse("this event was sealed earlier without a public proof, so the Bureau cannot fetch it", false);
  }
  const expires = typeof receipt.expires_at === "string" ? Date.parse(receipt.expires_at) : NaN;
  if (!Number.isFinite(expires)) {
    return refuse(
      "sealed with no expiry date, which the Bureau refuses. Set your organization's retention policy " +
        `(${RETENTION_MONTHS} months or less) before sealing; this packet keeps no expiry`,
      true
    );
  }
  const created = typeof receipt.created_at === "string" ? new Date(receipt.created_at) : new Date(NaN);
  const latest = new Date(created);
  latest.setUTCMonth(latest.getUTCMonth() + RETENTION_MONTHS);
  if (!Number.isFinite(latest.getTime()) || expires > latest.getTime()) {
    return refuse(
      `sealed to expire more than ${RETENTION_MONTHS} months after sealing, which the Bureau refuses. ` +
        "Shorten your organization's retention policy before sealing more",
      true
    );
  }
  return null;
}

/**
 * Seals one signed event: POST /v1/audit/ingest with the organization's ingest key and a public
 * proof. Sealing an event CounterAudit already holds returns the packet it has (`created: false`).
 */
export async function sealEvent(event: SignedEventV1, options: SealOptions): Promise<SealResult> {
  const { apiUrl, apiKey, timeoutMs = 30_000, retries = 3, onWait } = options;
  const body = JSON.stringify({ connector_id: CONNECTOR_ID, raw_event: event, public_proof: true });
  for (let attempt = 0; ; attempt += 1) {
    let res: Response;
    let text: string;
    try {
      res = await fetch(`${apiUrl}${INGEST_PATH}`, {
        method: "POST",
        headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
        body,
        // Never follow one: the request carries the ingest key.
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
      text = await readCapped(res);
    } catch (error) {
      const cause = (error as { cause?: { message?: unknown } }).cause?.message;
      const why = `${(error as Error).message}${typeof cause === "string" ? ` (${cause})` : ""}`;
      return { ok: false, reason: `could not reach CounterAudit: ${why}`, fatal: true };
    }
    let json: Record<string, unknown> = {};
    try {
      const parsed: unknown = text ? JSON.parse(text) : {};
      if (isObject(parsed)) json = parsed;
    } catch {
      json = {};
    }
    if (res.status === 201 || res.status === 200) {
      if (typeof json.packet_id !== "string" || !PACKET_ID.test(json.packet_id)) {
        return { ok: false, reason: `CounterAudit answered ${res.status} with no packet id`, fatal: true };
      }
      const packetId = json.packet_id.toLowerCase();
      return receiptProblem(event, packetId, json.receipt) ?? { ok: true, packetId, created: res.status === 201 };
    }
    if (res.status === 429 && json.error === "quota_exceeded") {
      return { ok: false, reason: "CounterAudit refused it: your organization's quota is used up", fatal: true };
    }
    if (res.status === 429 && attempt < retries) {
      const header = res.headers.get("retry-after");
      const after = header === null || header.trim() === "" ? NaN : Number(header);
      const seconds =
        Number.isFinite(after) && after >= 0 ? Math.min(after, MAX_RETRY_AFTER_SECONDS) : DEFAULT_RETRY_AFTER_SECONDS;
      onWait?.(seconds);
      await new Promise(resolve => setTimeout(resolve, seconds * 1000));
      continue;
    }
    const what = [json.error, json.message].filter(v => typeof v === "string").join(": ").slice(0, 300);
    const reason = `CounterAudit refused it (${res.status}${what ? ` ${what}` : ""})`;
    // A bad key, a key of another role or organization, a wrong address, rate limiting and server
    // trouble apply to every event alike. Anything else (a bad signature, an unknown signer, a
    // conflicting event) is this event's.
    const fatal = [401, 403, 404, 405, 429].includes(res.status) || res.status >= 500;
    return { ok: false, reason, fatal };
  }
}
