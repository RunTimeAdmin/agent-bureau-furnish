import { z } from "zod";

// Outcome event v0: one fact a furnisher reports about an agent it dealt with.
// README.md sets out the rules. This file is the source of truth;
// schema/outcome-event-v0.json is generated from it (npm run schema).

export const SCHEMA_VERSION = "0";
export const SCHEMA_URL =
  "https://theagentbureau.xyz/schemas/outcome-event-v0.json";

// The chains Nooscape indexes, so every subject can be matched to a record.
export const SUBJECT_CHAINS = [
  "arc",
  "base",
  "bnb",
  "robinhood",
  "solana",
] as const;

export const NEGATIVE_OUTCOMES = [
  "payment_failed",
  "not_delivered",
  "access_revoked",
  "policy_violation",
] as const;

export const OUTCOMES = [
  "paid",
  "refunded",
  "delivered",
  "disputed",
  ...NEGATIVE_OUTCOMES,
] as const;

const wallet = z.union([
  z.string().regex(/^0x[0-9a-fA-F]{40}$/, "EVM address"),
  z.string().regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/, "Solana address"),
]);

export const subjectRefSchema = z.union([
  z
    .object({
      chain: z.enum(SUBJECT_CHAINS),
      registry: z.string().min(1).max(64),
      id: z.string().min(1).max(128),
    })
    .strict(),
  z.object({ wallet }).strict(),
  z.object({ did: z.string().regex(/^did:[a-z0-9]+:\S+$/).max(256) }).strict(),
]);

// Missing-field messages name what to fill in, since most furnishers start
// from a spreadsheet rather than this schema.
const requiredFor = (field: string, fill: string) => (issue: { input: unknown }) =>
  issue.input === undefined ? `${field} is required for this outcome: ${fill}` : undefined;

export const amountSchema = z
  .object(
    {
      value: z.string().regex(/^\d+(\.\d+)?$/, "decimal string, e.g. 12.50"),
      asset: z.string().min(1).max(16),
      chain: z.string().regex(/^[a-z0-9-]{2,32}$/),
    },
    { error: requiredFor("amount", "give value, asset and chain") }
  )
  .strict();

// At least one pointer is required; the JSON Schema states it as minProperties.
export const evidenceSchema = z
  .object(
    {
      tx_hash: z.string().min(1).max(128).optional(),
      counteraudit_packet: z.string().min(1).max(128).optional(),
      log_ref: z.string().min(1).max(256).optional(),
    },
    {
      error: requiredFor(
        "evidence",
        "give tx_hash, counteraudit_packet or log_ref"
      ),
    }
  )
  .strict()
  .refine(evidence => Object.keys(evidence).length > 0, {
    message: "evidence needs tx_hash, counteraudit_packet or log_ref",
  });

const signature = z
  .string()
  .regex(/^ed25519:[A-Za-z0-9_-]{86}$/, "ed25519:<base64url signature>");

const base = {
  schema_version: z.literal(SCHEMA_VERSION),
  furnisher_id: z.string().regex(/^fur_[a-z0-9]{6,32}$/),
  event_id: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/),
  subject_ref: subjectRefSchema,
  occurred_at: z.iso.datetime(),
};

// Payment outcomes need an amount; negative outcomes need evidence.
function eventSchema<T extends z.ZodRawShape>(extra: T) {
  return z.discriminatedUnion("outcome", [
    z
      .object({
        ...base,
        ...extra,
        outcome: z.enum(["paid", "refunded"]),
        amount: amountSchema,
        evidence: evidenceSchema.optional(),
      })
      .strict(),
    z
      .object({
        ...base,
        ...extra,
        outcome: z.literal("payment_failed"),
        amount: amountSchema,
        evidence: evidenceSchema,
      })
      .strict(),
    z
      .object({
        ...base,
        ...extra,
        outcome: z.enum(["not_delivered", "access_revoked", "policy_violation"]),
        amount: amountSchema.optional(),
        evidence: evidenceSchema,
      })
      .strict(),
    z
      .object({
        ...base,
        ...extra,
        outcome: z.enum(["delivered", "disputed"]),
        amount: amountSchema.optional(),
        evidence: evidenceSchema.optional(),
      })
      .strict(),
  ]);
}

export const unsignedEventSchema = eventSchema({});
export const signedEventSchema = eventSchema({ signature });

export type UnsignedEvent = z.infer<typeof unsignedEventSchema>;
export type SignedEvent = z.infer<typeof signedEventSchema>;

export function outcomeEventJsonSchema(): Record<string, unknown> {
  const schema = z.toJSONSchema(signedEventSchema, {
    target: "draft-2020-12",
    override: ctx => {
      if (ctx.zodSchema === evidenceSchema) ctx.jsonSchema.minProperties = 1;
    },
  });
  return {
    $schema: schema.$schema,
    $id: SCHEMA_URL,
    title: "Agent Bureau outcome event v0",
    description:
      "One outcome a furnisher reports about an agent. Payment outcomes need an amount; payment_failed, not_delivered, access_revoked and policy_violation need evidence. The signature is Ed25519 over the canonical form described in the agent-bureau-furnish README.",
    ...Object.fromEntries(
      Object.entries(schema).filter(([key]) => key !== "$schema")
    ),
  };
}
