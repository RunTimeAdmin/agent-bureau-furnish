import { z } from "zod";
import {
  SCHEMA_VERSION,
  SCHEMA_VERSION_V1,
  unsignedEventSchema,
  unsignedEventV1Schema,
  type UnsignedEvent,
  type UnsignedEventV1,
} from "./event.js";

export const CSV_COLUMNS = [
  "event_id",
  "outcome",
  "occurred_at",
  "subject_chain",
  "subject_registry",
  "subject_id",
  "subject_wallet",
  "subject_did",
  "amount_value",
  "amount_asset",
  "amount_chain",
  "evidence_tx_hash",
  "evidence_counteraudit_packet",
  "evidence_log_ref",
] as const;

// v1 only: an optional relation to an earlier event, filled both or neither.
// key_id is not a column: one run signs with one key, so the CLI takes it
// once (--key-id) instead of trusting a label on each row.
export const CSV_COLUMNS_V1 = ["relation_type", "relation_target_event_id"] as const;

const REQUIRED_COLUMNS = ["event_id", "outcome", "occurred_at"];

// RFC 4180: commas, quoted fields with "" escapes, CRLF or LF line endings.
export function parseCsv(text: string): string[][] {
  const input = text.replace(/^﻿/, "");
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (quoted) {
      if (char !== '"') field += char;
      else if (input[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = false;
    } else if (char === '"' && field === "") quoted = true;
    else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && input[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += char;
  }
  if (quoted) throw new Error("A quoted field is never closed");
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

export type RowError = { line: number; message: string };

// Given for v1: the label of the key that will sign, set on every event.
export type V1Options = { keyId: string };

export function buildEvent(
  furnisherId: string,
  input: Record<string, unknown>,
  v1?: V1Options
): { event: UnsignedEvent | UnsignedEventV1 } | { error: string } {
  // The tool sets schema_version, furnisher_id and (v1) key_id; spreading the
  // caller's input first means a JSON input file cannot override them.
  const parsed = v1
    ? unsignedEventV1Schema.safeParse({
        ...input,
        schema_version: SCHEMA_VERSION_V1,
        furnisher_id: furnisherId,
        key_id: v1.keyId,
      })
    : unsignedEventSchema.safeParse({
        ...input,
        schema_version: SCHEMA_VERSION,
        furnisher_id: furnisherId,
      });
  return parsed.success
    ? { event: parsed.data }
    : { error: z.prettifyError(parsed.error) };
}

export function csvToEvents(
  text: string,
  furnisherId: string,
  v1?: V1Options
): { events: (UnsignedEvent | UnsignedEventV1)[]; errors: RowError[] } {
  const [header = [], ...rows] = parseCsv(text);
  const columns = header.map(name => name.trim());
  const v1Columns: readonly string[] = CSV_COLUMNS_V1;
  const unknown = columns.filter(
    name =>
      !(CSV_COLUMNS as readonly string[]).includes(name) &&
      !v1Columns.includes(name) &&
      name !== "key_id"
  );
  const missing = REQUIRED_COLUMNS.filter(name => !columns.includes(name));
  // A repeated column would make cell() read only the first and silently drop
  // the rest, so reject duplicate headers outright.
  const duplicates = [
    ...new Set(columns.filter((name, i) => columns.indexOf(name) !== i)),
  ];
  // v0 has nowhere to put these, so refuse them rather than drop them.
  const v1Only = v1 ? [] : columns.filter(name => v1Columns.includes(name));
  const problems = [
    unknown.length && `unknown columns: ${unknown.join(", ")}`,
    missing.length && `missing columns: ${missing.join(", ")}`,
    duplicates.length && `duplicate columns: ${duplicates.join(", ")}`,
    v1Only.length &&
      `v1-only columns: ${v1Only.join(", ")} (sign with --version 1, or remove them)`,
    columns.includes("key_id") && "key_id is not a column: give it once with --key-id",
  ].filter(Boolean);
  if (problems.length) {
    return { events: [], errors: [{ line: 1, message: problems.join("; ") }] };
  }

  const events: (UnsignedEvent | UnsignedEventV1)[] = [];
  const errors: RowError[] = [];
  const seen = new Set<string>();
  rows.forEach((cells, index) => {
    const line = index + 2;
    if (cells.every(cell => cell.trim() === "")) return;
    if (cells.length !== columns.length) {
      errors.push({ line, message: `expected ${columns.length} fields, found ${cells.length}` });
      return;
    }
    const cell = (name: string) => {
      const value = cells[columns.indexOf(name)]?.trim();
      return value ? value : undefined;
    };
    const pick = (prefix: string, names: string[]) => {
      const entries = names
        .map(name => [name, cell(prefix + name)] as const)
        .filter(([, value]) => value !== undefined);
      return entries.length ? Object.fromEntries(entries) : undefined;
    };

    const subjects = [
      pick("subject_", ["chain", "registry", "id"]),
      pick("subject_", ["wallet"]),
      pick("subject_", ["did"]),
    ].filter(Boolean);
    if (subjects.length !== 1) {
      errors.push({
        line,
        message:
          "fill exactly one subject: subject_chain + subject_registry + subject_id, subject_wallet, or subject_did",
      });
      return;
    }

    const relationType = cell("relation_type");
    const relationTarget = cell("relation_target_event_id");
    if ((relationType === undefined) !== (relationTarget === undefined)) {
      errors.push({
        line,
        message: "fill both relation_type and relation_target_event_id, or neither",
      });
      return;
    }

    const eventId = cell("event_id");
    if (eventId && seen.has(eventId)) {
      errors.push({ line, message: `event_id ${eventId} appears more than once` });
      return;
    }
    if (eventId) seen.add(eventId);

    const result = buildEvent(
      furnisherId,
      {
        event_id: eventId,
        outcome: cell("outcome"),
        occurred_at: cell("occurred_at"),
        subject_ref: subjects[0],
        amount: pick("amount_", ["value", "asset", "chain"]),
        evidence: pick("evidence_", ["tx_hash", "counteraudit_packet", "log_ref"]),
        ...(relationType
          ? { relation: { type: relationType, target_event_id: relationTarget } }
          : {}),
      },
      v1
    );
    if ("error" in result) errors.push({ line, message: result.error });
    else events.push(result.event);
  });
  return { events, errors };
}
