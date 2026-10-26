import { z } from "zod";
import { SCHEMA_VERSION, unsignedEventSchema, type UnsignedEvent } from "./event.js";

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

export function buildEvent(
  furnisherId: string,
  input: Record<string, unknown>
): { event: UnsignedEvent } | { error: string } {
  const parsed = unsignedEventSchema.safeParse({
    schema_version: SCHEMA_VERSION,
    furnisher_id: furnisherId,
    ...input,
  });
  return parsed.success
    ? { event: parsed.data }
    : { error: z.prettifyError(parsed.error) };
}

export function csvToEvents(
  text: string,
  furnisherId: string
): { events: UnsignedEvent[]; errors: RowError[] } {
  const [header = [], ...rows] = parseCsv(text);
  const columns = header.map(name => name.trim());
  const unknown = columns.filter(
    name => !(CSV_COLUMNS as readonly string[]).includes(name)
  );
  const missing = REQUIRED_COLUMNS.filter(name => !columns.includes(name));
  if (unknown.length || missing.length) {
    const problems = [
      unknown.length && `unknown columns: ${unknown.join(", ")}`,
      missing.length && `missing columns: ${missing.join(", ")}`,
    ].filter(Boolean);
    return { events: [], errors: [{ line: 1, message: problems.join("; ") }] };
  }

  const events: UnsignedEvent[] = [];
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

    const eventId = cell("event_id");
    if (eventId && seen.has(eventId)) {
      errors.push({ line, message: `event_id ${eventId} appears more than once` });
      return;
    }
    if (eventId) seen.add(eventId);

    const result = buildEvent(furnisherId, {
      event_id: eventId,
      outcome: cell("outcome"),
      occurred_at: cell("occurred_at"),
      subject_ref: subjects[0],
      amount: pick("amount_", ["value", "asset", "chain"]),
      evidence: pick("evidence_", ["tx_hash", "counteraudit_packet", "log_ref"]),
    });
    if ("error" in result) errors.push({ line, message: result.error });
    else events.push(result.event);
  });
  return { events, errors };
}
