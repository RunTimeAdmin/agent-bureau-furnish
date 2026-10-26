#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { buildEvent, csvToEvents, type RowError } from "./csv.js";
import { outcomeEventJsonSchema, type UnsignedEvent } from "./event.js";
import {
  generateFurnisherKey,
  parsePrivateKey,
  parsePublicKey,
  signEvent,
  verifyEvent,
} from "./sign.js";

const USAGE = `furnish: sign and verify outcome events for The Agent Bureau (v0)

  furnish keygen <private-key-file>
      Create an Ed25519 signing key and print the public key to register
      with the Bureau. Never share the private key file.

  furnish check --furnisher <fur_id> <events.csv|events.json>
      Check every event without signing. Nothing is written.

  furnish sign --key <private-key-file> --furnisher <fur_id> --out <signed.jsonl> <events.csv|events.json>
      Check every event and sign them all. Writes nothing if any event fails.

  furnish verify --public-key <ed25519:...> <signed.jsonl>
      Check the format and signature of every event in a signed file.

  furnish schema [--out <file>]
      Write the JSON Schema for outcome events (default: schema/outcome-event-v0.json).
`;

class UsageError extends Error {}

function readEvents(file: string, furnisherId: string) {
  const text = readFileSync(file, "utf8");
  if (file.toLowerCase().endsWith(".csv")) return csvToEvents(text, furnisherId);

  let items: unknown;
  try {
    items = JSON.parse(text);
  } catch {
    throw new UsageError(`${file} is not valid JSON`);
  }
  if (!Array.isArray(items)) throw new UsageError(`${file} must hold a JSON array of events`);
  const events: UnsignedEvent[] = [];
  const errors: RowError[] = [];
  items.forEach((item, index) => {
    const result = buildEvent(furnisherId, item as Record<string, unknown>);
    if ("error" in result) errors.push({ line: index + 1, message: result.error });
    else events.push(result.event);
  });
  return { events, errors };
}

// Reads and checks the input; returns null after reporting problems.
function loadValidEvents(input: string, furnisherId: string) {
  const { events, errors } = readEvents(input, furnisherId);
  if (errors.length) {
    for (const { line, message } of errors) console.error(`${input}:${line}: ${message}`);
    console.error(`${errors.length} event(s) failed.`);
    process.exitCode = 1;
    return null;
  }
  if (!events.length) throw new UsageError(`${input} has no events`);
  return events;
}

function keygen(args: string[]) {
  const [file] = parseArgs({ args, allowPositionals: true }).positionals;
  if (!file) throw new UsageError("Give a file name for the private key");
  const { privateKeyPem, publicKey } = generateFurnisherKey();
  try {
    writeFileSync(file, privateKeyPem, { mode: 0o600, flag: "wx" });
  } catch {
    throw new UsageError(`${file} already exists or cannot be written; nothing changed`);
  }
  console.log(`Private key written to ${file}. Keep it private.`);
  console.log(`Public key (send this to the Bureau): ${publicKey}`);
}

function check(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { furnisher: { type: "string" } },
  });
  const [input] = positionals;
  if (!values.furnisher || !input) throw new UsageError("check needs --furnisher and an input file");
  const events = loadValidEvents(input, values.furnisher);
  if (events) console.log(`${events.length} event(s) OK.`);
}

function signCommand(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      key: { type: "string" },
      furnisher: { type: "string" },
      out: { type: "string" },
    },
  });
  const [input] = positionals;
  if (!values.key || !values.furnisher || !values.out || !input) {
    throw new UsageError("sign needs --key, --furnisher, --out and an input file");
  }
  const events = loadValidEvents(input, values.furnisher);
  if (!events) {
    console.error("Nothing was signed.");
    return;
  }
  const key = parsePrivateKey(readFileSync(values.key, "utf8"));
  const lines = events.map(event => JSON.stringify(signEvent(event, key)));
  try {
    writeFileSync(values.out, lines.join("\n") + "\n", { flag: "wx" });
  } catch {
    throw new UsageError(`${values.out} already exists or cannot be written; nothing changed`);
  }
  console.log(`Signed ${events.length} event(s) to ${values.out}.`);
}

function verifyCommand(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { "public-key": { type: "string" } },
  });
  const [input] = positionals;
  if (!values["public-key"] || !input) {
    throw new UsageError("verify needs --public-key and a signed file");
  }
  const publicKey = parsePublicKey(values["public-key"]);
  const seen = new Set<string>();
  let valid = 0;
  let invalid = 0;
  readFileSync(input, "utf8")
    .split(/\r?\n/)
    .forEach((text, index) => {
      if (!text.trim()) return;
      const fail = (reason: string) => {
        invalid++;
        console.error(`${input}:${index + 1}: ${reason}`);
      };
      let item: unknown;
      try {
        item = JSON.parse(text);
      } catch {
        return fail("not valid JSON");
      }
      const result = verifyEvent(item, publicKey);
      if (!result.ok) return fail(result.reason);
      const key = `${result.event.furnisher_id}/${result.event.event_id}`;
      if (seen.has(key)) return fail(`duplicate event ${key}`);
      seen.add(key);
      valid++;
    });
  console.log(`${valid} valid, ${invalid} invalid.`);
  if (invalid || !valid) process.exitCode = 1;
}

function schemaCommand(args: string[]) {
  const { values } = parseArgs({ args, options: { out: { type: "string" } } });
  const out = values.out ?? path.join("schema", "outcome-event-v0.json");
  mkdirSync(path.dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(outcomeEventJsonSchema(), null, 2) + "\n");
  console.log(`Wrote ${out}`);
}

const commands: Record<string, (args: string[]) => void> = {
  keygen,
  check,
  sign: signCommand,
  verify: verifyCommand,
  schema: schemaCommand,
};

const [command, ...rest] = process.argv.slice(2);
try {
  if (command === "--help" || command === "-h") {
    console.log(USAGE);
  } else {
    const run = command ? commands[command] : undefined;
    if (!run) throw new UsageError(command ? `Unknown command: ${command}` : "No command given");
    run(rest);
  }
} catch (error) {
  const code = (error as { code?: string }).code ?? "";
  const usage = error instanceof UsageError || code.startsWith("ERR_PARSE_ARGS");
  console.error(error instanceof Error ? error.message : String(error));
  if (usage) console.error(`\n${USAGE}`);
  process.exitCode = 1;
}
