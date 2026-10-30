#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { buildEvent, csvToEvents, type RowError, type V1Options } from "./csv.js";
import {
  KEY_ID_PATTERN,
  outcomeEventJsonSchema,
  outcomeEventV1JsonSchema,
  type UnsignedEvent,
  type UnsignedEventV1,
} from "./event.js";
import {
  generateFurnisherKey,
  parsePrivateKey,
  parsePublicKey,
  signEvent,
  signEventV1,
  verifyEvent,
  verifyEventV1,
} from "./sign.js";

const USAGE = `furnish: sign and verify outcome events for The Agent Bureau

  furnish keygen <private-key-file>
      Create an Ed25519 signing key and print the public key to register
      with the Bureau. Never share the private key file.

  furnish check --furnisher <fur_id> [--version 1 --key-id <key_id>]
                <events.csv|events.json>
      Check every event without signing. Nothing is written.

  furnish sign --key <private-key-file> --furnisher <fur_id>
               [--version 1 --key-id <key_id>] --out <signed.jsonl>
               <events.csv|events.json>
      Check every event and sign them all. Writes nothing if any event fails.

  furnish verify --public-key <ed25519:...> [--furnisher <fur_id>]
                 [--version 1] <signed.jsonl>
      Check the format and signature of every event in a signed file. With
      --furnisher, also require every event to carry that furnisher id.

  furnish schema [--version 0|1] [--out <file>]
      Write the JSON Schema for outcome events (default: the v0 schema at
      schema/outcome-event-v0.json). --version 1 writes the draft v1 schema.

  --version 0|1 picks the event format. The default is 0. CounterAudit
  accepts only v1. A v1 event names the key that signed it: pass the
  key_id you registered with the public key as --key-id.
`;

class UsageError extends Error {}

function parseVersion(value: string | undefined): "0" | "1" {
  const version = value ?? "0";
  if (version !== "0" && version !== "1") {
    throw new UsageError("--version must be 0 or 1");
  }
  return version;
}

// v1 events name the key that signs them. One run signs with one key, so
// key_id is given once on the command line, not per row.
function v1Options(
  version: string | undefined,
  keyId: string | undefined
): V1Options | undefined {
  if (parseVersion(version) === "0") {
    if (keyId !== undefined) throw new UsageError("--key-id needs --version 1");
    return undefined;
  }
  if (keyId === undefined) {
    throw new UsageError(
      "--version 1 needs --key-id: the label you registered with your public key"
    );
  }
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new UsageError(
      "--key-id must be 1 to 64 letters, digits or . _ : -, starting with a letter or digit"
    );
  }
  return { keyId };
}

// Furnisher-supplied text (bad column names, rejected values, zod messages) is
// echoed to the operator's console. Strip control characters first so a crafted
// file cannot write terminal escape sequences that hide failures or fake the
// result line.
export function safe(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
}

function readEvents(file: string, furnisherId: string, v1?: V1Options) {
  const text = readFileSync(file, "utf8");
  if (file.toLowerCase().endsWith(".csv")) return csvToEvents(text, furnisherId, v1);

  let items: unknown;
  try {
    items = JSON.parse(text);
  } catch {
    throw new UsageError(`${file} is not valid JSON`);
  }
  if (!Array.isArray(items)) throw new UsageError(`${file} must hold a JSON array of events`);
  const events: (UnsignedEvent | UnsignedEventV1)[] = [];
  const errors: RowError[] = [];
  // Reject a repeated event_id within the batch, as the CSV path does, so a
  // JSON array cannot be signed with duplicate (furnisher_id, event_id) lines.
  const seen = new Set<string>();
  items.forEach((item, index) => {
    const result = buildEvent(furnisherId, item as Record<string, unknown>, v1);
    if ("error" in result) {
      errors.push({ line: index + 1, message: result.error });
      return;
    }
    if (seen.has(result.event.event_id)) {
      errors.push({
        line: index + 1,
        message: `event_id ${result.event.event_id} appears more than once`,
      });
      return;
    }
    seen.add(result.event.event_id);
    events.push(result.event);
  });
  return { events, errors };
}

// Reads and checks the input; returns null after reporting problems.
function loadValidEvents(input: string, furnisherId: string, v1?: V1Options) {
  const { events, errors } = readEvents(input, furnisherId, v1);
  if (errors.length) {
    for (const { line, message } of errors)
      console.error(`${input}:${line}: ${safe(message)}`);
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
    options: {
      furnisher: { type: "string" },
      version: { type: "string" },
      "key-id": { type: "string" },
    },
  });
  const [input] = positionals;
  if (!values.furnisher || !input) throw new UsageError("check needs --furnisher and an input file");
  const v1 = v1Options(values.version, values["key-id"]);
  const events = loadValidEvents(input, values.furnisher, v1);
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
      version: { type: "string" },
      "key-id": { type: "string" },
    },
  });
  const [input] = positionals;
  if (!values.key || !values.furnisher || !values.out || !input) {
    throw new UsageError("sign needs --key, --furnisher, --out and an input file");
  }
  const v1 = v1Options(values.version, values["key-id"]);
  const events = loadValidEvents(input, values.furnisher, v1);
  if (!events) {
    console.error("Nothing was signed.");
    return;
  }
  const key = parsePrivateKey(readFileSync(values.key, "utf8"));
  // The sign functions check each event against their own schema again.
  const lines = events.map(event =>
    JSON.stringify(
      v1
        ? signEventV1(event as UnsignedEventV1, key)
        : signEvent(event as UnsignedEvent, key)
    )
  );
  try {
    writeFileSync(values.out, lines.join("\n") + "\n", { flag: "wx" });
  } catch {
    throw new UsageError(`${values.out} already exists or cannot be written; nothing changed`);
  }
  console.log(`Signed ${events.length} event(s) to ${values.out}.`);
}

export function verifyCommand(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      "public-key": { type: "string" },
      furnisher: { type: "string" },
      version: { type: "string" },
    },
  });
  const [input] = positionals;
  if (!values["public-key"] || !input) {
    throw new UsageError("verify needs --public-key and a signed file");
  }
  const version = parseVersion(values.version);
  // A valid signature binds an event to a key, not to a claimed furnisher_id.
  // When --furnisher is given (the Bureau knows who sent the file), every line
  // must carry that id, so one furnisher cannot sign events under another's id
  // and a file cannot mix furnishers.
  const expectedFurnisher = values.furnisher;
  if (
    expectedFurnisher !== undefined &&
    !/^fur_[a-z0-9]{6,32}$/.test(expectedFurnisher)
  ) {
    throw new UsageError("--furnisher must look like fur_acme01");
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
        console.error(`${input}:${index + 1}: ${safe(reason)}`);
      };
      let item: unknown;
      try {
        item = JSON.parse(text);
      } catch {
        return fail("not valid JSON");
      }
      const result =
        version === "1" ? verifyEventV1(item, publicKey) : verifyEvent(item, publicKey);
      if (!result.ok) return fail(result.reason);
      if (
        expectedFurnisher !== undefined &&
        result.event.furnisher_id !== expectedFurnisher
      ) {
        return fail(
          `furnisher ${result.event.furnisher_id} does not match --furnisher ${expectedFurnisher}`
        );
      }
      const key = `${result.event.furnisher_id}/${result.event.event_id}`;
      if (seen.has(key)) return fail(`duplicate event ${key}`);
      seen.add(key);
      valid++;
    });
  console.log(`${valid} valid, ${invalid} invalid.`);
  if (invalid || !valid) process.exitCode = 1;
}

function schemaCommand(args: string[]) {
  const { values } = parseArgs({
    args,
    options: { out: { type: "string" }, version: { type: "string" } },
  });
  const version = parseVersion(values.version);
  const build = version === "1" ? outcomeEventV1JsonSchema : outcomeEventJsonSchema;
  const out = values.out ?? path.join("schema", `outcome-event-v${version}.json`);
  mkdirSync(path.dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(build(), null, 2) + "\n");
  console.log(`Wrote ${out}`);
}

const commands: Record<string, (args: string[]) => void> = {
  keygen,
  check,
  sign: signCommand,
  verify: verifyCommand,
  schema: schemaCommand,
};

export function runCli(argv: string[]): void {
  const [command, ...rest] = argv;
  try {
    if (command === "--help" || command === "-h") {
      console.log(USAGE);
    } else {
      // Object.hasOwn so an argument like "constructor" or "__proto__" cannot
      // resolve to an inherited function instead of a real command.
      const run =
        command && Object.hasOwn(commands, command) ? commands[command] : undefined;
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
}

// Run only when invoked as the CLI, so importing this module for its exports
// (for example in tests) does not parse argv or touch process.exitCode.
const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) {
  runCli(process.argv.slice(2));
}
