#!/usr/bin/env node
import { closeSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
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
import { apiBaseUrl, DEFAULT_API_URL, sealEvent } from "./seal.js";
import {
  generateFurnisherKey,
  parsePrivateKey,
  parsePublicKey,
  parseSignedEventV1,
  signEvent,
  signEventV1,
  verifyEvent,
  verifyEventV1,
} from "./sign.js";
import type { SignedEventV1 } from "./event.js";

const USAGE = `furnish: sign and verify outcome events for The Agent Bureau

  furnish keygen <private-key-file>
      Create an Ed25519 signing key and print the public key to register
      with the Bureau. Never share the private key file.

  furnish check --furnisher <fur_id> --key-id <key_id>
                <events.csv|events.json>
      Check every event without signing. Nothing is written.

  furnish sign --key <private-key-file> --furnisher <fur_id>
               --key-id <key_id> --out <signed.jsonl>
               <events.csv|events.json>
      Check every event and sign them all. Writes nothing if any event fails.

  furnish verify --public-key <ed25519:...> [--furnisher <fur_id>]
                 <signed.jsonl>
      Check the format and signature of every event in a signed file. With
      --furnisher, also require every event to carry that furnisher id.

  furnish seal --out <sealed.jsonl> [--api-url <url>] <signed.jsonl>
      Seal every signed event in your CounterAudit organization and write
      the sealed lines the Bureau takes, {"packet_id", "event"} per line.
      Reads the organization's ingest key from COUNTERAUDIT_INGEST_KEY.
      Checks every line first and sends nothing if any fails; writes
      nothing unless every event is sealed the way the Bureau takes it.
      Sealing an event again returns the packet it already has.

  furnish schema [--out <file>]
      Write the JSON Schema for outcome events (default:
      schema/outcome-event-v1.json).

  Events are format v1, which the Bureau and CounterAudit accept. A v1
  event names the key that signed it: pass the key_id you registered with
  the public key as --key-id. --version 0 reads and writes the earlier v0
  format, which has no key_id or relation and which CounterAudit refuses.
`;

class UsageError extends Error {}

function parseVersion(value: string | undefined): "0" | "1" {
  const version = value ?? "1";
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
    if (keyId !== undefined) throw new UsageError("--key-id is not used with --version 0");
    return undefined;
  }
  if (keyId === undefined) {
    throw new UsageError(
      "--key-id is required: the key id you registered with your public key (v0 files need --version 0)"
    );
  }
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new UsageError(
      "--key-id must be 1 to 64 letters, digits or . _ : -, starting with a letter or digit"
    );
  }
  return { keyId };
}

// Furnisher-supplied text (bad column names, rejected values, zod messages) and a
// server's answers are echoed to the operator's console. Strip control and format
// characters first (terminal escapes, bidi overrides, line separators) so crafted
// text cannot hide failures or fake the result line.
export function safe(text: string): string {
  return text.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ");
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

async function sealCommand(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      out: { type: "string" },
      "api-url": { type: "string" },
    },
  });
  const [input] = positionals;
  if (!values.out || !input) throw new UsageError("seal needs --out and a signed file");
  // From the environment, not a flag, so the key stays out of shell history and process lists.
  const apiKey = process.env.COUNTERAUDIT_INGEST_KEY?.trim();
  if (!apiKey) {
    throw new UsageError(
      "Set COUNTERAUDIT_INGEST_KEY to an ingest key of your CounterAudit organization; nothing was sealed"
    );
  }
  // Printable ASCII only. A key with a line break in it would otherwise be echoed whole in the
  // HTTP library's error about the header.
  if (!/^[\x21-\x7e]+$/.test(apiKey)) {
    throw new UsageError("COUNTERAUDIT_INGEST_KEY holds characters an API key cannot have; nothing was sealed");
  }
  let apiUrl: string;
  try {
    apiUrl = apiBaseUrl(values["api-url"] ?? DEFAULT_API_URL);
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
  const events: { line: number; event: SignedEventV1 }[] = [];
  const problems: string[] = [];
  const seen = new Set<string>();
  readFileSync(input, "utf8")
    .split(/\r?\n/)
    .forEach((text, index) => {
      if (!text.trim()) return;
      const fail = (reason: string) => problems.push(`${input}:${index + 1}: ${safe(reason)}`);
      let item: unknown;
      try {
        item = JSON.parse(text);
      } catch {
        return fail("not valid JSON");
      }
      // CounterAudit takes only v1, and checks the signature against the signer it holds.
      const parsed = parseSignedEventV1(item);
      if (!parsed.ok) return fail(parsed.reason);
      const key = `${parsed.event.furnisher_id}/${parsed.event.event_id}`;
      if (seen.has(key)) return fail(`duplicate event ${key}`);
      seen.add(key);
      events.push({ line: index + 1, event: parsed.event });
    });
  if (problems.length) {
    for (const problem of problems) console.error(problem);
    console.error(`${problems.length} line(s) failed. Nothing was sealed.`);
    process.exitCode = 1;
    return;
  }
  if (!events.length) throw new UsageError(`${input} has no events`);

  // Created before anything is sent, so a path that cannot be written stops the run first.
  let fd: number;
  try {
    fd = openSync(values.out, "wx");
  } catch (error) {
    const code = (error as { code?: string }).code ?? "unknown error";
    throw new Error(
      code === "EEXIST"
        ? `${values.out} already exists; nothing was sealed`
        : `${values.out} cannot be created (${code}); nothing was sealed`
    );
  }
  const discard = () => {
    closeSync(fd);
    unlinkSync(values.out!);
  };

  console.log(`Sealing ${events.length} event(s) at ${apiUrl}`);
  const onWait = (seconds: number) =>
    console.log(`CounterAudit is limiting requests; waiting ${seconds}s.`);
  const sealed: string[] = [];
  let created = 0;
  let failed = 0;
  for (const { line, event } of events) {
    const result = await sealEvent(event, { apiUrl, apiKey, onWait });
    if (result.ok) {
      sealed.push(JSON.stringify({ packet_id: result.packetId, event }));
      if (result.created) created += 1;
      continue;
    }
    failed += 1;
    console.error(`${input}:${line}: ${safe(result.reason)}`);
    if (result.fatal) {
      console.error("Stopped: the rest would fail the same way.");
      break;
    }
  }
  if (failed) {
    discard();
    console.error(
      `${sealed.length} of ${events.length} event(s) sealed the way the Bureau takes them. Nothing was ` +
        "written. Sealing an event again returns the packet it already has: fix what is wrong and run " +
        "seal on the whole file again, but a packet sealed without an expiry or a public proof stays that way."
    );
    process.exitCode = 1;
    return;
  }
  try {
    writeFileSync(fd, sealed.join("\n") + "\n");
    closeSync(fd);
  } catch (error) {
    try {
      discard();
    } catch {
      // Already closed, or gone: nothing more to undo.
    }
    const code = (error as { code?: string }).code ?? "unknown error";
    throw new Error(
      `${values.out} could not be written (${code}). Every event is sealed; run seal again to write the lines.`
    );
  }
  console.log(
    `Sealed ${events.length} event(s) to ${values.out} (${created} new, ${events.length - created} already sealed).`
  );
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

const commands: Record<string, (args: string[]) => void | Promise<void>> = {
  keygen,
  check,
  sign: signCommand,
  verify: verifyCommand,
  seal: sealCommand,
  schema: schemaCommand,
};

/** Runs a command. Returns a promise for one that waits on the network (seal), else nothing. */
export function runCli(argv: string[]): void | Promise<void> {
  const [command, ...rest] = argv;
  const fail = (error: unknown) => {
    const code = (error as { code?: string }).code ?? "";
    const usage = error instanceof UsageError || code.startsWith("ERR_PARSE_ARGS");
    console.error(error instanceof Error ? error.message : String(error));
    if (usage) console.error(`\n${USAGE}`);
    process.exitCode = 1;
  };
  try {
    if (command === "--help" || command === "-h") {
      console.log(USAGE);
    } else {
      // Object.hasOwn so an argument like "constructor" or "__proto__" cannot
      // resolve to an inherited function instead of a real command.
      const run =
        command && Object.hasOwn(commands, command) ? commands[command] : undefined;
      if (!run) throw new UsageError(command ? `Unknown command: ${command}` : "No command given");
      const pending = run(rest);
      if (pending) return pending.catch(fail);
    }
  } catch (error) {
    fail(error);
  }
}

// Run only when invoked as the CLI, so importing this module for its exports
// (for example in tests) does not parse argv or touch process.exitCode.
const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) {
  runCli(process.argv.slice(2));
}
