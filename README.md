# agent-bureau-furnish

A small command-line tool for businesses that report agent outcomes to [The Agent Bureau](https://theagentbureau.xyz). It checks your outcome events, signs them with your key, and verifies signed files.

The Bureau keeps one file per AI agent operator across Arc, Base, BNB Chain, Robinhood Chain and Solana, built from outcomes that businesses like yours report: who paid, who delivered, who got cut off. A signature proves a report came from you and hasn't been changed since. The Bureau is in a 90-day pilot; [brief us](https://theagentbureau.xyz/#contact) and choose "Partnership" to take part.

## Install

Node.js 20.11 or later.

```sh
# Run straight from GitHub, nothing to clone
npx github:RunTimeAdmin/agent-bureau-furnish --help

# Or clone it
git clone https://github.com/RunTimeAdmin/agent-bureau-furnish.git
cd agent-bureau-furnish
npm install
node dist/cli.js --help
```

The examples below use `furnish`. With `npx`, write `npx github:RunTimeAdmin/agent-bureau-furnish` in its place.

## Use

```sh
# 1. Once: create your signing key, choose a key id for it, and send the
#    printed public key and the key id to the Bureau
furnish keygen acme.key

# 2. Check an export before sending it (no key needed)
furnish check --furnisher fur_acme01 --key-id acme-2026-10 events.csv

# 3. Sign it
furnish sign --key acme.key --key-id acme-2026-10 --furnisher fur_acme01 --out signed.jsonl events.csv

# 4. Optional: verify the signed file yourself
furnish verify --public-key ed25519:... signed.jsonl
```

- `keygen` never overwrites a file. Keep the private key file to yourself; the Bureau only needs the public key.
- The key id is a name you choose for your key, such as `acme-2026-10`: up to 64 letters, digits or `. _ : -`, starting with a letter or digit. Choose a new one when you make a new key. One run signs with one key, so it is given once on the command line, not per row.
- `check` and `sign` report every problem by line. `sign` writes nothing unless every event passes.
- `verify` checks format and signature. Add `--furnisher fur_...` to also require every event to carry that furnisher id, which the Bureau does so one furnisher's key cannot sign events under another's id.
- Input is CSV or a JSON array of events. `schema_version`, `furnisher_id` and `key_id` are filled in for you. Output is one signed event per line (JSON Lines).
- Your furnisher id (`fur_...`) comes from the Bureau when you join.

See [`examples/events.csv`](examples/events.csv) for a starting point, and [`examples/events-v1.csv`](examples/events-v1.csv) for an event that corrects an earlier one.

## Seal in your own CounterAudit organization

If the Bureau has listed you as a furnisher that seals its own events, seal the signed file in your [CounterAudit](https://counteraudit.io) organization and send the Bureau the sealed file instead:

```sh
export COUNTERAUDIT_INGEST_KEY=...   # an ingest key of your organization
furnish seal --out sealed.jsonl signed.jsonl
```

- Each event goes to `POST /v1/audit/ingest` with `public_proof: true`. CounterAudit checks the signature against the signer registered in your organization, seals the whole event and serves a proof anyone can check without a key. The Bureau fetches that proof itself.
- `sealed.jsonl` has one line per event: `{"packet_id": "...", "event": {...}}`, the format the Bureau's sealed intake reads.
- The key is read from `COUNTERAUDIT_INGEST_KEY`, not a flag, so it stays out of your shell history. `--api-url` points at another CounterAudit (default `https://api.counteraudit.io`; plain http only to localhost). Redirects are not followed, since the request carries the key.
- Every line is checked before anything is sent, and nothing is sent if one fails. Then events are sealed one by one, and each receipt is checked for what the Bureau needs: the right connector, a public proof, the hash of this event, and an expiry no more than 24 months after sealing.
- An event CounterAudit refuses (a bad signature, an unknown signer, an event id you already used for a different event) is reported and the rest carry on. A refused key, a spent quota, an unreachable server, or a packet sealed with no expiry or too late a one stops the run, so the rest of the file is not sealed the same way. When CounterAudit limits requests, `seal` waits as long as it asks. `sealed.jsonl` is written only when every event passes.
- Sealing an event CounterAudit already holds returns the packet it has, so after fixing a refused event, run `seal` on the whole file again. That does not repair a packet: one sealed without a public proof, or before your retention policy was set, stays that way, and the Bureau refuses it. Its event needs a new `event_id`.

Before the first run, set up once with CounterAudit: register your signing key in your organization as an outcome signer (the same public key and key id you gave the Bureau), and set a retention policy of 24 months or less. Set the policy first: `seal` stops at the first packet sealed without an expiry, but that one event's packet cannot be given one later. The Bureau's side is in [its cross-organization intake notes](https://github.com/RunTimeAdmin/the-agent-bureau/blob/master/docs/cross-org-intake.md).

## CSV columns

| Column | Required | Notes |
| --- | --- | --- |
| `event_id` | yes | Your own reference, unique to you: letters, digits, `. _ : -`. Disputes and corrections point at it. |
| `outcome` | yes | `paid`, `refunded`, `payment_failed`, `delivered`, `not_delivered`, `disputed`, `access_revoked`, `policy_violation` |
| `occurred_at` | yes | UTC with seconds, e.g. `2026-10-20T14:03:00Z` |
| `subject_chain`, `subject_registry`, `subject_id` | one subject | Chain is `arc`, `base`, `bnb`, `robinhood` or `solana`; registry is e.g. `erc8004` |
| `subject_wallet` | one subject | EVM or Solana address |
| `subject_did` | one subject | e.g. `did:countersig:...` |
| `amount_value`, `amount_asset`, `amount_chain` | for `paid`, `refunded`, `payment_failed` | Value as a decimal string, e.g. `12.50` |
| `evidence_tx_hash`, `evidence_counteraudit_packet`, `evidence_log_ref` | at least one for `payment_failed`, `not_delivered`, `access_revoked`, `policy_violation` | A log reference is anything that lets you find the record again, kept for 24 months |
| `relation_type`, `relation_target_event_id` | optional; fill both or neither | Points this event at an earlier `event_id` of yours. Type is `disputes`, `corrects`, `supersedes` or `withdraws`. |

Fill exactly one subject per row. Unknown columns are rejected, so a typo can't silently drop data. There is no `key_id` column: give it once with `--key-id`. In JSON input, give `relation` as an object, e.g. `{"type": "corrects", "target_event_id": "inv-1001"}`. Report every outcome of a type for the agents you report on, good and bad.

## Format and signature

The full rules are in [`src/event.ts`](src/event.ts), and the same rules as JSON Schema are in [`schema/outcome-event-v1.json`](schema/outcome-event-v1.json) (`npm run schema` regenerates it).

An event carries two fields that let it be checked and amended later:

- `key_id`: which signing key produced the signature, so you can rotate keys without old events losing their attribution.
- `relation` (optional): points at an earlier `event_id` of yours with an explicit type, so a later fact amends an earlier one instead of silently replacing it.

Each event is signed with Ed25519 over the bytes of:

```
agent-bureau/outcome-event/v1\n<the event without "signature", as RFC 8785 canonical JSON>
```

RFC 8785 means object keys sorted at every level and no whitespace. The fixed prefix stops a signature your key made for something else from being replayed as an event. Public keys and signatures are written as `ed25519:` followed by base64url without padding, in its one canonical spelling. Keys that are small-order points are refused, since anyone could forge a signature under one.

## Test vectors

[`vectors/outcome-event-v1.json`](vectors/outcome-event-v1.json) holds the shared test vectors for v1: signed events with the result every implementation must reach (schema, signature, signed-event hash, and CounterAudit's answer), public keys to accept or refuse, CounterAudit's signer states (active and revoked), and one real CounterAudit proof. This tool, CounterAudit and the Bureau each run all of them; their copies are pinned by SHA-256, so an edited copy fails their tests. A copy does not update itself: after a change here, copy the file into both and update their pinned hash, or they keep testing the old cases.

The file is built by [`test/vectors.ts`](test/vectors.ts) from fixed test keys whose seeds are published in it. Those keys are for testing only: never register them anywhere real. To add a case, change `test/vectors.ts`, run `npm run vectors`, and update the copies and their pinned hash in CounterAudit and the Bureau.

CounterAudit, the Bureau's system of record for furnished events, accepts only this format: without `key_id` a key could not be rotated or revoked.

## v0

v0 is the earlier format, with no `key_id` or `relation`, signed over the `agent-bureau/outcome-event/v0\n` prefix. Its schema is [`schema/outcome-event-v0.json`](schema/outcome-event-v0.json). Add `--version 0` to read or write it, for example to verify a file signed before v1. Under `--version 0`, `--key-id` and the relation columns are refused. The two formats sign over different prefixes, so a v0 signature can never pass as a v1 event or the reverse. CounterAudit refuses v0 events.

## No signature yet?

During the pilot, the Bureau also accepts an unsigned CSV through the channel agreed when you join. Run `furnish check` on it first. Those events are marked "unsigned" on Bureau files, so signing is the better route.

## Develop

```sh
npm install      # also builds dist/
npm test
npm run typecheck
npm run schema   # after changing src/event.ts (add -- --version 0 for v0); a test fails until you do
npm run vectors  # after changing test/vectors.ts; a test fails until you do
```

`zod` is pinned to an exact version on purpose: its JSON Schema output and date rules change between releases, and the furnisher and the Bureau must validate the same way.

## License

MIT
