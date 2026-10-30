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
# 1. Once: create your signing key, then send the printed public key to the Bureau
furnish keygen acme.key

# 2. Check an export before sending it (no key needed)
furnish check --furnisher fur_acme01 events.csv

# 3. Sign it
furnish sign --key acme.key --furnisher fur_acme01 --out signed.jsonl events.csv

# 4. Optional: verify the signed file yourself
furnish verify --public-key ed25519:... signed.jsonl
```

- `keygen` never overwrites a file. Keep the private key file to yourself; the Bureau only needs the public key.
- `check` and `sign` report every problem by line. `sign` writes nothing unless every event passes.
- `verify` checks format and signature. Add `--furnisher fur_...` to also require every event to carry that furnisher id, which the Bureau does so one furnisher's key cannot sign events under another's id.
- Input is CSV or a JSON array of events. `schema_version`, `furnisher_id` and, for v1, `key_id` are filled in for you. Output is one signed event per line (JSON Lines).
- Your furnisher id (`fur_...`) comes from the Bureau when you join.
- These commands use the v0 format unless you add `--version 1`. CounterAudit accepts only v1; see [v1](#v1) for how to sign it.

See [`examples/events.csv`](examples/events.csv) for a starting point, or [`examples/events-v1.csv`](examples/events-v1.csv) for v1.

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
| `relation_type`, `relation_target_event_id` | v1 only, optional; fill both or neither | Points this event at an earlier `event_id` of yours. Type is `disputes`, `corrects`, `supersedes` or `withdraws`. |

Fill exactly one subject per row. Unknown columns are rejected, so a typo can't silently drop data. Under v0 the relation columns are rejected for the same reason. There is no `key_id` column: give it once with `--key-id`. Report every outcome of a type for the agents you report on, good and bad.

## Format and signature

The full rules are in [`src/event.ts`](src/event.ts), and the same rules as JSON Schema are in [`schema/outcome-event-v0.json`](schema/outcome-event-v0.json), also published at `https://theagentbureau.xyz/schemas/outcome-event-v0.json`.

Each event is signed with Ed25519 over the bytes of:

```
agent-bureau/outcome-event/v0\n<the event without "signature", as RFC 8785 canonical JSON>
```

RFC 8785 means object keys sorted at every level and no whitespace. The fixed prefix stops a signature your key made for something else from being replayed as an event. Public keys and signatures are written as `ed25519:` followed by base64url without padding.

## v1

`v1` is defined alongside `v0` in [`src/event.ts`](src/event.ts), generated to [`schema/outcome-event-v1.json`](schema/outcome-event-v1.json) with `node dist/cli.js schema --version 1`, where it is still marked as a draft. It keeps the same outcome, amount and evidence rules and adds two fields:

- `key_id`: which signing key produced the signature, so a furnisher can rotate keys without old events losing their attribution.
- `relation` (optional): points at an earlier `event_id` with an explicit type (`disputes`, `corrects`, `supersedes` or `withdraws`), so a later fact can amend an earlier one instead of silently replacing it.

v1 signs over the `agent-bureau/outcome-event/v1\n` prefix, a separate signing domain, so a v0 signature can never be accepted as a v1 event or the reverse.

CounterAudit, the Bureau's system of record for furnished events, accepts only v1, because without `key_id` a key cannot be rotated or revoked. To work with v1, add `--version 1` to each command, and your key id to `check` and `sign`:

```sh
furnish check --version 1 --key-id acme-2026-10 --furnisher fur_acme01 events.csv
furnish sign --version 1 --key-id acme-2026-10 --key acme.key --furnisher fur_acme01 --out signed.jsonl events.csv
furnish verify --version 1 --public-key ed25519:... signed.jsonl
```

- The key id is a name you choose for your key, such as `acme-2026-10`: up to 64 letters, digits or `. _ : -`, starting with a letter or digit. Send it to the Bureau with the public key, and choose a new one when you make a new key.
- One run signs with one key, so the key id is given once on the command line, not per row.
- In CSV, a relation takes the two `relation_` columns in the table above. In JSON input, give `relation` as an object, e.g. `{"type": "corrects", "target_event_id": "inv-1001"}`.
- Without `--version`, every command reads and writes v0 as before.

## No signature yet?

During the pilot, the Bureau also accepts an unsigned CSV through the channel agreed when you join. Run `furnish check` on it first. Those events are marked "unsigned" on Bureau files, so signing is the better route.

## Develop

```sh
npm install      # also builds dist/
npm test
npm run typecheck
npm run schema   # after changing src/event.ts; a test fails until you do
```

`zod` is pinned to an exact version on purpose: its JSON Schema output and date rules change between releases, and the furnisher and the Bureau must validate the same way.

## License

MIT
