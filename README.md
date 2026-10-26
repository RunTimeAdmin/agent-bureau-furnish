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
- Input is CSV or a JSON array of events. `schema_version` and `furnisher_id` are filled in for you. Output is one signed event per line (JSON Lines).
- Your furnisher id (`fur_...`) comes from the Bureau when you join.

See [`examples/events.csv`](examples/events.csv) for a starting point.

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

Fill exactly one subject per row. Unknown columns are rejected, so a typo can't silently drop data. Report every outcome of a type for the agents you report on, good and bad.

## Format and signature

The full rules are in [`src/event.ts`](src/event.ts), and the same rules as JSON Schema are in [`schema/outcome-event-v0.json`](schema/outcome-event-v0.json), also published at `https://theagentbureau.xyz/schemas/outcome-event-v0.json`.

Each event is signed with Ed25519 over the bytes of:

```
agent-bureau/outcome-event/v0\n<the event without "signature", as RFC 8785 canonical JSON>
```

RFC 8785 means object keys sorted at every level and no whitespace. The fixed prefix stops a signature your key made for something else from being replayed as an event. Public keys and signatures are written as `ed25519:` followed by base64url without padding.

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
