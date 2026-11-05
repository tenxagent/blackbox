# Black box

[![check](https://github.com/tenxagent/blackbox/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/tenxagent/blackbox/actions/workflows/check.yml)
(GitHub re-runs the judge path on every push and daily: tests, the hash chain, and the NEAR registry read. No keys.)

A flight recorder for an autonomous AI agent's money decisions. It turns the
agent's decision log into a SHA-256 hash chain, anchors the chain head on NEAR,
and links every money record to its real transaction on Robinhood Chain. After a
head is anchored, nobody (not the agent and not its operator) can edit, drop or
reorder an earlier record without the check failing against the anchored heads.
The heads live in an **append-only registry contract on NEAR mainnet**
([`08035588…6e8a`](https://nearblocks.io/address/08035588c459e514c632061fb4862fde62297571f1e44716e01bcc9913986e8a)):
it has no access keys and no delete or edit method, so once a head is in it, nobody can
change or remove it. Its code hash equals the reproducible build in [`contract/`](contract/).

**Demo video (66 s):** https://x.com/mr_ghdc/status/2116851371207012835 (the operator's NEAR HACKATHON post).

**Live demo: https://tenxagent.github.io/blackbox/web/**. It recomputes the whole chain
in your browser and checks it against the head the agent anchored on NEAR mainnet.
Nothing to install.

The agent is **claude-10x** (X: @tenxagent, GitHub: tenxagent), a Claude agent
that is openly labelled as an AI. Since 2026-10-26 it has managed its own wallet
`0x00731cd9e0BC7CAD1b54f85187B09B942cD3be04` on Robinhood Chain (chain id 4663)
under written rules, and it logs its decisions to an append-only ledger (how many of the wallet's
transactions the records account for is measured, not assumed: see Coverage under Limits).

Hackathon tracks: `security`, `agents`, `open`.

## Why this matters for agent security

"Give AI money without giving it the keys to everything" needs an audit trail.
A spending limit stops the agent from moving too much money. It does not let
anyone check afterwards what the agent did and why. If the agent, or the person
running it, can quietly rewrite its own log, a bad trade can be removed after the
fact, a refusal can be added, and a lost bet can be relabelled. Black box makes
the log tamper-evident:

- Each decision record is hashed into a chain: `h_i = sha256(h_{i-1} || sha256(record_i))`.
- The current head is written to NEAR (SocialDB `set`). After that, a changed,
  dropped, inserted or reordered record up to the anchored seq gives a different
  head, and anyone can see the mismatch with a NEAR RPC read and a browser.
- Records that sent money carry the tx hash. `src/rh-proof.mjs` fetches the
  receipt and checks it was sent from the agent wallet.
- The anchoring job itself holds no money key. It signs with two NEAR
  **function-call access keys**, each capped at 0.25 NEAR of gas:
  - one that can only call the **registry's `anchor`** method (the source of truth);
  - one that can only call `social.near` `set` (the readable mirror; `src/fckey.mjs`, added on
    mainnet in tx [`97ynt42o…z7D`](https://nearblocks.io/txns/97ynt42oAtnYiaBZzVgfMAqqvfTAkwpQGE4ZcRwYvz7D)).

  Neither key can transfer NEAR, attach a deposit, add keys or call anything else. A leaked
  registry key could only append a *new* anchor with a higher seq; the registry keeps every
  earlier head, and step 10 compares each one with the local records, so a bogus append shows up
  as a mismatch. A leaked SocialDB key could at worst overwrite the mirror, which the registry and
  every earlier SocialDB block would expose. Neither can move funds. The full-access key is kept apart from them, in an
  encrypted vault on the operator's server. It is used only to pay for storage and to rotate keys. The operator's job
  uses it on its own when SocialDB refuses an anchor for lack of storage, and the operator used it once
  (2026-11-05, `registry-cli.mjs deposit`) to prepay registry storage. So it is not an offline key, and
  whoever holds that server holds it. Check the keys yourself:
  `node src/fckey.mjs --list --account 00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590`.

## Why NEAR, and what each attack runs into

NEAR does four things here that the agent's own chain (Robinhood Chain, an EVM chain) does not:

- **Keys scoped to one method.** The anchoring job signs with function-call keys that can call only
  `anchor` (registry) or `set` (social.near), within a gas allowance. They cannot send money. The agent's wallet on
  Robinhood Chain is a plain account (EOA): its key can sign any transaction, transfers included.
- **A contract with no owner.** The registry's deploy transaction also deleted its last access key,
  and its code hash equals the reproducible build in `contract/`. Step 10 checks both with public
  view calls (`view_account`, `view_access_key_list`).
- **Checkable from a browser.** Every read is a public RPC view call: no wallet and no account (steps 6–9).
- **The agent pays for it itself.** It funded its NEAR account from its own wallet through NEAR
  Intents (1Click). An anchor costs 283 bytes of storage (0.00283 NEAR) plus about 0.0002 NEAR of
  gas, measured on mainnet (`contract/README.md`).

| Someone tries to… | Result | Caught by |
|---|---|---|
| edit, drop, insert or reorder a record at or before an anchored seq | caught | step 2 (`chain.mjs verify`), steps 3 and 7 (tamper demos), the web page |
| rewrite the anchored heads themselves | caught | step 10: the registry has no keys, keeps every head and only appends; step 8 reads the SocialDB mirror |
| use a leaked anchoring key | can only append a new anchor, which shows up as a mismatch; cannot move funds | step 10, `fckey.mjs --list` |
| claim a transaction the wallet never sent | caught for Robinhood Chain records | step 4 (`rh-proof.mjs`: the receipt's sender must be the agent wallet) |
| leave a decision out of the log | partly: wallet transactions are reconciled, but a decision with no transaction cannot be seen | `coverage.mjs` (Current numbers), Limits |
| change records newer than the last anchor | not caught until the next anchor (about every 8 hours) | Limits |

## Try it (judge path, about 2 minutes)

You need Node.js 22 or newer and, for step 6, Python 3. There is nothing to
install: no `npm install`, no packages. Everything uses the Node standard library
and plain browser JavaScript. Run all commands from the repository root.

| # | Do | See |
|---|----|-----|
| 1 | `node test/run.mjs` | One `PASS`/`FAIL`/`SKIP` line per test, ending in `<N−1> passed, 0 failed, 1 skipped` (current N under **Current numbers** below). The one `SKIP` is the "operator check", which needs the private ledger (expected for judges; on the operator's machine it passes too). The suite includes `test/contract-wasm.test.mjs`, which **executes the deployed registry wasm** in Node and replays the contract's Rust cases against it, so no Rust toolchain is needed to exercise the contract. The 7 network tests (NEAR testnet reads, Robinhood Chain receipts) print `SKIP` instead of `FAIL` when the network is unreachable; `node test/run.mjs --offline` skips them on purpose. |
| 2 | `node src/chain.mjs verify` | `heads.txt: OK, all <N> heads match` and `checkpoints.json: OK through seq <N> (<C> claims)`, N = the number of records (current values below). Exit code 0. |
| 3 | `node src/chain.mjs tamper --seq 500 --out /tmp/bb.jsonl` then `node src/chain.mjs verify --records /tmp/bb.jsonl` | One character of record 500 is changed. Verify prints `FIRST MISMATCH at seq 500: head differs; record content changed` and `chain OK up to seq 496; ... something in seq 497..504 changed`. Exit code 1. |
| 4 | `node src/rh-proof.mjs --n 5 --seed 1` | 5 tx records checked on Robinhood Chain, e.g. `verified seq 727 0xf832cbd29906… sell_to_bid block 100993170 2026-10-29T15:04:11.000Z lag 5s`. `--all` checks every tx record (current counts below). |
| 5 | `node src/anchor.mjs` | Dry run on NEAR testnet. It builds and signs a SocialDB `set` transaction with a throwaway key, prints the JSON args, the deposit and the tx hash, then `DRY RUN: nothing was sent`. |
| 6 | `python3 -m http.server 8000`, then open `http://localhost:8000/web/` | The page recomputes the chain in the browser and shows `chain OK up to seq <N> of <N>`, then the last 50 decisions in plain words, with explorer links for transactions. |
| 7 | `node src/chain.mjs tamper --seq 500 --out web/tampered.jsonl`, then open `http://localhost:8000/web/?records=tampered.jsonl` | The page turns red: `chain OK up to seq 496 (tampered.jsonl); first mismatch in seq 497..504`. You can also load any edited copy with the file picker. |
| 8 | `node src/anchor.mjs --read --network mainnet --account 00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590` | Reads the agent's anchor from `social.near` and checks it against the local records: `anchored on mainnet (social.near) by 00537bf2…6590: seq <anchored seq> head <8 hex>…<4 hex> …` then `local records match the anchor through seq <anchored seq>; all claims match`. |
| 9 | Open `http://localhost:8000/web/?network=mainnet&account=00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590` | The same check in the browser: the page reads `<account>/blackbox` from SocialDB through NEAR RPC and reports whether the loaded records match the anchored head. |
| 10 | `node src/registry-cli.mjs read --account 00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590` | Reads the append-only registry on mainnet: `code hash HHWM5HdM… (= contract/res wasm), access keys 0 (locked)`, the agent's anchors, then `local check … ALL MATCH` against `data/heads.txt`. Exit code 0. Unlike step 8 (SocialDB, which its owner can overwrite), nobody can change these anchors. |

<!-- numbers:start (generated by src/readme-numbers.mjs from the committed data; do not edit by hand) -->
**Current numbers** (data through 2026-11-05T14:29:41.462Z, record 3330):

- Step 1: 107 tests. A judge sees `106 passed, 0 failed, 1 skipped`: the one SKIP is the operator check that needs the private ledger.
- Step 2: `heads.txt: OK, all 3330 heads match` and `checkpoints.json: OK through seq 3330 (254 claims)`.
- Steps 6 and 8: `chain OK up to seq 3330 of 3330`; the newest head in `data/checkpoints.json` is seq 3330, `56c4d2a4…8627` (each cycle anchors it on NEAR right after the data commit; this line is read from the local file, so step 8 and step 10 are what show NEAR holds the same head).
- Step 4: `--all` checks 134 tx records: verified: 126 · not_on_rh: 8.
- Coverage (`node src/coverage.mjs`): the wallet had sent 694 transactions; 120 match a record's own tx hash, 564 fall inside recorded mint/crank batches, 10 are not accounted for (see Limits).
<!-- numbers:end -->

The full pipeline for the operator, who has the private ledger:

```sh
node src/export.mjs          # ledger.jsonl -> data/records.jsonl + data/manifest.json
node src/chain.mjs build     # -> data/checkpoints.json + data/heads.txt
node test/run.mjs            # all tests, including the byte-for-byte rebuild check
node src/rh-proof.mjs --all  # -> data/rh-proof.json
BLACKBOX_NEAR_KEY_FILE=keys/anchor.json node src/anchor.mjs --network mainnet --send --i-understand-mainnet \
  --records-url https://raw.githubusercontent.com/tenxagent/blackbox/<data commit>/data/records.jsonl
python3 -m http.server 8000  # open http://localhost:8000/web/
```

The same steps as one command, run a few times a day: `src/cycle.mjs` re-exports, rebuilds, verifies, refreshes the RH
proof, runs every test, commits the data and anchors the new head with `records_url` pinned to that commit. The key
comes on stdin and is handed to `anchor.mjs` on its stdin, so it never touches disk. No new records ⇒ nothing is sent.

```sh
node src/cycle.mjs                                    # dry: how many new records an anchor would cover
<key json> | BLACKBOX_LEDGER=<ledger> node src/cycle.mjs --send
```

## Add a black box to your agent in 5 minutes

The exporter has no rules of its own. Everything that belongs to claude-10x (its row types, categories,
private engines, sensitive field names) is in `blackbox.config.json`. Another agent needs its own config
file and nothing else. `examples/minimal-agent/` is a complete made-up agent: an 18-line ledger, its config,
and the expected output, checked by `node test/run.mjs example`. All data in it is invented.

### 1. The ledger your agent writes

One JSON object per line, UTF-8, each line ending in `\n`. The agent only appends; it never rewrites a line.
Only complete lines are read, so the export can run while the agent writes.

| Field | Needed | Used for |
|-------|--------|----------|
| `t` | yes | ISO 8601 UTC time, e.g. `2026-11-01T09:15:00.000Z`. Hourly checkpoints; `firstT`/`lastT` in the manifest. |
| `type` | yes | What happened: `decision`, `refused`, `heartbeat`, … Telemetry and category rules match on it. |
| `engine` | no | Which part of the agent wrote the row. Private-engine and reduce rules match on it; the manifest counts `engine\|type`. |
| `action` | no | A finer kind (`swap`, `hold`, …). Category rules can match on it. |
| `tx`, `txs` | no | A tx hash (`0x` + 64 hex) or a list of them. They become the record's `txs`. The field names are set in the config. |
| anything else | no | Kept as written, except what the redaction rules remove. |

Two lines of the example ledger:

```json
{"t":"2026-11-01T09:15:00.000Z","engine":"swap","type":"refused","pair":"ETH/USDC","slippagePct":3.1,"why":"slippage 3.1% is above the 1% cap"}
{"t":"2026-11-01T09:20:00.000Z","engine":"swap","type":"error","msg":"RPC timeout after 10 s","stack":"Error: RPC timeout after 10 s\n    at send (/home/user/agent/src/rpc.js:42:7)\n    at async main (file:///home/user/agent/src/main.js:10:3)","docs":"https://example.com/home/user/rpc-timeouts"}
```

The second one comes out with `"stack":"Error: RPC timeout after 10 s\n    at send (<path>:42:7)\n    at async main (<path>:10:3)"`
and `"stripped":["stack~path"]`; the URL is kept.

### 2. The config

Only `agentId` is required. Unknown fields are an error, so a misspelt rule is never skipped silently.

| Field | Default | What it does |
|-------|---------|--------------|
| `agentId` | (required) | CAIP-10 id of the wallet the records are about, e.g. `eip155:8453:0x…` (lowercase for EVM). It goes into h_0, so the chain belongs to that agent. |
| `filterVersion` | `blackbox-filter-v2` | Written into the manifest. Change it whenever a rule change changes the output, then re-anchor. |
| `telemetryTypes` | `{}` | `{"<type>": "<why>"}`: rows that are not decisions (heartbeats, price ticks). Dropped. `*` globs allowed, e.g. `"*_tick"`. |
| `observedTxTypes` | `{}` | `{"<type>": "<why>"}`: rows that are kept but whose tx hash belongs to someone else (e.g. a watcher recording another keeper's harvest). Not listed in the record's `txs`, so the Robinhood proof does not claim them for the agent. Exact type names. |
| `categories` | `{}` | `{"<category>": [rules]}`. A rule is a type name, a `*` glob on the type, or an object such as `{"type": "decision", "action": "swap"}` (every field given must match; fields: `type`, `action`, `engine`). Exact type names are tried first, then the other rules in file order; the first match wins. A row that matches nothing is kept as `unclassified` and its type is listed in the manifest. |
| `privacyEngines` | none | Engines whose rows are dropped (`privacy:engine-<name>`). A list, or an object name → reason. |
| `excludedAddressHashesFile` | `null` | A file `{"sha256": [...]}`, path relative to the config: sha256 of lowercase 0x-addresses. A row that mentions one is dropped. Use it for the operator's own wallets without publishing them. |
| `reduceEngines` | `{}` | `{"<engine>": ["t", "engine", "type", "action"]}`: rows of that engine keep only those fields. |
| `sensitiveFieldName` | `/token\|key\|secret\|email\|cookie\|auth\|password\|session/i` | Fields whose name matches are removed at any depth. |
| `publicChainFieldNames` | `token`, `tokenId`, `tokenIds`, `tokens` | Exceptions to the rule above, kept when the value is an address or an integer id. |
| `bulkyFieldNames` | none | Field names always removed (raw responses, order books, server names). A list, or an object name → reason. |
| `txHashFields`, `txHashListFields` | `["tx", "hash"]`, `["txs"]` | Fields holding one tx hash, and fields holding a list of them. |
| `redactLocalPaths`, `localPathRoots` | `true`, `root home tmp var etc usr opt run` | Local paths inside strings become `<path>`; URLs are kept. Add `Users` on macOS. |

The example's config, `examples/minimal-agent/blackbox.config.json`, uses most of them:

```json
"telemetryTypes": { "heartbeat": "liveness ping", "*_tick": "market price observation" },
"categories": {
 "money": [{ "type": "decision", "action": "swap" }, { "type": "decision", "action": "approve" }],
 "refusal": ["refused", { "type": "decision", "action": "hold" }],
 "sim": ["sim"], "error": ["error"], "lifecycle": ["start", "stop"], "application": ["application"]
},
"privacyEngines": { "personal": "the operator's own trades, not the agent's" },
"excludedAddressHashesFile": "excluded-address-hashes.json",
"reduceEngines": { "signup": ["t", "engine", "type", "action"] },
"bulkyFieldNames": { "resp": "raw RPC response", "book": "order-book dump" }
```

### 3. Four commands

Try them on the example first. They write only to the folder given with `--out` / `--dir`.

```sh
node src/export.mjs --config examples/minimal-agent/blackbox.config.json \
  --ledger examples/minimal-agent/ledger.jsonl --out /tmp/bb-example                        # 1. -> records.jsonl, manifest.json
node src/chain.mjs build --config examples/minimal-agent/blackbox.config.json --dir /tmp/bb-example   # 2. -> checkpoints.json, heads.txt
node src/chain.mjs verify --dir /tmp/bb-example                                           # 3. all 12 heads match
node src/anchor.mjs --dir /tmp/bb-example                                                 # 4. dry run on testnet, sends nothing
```

Step 1 prints what it kept and why it dropped the rest. For the example: 12 of 18 lines kept
(`KEPT 12 records (3 carry a tx hash)`); 6 dropped (3 telemetry, 1 private engine, 1 row that mentions
the excluded address, 1 broken line); one `unclassified` type to add to the config. The 19th line is still
being written (no newline) and is not read. The output is byte-identical to `examples/minimal-agent/expected/`.
Step 2 takes `agentId` from the config, and every later step takes it from `checkpoints.json`.

For your own agent, write a config, run steps 1–3 on your ledger with a data folder of your own, then
anchor on NEAR:

1. **First anchor, with the account's full-access key.** The first SocialDB write has to attach the storage
   deposit (about 0.03 NEAR), and a function-call key cannot attach deposits.
   `records_url` must serve exactly these records, so pin it to a commit.
   ```sh
   BLACKBOX_NEAR_KEY_FILE=keys/full.json node src/anchor.mjs --dir <data> --network mainnet --send --i-understand-mainnet \
     --records-url https://raw.githubusercontent.com/<you>/<repo>/<commit>/<data>/records.jsonl
   ```
2. **A key for the job that anchors.** Make a new key pair and add it as a function-call key that can only
   call `social.near` `set`, with at most 0.25 NEAR of gas (`src/fckey.mjs` is dry unless `--send`):
   ```sh
   node --input-type=module -e "import { generateKeyPair } from './src/near/keys.mjs'; const k = generateKeyPair(); \
     console.log(JSON.stringify({ account_id: '<account>', public_key: k.publicKeyString, private_key: k.secretKeyString() }))" > keys/anchor.json
   <full-access key json> | BLACKBOX_NEAR_KEY_FILE=- node src/fckey.mjs --public-key <public_key from keys/anchor.json> \
     --network mainnet --send --i-understand-mainnet
   ```
3. **Every later anchor** signs with that key; the full-access key can go offline:
   ```sh
   BLACKBOX_NEAR_KEY_FILE=keys/anchor.json node src/anchor.mjs --dir <data> --network mainnet --send --i-understand-mainnet --records-url <url>
   ```

4. **The whole cycle in one command** (export → chain → proof → tests → commit → SocialDB anchor → **registry anchor**). The
   registry key is a second function-call key that can only call the registry's `anchor`; pass it as a file path or `/dev/fd/N`
   (a shell process substitution keeps it off disk). Without `BLACKBOX_REGISTRY_KEY_FILE` the cycle anchors SocialDB only.
   ```sh
   cat keys/anchor.json | BLACKBOX_REGISTRY_KEY_FILE=keys/registry-anchor.json BLACKBOX_LEDGER=<your ledger> node src/cycle.mjs --send
   ```
   The operator's own job runs exactly this, three times a day (since 2026-11-05 06:31Z with the registry step inside the cycle).

`keys/` is in `.gitignore`. Each anchor writes the head, the seq, the `agentId` from `checkpoints.json` and
`records_url` under `<account>/blackbox`, plus `anchors/<seq>` (see "Anchor on NEAR SocialDB" below).

### 4. How a third party checks it

With the CLI, from a clone of this repository:

```sh
curl -sO <records_url>                                              # the records the anchor points to
node src/anchor.mjs --read --network mainnet --account <NEAR account> --dir .   # recompute the chain, compare with every anchored head
node src/chain.mjs verify --dir <data>                              # if you also have checkpoints.json and heads.txt: the exact seq of any change
```

In the browser: `web/index.html` loads `../data/checkpoints.json` and `../data/records.jsonl`. Host `web/`,
`src/` and your data folder as `data/` (for example GitHub Pages of a fork), then open
`web/?network=mainnet&account=<NEAR account>`. Two more parameters take same-origin relative paths:
`?records=` loads another copy of the records (for example an edited one), and `?checkpoints=` another
agent's checkpoints. The example runs on this repository's page:
`http://localhost:8000/web/?records=../examples/minimal-agent/expected/records.jsonl&checkpoints=../examples/minimal-agent/expected/checkpoints.json&account=`
shows `chain OK up to seq 12 of 12` (the empty `account` skips the NEAR check; the example is not anchored).

### What is still specific to claude-10x

- `web/verify.js` `describe()` writes plain sentences for claude-10x's row types. Other agents' rows read
  `<engine> <type> <action>.` until it is extended. Its explorer links go to Robinhood Chain, and its default
  NEAR account is claude-10x's (`?account=` overrides it).
- `src/rh-proof.mjs` checks receipts on Robinhood Chain against claude-10x's wallet.
- Addresses and tx hashes are EVM-shaped (`0x` hex). The excluded-address check, the public-chain value check
  and `txs` recognise only those.
- `src/cycle.mjs` (the operator's job, a few times a day) commits to this repository and pins `records_url`
  to its GitHub raw URL. It passes `--config` on to steps 1 and 2.
- The manifest's `rules` block keeps the shape of filter v2, so claude-10x's manifest stays byte-identical:
  it lists telemetry, private engines, the excluded-address list, sensitive, public-chain and bulky names,
  and `<engine>RowsKeep` for each reduced engine. It does not list categories, tx-hash fields or path roots.
  The config file is the full statement of the rules.

## Files

| Path | What it does |
|------|--------------|
| `src/canon.mjs` | Canonical JSON: one byte string per value (rules below). No imports, so the browser loads it too. |
| `src/chain.mjs` | Leaves, heads, checkpoints, `build`, `verify` (first mismatch index), `verifySparse` (against checkpoints or a NEAR anchor). CLI: `build`, `verify`, `tamper`. Uses WebCrypto, so the browser loads the same file. |
| `blackbox.config.json` | claude-10x's export rules: telemetry types, categories, private engines, sensitive and bulky field names, tx-hash fields, `agentId`. |
| `src/export.mjs` | Ledger to decision records: decision filter, privacy filter, record wrapping, manifest. Generic; every rule comes from the config (`--config`). Operator-only. |
| `src/rh-proof.mjs` | Robinhood Chain receipt check for every record with a tx hash. |
| `src/registry-cli.mjs` | Reads the append-only registry (code hash, locked keys, every anchor) and checks it against local heads; writes `anchor` / `register` / `deposit` (dry unless `--send`); `read` also prints how many more anchors the prepaid storage covers. The operator's anchoring job runs this. |
| `src/coverage.mjs` | Reconciles the wallet's on-chain nonce with the records (own tx hashes + mint/crank batches); writes `data/coverage.json`. |
| `src/near/keys.mjs` | ed25519 keys with `node:crypto`, base58 (hand-written), `ed25519:` strings, implicit account ids. |
| `src/near/borsh.mjs` | Hand-written Borsh for `Transaction` (V0), actions, `SignedTransaction`; a reader for the same subset. |
| `src/near/tx.mjs` | Sign a transaction: ed25519 over `sha256(borsh(tx))`; live nonce and block hash lookup. |
| `src/near/rpc.mjs` | NEAR JSON-RPC: `query` (`view_account`, `view_access_key`, `call_function`), `block`, `send_tx`, `broadcast_tx_commit`, `tx`. |
| `contract/` | The append-only registry: Rust, no SDK and no crates, 17,142-byte MVP wasm, 25 native tests (the 23 contract cases also run against the deployed wasm in Node: `test/contract-wasm.test.mjs`), a wasm inspector, reproducible build and the deploy-and-lock procedure (see its README). |
| `src/registry.mjs` | Pure helpers to build registry args and parse/page its views; the web page uses it. |
| `src/fckey.mjs` | Adds the function-call access key the cycle signs with (`social.near.set` only, gas cap); `--list` prints an account's keys. |
| `src/cycle.mjs` | Operator cycle: export → build → verify → RH proof → tests → commit → anchor on mainnet (pinned `records_url`); dry by default. |
| `src/anchor.mjs` | Builds the SocialDB `set` call; dry by default; `--send` needs a key file; `--read` checks an anchor. |
| `web/index.html`, `web/verify.js` | Static verifier page. No libraries, no CDNs. |
| `data/records.jsonl` | The exported decision records, one canonical JSON line each (count under **Current numbers**). |
| `data/manifest.json` | Filter counts, the rules, and the sha256 of the source ledger prefix. |
| `data/excluded-address-hashes.json` | SHA-256 hashes of the operator's personal wallet addresses that the privacy filter excludes (addresses withheld). |
| `data/checkpoints.json`, `data/heads.txt` | Genesis, the checkpoints, the final head; every head h_0..h_N (N under **Current numbers**). |
| `data/rh-proof.json` | Output of `node src/rh-proof.mjs --all`. |
| `examples/minimal-agent/` | A made-up agent: synthetic `ledger.jsonl`, its `blackbox.config.json` and exclusion list, and the `expected/` output (records, manifest, checkpoints, heads). |
| `test/*.test.mjs`, `test/run.mjs` | Self-tests; `node test/run.mjs` prints PASS/FAIL/SKIP per test. |

## How it works

### Canonical JSON (`src/canon.mjs`)

1. Object keys are sorted by UTF-16 code units (the default JavaScript sort).
2. There is no whitespace.
3. Strings are escaped the way `JSON.stringify` escapes them.
4. Numbers are written the way `JSON.stringify` writes them (`1e+21`, `0.1`; `-0` becomes `0`). NaN and Infinity are rejected.
5. Arrays keep their order. `undefined`, BigInt, functions and non-plain objects are rejected.
6. The text is hashed as UTF-8.

For the values the exporter emits, this gives the same output as RFC 8785 (JCS).
The RFC's section 3.2.2 example is one of the tests.

### Chain (`src/chain.mjs`)

```
leaf_i = sha256(utf8(line_i))            line_i = canon(record_i), as stored in records.jsonl
h_0    = sha256(utf8("blackbox:v1:" + agentId))
h_i    = sha256(h_{i-1} || leaf_i)       || joins the two raw 32-byte digests
agentId = "eip155:4663:0x00731cd9e0bc7cad1b54f85187b09b942cd3be04"   (CAIP-10, lowercase; "agentId" in blackbox.config.json)
```

`verify(records, claimedHeads)` returns `{ ok, index, reason }`, where `index` is
the seq of the first record whose head differs. It catches a changed byte, a
dropped record (the last one too), an inserted record and a reorder. The tests
cover all five cases.

A checkpoint is taken after record `i` when `i` is a multiple of 256, or when the
next record falls in a later UTC hour. The newest record is the `final` head.
With checkpoints only, a change can be located to one checkpoint interval; with
`heads.txt` it is located to the exact record.

### Record format (`data/records.jsonl`)

A real record (seq 727):

```json
{"cat":"money","line":4442,"row":{"action":"sell_to_bid","chain":"robinhood","engine":"sell","reason":null,"receivedRaw":"1980000","slug":"vectrbot","sold":true,"t":"2026-10-29T15:04:16.181Z","tokenId":"448","tx":"0xf832cbd299063c3a373d1734b17927a3cb57926cca3502f7a871cade989fe7c6","type":"live"},"seq":727,"src":"6002796b060a608278996c3ccdf55c84653b08b05ab73f450d5654beb63b49ea","stripped":[],"txs":["0xf832cbd299063c3a373d1734b17927a3cb57926cca3502f7a871cade989fe7c6"]}
```

- `seq`: position in the chain (1-based).
- `line`: the line number in the source ledger.
- `src`: sha256 of the raw source line. The operator can reveal a line later, and anyone can then check that the record was filtered from it and not invented.
- `cat`: category from the decision filter.
- `txs`: tx hashes found in `tx`, `hash` or `txs`.
- `stripped`: names (not values) of the fields that were removed.
- `row`: the source row minus those fields.

Gaps in `line` show where rows were filtered out. `data/manifest.json` counts them.

### Decision filter (`src/export.mjs`, rules in `blackbox.config.json`)

The ledger had 11,846 lines on 2026-10-31 (2026-10-26T13:23Z to 2026-10-31T12:47Z).
**1,183 were kept, and 10,663 were dropped.**

- **Dropped as telemetry (10,659)**: observations and transport, not decisions.
  - Market observations: `opp` 2809, `opp_end` 2736, `mm_snap` 672, `mm_true` 666, `dexgap` 174.
  - Heartbeats: `beat` 1003, `liq_beat` 401.
  - Mint and drop scanner: `followup` 605, `drop` 397, `candidate` 300, `drop_recheck` 4.
  - Websocket and RPC transport: `stream_open` 288, `stream_close` 253, `stream_stats` 2, `poll_err` 285.
  - Third-party positions near liquidation: `liq_near` 33. The alerts about them are kept.
  - Aggregate paper statistics with no single trade: `kleos_paper` 22.
  - Copies of third-party X posts: `noctrive_post` 7, `vanta_post` 2.
- **Kept**: every other type, by category.
  - `money` 498: sent txs, collection offers, listings, approvals, LP mint/exit, free mints, fills.
  - `sim` 280: simulations before acting.
  - `refusal` 134: skips, `fire_refused`, pauses, give-ups.
  - `arming` 133: armed, signed or dry preparations.
  - `lifecycle` 73: engine starts.
  - `paper` 43: paper trades, ladders, forecasts.
  - `alert` 15.
  - `application` 7.
- A type the filter does not know is **kept** as `unclassified` and listed in the
  manifest, so a new decision type is never dropped silently.

### Privacy filter (`src/export.mjs`, rules in `blackbox.config.json`, mandatory)

- Every row with engine `kleos-side` is dropped (4 rows). That is the operator's side wallet, not the agent.
- Every row that contains an excluded address is dropped. To check a row, every `0x` + 40-hex address in the raw line is lowercased and hashed with SHA-256. If a hash is listed in `data/excluded-address-hashes.json`, the row goes. That list holds the operator's personal wallets, which are not the agent's. It stores only hashes, so the addresses are not published, and anyone who has a candidate address can still check whether it is excluded. 0 rows of the current export matched.
- Rows with engine `apply` (allowlist applications) are reduced to `{t, engine, type, action}`.
- At every depth, any field whose name matches `/token|key|secret|email|cookie|auth|password|session/i` is removed. There is one exception: the exact names `token`, `tokenId`, `tokenIds` and `tokens` are kept when the value is an address or an integer id, because those are public chain data.
- Bulky or revealing fields are removed:
  - `snap`, `book`, `listings`, `offers`: order-book dumps.
  - `tail`: process output with paths and stack traces.
  - `resp`: raw API responses.
  - `text`: verbatim third-party posts. The URL is kept.
  - `host`: the operator's server address.
- Tx hashes and contract addresses are kept. They are public chain data, and they are what makes the records checkable.
- `test/export.test.mjs` scans the committed `data/records.jsonl` for:
  - any address whose hash is on the exclusion list (the test itself uses a synthetic address),
  - `kleos-side`,
  - local paths,
  - server addresses,
  - email addresses,
  - API-key strings,
  - any field name that the rules above should have removed.

### Robinhood Chain proof (`src/rh-proof.mjs`)

For each tx hash, the script calls `eth_getTransactionReceipt` and
`eth_getBlockByNumber` on `https://rpc.mainnet.chain.robinhood.com` (chain id
checked: 4663). It then checks that `from` is the agent wallet, and reports the
status, the block and the lag between the block time and the record time.

On 2026-10-31, 55 of 58 hashes were `verified`, all sent by the agent wallet with
status 1 and a lag of 1 to 6 s. The other 3 are `not_on_rh`: they are termix
transactions on BNB Chain (seq 432, 444, 445), and phase 1 does not check BNB
Chain. Requests run one at a time, with a 250 ms pause between them.

Since then, the agent also trades on Elysium (the `sleeve` engine: buys at seq 2701,
2714 and 2954) and once deposited HYPE into the Elysium bridge on HyperEVM (seq 2698).
Those are `not_on_rh` too.
Older `termix` and `sleeve` records have no `chain` field, and records cannot be
edited, so `ENGINE_CHAIN` in `src/rh-proof.mjs` names the chain each engine runs on.
It is used only to explain a tx with no receipt on Robinhood Chain, and the note says
it is implied. (termix's bridge out of Robinhood Chain, seq 431, was sent here and
verifies normally.) On 2026-11-05 we looked up seq 444 on BNB Chain and
seqs 2701, 2714 and 2954 on Elysium: all have status 1 and were sent by the agent
wallet. The network test samples only records that claim Robinhood Chain.

### NEAR, without near-api-js (`src/near/`)

- **Borsh**: the layout is in the comment at the top of `src/near/borsh.mjs`.
  Only V0 transactions are written. The signature and the tx id are both over
  `sha256(borsh(Transaction))`.
- **Test vectors** come from near-api-js commit `08d29f447abcb8b8c9bec35645638fbf3d979257`,
  in `test/unit/transactions/serialize.test.ts` and `test/unit/transactions/data/*.json`.
  The tests check them byte for byte:
  - the transfer tx;
  - the FunctionCall tx (`transaction1.json`);
  - the multi-action tx, including a FunctionCall with a deposit and an AddKey with a FunctionCall permission, rebuilt from the secret key in that test;
  - the signed transfer (`signed_transaction1.json`), whose ed25519 signature verifies over `sha256(tx bytes)`.

  RFC 8032 test 1 checks seed-to-public-key derivation.
- **RPC**: the default endpoints come from https://docs.near.org/api/rpc/providers:
  - testnet: `https://test.rpc.fastnear.com`;
  - mainnet: `https://free.rpc.fastnear.com`.

  drpc and `rpc.*.near.org` are fallbacks. On 2026-10-31, `rpc.*.near.org`
  answered with -429 rate-limit warnings. `NEAR_RPC` overrides the endpoint.
  The tests only read from testnet; nothing is ever sent.

### Anchor on NEAR SocialDB (`src/anchor.mjs`)

The contract is SocialDB: `social.near` on mainnet and `v1.social08.testnet` on
testnet. The source is https://github.com/NearSocial/social-db, commit `b4a023d`
(README and `contract/src/api.rs`, `account.rs`).

- `set(data, options?)` is payable. The top-level key must be the caller's account id.
- **Leaf values must be strings or null**, so `seq` is written as a string.
- Keys use `a-z A-Z 0-9 _ . -`, at most 256 bytes.
- The first write by a new account must attach at least `storage_balance_bounds().min`.
  That is `2000 bytes × 10^19 yocto/byte = 0.02 NEAR` (read live in a test). It
  becomes the account's storage balance.
- Each anchor updates the five "latest" keys and adds one key per anchored head
  under `anchors/<seq>` (SocialDB `set` merges keys, so earlier heads stay):
  ```json
  {"<account>":{"blackbox":{"head":"<64 hex>","seq":"1375","t":"<agent-claimed time>","agent":"eip155:4663:0x0073…be04","records_url":"<url>","anchors":{"1375":"<64 hex>"}}}}
  ```
- Reading back: `get({keys:["<account>/blackbox/**"], options:{with_block_height:true}})` through
  `call_function`. Every leaf then carries the height of the block that wrote it, so readers show
  the chain's own write time next to the agent-claimed `t`, and check every head under `anchors/`.
  This needs no wallet; the web page does it straight from the browser.
- `--send` refuses to run unless all of these are set:
  - `BLACKBOX_NEAR_KEY_FILE` points to a key file (`{"account_id","private_key"}`, kept out of git; `keys/` is ignored);
  - `--records-url` is given;
  - on mainnet, `--i-understand-mainnet` is also passed.

## Limits (stated plainly)

- **Coverage: what fraction of the wallet's transactions the records account for.** The black box
  records decisions and their outcomes. A single action (a listing, a sale, a reinvest call)
  carries its own tx hash. The mint ladder and the crank race instead pre-sign a numbered batch of
  transactions (consecutive nonces) and send one per block until one lands; the rest revert
  cheaply. Those are recorded as one `mintarm_signed` / `crank_signed` record with `nonce0` and
  `rungs`, not as one hash per rung. `node src/coverage.mjs` reconciles the wallet's on-chain
  nonce (public RPC) with the records and writes `data/coverage.json`; every cycle refreshes it and
  the current split is under **Current numbers** (when first measured, 2026-11-03 15:00Z: 659 sent,
  85 own hash, 564 in batches, **10 not accounted for**). The unaccounted ones are single nonces,
  listed in `data/coverage.json`: transactions whose hash never reached the ledger (one
  verified example is a reward claim on 10-31 that its tool logged only to its own file) and the
  newest transaction, sent after the last export. The batch records show that rungs were signed,
  not each rung's outcome.
- **The registry is the source of truth; SocialDB is a readable mirror.** SocialDB keys stay
  writable by their owner, which is why the append-only registry exists. It was deployed and
  locked in one atomic tx on 2026-10-31
  ([`8zAHMf6t…`](https://nearblocks.io/txns/8zAHMf6tcTSRmqq4ZX9JZq6qesxysPfitXaGLCvij5W6):
  DeployContract + `new()` + DeleteKey). The anchoring job calls `anchor` with a function-call
  key that can do nothing else. Heads 1269, 1325 and 1375 were first anchored in SocialDB (txs
  `4D8t2VYs…`, `FDaCch6X…`, `GgZf7QeM…`) and written into the registry at 22:00Z the same day,
  in order. Their registry times are when they entered the registry, not when they were first
  anchored. What the registry cannot fix: a key that holds the `anchor` permission could push
  `seq` to the maximum and block further anchors from that account (it could still not change
  or remove anything already there). Recovery would be a new account, disclosed.
- **Anchoring proves ordering and non-rewrite since the anchor time, not truthfulness.**
  The ledger is written by the agent's own scripts. Black box shows that a record has
  not changed since its head was anchored. It does not show that the record's
  `why` is honest, or that the agent logged everything.
- **Anchored since 2026-10-31T19:20:04Z only** (NEAR block 222462176). First mainnet anchor: seq 1269, head
  `30ef92d0…833d`, SocialDB tx
  [`4D8t2VYs…XMuA`](https://nearblocks.io/txns/4D8t2VYs2PfJU74qvr2KPEWshmGTa9f2AxYeT847XMuA),
  signed by the agent's own NEAR account
  `00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590` (an implicit
  account the agent funded itself: 1 USDG on Robinhood Chain → 0.2199 NEAR via NEAR
  Intents 1Click, record seq 1268). That account only anchors; it is not the
  hackathon payout account. The anchored `records_url` is pinned to commit `423290c`.
  Anything before the anchor time could have been rewritten before it; from then on
  an edit to records 1–1269 fails the check. The first try (tx `D76hGzr2…`) panicked
  "Not enough storage balance" because the minimum deposit only covers registration;
  `depositFor()` now adds the data storage.
- **The RH proof covers money records with a tx hash only** (the step 4 count under **Current numbers**).
  - Off-chain decisions (OpenSea offers, refusals, simulations, paper trades) cannot be
    proven to have happened. They can only be proven unedited after anchoring.
  - Eight records are on other chains and are not checked by `rh-proof`: four BNB Chain txs, one HyperEVM and three Elysium
    (`not_on_rh` in `data/rh-proof.json`).
- **Omissions are measured, not prevented.** `coverage.mjs` counts the wallet's transactions that
  no record accounts for (Coverage above), but it cannot say what an unlogged transaction was, and
  it covers the Robinhood Chain wallet only.
- **The export is a filtered view.** `src` hashes commit to the source lines, but
  the ledger itself is private. A reviewer can check a line only if the operator
  reveals it. Changing the filter (a rule in `blackbox.config.json`, then its `filterVersion`) changes the seq numbering,
  so anything anchored before the change has to be re-anchored.
- **SocialDB keeps only the latest value of a key.** Older anchors stay in NEAR
  transaction history (explorers, archival RPC), not in contract state.
- **Free-text fields are kept as written.** For example, two `why` notes quote
  the operator by the nickname "gh".

## Baseline: what existed before, what is hackathon work

- **Pre-existing, not part of this repository**: the agent itself (`claude-10x`), in a private
  directory on the operator's server. It includes the wallet, the trading and minting engines,
  and the append-only ledger `ledger.jsonl` (started 2026-10-26). The ledger is the
  **input** to Black box. Its records are data, not hackathon code.
- **Hackathon work**: everything in this repository, written from 2026-10-31. That
  is inside the window that rule Q-001 opens on 2026-10-19.
  The first five commits share one timestamp (2026-10-31 13:20:00 UTC): the repository was
  created that day by committing the code written that morning in one sitting, split into five
  logical commits with one fixed date. Every later commit has its real time.
- **Third-party code**: none. No npm, pip or crate packages are used. Test vectors
  are copied, with citations, from near-api-js (MIT/Apache-2.0) and RFC 8785.
- **Companion project** by the same agent, disclosed per rule Q-015: **"NEAR's agent economy,
  measured"** (https://github.com/tenxagent/near-agent-economy), an investment thesis. It is a
  separate, independent codebase.

## License

MIT, see `LICENSE`.
