# Black box

A flight recorder for an autonomous AI agent's money decisions. It turns the
agent's decision log into a SHA-256 hash chain, anchors the chain head on NEAR,
and links every money record to its real transaction on Robinhood Chain. After a
head is anchored, nobody (not the agent and not its operator) can edit, drop or
reorder an earlier record without the check failing.

The agent is **claude-10x** (X: @tenxagent, GitHub: tenxagent), a Claude agent
that is openly labelled as an AI. Since 2026-10-26 it has managed its own wallet
`0x00731cd9e0BC7CAD1b54f85187B09B942cD3be04` on Robinhood Chain (chain id 4663)
under written rules, and it logs every decision to an append-only ledger.

Hackathon tracks: `security`, `open`.

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
- The anchoring job itself holds no money key. It signs with a NEAR
  **function-call access key** that can only call `social.near` `set` and burn at
  most 0.25 NEAR of gas (`src/fckey.mjs`, added on mainnet in tx
  [`97ynt42o…z7D`](https://nearblocks.io/txns/97ynt42oAtnYiaBZzVgfMAqqvfTAkwpQGE4ZcRwYvz7D)).
  Such a key cannot transfer NEAR, attach a deposit, add keys or call any other
  contract, so a leaked anchoring key can at worst rewrite the agent's own anchor
  (which the next honest anchor and every earlier SocialDB block would expose), never
  move funds. The full-access key stays offline and is only needed to top up
  SocialDB storage or rotate keys. Check it yourself:
  `node src/fckey.mjs --list --account 00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590`.

## Try it (judge path, about 2 minutes)

You need Node.js 22 or newer and, for step 6, Python 3. There is nothing to
install: no `npm install`, no packages. Everything uses the Node standard library
and plain browser JavaScript. Run all commands from the repository root.

| # | Do | See |
|---|----|-----|
| 1 | `node test/run.mjs` | One `PASS`/`FAIL`/`SKIP` line per test (56 tests), ending in `55 passed, 0 failed, 1 skipped`. The one `SKIP` is the "operator check", which needs the private ledger (expected for judges; on the operator's machine it is `56 passed`). The 7 network tests (NEAR testnet reads, Robinhood Chain receipts) print `SKIP` instead of `FAIL` when the network is unreachable; `node test/run.mjs --offline` skips them on purpose. |
| 2 | `node src/chain.mjs verify` | `heads.txt: OK, all 1269 heads match` and `checkpoints.json: OK through seq 1269 (126 claims)`. Exit code 0. |
| 3 | `node src/chain.mjs tamper --seq 500 --out /tmp/bb.jsonl` then `node src/chain.mjs verify --records /tmp/bb.jsonl` | One character of record 500 is changed. Verify prints `FIRST MISMATCH at seq 500: head differs; record content changed` and `chain OK up to seq 496; ... something in seq 497..504 changed`. Exit code 1. |
| 4 | `node src/rh-proof.mjs --n 5 --seed 1` | 5 tx records checked on Robinhood Chain, e.g. `verified seq 727 0xf832cbd29906… sell_to_bid block 100993170 2026-10-29T15:04:11.000Z lag 5s`. `--all` checks all 63 and gives `verified: 60 · not_on_rh: 3`. |
| 5 | `node src/anchor.mjs` | Dry run on NEAR testnet. It builds and signs a SocialDB `set` transaction with a throwaway key, prints the JSON args, the deposit and the tx hash, then `DRY RUN: nothing was sent`. |
| 6 | `python3 -m http.server 8000`, then open `http://localhost:8000/web/` | The page recomputes the chain in the browser and shows `chain OK up to seq 1269 of 1269`, then the last 50 decisions in plain words, with explorer links for transactions. |
| 7 | `node src/chain.mjs tamper --seq 500 --out web/tampered.jsonl`, then open `http://localhost:8000/web/?records=tampered.jsonl` | The page turns red: `chain OK up to seq 496 (tampered.jsonl); first mismatch in seq 497..504`. You can also load any edited copy with the file picker. |
| 8 | `node src/anchor.mjs --read --network mainnet --account 00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590` | Reads the agent's anchor from `social.near` and checks it against the local records: `anchored on mainnet (social.near) by 00537bf2…6590: seq 1269 head 30ef92d0…833d …` then `local records match the anchor through seq 1269; all claims match`. |
| 9 | Open `http://localhost:8000/web/?network=mainnet&account=00537bf24e164c18f3512de1040d34c88a11f37976a3ef6d4de673dc9cef6590` | The same check in the browser: the page reads `<account>/blackbox` from SocialDB through NEAR RPC and reports whether the loaded records match the anchored head. |

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

## Files

| Path | What it does |
|------|--------------|
| `src/canon.mjs` | Canonical JSON: one byte string per value (rules below). No imports, so the browser loads it too. |
| `src/chain.mjs` | Leaves, heads, checkpoints, `build`, `verify` (first mismatch index), `verifySparse` (against checkpoints or a NEAR anchor). CLI: `build`, `verify`, `tamper`. Uses WebCrypto, so the browser loads the same file. |
| `src/export.mjs` | Ledger to decision records: decision filter, privacy filter, record wrapping, manifest. Operator-only. |
| `src/rh-proof.mjs` | Robinhood Chain receipt check for every record with a tx hash. |
| `src/near/keys.mjs` | ed25519 keys with `node:crypto`, base58 (hand-written), `ed25519:` strings, implicit account ids. |
| `src/near/borsh.mjs` | Hand-written Borsh for `Transaction` (V0), actions, `SignedTransaction`; a reader for the same subset. |
| `src/near/tx.mjs` | Sign a transaction: ed25519 over `sha256(borsh(tx))`; live nonce and block hash lookup. |
| `src/near/rpc.mjs` | NEAR JSON-RPC: `query` (`view_account`, `view_access_key`, `call_function`), `block`, `send_tx`, `broadcast_tx_commit`, `tx`. |
| `src/fckey.mjs` | Adds the function-call access key the cycle signs with (`social.near.set` only, gas cap); `--list` prints an account's keys. |
| `src/cycle.mjs` | Operator cycle: export → build → verify → RH proof → tests → commit → anchor on mainnet (pinned `records_url`); dry by default. |
| `src/anchor.mjs` | Builds the SocialDB `set` call; dry by default; `--send` needs a key file; `--read` checks an anchor. |
| `web/index.html`, `web/verify.js` | Static verifier page. No libraries, no CDNs. |
| `data/records.jsonl` | 1269 exported decision records, one canonical JSON line each. |
| `data/manifest.json` | Filter counts, the rules, and the sha256 of the source ledger prefix. |
| `data/excluded-address-hashes.json` | SHA-256 hashes of the operator's personal wallet addresses that the privacy filter excludes (addresses withheld). |
| `data/checkpoints.json`, `data/heads.txt` | Genesis, 124 checkpoints, the final head; all 1270 heads (h_0..h_1269). |
| `data/rh-proof.json` | Output of `node src/rh-proof.mjs --all`. |
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
agentId = "eip155:4663:0x00731cd9e0bc7cad1b54f85187b09b942cd3be04"   (CAIP-10, lowercase)
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

### Decision filter (`src/export.mjs`)

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

### Privacy filter (`src/export.mjs`, mandatory)

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
- Each anchor overwrites the same five keys:
  ```json
  {"<account>":{"blackbox":{"head":"<64 hex>","seq":"1269","t":"2026-10-31T16:56:50.927Z","agent":"eip155:4663:0x0073…be04","records_url":"<url>"}}}
  ```
- Reading back: `get({keys:["<account>/blackbox/**"]})` through `call_function`. This needs no wallet; the web page does it straight from the browser.
- `--send` refuses to run unless all of these are set:
  - `BLACKBOX_NEAR_KEY_FILE` points to a key file (`{"account_id","private_key"}`, kept out of git; `keys/` is ignored);
  - `--records-url` is given;
  - on mainnet, `--i-understand-mainnet` is also passed.

## Limits (stated plainly)

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
- **The RH proof covers money records with a tx hash only** (63 of 1,269 records).
  - Off-chain decisions (OpenSea offers, refusals, simulations, paper trades) cannot be
    proven to have happened. They can only be proven unedited after anchoring.
  - Three BNB Chain txs are not checked.
- **Omissions are not detected.** If the agent sends a tx and never logs it, the
  chain cannot show that. A later check could list the wallet's on-chain txs and
  flag any without a record.
- **The export is a filtered view.** `src` hashes commit to the source lines, but
  the ledger itself is private. A reviewer can check a line only if the operator
  reveals it. Changing the filter (`FILTER_VERSION`) changes the seq numbering,
  so anything anchored before the change has to be re-anchored.
- **SocialDB keeps only the latest value of a key.** Older anchors stay in NEAR
  transaction history (explorers, archival RPC), not in contract state.
- **Free-text fields are kept as written.** For example, two `why` notes quote
  the operator by the nickname "gh".

## Baseline: what existed before, what is hackathon work

- **Pre-existing, not part of this repository**: the agent itself, `/root/claude-10x`
  on the operator's server. It includes the wallet, the trading and minting engines,
  and the append-only ledger `ledger.jsonl` (started 2026-10-26). The ledger is the
  **input** to Black box. Its records are data, not hackathon code.
- **Hackathon work**: everything in this repository, written from 2026-10-31. That
  is inside the window that rule Q-001 opens on 2026-10-19.
- **Third-party code**: none. No npm, pip or crate packages are used. Test vectors
  are copied, with citations, from near-api-js (MIT/Apache-2.0) and RFC 8785.

## License

MIT, see `LICENSE`.
