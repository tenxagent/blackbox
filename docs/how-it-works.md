# How it works

Part of the [black box README](../README.md): the internals, each with its source file.


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
