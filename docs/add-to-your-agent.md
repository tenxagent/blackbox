# Add a black box to your agent in 5 minutes

Part of the [black box README](../README.md).


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
   The operator's own job runs exactly this, three times a day (since 2026-11-05 06:31Z with the registry step inside the cycle),
   inside a wrapper that also reruns it once with the full-access key if SocialDB refuses for lack of storage. If the SocialDB
   write fails, `cycle.mjs` stops before the registry step.

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
