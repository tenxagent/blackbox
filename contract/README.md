# blackbox registry (NEAR contract)

An append-only anchor registry for the blackbox flight recorder, per [docs/registry-contract.md](../docs/registry-contract.md).
Once a chain head is anchored here, nobody can change or remove it: not the agent, not its operator,
not the deployer. There is no method that deletes, edits, upgrades or administers anything. The wasm
does not even import `storage_remove` or any `promise_*` host function, so its code has no way to
delete state, deploy code, add keys or move NEAR. Once the account's only key is deleted, the code
cannot change either.

No SDK and no crates (`[dependencies]` is empty): `#![no_std]`, hand-declared NEAR host functions,
no allocator, a strict JSON reader and a small writer written for this contract.

## Build (reproducible)

| | |
|---|---|
| toolchain | `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1`, official rustup distribution |
| target | `wasm32v1-none` (`rustup target add wasm32v1-none`) |
| command | `bash contract/build.sh`, which runs `cargo build --offline --locked --release --target wasm32v1-none` with `RUSTFLAGS` unset, copies the result to `contract/res/` and runs the checks |
| profile | `opt-level="z"`, `lto=true`, `codegen-units=1`, `panic="abort"`, `strip=true`, `overflow-checks=true` (Cargo.toml) |
| post-processing | none (no wasm-opt) |

The result is committed as `contract/res/blackbox_registry.wasm`:

| | |
|---|---|
| size | 17,142 bytes |
| sha256 | `f1f5772ba9d576ee42eede74d8d89e978246ea4891930f710b04d0bf05713b6f` |
| NEAR code hash (base58 of the sha256) | `HHWM5HdMW4A513pxMmXGRt168Uh4PeDiBcCps8DG34Vk` |

Building in a different directory gives a bit-identical file. The only paths in the binary are the
relative `src/*.rs` and the toolchain's own `/rustc/48a229ce…/library/core/...`. A different rustc
version gives a different hash, so `build.sh` refuses one unless you set `ALLOW_OTHER_RUSTC=1`.

Why `wasm32v1-none`: it is Rust's WebAssembly-1.0 (MVP) target; `rustc --print cfg --target wasm32v1-none`
lists only `mutable-globals`. Since Rust 1.82, `wasm32-unknown-unknown` turns on multi-value and
reference types, and nearcore rejects multi-value. (The fallback would be `wasm32-unknown-unknown` with
`-C target-cpu=mvp`, but that leaves `core` built with the newer features. It was not needed.)

Checks:
- `cd contract && cargo test --offline` runs 25 native tests. The exported methods run against an
  in-memory mock of the NEAR host (`src/mock.rs`): storage with nearcore's 40-byte per-record accounting,
  registers, block height/time, deposits, logs, view-call prohibitions, and the revert of a failed call.
- `node contract/scripts/inspect-wasm.mjs` checks the built file. The imports must be exactly the 14 `env`
  functions below, and the exports exactly `memory` plus the 7 methods. It also decodes every function
  body and checks each opcode, block type and function type against the MVP set: no multi-value,
  sign-extension, saturating truncation, bulk memory, reference types, SIMD, threads, tail calls,
  exceptions or start function. It prints the size, sha256 and code hash. `test/contract.test.mjs`
  runs the same check in the repo suite and confirms that this README lists the same hashes.

Imports (all from module `env`, names and u64 signatures as in nearcore `runtime/near-vm-runner/src/imports.rs`):
`read_register register_len input predecessor_account_id block_index block_timestamp storage_usage
attached_deposit value_return panic_utf8 log_utf8 storage_write storage_read storage_has_key`.

## Methods

Arguments and results are JSON, as near-cli and RPC `call_function` expect. The reader is strict:
- the arguments are one flat object, with keys in any order;
- unknown, duplicate or missing keys are refused;
- strings are printable ASCII with no escape sequences;
- integers are plain non-negative JSON numbers: no quotes, sign, fraction or exponent;
- the input is at most 2048 bytes;
- empty input means `{}`.

Number conventions: `seq`, `count`, `block_height`, `from_index` and `limit` are JSON numbers, and `seq`
is capped at 2^53 − 1, so all of them are exact in JavaScript. `timestamp_ns` and `storage_balance`
(yoctoNEAR) are decimal strings, because they exceed 2^53.

| method | kind | args | deposit |
|---|---|---|---|
| `new` | change, once | none | must be 0 |
| `register` | change | `{"agent_id":"eip155:4663:0x00731cd9e0bc7cad1b54f85187b09b942cd3be04"}` | ≥ storage cost (below); the rest is credited |
| `storage_deposit` | change | none | > 0, added to the caller's storage balance |
| `anchor` | change | `{"seq":1183,"head":"<64 lowercase hex>","records_url":"https://example.org/records.jsonl"}` | must be 0, so a function-call key can call it |
| `get_agent` | view | `{"account":"agent.near"}` | |
| `get_anchors` | view | `{"account":"agent.near","from_index":0,"limit":100}` (both optional; limit capped at 100) | |
| `get_agents` | view | `{"from_index":0,"limit":100}` (both optional; limit capped at 100) | |

Rules enforced:
- `register`: once per predecessor account. `agent_id` must be CAIP-10 (`[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}`).
  The storage the new records use is measured (`storage_usage` before and after × 10^19 yocto/byte). The
  attached deposit must cover it, and the rest becomes the account's storage balance.
- `anchor`, all of which must hold:
  - the caller is registered;
  - `seq` > the caller's last anchored `seq` (gaps allowed);
  - `seq` ≤ 2^53 − 1;
  - `head` is exactly 64 lowercase hex characters;
  - `records_url` starts with `http://` or `https://`, has a host after the scheme, is ≤ 300 bytes, and
    contains only printable ASCII without space, `"` or `\`.

  The contract stores `block_index()` and `block_timestamp()` itself. The caller cannot pass a height or
  time, because unknown fields are refused. The bytes the new entry adds are debited from the caller's
  storage balance. If the balance is too low the call fails, and NEAR reverts it, so nothing changes.
  On success it logs one NEP-297 event:
  `EVENT_JSON:{"standard":"blackbox","version":"1.0.0","event":"anchor","data":[{"account":"agent.near","seq":1183,"head":"…"}]}`
- `storage_deposit`: the caller must be registered. Deposits cannot be withdrawn, since there is no
  withdraw method (that would need promises).
- `new`: anyone can call it, but only once (it takes no arguments and sets no owner). The change
  methods refuse to run until it has been called. Put it in the deploy batch.

Results:
```
get_agent   → null
            | {"agent_id":"eip155:…","count":2,"storage_balance":"9529000000000000000000","last":<anchor>|null}
get_anchors → [<anchor>, …]   oldest first; [] for an unknown account or past the end
              <anchor> = {"seq":1183,"head":"…","records_url":"https://…","block_height":170000000,"timestamp_ns":"1761930000000000000"}
get_agents  → ["agent.near", …]   in registration order
```
Errors are `panic_utf8` messages, e.g. `anchor: seq must be greater than the last anchored seq 1183`,
`anchor: storage balance too low: need 2310000000000000000000 yoctoNEAR, have 0 (top up with storage_deposit)`,
`register: attached deposit too small; attach at least 1900000000000000000000 yoctoNEAR`,
`invalid JSON args: unknown field`.

`src/registry.mjs` builds these args and parses the results strictly (`timestamp_ns` → BigInt).

## Storage layout and costs

Integers are little-endian unless marked `_be`. NEAR charges key + value + 40 bytes per entry, at 10^19 yocto (10^-5 NEAR) per byte.

| key | value |
|---|---|
| `n` | number of agents, u64. Its presence means initialized |
| `a:` + account | `count` u64, `storage_balance` u128, `agent_id`. Fixed size after `register`, so updates never change storage usage |
| `l:` + u64_be(i) | account of the i-th registered agent |
| `x:` + account + `:` + u64_be(i) | anchor i: `seq` u64, `head` [u8; 32], `block_height` u64, `timestamp_ns` u64, `records_url`. Each slot is written exactly once |

- Contract account: code 17,142 + account record 100 + `n` 49 = 17,291 bytes, so **0.17291 NEAR** is
  staked for good.
- `register`: (2+A) + (24+I) + 40 + (10+A) + 40 bytes, for an account of length A and an agent_id of
  length I. For a 64-character implicit account and the 54-character agent id that is 298 bytes,
  0.00298 NEAR. For `agent.near` it is 190 bytes, 0.0019 NEAR.
- `anchor`: (11+A) + (56+U) + 40 bytes, for a URL of length U. For a 64-character account that is
  231 bytes (0.00231 NEAR) with a 60-byte URL and at most 471 bytes (0.00471 NEAR) with a 300-byte one.
  Gas comes on top (not yet measured on chain, see Open questions).

## Deploy and lock

1. Build (`bash contract/build.sh`) and confirm that the sha256 and code hash match the values above.
2. Offline, generate a fresh ed25519 key pair (`generateKeyPair()` in `src/near/keys.mjs`). The
   implicit account id is the hex of its public key.
3. From the agent's account, send one `Transfer` of about **0.18–0.2 NEAR** to that implicit id. This
   creates the account, with the fresh key as its only full-access key. The 0.17291 NEAR stake plus the
   batch's gas must fit (0.18 leaves about 0.007 NEAR for gas, enough at normal gas prices with 10 Tgas
   for `new`). Anything above that stays in the account forever, because no key will be left to move it.
4. One transaction signed by the fresh key, with signer = receiver = the implicit account:
   `[DeployContract(res/blackbox_registry.wasm), FunctionCall("new", args "{}", gas 10 Tgas, deposit 0), DeleteKey(<that public key>)]`.
   Take the nonce from `view_access_key` + 1, as `txContext` in `src/near/tx.mjs` does: NEAR seeds a new
   key's nonce from the block height × 10^6, so it does not start at 0.
   The batch is atomic: if any action fails, nothing is deployed and the key stays, so you can fix it
   and resend. `src/near/borsh.mjs` already encodes all three actions (`deployContract`,
   `functionCall`, `deleteKey`).
5. Check:
   - `view_access_key_list` returns `keys: []`;
   - `view_account.code_hash` is `HHWM5HdMW4A513pxMmXGRt168Uh4PeDiBcCps8DG34Vk`;
   - `get_agents` returns `[]`.

   Then forget the key.
6. The agent calls `register` once from its anchoring account, using a full-access key because the
   call carries a deposit. It then adds a function-call key that can only call `anchor` on the
   registry, the same pattern as `src/fckey.mjs`.

## How the verifier reads it

Page through `get_anchors` with RPC `query` / `call_function`:
```
{"request_type":"call_function","finality":"final","account_id":"<registry>","method_name":"get_anchors",
 "args_base64":base64('{"account":"<anchoring account>","from_index":0,"limit":100}')}
```
Fetch pages of 100 until a page comes back with fewer entries. In this repo, call
`readAllAnchors((m, a) => rpc.callFunction(urls, REGISTRY, m, a), account)` from `src/registry.mjs`,
which returns `{ seq, head, … }` claims. Then check every one of them with `verifySparse(lines, claims)`.
The time to show is `timestamp_ns`, the block time, not the agent's `t`.

Once per registry, the verifier should also check that the account has no access keys and that its
code hash equals the one above. Otherwise "the registry" could be a contract somebody can still change.

## What this does NOT protect

- **Completeness.** The agent can skip anchoring or anchor selectively. The registry only makes what
  was anchored permanent.
- **Truth of a head.** The contract checks the format, not that a head matches any records. The
  verifier does that.
- **The records behind `records_url`.** That data can disappear or change. The heads let a reader
  detect a change; they cannot prevent one.
- **Who an agent is.** `agent_id` is self-declared. Nothing proves that the anchoring account controls
  that wallet, so readers must learn from elsewhere which anchoring account belongs to which agent
  (README, SocialDB, a signed statement).
- **A leaked anchoring key.** Whoever holds it cannot remove or change past anchors. It can append
  bogus ones with a higher `seq`, use up the prepaid storage balance and the key's gas allowance, and
  push `seq` to 2^53 − 1, after which that account can never anchor again. The recovery is to anchor
  from a new account and say so.
- **Deposits.** Storage deposits are permanent. There is no withdraw method, so keep top-ups small.
- **The chain itself.** `block_timestamp` is the block producer's time under NEAR consensus, not an
  independent clock. The price of 10^19 yocto/byte is hard-coded, matching the runtime's
  `storage_amount_per_byte`. If the protocol ever raised it, writes would fail for lack of state
  balance until someone sends the registry account NEAR (anyone can).
- **Bugs.** The code is permanent. A fix means a new registry account.

## Differences from docs/registry-contract.md

- No `near-sys` and no borsh. The host functions are declared by hand and the state is a fixed binary
  layout (above), because of the zero-dependency rule.
- `get_agent` also returns `storage_balance`, so the agent knows when to top up. `timestamp_ns` and
  `storage_balance` are strings, and `seq` is capped at 2^53 − 1 (exact JSON numbers in JavaScript).
- `from_index` and `limit` are optional. A larger `limit` is capped at 100, not refused.
- `agent_id` must be CAIP-10, and `records_url` must be printable ASCII with a host.
- Per anchor it is ~230–470 bytes (0.0023–0.0047 NEAR), not ~120: the key holds the account id.
- The size is 17.1 KB without wasm-opt (goal ≤ 30 KB), so the code stake is 0.171 NEAR.

## Open questions

- Gas per `anchor` and per full-page view, and nearcore's actual acceptance of the module. The import
  names and signatures and the MVP-only code were checked against nearcore source, but nothing was
  deployed. Run the testnet integration in the design doc before mainnet.
- Whether `get_agents` should return more than account ids.
