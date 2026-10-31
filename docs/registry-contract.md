# Append-only anchor registry (design, 2026-10-31; build from 2026-11-05)

## Why

Today the agent anchors its chain head in SocialDB. Since 2026-10-31 every head is kept under
`blackbox/anchors/<seq>` and readers check all of them, but SocialDB keys stay writable by their
owner: the account that anchors could delete or overwrite its own history, and a reader who only
looks at current state would not see it (NEAR's transaction history would still show it). A
small contract closes that gap: once a head is in it, nobody can change or remove it, including
the agent, its operator and the contract's deployer.

## Contract

One registry for any number of agents. An agent is identified by the NEAR account that anchors
for it (the predecessor), plus the CAIP-10 id of the wallet whose decisions it records.

State (per agent account):
- `agent_id: String`: CAIP-10 id of the recorded wallet, set once at `register`.
- `anchors: Vector<Anchor>`, append-only: `Anchor { seq: u64, head: [u8; 32], records_url: String, block_height: u64, timestamp_ns: u64 }`.
- `storage_balance: u128`: prepaid storage (see below).

Methods:
- `register(agent_id: String)` (payable). First call by an account; attaches ≥ the storage needed for
  the entry, and the rest is credited to its storage balance. It fails if the account is already registered.
- `storage_deposit()` (payable). Tops up the caller's storage balance (full-access key only: function-call
  keys cannot attach deposits).
- `anchor(seq: u64, head: String, records_url: String)` (NOT payable, so a function-call key can call it).
  The contract stores `block_height` and `timestamp_ns` itself, so the anchor time is the chain's clock,
  not a claim. It requires:
  - the caller is registered;
  - `seq` > the last anchored seq (strictly increasing; never rewrites);
  - `head` is 64 lowercase hex characters;
  - `records_url` is ≤ 300 bytes and http(s);
  - the storage used by the new entry is ≤ the caller's storage balance, which is debited.
  It emits a NEP-297 event: `EVENT_JSON:{"standard":"blackbox","version":"1.0.0","event":"anchor","data":[{"account","seq","head"}]}`.
- Views:
  - `get_agent(account)` returns `{ agent_id, count, last: Anchor | null }`;
  - `get_anchors(account, from_index, limit)` (limit ≤ 100);
  - `get_agents(from_index, limit)`.

There are deliberately no methods that delete, edit, upgrade or administer anything.

Immutability:
- Deploy to a fresh implicit account.
- Call `new()`.
- Delete that account's only full-access key in the same batch transaction (`DeployContract` + `FunctionCall new` + `DeleteKey`).

After that the code can never change. Anyone can check it: the account has no access keys, and
its code hash matches the wasm built from this repo's source (reproducible build instructions next
to it).

## Agent side

- The anchoring cycle adds a second function-call key: receiver = registry account, method `anchor`,
  gas allowance 0.25 NEAR, the same pattern as `src/fckey.mjs`.
- `src/cycle.mjs` calls `anchor` on the registry first, then mirrors to SocialDB (cheap, human-readable).
- The verifier (CLI and web page) reads `get_anchors` and checks EVERY head with `verifySparse`. Any
  head that does not match the records fails the check, and the registry cannot drop the old ones.
- The time shown is `timestamp_ns` from the contract, not the agent's `t`.

## Size and cost (estimate; measure at build time)

- A `near-sdk` contract with `wasm-opt -Oz` is usually ~100–150 KB. That costs ~1–1.5 NEAR in storage
  staking (10^19 yocto/byte), which is a lot for this agent's bankroll.
- Target: a minimal contract with no SDK collections beyond `near-sys` host functions and hand-written
  borsh. Goal ≤ 30 KB, about 0.3 NEAR. If the SDK version comes in under ~60 KB, use it (much easier
  to audit).
- Per anchor: ~120 bytes, about 0.0012 NEAR of prepaid storage plus gas.

## Tests (written before the contract)

Unit tests (wasm-free, the contract logic as plain Rust):
1. `register` twice from the same account fails.
2. `anchor` from an unregistered account fails.
3. `anchor` with seq ≤ last fails; seq > last succeeds; the gap is allowed.
4. A bad head (not 64 hex, uppercase, wrong length) fails.
5. `anchor` without enough storage balance fails, and the balance is unchanged.
6. The stored `block_height` / `timestamp_ns` come from the env, not the caller.
7. Views paginate (limit capped at 100).
8. No method can remove or edit an anchor (an API surface test).

Integration (testnet, then mainnet):
- Deploy + `new` + delete-key batch; `view_access_key_list` shows none; the code hash matches the local build.
- Register the agent; anchor three heads; a re-anchor of an old seq is refused on chain.
- The verifier page reads the registry.

## Not in scope

There is no proof that the agent logged everything, and no proof that a `why` is honest (see README,
Limits). The registry only makes "what was anchored" permanent.
