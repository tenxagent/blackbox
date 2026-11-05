// The DEPLOYED registry wasm, executed in Node. contract/res/blackbox_registry.wasm (its NEAR code hash is the one
// on mainnet; contract.test.mjs checks that) runs against a JavaScript model of the 14 NEAR host functions it
// imports, a port of contract/src/mock.rs, and replays the cases of contract/src/tests.rs. A judge without Rust
// exercises the exact bytes that run on chain. (`cargo test` runs the same Rust code natively; the two JSON-reader
// unit tests there call an internal function, so here the reader is exercised through every exported method.)
//
// The host model, as in mock.rs:
// - registers: register_len of an unused register is u64::MAX; reading one is a host error;
// - storage usage = base + Σ(key + value + 40) (nearcore storage_num_extra_bytes_record), updated inline;
// - view calls: predecessor_account_id, attached_deposit and storage_write are prohibited (ProhibitedInView);
// - panic_utf8 aborts the call; the harness then restores the state from before the call (NEAR discards every
//   change of a failed receipt); anything the real host would refuse throws HostViolation and fails the test;
// - storage keys ≤ 2048 bytes, logs ≤ 16384 bytes in total, logs and panics must be UTF-8;
// - every call runs on a fresh instance, as NEAR instantiates the contract per function call.
import { assert, Skip } from './lib.mjs';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const wasmPath = fileURLToPath(new URL('../contract/res/blackbox_registry.wasm', import.meta.url));
let compiled = null;
function wasm() {
  if (!existsSync(wasmPath)) throw new Skip('contract/res/blackbox_registry.wasm not built (bash contract/build.sh)');
  return (compiled ??= new WebAssembly.Module(readFileSync(wasmPath)));
}

class ContractPanic extends Error {}
class HostViolation extends Error {}
const enc = new TextEncoder();
const utf8 = (b) => new TextDecoder('utf-8', { fatal: true }).decode(b);
const U64_MAX = 0xffffffffffffffffn;
const kstr = (bytes) => Buffer.from(bytes).toString('latin1'); // storage key bytes -> Map key (1 char per byte)

// ------------------------------------------------------------------ constants (same as tests.rs)
const AGENT = 'eip155:4663:0x00731cd9e0bc7cad1b54f85187b09b942cd3be04';
const ALICE = 'alice.near', BOB = 'bob.near', REGISTRY = 'registry.near';
const IMPLICIT = '98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de';
const URL_ = 'https://example.org/blackbox/records.jsonl';
const YOCTO_PER_BYTE = 10n ** 19n, NEAR = 10n ** 24n;
const HEIGHT0 = 170_000_000n, TS0 = 1_761_930_000_000_000_000n; // TS0 > 2^53: must come back exact
const JS_MAX_SAFE = 9_007_199_254_740_991n;
const METHODS = ['new', 'register', 'storage_deposit', 'anchor', 'get_agent', 'get_anchors', 'get_agents'];

// ------------------------------------------------------------------ host model
let S;
function reset() {
  S = { storage: new Map(), registers: new Map(), input: new Uint8Array(), predecessor: new Uint8Array(),
    blockIndex: HEIGHT0, blockTimestamp: TS0, deposit: 0n, baseUsage: 100n + 20_000n, logs: [], returned: null,
    view: false, written: [] };
}
const usage = () => [...S.storage].reduce((s, [k, v]) => s + BigInt(k.length + v.length) + 40n, S.baseUsage);
const snapshot = () => ({ ...S, storage: new Map(S.storage), registers: new Map(S.registers), logs: [...S.logs], written: [...S.written] });

function hostImports(memory) {
  const bytes = (ptr, len) => (len === 0n ? new Uint8Array() : new Uint8Array(memory().buffer, Number(ptr), Number(len)).slice());
  const notInView = (name) => { if (S.view) throw new HostViolation(`ProhibitedInView { method_name: "${name}" }`); };
  const checkKey = (k) => { if (k.length > 2048) throw new HostViolation(`KeyLengthExceeded(${k.length})`); };
  const text = (ptr, len, what) => { try { return utf8(bytes(ptr, len)); } catch { throw new HostViolation(`${what}: BadUTF8`); } };
  return {
    env: {
      read_register(id, ptr) {
        const d = S.registers.get(id);
        if (!d) throw new HostViolation(`InvalidRegisterId(${id})`);
        new Uint8Array(memory().buffer).set(d, Number(ptr));
      },
      register_len: (id) => (S.registers.has(id) ? BigInt(S.registers.get(id).length) : U64_MAX),
      input(id) { S.registers.set(id, S.input); },
      predecessor_account_id(id) { notInView('predecessor_account_id'); S.registers.set(id, S.predecessor); },
      block_index: () => S.blockIndex,
      block_timestamp: () => S.blockTimestamp,
      storage_usage: () => usage(),
      attached_deposit(ptr) {
        notInView('attached_deposit');
        const b = new Uint8Array(16);
        for (let i = 0, d = S.deposit; i < 16; i++, d >>= 8n) b[i] = Number(d & 0xffn); // u128 little-endian
        new Uint8Array(memory().buffer).set(b, Number(ptr));
      },
      value_return(len, ptr) { S.returned = bytes(ptr, len); },
      panic_utf8(len, ptr) { throw new ContractPanic(text(ptr, len, 'panic_utf8')); },
      log_utf8(len, ptr) {
        const m = text(ptr, len, 'log_utf8');
        if (S.logs.reduce((n, l) => n + Buffer.byteLength(l), 0) + Buffer.byteLength(m) > 16384) throw new HostViolation('TotalLogLengthExceeded');
        S.logs.push(m);
      },
      storage_write(kl, kp, vl, vp, reg) {
        notInView('storage_write');
        const k = bytes(kp, kl), v = bytes(vp, vl);
        checkKey(k);
        const ks = kstr(k), old = S.storage.get(ks);
        S.written.push(ks);
        S.storage.set(ks, v);
        if (old) { S.registers.set(reg, old); return 1n; }
        return 0n;
      },
      storage_read(kl, kp, reg) {
        const k = bytes(kp, kl);
        checkKey(k);
        const v = S.storage.get(kstr(k));
        if (v) { S.registers.set(reg, v); return 1n; }
        return 0n;
      },
      storage_has_key(kl, kp) { const k = bytes(kp, kl); checkKey(k); return S.storage.has(kstr(k)) ? 1n : 0n; },
    },
  };
}

// One function call: a fresh instance; on a contract panic the state is restored and the message returned.
function run(method, args, who, deposit, view) {
  const before = snapshot();
  Object.assign(S, { input: enc.encode(args), predecessor: enc.encode(who), deposit: BigInt(deposit), view,
    registers: new Map(), returned: null, logs: [] });
  let inst = null;
  inst = new WebAssembly.Instance(wasm(), hostImports(() => inst.exports.memory));
  try {
    inst.exports[method]();
    return { ok: true, value: S.returned ? utf8(S.returned) : '' };
  } catch (e) {
    S = before;
    if (e instanceof ContractPanic) return { ok: false, error: e.message };
    throw e; // host violation or a trap: a bug, fail the test
  }
}
const call = (m, args, who, deposit = 0n) => run(m, args, who, deposit, false);
const view = (m, args) => run(m, args, '', 0n, true);
function ok(r) { if (!r.ok) throw new Error(`unexpected contract panic: ${r.error}`); return r.value; }
function err(r, needle) {
  if (r.ok) throw new Error(`expected a failure containing ${JSON.stringify(needle)}, got Ok(${JSON.stringify(r.value)})`);
  assert.ok(r.error.includes(needle), `error ${JSON.stringify(r.error)} does not contain ${JSON.stringify(needle)}`);
}
const setBlock = (h, ts) => { S.blockIndex = h; S.blockTimestamp = ts; };
const head = (n) => BigInt(n).toString(16).padStart(64, '0');
const regArgs = (id) => `{"agent_id":"${id}"}`;
const anchorArgs = (seq, h, url) => `{"seq":${seq},"head":"${h}","records_url":"${url}"}`;
const accountArgs = (a) => `{"account":"${a}"}`;
const registerCost = (acct, id) => BigInt((2 + acct.length + 8 + 16 + id.length + 40) + (2 + 8 + acct.length + 40)) * YOCTO_PER_BYTE;
const anchorCost = (acct, url) => BigInt((2 + acct.length + 1 + 8) + (8 + 32 + 8 + 8 + url.length) + 40) * YOCTO_PER_BYTE;
function setup() { reset(); ok(call('new', '', REGISTRY)); }
const registered = (acct, prepaid) => ok(call('register', regArgs(AGENT), acct, registerCost(acct, AGENT) + prepaid));
const anchorOk = (acct, seq) => ok(call('anchor', anchorArgs(seq, head(seq), URL_), acct));
const agentJson = (acct) => ok(view('get_agent', accountArgs(acct)));
const seqs = (json) => json.split('"seq":').slice(1).map((p) => BigInt(p.split(',')[0]));
const names = (json) => JSON.parse(json);
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
const storageCopy = () => new Map(S.storage);

// ------------------------------------------------------------------ the cases of contract/src/tests.rs
const cases = {
  new_initializes_once_and_is_required() {
    reset();
    err(call('register', regArgs(AGENT), ALICE, NEAR), 'not initialized');
    err(call('storage_deposit', '', ALICE, NEAR), 'not initialized');
    err(call('anchor', anchorArgs(1, head(1), URL_), ALICE), 'not initialized');
    assert.equal(ok(view('get_agents', '')), '[]');
    err(call('new', '', REGISTRY, 1n), 'not payable');
    err(call('new', '{"owner_id":"x.near"}', REGISTRY), 'unknown field');
    ok(call('new', ' { } ', REGISTRY));
    err(call('new', '', REGISTRY), 'already initialized');
    err(call('new', '{}', ALICE), 'already initialized');
    assert.equal(S.storage.size, 1, 'new() writes only the agent counter');
  },
  register_twice_from_the_same_account_fails() {
    setup();
    registered(ALICE, 0n);
    const before = storageCopy();
    err(call('register', regArgs(AGENT), ALICE, NEAR), 'already registered');
    err(call('register', regArgs('eip155:1:0xabc'), ALICE, NEAR), 'already registered');
    assert.deepEqual(S.storage, before);
    registered(BOB, 0n);
  },
  register_deposit_covers_its_storage_and_the_rest_is_credited() {
    setup();
    const cost = registerCost(ALICE, AGENT);
    err(call('register', regArgs(AGENT), ALICE, 0n), 'attached deposit');
    err(call('register', regArgs(AGENT), ALICE, cost - 1n), 'attached deposit');
    const u0 = usage();
    ok(call('register', regArgs(AGENT), ALICE, cost + (5n * NEAR) / 1000n));
    assert.equal((usage() - u0) * YOCTO_PER_BYTE, cost, 'the record layout is what the test expects');
    assert.equal(agentJson(ALICE), `{"agent_id":"${AGENT}","count":0,"storage_balance":"${(5n * NEAR) / 1000n}","last":null}`);
    ok(call('register', regArgs(AGENT), BOB, registerCost(BOB, AGENT)));
    assert.ok(agentJson(BOB).includes('"storage_balance":"0"'));
    reset();
    ok(call('new', '', REGISTRY));
    const r = call('register', regArgs(AGENT), ALICE, 1n);
    assert.ok(!r.ok && r.error.includes(String(cost)), `the message names the cost: ${r.error}`);
  },
  register_requires_a_caip10_agent_id() {
    setup();
    for (const bad of ['', 'eip155', 'eip155:1', 'eip155:1:', ':1:0xab', 'eip155::0xab', 'EIP155:1:0xab', 'ei:1:0xab',
      'eip155abc:1:0xab', 'eip155:1:0x ab', 'eip155:1:0xab:extra', 'eip155:1!:0xab', 'eip155:1:0x/ab',
      `eip155:1:${'a'.repeat(129)}`, `eip155:${'1'.repeat(33)}:0xab`]) {
      err(call('register', regArgs(bad), ALICE, NEAR), 'agent_id');
    }
    err(call('register', '{}', ALICE, NEAR), 'missing field');
    err(call('register', '{"agent_id":5}', ALICE, NEAR), 'invalid JSON');
    const longest = `abcdefgh:${'R'.repeat(32)}:${'a'.repeat(128)}`;
    ok(call('register', regArgs(longest), ALICE, NEAR));
    ok(call('register', regArgs('cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0'), BOB, NEAR));
    ok(call('register', regArgs('near:mainnet:a-b.c%20d'), 'carol.near', NEAR));
    assert.ok(agentJson(ALICE).includes(longest));
  },
  anchor_from_an_unregistered_account_fails() {
    setup();
    err(call('anchor', anchorArgs(1, head(1), URL_), ALICE), 'not registered');
    registered(BOB, NEAR);
    err(call('anchor', anchorArgs(1, head(1), URL_), ALICE), 'not registered');
    anchorOk(BOB, 1);
  },
  anchor_seq_must_increase_strictly_and_gaps_are_allowed() {
    setup();
    registered(ALICE, NEAR);
    anchorOk(ALICE, 5);
    for (const stale of [5, 4, 0]) err(call('anchor', anchorArgs(stale, head(99), URL_), ALICE), 'seq');
    anchorOk(ALICE, 6);
    anchorOk(ALICE, 1000);
    err(call('anchor', anchorArgs(999, head(1), URL_), ALICE), 'seq');
    assert.deepEqual(seqs(ok(view('get_anchors', accountArgs(ALICE)))), [5n, 6n, 1000n]);
    assert.ok(agentJson(ALICE).includes('"count":3'));
    registered(BOB, NEAR);
    anchorOk(BOB, 0);
    err(call('anchor', anchorArgs(0, head(0), URL_), BOB), 'seq');
    anchorOk(BOB, 1);
  },
  anchor_seq_stays_exact_in_javascript() {
    setup();
    registered(ALICE, NEAR);
    err(call('anchor', anchorArgs(JS_MAX_SAFE + 1n, head(1), URL_), ALICE), 'seq');
    err(call('anchor', anchorArgs(U64_MAX, head(1), URL_), ALICE), 'seq');
    anchorOk(ALICE, JS_MAX_SAFE);
    err(call('anchor', anchorArgs(JS_MAX_SAFE, head(2), URL_), ALICE), 'seq');
  },
  anchor_requires_64_lowercase_hex_head() {
    setup();
    registered(ALICE, NEAR);
    const ab = 'ab'.repeat(32);
    for (const bad of [ab.toUpperCase(), `Ab${'ab'.repeat(31)}`, ab.slice(0, 63), `${ab}0`, 'g'.repeat(64), `0x${ab.slice(0, 62)}`, `${ab.slice(0, 63)} `, '']) {
      err(call('anchor', anchorArgs(1, bad, URL_), ALICE), 'head');
    }
    assert.ok(agentJson(ALICE).includes('"count":0'));
    ok(call('anchor', anchorArgs(1, ab, URL_), ALICE));
    ok(call('anchor', anchorArgs(2, '0123456789abcdef'.repeat(4), URL_), ALICE));
  },
  anchor_requires_an_http_records_url_of_at_most_300_bytes() {
    setup();
    registered(ALICE, NEAR);
    const atLimit = `https://x.org/${'a'.repeat(300 - 14)}`;
    assert.equal(atLimit.length, 300);
    for (const bad of ['', 'ftp://x.org/r', 'example.org/r', 'https://', 'http://', 'HTTPS://x.org/r', 'https:/x.org/r',
      'https://x.org/a b', 'javascript:alert(1)', 'data:text/plain,hi', `${atLimit}a`]) {
      err(call('anchor', anchorArgs(1, head(1), bad), ALICE), 'records_url');
    }
    ok(call('anchor', anchorArgs(1, head(1), 'http://x.org/r'), ALICE));
    ok(call('anchor', anchorArgs(2, head(2), atLimit), ALICE));
    assert.ok(ok(view('get_anchors', accountArgs(ALICE))).includes(atLimit));
  },
  anchor_without_enough_storage_balance_fails_and_leaves_state_unchanged() {
    setup();
    registered(ALICE, 0n);
    const cost = anchorCost(ALICE, URL_);
    let before = storageCopy();
    err(call('anchor', anchorArgs(1, head(1), URL_), ALICE), 'storage balance');
    assert.deepEqual(S.storage, before, 'a failed anchor leaves no trace');
    assert.deepEqual(S.logs, [], 'no event for a failed anchor');
    ok(call('storage_deposit', '', ALICE, cost - 1n));
    before = storageCopy();
    err(call('anchor', anchorArgs(1, head(1), URL_), ALICE), 'storage balance');
    assert.deepEqual(S.storage, before);
    assert.ok(agentJson(ALICE).includes(`"count":0,"storage_balance":"${cost - 1n}"`));
    ok(call('storage_deposit', '{}', ALICE, 1n));
    anchorOk(ALICE, 1);
    assert.ok(agentJson(ALICE).includes('"count":1,"storage_balance":"0"'));
    err(call('anchor', anchorArgs(2, head(2), URL_), ALICE), 'storage balance');
  },
  anchor_debits_exactly_the_storage_it_adds() {
    setup();
    registered(IMPLICIT, NEAR);
    const url = `https://x.org/${'u'.repeat(286)}`;
    const u0 = usage();
    ok(call('anchor', anchorArgs(JS_MAX_SAFE, head(7), url), IMPLICIT));
    const added = usage() - u0, cost = anchorCost(IMPLICIT, url);
    assert.equal(added * YOCTO_PER_BYTE, cost);
    assert.equal(added, 471n, 'largest anchor entry (64-char account, 300-byte url)');
    assert.ok(agentJson(IMPLICIT).includes(`"storage_balance":"${NEAR - cost}"`));
  },
  anchor_height_and_time_come_from_the_env_not_the_caller() {
    setup();
    registered(ALICE, NEAR);
    setBlock(123_456_789n, TS0 + 7n);
    ok(call('anchor', anchorArgs(1, head(1), URL_), ALICE));
    assert.equal(ok(view('get_anchors', accountArgs(ALICE))),
      `[{"seq":1,"head":"${head(1)}","records_url":"${URL_}","block_height":123456789,"timestamp_ns":"1761930000000000007"}]`);
    const h = head(2);
    err(call('anchor', `{"seq":2,"head":"${h}","records_url":"${URL_}","block_height":1}`, ALICE), 'unknown field');
    err(call('anchor', `{"seq":2,"head":"${h}","records_url":"${URL_}","timestamp_ns":1}`, ALICE), 'unknown field');
    setBlock(123_456_790n, U64_MAX);
    anchorOk(ALICE, 2);
    assert.ok(ok(view('get_anchors', accountArgs(ALICE))).includes('"block_height":123456790,"timestamp_ns":"18446744073709551615"'));
  },
  anchor_is_not_payable() {
    setup();
    registered(ALICE, NEAR);
    err(call('anchor', anchorArgs(1, head(1), URL_), ALICE, 1n), 'not payable');
    err(call('anchor', anchorArgs(1, head(1), URL_), ALICE, NEAR), 'not payable');
    anchorOk(ALICE, 1);
  },
  anchor_never_overwrites_an_existing_slot() {
    setup();
    registered(ALICE, NEAR);
    anchorOk(ALICE, 1);
    const k = kstr([...enc.encode('x:alice.near:'), 0, 0, 0, 0, 0, 0, 0, 1]); // u64 big-endian index 1
    S.storage.set(k, enc.encode('planted'));
    err(call('anchor', anchorArgs(2, head(2), URL_), ALICE), 'slot');
    assert.equal(utf8(S.storage.get(k)), 'planted');
  },
  anchor_emits_the_nep297_event_exactly() {
    setup();
    registered(ALICE, NEAR);
    assert.deepEqual(S.logs, [], 'register emits nothing');
    const ab = 'ab'.repeat(32);
    ok(call('anchor', anchorArgs(7, ab, URL_), ALICE));
    assert.deepEqual(S.logs, [`EVENT_JSON:{"standard":"blackbox","version":"1.0.0","event":"anchor","data":[{"account":"alice.near","seq":7,"head":"${ab}"}]}`]);
    err(call('anchor', anchorArgs(7, ab, URL_), ALICE), 'seq');
    assert.equal(S.logs.length, 1);
  },
  storage_deposit_tops_up_a_registered_account_only() {
    setup();
    err(call('storage_deposit', '', ALICE, NEAR), 'not registered');
    registered(ALICE, 0n);
    err(call('storage_deposit', '', ALICE, 0n), 'deposit');
    ok(call('storage_deposit', '', ALICE, 7n));
    ok(call('storage_deposit', '{}', ALICE, 3n));
    assert.ok(agentJson(ALICE).includes('"storage_balance":"10"'));
    err(call('storage_deposit', '{"account_id":"bob.near"}', ALICE, 1n), 'unknown field');
    const u0 = usage();
    ok(call('storage_deposit', '', ALICE, NEAR));
    assert.equal(usage(), u0, 'a top-up does not grow storage');
  },
  get_anchors_paginates_with_limit_capped_at_100() {
    setup();
    registered(ALICE, NEAR);
    for (let i = 1; i <= 150; i++) anchorOk(ALICE, i * 2);
    const page = (args) => seqs(ok(view('get_anchors', args)));
    const first = range(1, 100).map((i) => BigInt(i * 2));
    assert.deepEqual(page(accountArgs(ALICE)), first, 'defaults: from 0, limit 100');
    assert.deepEqual(page('{"account":"alice.near","from_index":0,"limit":1000}'), first, 'limit capped');
    assert.deepEqual(page('{"limit":100,"from_index":100,"account":"alice.near"}'), range(101, 150).map((i) => BigInt(i * 2)));
    assert.deepEqual(page('{"account":"alice.near","from_index":149,"limit":5}'), [300n]);
    assert.deepEqual(page('{"account":"alice.near","from_index":10,"limit":2}'), [22n, 24n]);
    assert.equal(ok(view('get_anchors', '{"account":"alice.near","from_index":150}')), '[]');
    assert.equal(ok(view('get_anchors', '{"account":"alice.near","from_index":18446744073709551615,"limit":100}')), '[]');
    assert.equal(ok(view('get_anchors', '{"account":"alice.near","limit":0}')), '[]');
    assert.equal(ok(view('get_anchors', accountArgs(BOB))), '[]', 'unknown account');
    err(view('get_anchors', '{}'), 'missing field');
  },
  get_anchors_full_page_of_largest_entries_fits() {
    setup();
    registered(IMPLICIT, NEAR);
    const url = `https://x.org/${'u'.repeat(286)}`;
    setBlock(U64_MAX, U64_MAX);
    for (let i = 0n; i < 100n; i++) ok(call('anchor', anchorArgs(JS_MAX_SAFE - 100n + i, head(i), url), IMPLICIT));
    const out = ok(view('get_anchors', accountArgs(IMPLICIT)));
    assert.equal(seqs(out).length, 100);
    assert.ok(out.length > 48_000, String(out.length));
  },
  get_agents_paginates_with_limit_capped_at_100() {
    setup();
    const accts = range(0, 119).map((i) => `a${i}.near`);
    for (const a of accts) registered(a, 0n);
    assert.deepEqual(names(ok(view('get_agents', ''))), accts.slice(0, 100));
    assert.deepEqual(names(ok(view('get_agents', '{"from_index":0,"limit":500}'))), accts.slice(0, 100));
    assert.deepEqual(names(ok(view('get_agents', '{"from_index":100}'))), accts.slice(100));
    assert.deepEqual(names(ok(view('get_agents', '{"from_index":5,"limit":3}'))), accts.slice(5, 8));
    assert.equal(ok(view('get_agents', '{"from_index":120}')), '[]');
    assert.equal(ok(view('get_agents', '{"limit":0}')), '[]');
    err(view('get_agents', '{"account":"a0.near"}'), 'unknown field');
  },
  get_agent_returns_the_last_anchor_or_null() {
    setup();
    assert.equal(agentJson(ALICE), 'null');
    registered(ALICE, NEAR);
    anchorOk(ALICE, 3);
    setBlock(HEIGHT0 + 1n, TS0 + 1n);
    anchorOk(ALICE, 9);
    const balance = NEAR - 2n * anchorCost(ALICE, URL_);
    assert.equal(agentJson(ALICE),
      `{"agent_id":"${AGENT}","count":2,"storage_balance":"${balance}","last":{"seq":9,"head":"${head(9)}","records_url":"${URL_}","block_height":${HEIGHT0 + 1n},"timestamp_ns":"${TS0 + 1n}"}}`);
    for (const bad of ['', 'A.near', 'alice..near', '.alice', 'alice.', 'a', 'a'.repeat(65), 'alice near', 'alice:near']) {
      err(view('get_agent', accountArgs(bad)), 'account');
    }
    ok(view('get_agent', accountArgs('a'.repeat(64))));
    ok(view('get_agent', accountArgs('a-b_c.d-e.near')));
  },
  views_only_use_host_functions_allowed_in_view_calls() {
    // view() sets view mode: predecessor_account_id, attached_deposit and storage_write then throw HostViolation
    setup();
    registered(ALICE, NEAR);
    anchorOk(ALICE, 1);
    ok(view('get_agent', accountArgs(ALICE)));
    ok(view('get_agent', accountArgs(BOB)));
    ok(view('get_anchors', '{"account":"alice.near","from_index":0,"limit":10}'));
    ok(view('get_agents', '{"from_index":0,"limit":10}'));
    err(view('get_agents', '{'), 'invalid JSON');
    // and the harness really enforces it: a state-changing method run as a view is a host violation
    assert.throws(() => view('anchor', anchorArgs(2, head(2), URL_)), HostViolation);
  },
  malformed_args_are_a_clean_contract_panic_for_every_method() {
    setup();
    registered(ALICE, NEAR);
    for (const name of METHODS) {
      for (const bad of ['{', '[]', 'null', '{"x":1}', '{"seq":1,"seq":2}', '{"agent_id":"a\\u0041"}']) {
        const r = name.startsWith('get_') ? view(name, bad) : call(name, bad, ALICE);
        assert.ok(!r.ok, `${name}(${bad}) accepted: ${r.value}`);
        assert.ok(['invalid JSON', 'unknown field', 'not payable', 'already'].some((s) => r.error.includes(s)), `${name}(${bad}): ${r.error}`);
      }
      const huge = `{"agent_id":"${'a'.repeat(5000)}"}`;
      err(name.startsWith('get_') ? view(name, huge) : call(name, huge, ALICE), 'too large');
    }
  },
  no_method_can_remove_or_rewrite_an_anchor() {
    setup();
    registered(ALICE, NEAR);
    registered(BOB, NEAR);
    for (const s of [1, 2, 3]) anchorOk(ALICE, s);
    anchorOk(BOB, 10);
    const anchorsBefore = new Map([...S.storage].filter(([k]) => k.startsWith('x:')));
    const keysBefore = [...S.storage.keys()];
    const h = head(0xdead);
    const inputs = ['', '{}', anchorArgs(1, h, URL_), anchorArgs(3, h, URL_), anchorArgs(2, h, 'https://evil.example/r'),
      anchorArgs(10, h, URL_), anchorArgs(11, h, URL_), `{"seq":1,"head":"${h}","records_url":"${URL_}","index":0}`,
      `{"seq":1,"head":"${h}","records_url":"${URL_}","account":"alice.near"}`, regArgs(AGENT), regArgs('eip155:1:0xevil'),
      accountArgs(ALICE), '{"account":"alice.near","from_index":0,"limit":3}', '{"from_index":0,"limit":100}', '{"seq":'];
    const start = S.written.length;
    for (const name of METHODS) for (const input of inputs) for (const who of [ALICE, BOB, REGISTRY, IMPLICIT]) for (const d of [0n, 1n, NEAR]) {
      if (name.startsWith('get_')) view(name, input); else call(name, input, who, d);
    }
    for (const [k, v] of anchorsBefore) assert.deepEqual(S.storage.get(k), v, `anchor ${JSON.stringify(k)} changed or vanished`);
    for (const k of keysBefore) assert.ok(S.storage.has(k), `key ${JSON.stringify(k)} was removed`);
    const anchorWrites = S.written.slice(start).filter((k) => k.startsWith('x:'));
    assert.equal(new Set(anchorWrites).size, anchorWrites.length, 'an anchor key was written twice');
    assert.ok(anchorWrites.every((k) => !anchorsBefore.has(k)), 'an existing anchor key was rewritten');
    assert.ok(anchorWrites.length > 0, 'the valid inputs above do append');
  },
};

export const tests = Object.entries(cases).map(([name, fn]) => ({
  name: `deployed wasm in Node: ${name.replaceAll('_', ' ')}`,
  fn() { wasm(); fn(); },
}));
