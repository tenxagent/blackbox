//! The registry: method bodies, validation and the storage layout. See ../README.md for the JSON shapes.
//!
//! Storage layout (integers little-endian unless noted; NEAR charges key + value + 40 bytes per entry):
//!   b"n"                                  → agents: u64. Written by new(); its presence = initialized.
//!   b"a:" + account                       → agent: count u64 | storage_balance u128 | agent_id (CAIP-10)
//!   b"l:" + u64_be(i)                     → account of the i-th registered agent (for get_agents)
//!   b"x:" + account + b":" + u64_be(i)    → anchor i of account:
//!                                           seq u64 | head [u8; 32] | block_height u64 | timestamp_ns u64 | records_url
//! Agent records have a fixed size once written, so updating count / balance never changes storage usage,
//! and the storage an anchor adds is exactly its own entry. Nothing is ever removed (there is no
//! storage_remove import) and an anchor slot is only ever written once (`write_new`).

use crate::json::{parse_object, Field, Kind, Out, Val};
use crate::sys;

const MAX_INPUT: usize = 2048;
const MAX_ACCOUNT: usize = 64;
const MAX_AGENT_ID: usize = 8 + 1 + 32 + 1 + 128; // CAIP-10: namespace:reference:address
const MAX_URL: usize = 300;
const MAX_LIMIT: u64 = 100;
/// Largest seq accepted: 2^53 - 1, so every number in this contract's JSON is exact in JavaScript.
const MAX_SEQ: u64 = (1 << 53) - 1;
/// NEAR storage staking price (runtime parameter `storage_amount_per_byte`, 10^19 yocto = 10^-5 NEAR).
pub const YOCTO_PER_BYTE: u128 = 10_000_000_000_000_000_000;

const REG: u64 = 0; // scratch register for reads
const EVICTED: u64 = 1; // storage_write puts a replaced value here

const KEY_AGENTS: &[u8] = b"n";
const AGENT_FIXED: usize = 8 + 16;
const AGENT_MAX: usize = AGENT_FIXED + MAX_AGENT_ID;
const ANCHOR_FIXED: usize = 8 + 32 + 8 + 8;
const ANCHOR_MAX: usize = ANCHOR_FIXED + MAX_URL;
const KEY_MAX: usize = 2 + MAX_ACCOUNT + 1 + 8;
/// get_anchors: 100 entries of at most 489 bytes (16-digit seq, 300-byte url, 20-digit height and time).
const ANCHORS_OUT: usize = 50 * 1024;
const AGENTS_OUT: usize = 2 + 100 * (MAX_ACCOUNT + 3);

// ---------------------------------------------------------------- host helpers

pub fn fail(msg: &[u8]) -> ! {
    unsafe { sys::panic_utf8(msg.len() as u64, msg.as_ptr() as u64) }
}

fn fail_with(a: &[u8], b: &[u8]) -> ! {
    let mut m = [0u8; 160];
    let mut o = Out::new(&mut m);
    o.push(a).push(b);
    fail(o.bytes())
}

fn read_register<'a>(buf: &'a mut [u8], too_large: &[u8]) -> &'a [u8] {
    let len = unsafe { sys::register_len(REG) };
    if len > buf.len() as u64 {
        fail(too_large);
    }
    unsafe { sys::read_register(REG, buf.as_mut_ptr() as u64) };
    match buf.get(..len as usize) {
        Some(v) => v,
        None => fail(too_large),
    }
}

fn args<'a, const N: usize>(buf: &'a mut [u8; MAX_INPUT], fields: &[Field; N]) -> [Option<Val<'a>>; N] {
    unsafe { sys::input(REG) };
    let input = read_register(buf, b"invalid JSON args: input too large (max 2048 bytes)");
    match parse_object(input, fields) {
        Ok(v) => v,
        Err(e) => fail_with(b"invalid JSON args: ", e.as_bytes()),
    }
}

fn str_arg(v: Option<Val<'_>>) -> &[u8] {
    match v {
        Some(Val::Str(s)) => s,
        _ => fail(b"internal error: argument kind"),
    }
}

fn u64_arg(v: Option<Val<'_>>, default: u64) -> u64 {
    match v {
        Some(Val::U64(n)) => n,
        None => default,
        _ => fail(b"internal error: argument kind"),
    }
}

/// Not callable from a view: predecessor_account_id is ProhibitedInView.
fn predecessor(buf: &mut [u8; MAX_ACCOUNT]) -> &[u8] {
    unsafe { sys::predecessor_account_id(REG) };
    read_register(buf, b"internal error: predecessor too long")
}

/// Not callable from a view: attached_deposit is ProhibitedInView.
fn attached_deposit() -> u128 {
    let mut b = [0u8; 16];
    unsafe { sys::attached_deposit(b.as_mut_ptr() as u64) };
    u128::from_le_bytes(b)
}

fn not_payable(method: &[u8]) {
    if attached_deposit() != 0 {
        fail_with(method, b": not payable (attach no deposit)");
    }
}

fn has(key: &[u8]) -> bool {
    unsafe { sys::storage_has_key(key.len() as u64, key.as_ptr() as u64) == 1 }
}

fn read<'a>(key: &[u8], buf: &'a mut [u8]) -> Option<&'a [u8]> {
    if unsafe { sys::storage_read(key.len() as u64, key.as_ptr() as u64, REG) } == 0 {
        return None;
    }
    Some(read_register(buf, b"internal error: stored value too large"))
}

/// Writes key → value; true if it replaced an existing value.
fn write(key: &[u8], value: &[u8]) -> bool {
    unsafe {
        sys::storage_write(key.len() as u64, key.as_ptr() as u64, value.len() as u64, value.as_ptr() as u64, EVICTED)
            == 1
    }
}

/// Writes a key that must not exist yet. If it did, the call fails and the runtime reverts the write.
fn write_new(key: &[u8], value: &[u8], what: &[u8]) {
    if write(key, value) {
        fail_with(what, b": slot already taken (corrupt state)");
    }
}

fn storage_usage() -> u64 {
    unsafe { sys::storage_usage() }
}

/// yoctoNEAR for the bytes added since `before` (u64 bytes × 10^19 always fits in a u128).
fn storage_cost_since(before: u64) -> u128 {
    match storage_usage().checked_sub(before) {
        Some(bytes) => bytes as u128 * YOCTO_PER_BYTE,
        None => fail(b"internal error: storage usage went down"),
    }
}

fn ret(v: &[u8]) {
    unsafe { sys::value_return(v.len() as u64, v.as_ptr() as u64) }
}

/// `v[from..to]` (`to` = None: to the end), or the call stops: stored records have fixed layouts.
fn part(v: &[u8], from: usize, to: Option<usize>) -> &[u8] {
    let p = match to {
        Some(to) => v.get(from..to),
        None => v.get(from..),
    };
    match p {
        Some(p) => p,
        None => fail(b"internal error: corrupt state"),
    }
}

fn le_u64(b: &[u8]) -> u64 {
    match <[u8; 8]>::try_from(b) {
        Ok(a) => u64::from_le_bytes(a),
        Err(_) => fail(b"internal error: corrupt state"),
    }
}

fn le_u128(b: &[u8]) -> u128 {
    match <[u8; 16]>::try_from(b) {
        Ok(a) => u128::from_le_bytes(a),
        Err(_) => fail(b"internal error: corrupt state"),
    }
}

// ---------------------------------------------------------------- validation

fn valid_account(a: &[u8]) -> bool {
    // NEAR account id: 2..=64 of [a-z0-9], parts joined by single '.', '-' or '_' (not at either end)
    if a.len() < 2 || a.len() > MAX_ACCOUNT {
        return false;
    }
    let mut prev_sep = true;
    for &b in a {
        let sep = b == b'.' || b == b'-' || b == b'_';
        if sep && prev_sep || !sep && !(b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return false;
        }
        prev_sep = sep;
    }
    !prev_sep
}

fn valid_caip10(id: &[u8]) -> bool {
    // CAIP-2 namespace [-a-z0-9]{3,8} : reference [-_a-zA-Z0-9]{1,32} : CAIP-10 address [-.%a-zA-Z0-9]{1,128}
    let mut parts = id.split(|&b| b == b':');
    let (Some(ns), Some(rf), Some(addr), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    (3..=8).contains(&ns.len())
        && ns.iter().all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && (1..=32).contains(&rf.len())
        && rf.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && (1..=128).contains(&addr.len())
        && addr.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'%')
}

fn valid_url(u: &[u8]) -> bool {
    let rest = if let Some(r) = u.strip_prefix(b"https://") {
        r
    } else if let Some(r) = u.strip_prefix(b"http://") {
        r
    } else {
        return false;
    };
    u.len() <= MAX_URL
        && rest.first().is_some_and(|&b| b != b'/')
        && u.iter().all(|&b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn parse_head(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut h = [0u8; 32];
    let (pairs, _) = s.as_chunks::<2>(); // 32 pairs, no remainder (length checked above)
    for (dst, [hi, lo]) in h.iter_mut().zip(pairs) {
        *dst = nibble(*hi)? << 4 | nibble(*lo)?;
    }
    Some(h)
}

fn account_arg(v: Option<Val<'_>>) -> &[u8] {
    let a = str_arg(v);
    if !valid_account(a) {
        fail(b"invalid account id");
    }
    a
}

// ---------------------------------------------------------------- records

fn agent_key<'a>(buf: &'a mut [u8; KEY_MAX], account: &[u8]) -> &'a [u8] {
    let mut o = Out::new(buf);
    o.push(b"a:").push(account);
    o.done()
}

fn anchor_key<'a>(buf: &'a mut [u8; KEY_MAX], account: &[u8], index: u64) -> &'a [u8] {
    let mut o = Out::new(buf);
    o.push(b"x:").push(account).push(b":").push(&index.to_be_bytes());
    o.done()
}

fn list_key(index: u64) -> [u8; 10] {
    let [a, b, c, d, e, f, g, h] = index.to_be_bytes();
    [b'l', b':', a, b, c, d, e, f, g, h]
}

fn agents_count() -> Option<u64> {
    let mut b = [0u8; 8];
    read(KEY_AGENTS, &mut b).map(le_u64)
}

fn require_init() -> u64 {
    match agents_count() {
        Some(n) => n,
        None => fail(b"registry not initialized: call new() first"),
    }
}

struct Agent<'a> {
    count: u64,
    balance: u128,
    agent_id: &'a [u8],
}

fn load_agent<'a>(account: &[u8], buf: &'a mut [u8; AGENT_MAX]) -> Option<Agent<'a>> {
    let mut kb = [0u8; KEY_MAX];
    let v = read(agent_key(&mut kb, account), buf)?;
    if v.len() < AGENT_FIXED {
        fail(b"internal error: corrupt agent record");
    }
    Some(Agent {
        count: le_u64(part(v, 0, Some(8))),
        balance: le_u128(part(v, 8, Some(24))),
        agent_id: part(v, 24, None),
    })
}

fn save_agent(account: &[u8], count: u64, balance: u128, agent_id: &[u8], first: bool) {
    let mut kb = [0u8; KEY_MAX];
    let key = agent_key(&mut kb, account);
    let mut vb = [0u8; AGENT_MAX];
    let mut v = Out::new(&mut vb);
    v.push(&count.to_le_bytes()).push(&balance.to_le_bytes()).push(agent_id);
    if first {
        write_new(key, v.bytes(), b"register");
    } else {
        write(key, v.bytes());
    }
}

struct Anchor<'a> {
    seq: u64,
    head: &'a [u8],
    block_height: u64,
    timestamp_ns: u64,
    records_url: &'a [u8],
}

fn load_anchor<'a>(account: &[u8], index: u64, buf: &'a mut [u8; ANCHOR_MAX]) -> Anchor<'a> {
    let mut kb = [0u8; KEY_MAX];
    let Some(v) = read(anchor_key(&mut kb, account, index), buf) else {
        fail(b"internal error: missing anchor");
    };
    if v.len() < ANCHOR_FIXED {
        fail(b"internal error: corrupt anchor");
    }
    Anchor {
        seq: le_u64(part(v, 0, Some(8))),
        head: part(v, 8, Some(40)),
        block_height: le_u64(part(v, 40, Some(48))),
        timestamp_ns: le_u64(part(v, 48, Some(56))),
        records_url: part(v, 56, None),
    }
}

fn anchor_json(o: &mut Out<'_>, a: &Anchor<'_>) {
    o.push(b"{\"seq\":").u64(a.seq);
    o.push(b",\"head\":\"").hex(a.head);
    o.push(b"\",\"records_url\":").str(a.records_url);
    o.push(b",\"block_height\":").u64(a.block_height);
    o.push(b",\"timestamp_ns\":\"").u64(a.timestamp_ns).push(b"\"}");
}

// ---------------------------------------------------------------- change methods

/// `new()`: initialize once. No arguments, no deposit, no owner.
pub fn new() {
    not_payable(b"new");
    let mut ib = [0u8; MAX_INPUT];
    let [] = args(&mut ib, &[]);
    if has(KEY_AGENTS) {
        fail(b"new: already initialized");
    }
    write(KEY_AGENTS, &0u64.to_le_bytes());
}

/// `register({"agent_id": "<CAIP-10>"})`, payable: the deposit pays for the agent's records and the rest
/// becomes its prepaid storage balance. Once per account.
pub fn register() {
    let n = require_init();
    let mut ib = [0u8; MAX_INPUT];
    let [agent_id] = args(&mut ib, &[Field { name: b"agent_id", kind: Kind::Str, required: true }]);
    let agent_id = str_arg(agent_id);
    if !valid_caip10(agent_id) {
        fail(b"register: agent_id must be a CAIP-10 account id (namespace:reference:address)");
    }
    let mut pb = [0u8; MAX_ACCOUNT];
    let account = predecessor(&mut pb);
    let mut kb = [0u8; KEY_MAX];
    if has(agent_key(&mut kb, account)) {
        fail(b"register: account already registered");
    }
    let deposit = attached_deposit();
    let before = storage_usage();
    save_agent(account, 0, 0, agent_id, true);
    write_new(&list_key(n), account, b"register");
    write(KEY_AGENTS, &(n + 1).to_le_bytes()); // same size: no storage change
    let cost = storage_cost_since(before);
    let Some(balance) = deposit.checked_sub(cost) else {
        let mut m = [0u8; 160];
        let mut o = Out::new(&mut m);
        o.push(b"register: attached deposit too small; attach at least ").u128(cost).push(b" yoctoNEAR");
        fail(o.bytes());
    };
    save_agent(account, 0, balance, agent_id, false); // same size as above
}

/// `storage_deposit()`, payable: adds the deposit to the caller's storage balance. Registered accounts only.
pub fn storage_deposit() {
    require_init();
    let mut ib = [0u8; MAX_INPUT];
    let [] = args(&mut ib, &[]);
    let deposit = attached_deposit();
    if deposit == 0 {
        fail(b"storage_deposit: attach a deposit");
    }
    let mut pb = [0u8; MAX_ACCOUNT];
    let account = predecessor(&mut pb);
    let mut ab = [0u8; AGENT_MAX];
    let Some(a) = load_agent(account, &mut ab) else {
        fail(b"storage_deposit: account not registered");
    };
    let Some(balance) = a.balance.checked_add(deposit) else {
        fail(b"storage_deposit: balance overflow");
    };
    save_agent(account, a.count, balance, a.agent_id, false);
}

/// `anchor({"seq": n, "head": "<64 hex>", "records_url": "http(s)://..."})`, not payable (a function-call key
/// can call it). Appends one anchor stamped with the block height and time; pays its storage from the
/// caller's storage balance; emits a NEP-297 event.
pub fn anchor() {
    require_init();
    not_payable(b"anchor");
    let mut ib = [0u8; MAX_INPUT];
    let [seq, head, records_url] = args(
        &mut ib,
        &[
            Field { name: b"seq", kind: Kind::U64, required: true },
            Field { name: b"head", kind: Kind::Str, required: true },
            Field { name: b"records_url", kind: Kind::Str, required: true },
        ],
    );
    let (seq, head, records_url) = (u64_arg(seq, 0), str_arg(head), str_arg(records_url));
    if seq > MAX_SEQ {
        fail(b"anchor: seq must be at most 9007199254740991 (2^53 - 1)");
    }
    let Some(head) = parse_head(head) else {
        fail(b"anchor: head must be 64 lowercase hex characters");
    };
    if !valid_url(records_url) {
        fail(b"anchor: records_url must be an http:// or https:// URL of at most 300 printable ASCII bytes");
    }
    let mut pb = [0u8; MAX_ACCOUNT];
    let account = predecessor(&mut pb);
    let mut ab = [0u8; AGENT_MAX];
    let Some(agent) = load_agent(account, &mut ab) else {
        fail(b"anchor: account not registered (call register first)");
    };
    if agent.count > 0 {
        let mut eb = [0u8; ANCHOR_MAX];
        let last = load_anchor(account, agent.count - 1, &mut eb);
        if seq <= last.seq {
            let mut m = [0u8; 160];
            let mut o = Out::new(&mut m);
            o.push(b"anchor: seq must be greater than the last anchored seq ").u64(last.seq);
            fail(o.bytes());
        }
    }

    let before = storage_usage();
    let mut kb = [0u8; KEY_MAX];
    let mut eb = [0u8; ANCHOR_MAX];
    let mut e = Out::new(&mut eb);
    let height = unsafe { sys::block_index() };
    let time = unsafe { sys::block_timestamp() };
    e.push(&seq.to_le_bytes()).push(&head).push(&height.to_le_bytes()).push(&time.to_le_bytes()).push(records_url);
    write_new(anchor_key(&mut kb, account, agent.count), e.bytes(), b"anchor");
    let cost = storage_cost_since(before);
    let Some(balance) = agent.balance.checked_sub(cost) else {
        let mut m = [0u8; 160];
        let mut o = Out::new(&mut m);
        o.push(b"anchor: storage balance too low: need ").u128(cost).push(b" yoctoNEAR, have ").u128(agent.balance);
        o.push(b" (top up with storage_deposit)");
        fail(o.bytes());
    };
    save_agent(account, agent.count + 1, balance, agent.agent_id, false);

    let mut lb = [0u8; 320];
    let mut l = Out::new(&mut lb);
    l.push(b"EVENT_JSON:{\"standard\":\"blackbox\",\"version\":\"1.0.0\",\"event\":\"anchor\",\"data\":[{\"account\":");
    l.str(account).push(b",\"seq\":").u64(seq).push(b",\"head\":\"").hex(&head).push(b"\"}]}");
    let log = l.bytes();
    unsafe { sys::log_utf8(log.len() as u64, log.as_ptr() as u64) };
}

// ---------------------------------------------------------------- views (no predecessor, deposit or writes)

/// `get_agent({"account": "..."})` → `{"agent_id","count","storage_balance","last": anchor | null}` or `null`.
pub fn get_agent() {
    let mut ib = [0u8; MAX_INPUT];
    let [account] = args(&mut ib, &[Field { name: b"account", kind: Kind::Str, required: true }]);
    let account = account_arg(account);
    let mut ab = [0u8; AGENT_MAX];
    let Some(a) = load_agent(account, &mut ab) else {
        return ret(b"null");
    };
    let mut ob = [0u8; 1024];
    let mut o = Out::new(&mut ob);
    o.push(b"{\"agent_id\":").str(a.agent_id);
    o.push(b",\"count\":").u64(a.count);
    o.push(b",\"storage_balance\":\"").u128(a.balance);
    o.push(b"\",\"last\":");
    if a.count == 0 {
        o.push(b"null");
    } else {
        let mut eb = [0u8; ANCHOR_MAX];
        anchor_json(&mut o, &load_anchor(account, a.count - 1, &mut eb));
    }
    o.push(b"}");
    ret(o.bytes());
}

/// `get_anchors({"account": "...", "from_index"?: n, "limit"?: n})` → `[anchor, ...]`, oldest first,
/// at most 100 (limit is capped). Unknown account → `[]`.
pub fn get_anchors() {
    let mut ib = [0u8; MAX_INPUT];
    let [account, from, limit] = args(
        &mut ib,
        &[
            Field { name: b"account", kind: Kind::Str, required: true },
            Field { name: b"from_index", kind: Kind::U64, required: false },
            Field { name: b"limit", kind: Kind::U64, required: false },
        ],
    );
    let account = account_arg(account);
    let from = u64_arg(from, 0);
    let limit = u64_arg(limit, MAX_LIMIT).min(MAX_LIMIT);
    let mut ab = [0u8; AGENT_MAX];
    let count = load_agent(account, &mut ab).map_or(0, |a| a.count);
    let end = from.saturating_add(limit).min(count);
    let mut ob = [0u8; ANCHORS_OUT];
    let mut o = Out::new(&mut ob);
    o.push(b"[");
    let mut i = from;
    while i < end {
        if i > from {
            o.push(b",");
        }
        let mut eb = [0u8; ANCHOR_MAX];
        anchor_json(&mut o, &load_anchor(account, i, &mut eb));
        i += 1;
    }
    o.push(b"]");
    ret(o.bytes());
}

/// `get_agents({"from_index"?: n, "limit"?: n})` → `["account", ...]` in registration order, at most 100.
pub fn get_agents() {
    let mut ib = [0u8; MAX_INPUT];
    let [from, limit] = args(
        &mut ib,
        &[
            Field { name: b"from_index", kind: Kind::U64, required: false },
            Field { name: b"limit", kind: Kind::U64, required: false },
        ],
    );
    let from = u64_arg(from, 0);
    let limit = u64_arg(limit, MAX_LIMIT).min(MAX_LIMIT);
    let end = from.saturating_add(limit).min(agents_count().unwrap_or(0));
    let mut ob = [0u8; AGENTS_OUT];
    let mut o = Out::new(&mut ob);
    o.push(b"[");
    let mut i = from;
    while i < end {
        if i > from {
            o.push(b",");
        }
        let mut nb = [0u8; MAX_ACCOUNT];
        match read(&list_key(i), &mut nb) {
            Some(account) => o.str(account),
            None => fail(b"internal error: missing agent"),
        };
        i += 1;
    }
    o.push(b"]");
    ret(o.bytes());
}
