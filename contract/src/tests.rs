//! Native tests: the exported contract functions run against the mock host (`mock.rs`).
//! `cargo test --offline`
//!
//! The harness models NEAR's all-or-nothing receipts: it snapshots the whole mock state before each call
//! and restores it when the call panics, as the runtime discards every change of a failed call.

use crate::contract::{anchor, get_agent, get_agents, get_anchors, new, register, storage_deposit};
use crate::json::{parse_object, Field, Kind, Val};
use crate::mock::{ContractPanic, State, STATE};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

const AGENT: &str = "eip155:4663:0x00731cd9e0bc7cad1b54f85187b09b942cd3be04";
const ALICE: &str = "alice.near";
const BOB: &str = "bob.near";
const REGISTRY: &str = "registry.near";
const IMPLICIT: &str = "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de";
const URL: &str = "https://example.org/blackbox/records.jsonl";
const YOCTO_PER_BYTE: u128 = 10_000_000_000_000_000_000;
const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const HEIGHT0: u64 = 170_000_000;
const TS0: u64 = 1_761_930_000_000_000_000; // > 2^53: must come back exact
const JS_MAX_SAFE: u64 = 9_007_199_254_740_991;

type Method = fn();
const METHODS: [(&str, Method); 7] = [
    ("new", new),
    ("register", register),
    ("storage_deposit", storage_deposit),
    ("anchor", anchor),
    ("get_agent", get_agent),
    ("get_anchors", get_anchors),
    ("get_agents", get_agents),
];

// ---------------------------------------------------------------- harness

fn quiet_contract_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info.payload().is::<ContractPanic>() {
                prev(info)
            }
        }));
    });
}

fn reset() {
    STATE.with(|s| {
        *s.borrow_mut() =
            State { base_usage: 100 + 20_000, block_index: HEIGHT0, block_timestamp: TS0, ..State::default() }
    });
}

fn run(method: Method, args: &str, who: &str, deposit: u128, view_call: bool) -> Result<String, String> {
    quiet_contract_panics();
    let before = STATE.with(|s| s.borrow().clone());
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.input = args.as_bytes().to_vec();
        s.predecessor = who.as_bytes().to_vec();
        s.attached_deposit = deposit;
        s.view = view_call;
        s.registers.clear();
        s.returned = None;
        s.logs.clear(); // logs (and their 16 KiB limit) belong to one call's outcome
    });
    match catch_unwind(AssertUnwindSafe(method)) {
        Ok(()) => {
            let out = STATE.with(|s| s.borrow().returned.clone());
            Ok(out.map(|v| String::from_utf8(v).expect("return value is UTF-8")).unwrap_or_default())
        }
        Err(payload) => {
            STATE.with(|s| *s.borrow_mut() = before); // the runtime reverts a failed call
            match payload.downcast_ref::<ContractPanic>() {
                Some(ContractPanic(msg)) => Err(msg.clone()),
                None => std::panic::resume_unwind(payload), // host violation or a Rust bug: fail the test
            }
        }
    }
}

fn call(method: Method, args: &str, who: &str, deposit: u128) -> Result<String, String> {
    run(method, args, who, deposit, false)
}

fn view(method: Method, args: &str) -> Result<String, String> {
    run(method, args, "", 0, true)
}

#[track_caller]
fn ok(r: Result<String, String>) -> String {
    match r {
        Ok(v) => v,
        Err(e) => panic!("unexpected contract panic: {e}"),
    }
}

#[track_caller]
fn err(r: Result<String, String>, needle: &str) {
    match r {
        Ok(v) => panic!("expected a failure containing {needle:?}, got Ok({v:?})"),
        Err(e) => assert!(e.contains(needle), "error {e:?} does not contain {needle:?}"),
    }
}

fn storage() -> BTreeMap<Vec<u8>, Vec<u8>> {
    STATE.with(|s| s.borrow().storage.clone())
}

fn logs() -> Vec<String> {
    STATE.with(|s| s.borrow().logs.clone())
}

fn usage() -> u64 {
    STATE.with(|s| s.borrow().usage())
}

fn set_block(height: u64, ts: u64) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.block_index = height;
        s.block_timestamp = ts;
    });
}

fn head(n: u64) -> String {
    format!("{n:064x}")
}

fn reg_args(id: &str) -> String {
    format!(r#"{{"agent_id":"{id}"}}"#)
}

fn anchor_args(seq: u64, head: &str, url: &str) -> String {
    format!(r#"{{"seq":{seq},"head":"{head}","records_url":"{url}"}}"#)
}

fn account_args(acct: &str) -> String {
    format!(r#"{{"account":"{acct}"}}"#)
}

/// Bytes `register` adds: the agent record ("a:"+account → count u64 | balance u128 | agent_id) and the
/// list entry ("l:"+u64_be(n) → account), each + 40 bytes of per-record overhead.
fn register_cost(acct: &str, agent_id: &str) -> u128 {
    let bytes = (2 + acct.len() + 8 + 16 + agent_id.len() + 40) + (2 + 8 + acct.len() + 40);
    bytes as u128 * YOCTO_PER_BYTE
}

/// Bytes `anchor` adds: "x:"+account+":"+u64_be(i) → seq u64 | head [32] | height u64 | ts u64 | url, + 40.
fn anchor_cost(acct: &str, url: &str) -> u128 {
    let bytes = (2 + acct.len() + 1 + 8) + (8 + 32 + 8 + 8 + url.len()) + 40;
    bytes as u128 * YOCTO_PER_BYTE
}

fn setup() {
    reset();
    ok(call(new, "", REGISTRY, 0));
}

/// Registers `acct` with exactly the storage it needs plus `prepaid` yocto of storage balance.
fn registered(acct: &str, prepaid: u128) {
    ok(call(register, &reg_args(AGENT), acct, register_cost(acct, AGENT) + prepaid));
}

fn anchor_ok(acct: &str, seq: u64) {
    ok(call(anchor, &anchor_args(seq, &head(seq), URL), acct, 0));
}

fn agent_json(acct: &str) -> String {
    ok(view(get_agent, &account_args(acct)))
}

/// The `seq` values in a get_anchors result, in order.
fn seqs(json: &str) -> Vec<u64> {
    json.split("\"seq\":").skip(1).map(|p| p.split(',').next().unwrap().parse().unwrap()).collect()
}

/// The account names in a get_agents result, in order.
fn names(json: &str) -> Vec<String> {
    let inner = json.strip_prefix('[').unwrap().strip_suffix(']').unwrap();
    if inner.is_empty() {
        return vec![];
    }
    inner.split(',').map(|s| s.trim_matches('"').to_string()).collect()
}

// ---------------------------------------------------------------- init

#[test]
fn new_initializes_once_and_is_required() {
    reset();
    err(call(register, &reg_args(AGENT), ALICE, NEAR), "not initialized");
    err(call(storage_deposit, "", ALICE, NEAR), "not initialized");
    err(call(anchor, &anchor_args(1, &head(1), URL), ALICE, 0), "not initialized");
    assert_eq!(ok(view(get_agents, "")), "[]");
    err(call(new, "", REGISTRY, 1), "not payable");
    err(call(new, r#"{"owner_id":"x.near"}"#, REGISTRY, 0), "unknown field");
    ok(call(new, " { } ", REGISTRY, 0));
    err(call(new, "", REGISTRY, 0), "already initialized");
    err(call(new, "{}", ALICE, 0), "already initialized");
    assert_eq!(storage().len(), 1, "new() writes only the agent counter");
}

// ---------------------------------------------------------------- register (doc test 1)

#[test]
fn register_twice_from_the_same_account_fails() {
    setup();
    registered(ALICE, 0);
    let before = storage();
    err(call(register, &reg_args(AGENT), ALICE, NEAR), "already registered");
    err(call(register, &reg_args("eip155:1:0xabc"), ALICE, NEAR), "already registered");
    assert_eq!(storage(), before);
    registered(BOB, 0); // a different account is fine
}

#[test]
fn register_deposit_covers_its_storage_and_the_rest_is_credited() {
    setup();
    let cost = register_cost(ALICE, AGENT);
    err(call(register, &reg_args(AGENT), ALICE, 0), "attached deposit");
    err(call(register, &reg_args(AGENT), ALICE, cost - 1), "attached deposit");
    let u0 = usage();
    ok(call(register, &reg_args(AGENT), ALICE, cost + 5 * NEAR / 1000));
    assert_eq!((usage() - u0) as u128 * YOCTO_PER_BYTE, cost, "the record layout is what the test expects");
    assert_eq!(
        agent_json(ALICE),
        format!(r#"{{"agent_id":"{AGENT}","count":0,"storage_balance":"{}","last":null}}"#, 5 * NEAR / 1000)
    );
    // exactly the cost is fine too (balance 0)
    ok(call(register, &reg_args(AGENT), BOB, register_cost(BOB, AGENT)));
    assert!(agent_json(BOB).contains(r#""storage_balance":"0""#));
    // the deposit-too-small message tells the caller how much to attach
    reset();
    ok(call(new, "", REGISTRY, 0));
    match call(register, &reg_args(AGENT), ALICE, 1) {
        Err(e) => assert!(e.contains(&cost.to_string()), "{e}"),
        Ok(_) => panic!("register with 1 yocto succeeded"),
    }
}

#[test]
fn register_requires_a_caip10_agent_id() {
    setup();
    let long_addr = format!("eip155:1:{}", "a".repeat(129));
    let long_ref = format!("eip155:{}:0xab", "1".repeat(33));
    for bad in [
        "",
        "eip155",
        "eip155:1",
        "eip155:1:",
        ":1:0xab",
        "eip155::0xab",
        "EIP155:1:0xab",
        "ei:1:0xab",
        "eip155abc:1:0xab",
        "eip155:1:0x ab",
        "eip155:1:0xab:extra",
        "eip155:1!:0xab",
        "eip155:1:0x/ab",
        &long_addr,
        &long_ref,
    ] {
        err(call(register, &reg_args(bad), ALICE, NEAR), "agent_id");
    }
    err(call(register, "{}", ALICE, NEAR), "missing field");
    err(call(register, r#"{"agent_id":5}"#, ALICE, NEAR), "invalid JSON");
    // longest valid id: namespace 8, reference 32, address 128; and the CAIP-10 punctuation (- _ . %)
    let longest = format!("abcdefgh:{}:{}", "R".repeat(32), "a".repeat(128));
    ok(call(register, &reg_args(&longest), ALICE, NEAR));
    ok(call(register, &reg_args("cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0"), BOB, NEAR));
    ok(call(register, &reg_args("near:mainnet:a-b.c%20d"), "carol.near", NEAR));
    assert!(agent_json(ALICE).contains(&longest));
}

// ---------------------------------------------------------------- anchor (doc tests 2-6)

#[test]
fn anchor_from_an_unregistered_account_fails() {
    setup();
    err(call(anchor, &anchor_args(1, &head(1), URL), ALICE, 0), "not registered");
    registered(BOB, NEAR);
    err(call(anchor, &anchor_args(1, &head(1), URL), ALICE, 0), "not registered");
    anchor_ok(BOB, 1);
}

#[test]
fn anchor_seq_must_increase_strictly_and_gaps_are_allowed() {
    setup();
    registered(ALICE, NEAR);
    anchor_ok(ALICE, 5);
    for stale in [5, 4, 0] {
        err(call(anchor, &anchor_args(stale, &head(99), URL), ALICE, 0), "seq");
    }
    anchor_ok(ALICE, 6);
    anchor_ok(ALICE, 1000); // gap
    err(call(anchor, &anchor_args(999, &head(1), URL), ALICE, 0), "seq");
    assert_eq!(seqs(&ok(view(get_anchors, &account_args(ALICE)))), vec![5, 6, 1000]);
    assert!(agent_json(ALICE).contains(r#""count":3"#));
    // each account has its own sequence; 0 is a valid first seq
    registered(BOB, NEAR);
    anchor_ok(BOB, 0);
    err(call(anchor, &anchor_args(0, &head(0), URL), BOB, 0), "seq");
    anchor_ok(BOB, 1);
}

#[test]
fn anchor_seq_stays_exact_in_javascript() {
    setup();
    registered(ALICE, NEAR);
    err(call(anchor, &anchor_args(JS_MAX_SAFE + 1, &head(1), URL), ALICE, 0), "seq");
    err(call(anchor, &anchor_args(u64::MAX, &head(1), URL), ALICE, 0), "seq");
    anchor_ok(ALICE, JS_MAX_SAFE);
    err(call(anchor, &anchor_args(JS_MAX_SAFE, &head(2), URL), ALICE, 0), "seq");
}

#[test]
fn anchor_requires_64_lowercase_hex_head() {
    setup();
    registered(ALICE, NEAR);
    let ab = "ab".repeat(32);
    for bad in [
        ab.to_uppercase(),
        format!("Ab{}", "ab".repeat(31)),
        ab[..63].to_string(),
        format!("{ab}0"),
        "g".repeat(64),
        format!("0x{}", &ab[..62]),
        format!("{} ", &ab[..63]),
        String::new(),
    ] {
        err(call(anchor, &anchor_args(1, &bad, URL), ALICE, 0), "head");
    }
    assert!(agent_json(ALICE).contains(r#""count":0"#));
    ok(call(anchor, &anchor_args(1, &ab, URL), ALICE, 0));
    ok(call(anchor, &anchor_args(2, &"0123456789abcdef".repeat(4), URL), ALICE, 0));
}

#[test]
fn anchor_requires_an_http_records_url_of_at_most_300_bytes() {
    setup();
    registered(ALICE, NEAR);
    let at_limit = format!("https://x.org/{}", "a".repeat(300 - 14));
    assert_eq!(at_limit.len(), 300);
    let over = format!("{at_limit}a");
    for bad in [
        "",
        "ftp://x.org/r",
        "example.org/r",
        "https://",
        "http://",
        "HTTPS://x.org/r",
        "https:/x.org/r",
        "https://x.org/a b",
        "javascript:alert(1)",
        "data:text/plain,hi",
        &over,
    ] {
        err(call(anchor, &anchor_args(1, &head(1), bad), ALICE, 0), "records_url");
    }
    ok(call(anchor, &anchor_args(1, &head(1), "http://x.org/r"), ALICE, 0));
    ok(call(anchor, &anchor_args(2, &head(2), &at_limit), ALICE, 0));
    assert!(ok(view(get_anchors, &account_args(ALICE))).contains(&at_limit));
}

#[test]
fn anchor_without_enough_storage_balance_fails_and_leaves_state_unchanged() {
    setup();
    registered(ALICE, 0); // storage balance 0
    let cost = anchor_cost(ALICE, URL);
    let before = storage();
    err(call(anchor, &anchor_args(1, &head(1), URL), ALICE, 0), "storage balance");
    assert_eq!(storage(), before, "a failed anchor leaves no trace");
    assert!(logs().is_empty(), "no event for a failed anchor");

    ok(call(storage_deposit, "", ALICE, cost - 1));
    let before = storage();
    err(call(anchor, &anchor_args(1, &head(1), URL), ALICE, 0), "storage balance");
    assert_eq!(storage(), before);
    assert!(agent_json(ALICE).contains(&format!(r#""count":0,"storage_balance":"{}""#, cost - 1)));

    ok(call(storage_deposit, "{}", ALICE, 1));
    anchor_ok(ALICE, 1);
    assert!(agent_json(ALICE).contains(r#""count":1,"storage_balance":"0""#));
    err(call(anchor, &anchor_args(2, &head(2), URL), ALICE, 0), "storage balance");
}

#[test]
fn anchor_debits_exactly_the_storage_it_adds() {
    setup();
    registered(IMPLICIT, NEAR);
    let url = format!("https://x.org/{}", "u".repeat(286)); // 300 bytes: the largest entry
    let u0 = usage();
    ok(call(anchor, &anchor_args(JS_MAX_SAFE, &head(7), &url), IMPLICIT, 0));
    let added = usage() - u0;
    let cost = anchor_cost(IMPLICIT, &url);
    assert_eq!(added as u128 * YOCTO_PER_BYTE, cost);
    assert_eq!(added, 471, "largest anchor entry (64-char account, 300-byte url)");
    assert!(agent_json(IMPLICIT).contains(&format!(r#""storage_balance":"{}""#, NEAR - cost)));
}

#[test]
fn anchor_height_and_time_come_from_the_env_not_the_caller() {
    setup();
    registered(ALICE, NEAR);
    set_block(123_456_789, TS0 + 7);
    ok(call(anchor, &anchor_args(1, &head(1), URL), ALICE, 0));
    assert_eq!(
        ok(view(get_anchors, &account_args(ALICE))),
        format!(
            r#"[{{"seq":1,"head":"{}","records_url":"{URL}","block_height":123456789,"timestamp_ns":"1761930000000000007"}}]"#,
            head(1)
        )
    );
    // the caller cannot supply its own height or time
    let h = head(2);
    err(
        call(anchor, &format!(r#"{{"seq":2,"head":"{h}","records_url":"{URL}","block_height":1}}"#), ALICE, 0),
        "unknown field",
    );
    err(
        call(anchor, &format!(r#"{{"seq":2,"head":"{h}","records_url":"{URL}","timestamp_ns":1}}"#), ALICE, 0),
        "unknown field",
    );
    set_block(123_456_790, u64::MAX);
    anchor_ok(ALICE, 2);
    assert!(ok(view(get_anchors, &account_args(ALICE)))
        .contains(r#""block_height":123456790,"timestamp_ns":"18446744073709551615""#));
}

#[test]
fn anchor_is_not_payable() {
    setup();
    registered(ALICE, NEAR);
    err(call(anchor, &anchor_args(1, &head(1), URL), ALICE, 1), "not payable");
    err(call(anchor, &anchor_args(1, &head(1), URL), ALICE, NEAR), "not payable");
    anchor_ok(ALICE, 1);
}

#[test]
fn anchor_never_overwrites_an_existing_slot() {
    // Defence in depth: if the slot for the next index were somehow taken, anchor refuses instead of overwriting.
    setup();
    registered(ALICE, NEAR);
    anchor_ok(ALICE, 1);
    let mut key = b"x:alice.near:".to_vec();
    key.extend_from_slice(&1u64.to_be_bytes());
    STATE.with(|s| s.borrow_mut().storage.insert(key.clone(), b"planted".to_vec()));
    err(call(anchor, &anchor_args(2, &head(2), URL), ALICE, 0), "slot");
    assert_eq!(storage().get(&key).unwrap(), b"planted");
}

#[test]
fn anchor_emits_the_nep297_event_exactly() {
    setup();
    registered(ALICE, NEAR);
    assert!(logs().is_empty(), "register emits nothing");
    let ab = "ab".repeat(32);
    ok(call(anchor, &anchor_args(7, &ab, URL), ALICE, 0));
    assert_eq!(
        logs(),
        vec![format!(
            r#"EVENT_JSON:{{"standard":"blackbox","version":"1.0.0","event":"anchor","data":[{{"account":"alice.near","seq":7,"head":"{ab}"}}]}}"#
        )]
    );
    err(call(anchor, &anchor_args(7, &ab, URL), ALICE, 0), "seq");
    assert_eq!(logs().len(), 1);
}

// ---------------------------------------------------------------- storage_deposit

#[test]
fn storage_deposit_tops_up_a_registered_account_only() {
    setup();
    err(call(storage_deposit, "", ALICE, NEAR), "not registered");
    registered(ALICE, 0);
    err(call(storage_deposit, "", ALICE, 0), "deposit");
    ok(call(storage_deposit, "", ALICE, 7));
    ok(call(storage_deposit, "{}", ALICE, 3));
    assert!(agent_json(ALICE).contains(r#""storage_balance":"10""#));
    err(call(storage_deposit, r#"{"account_id":"bob.near"}"#, ALICE, 1), "unknown field");
    let u0 = usage();
    ok(call(storage_deposit, "", ALICE, NEAR));
    assert_eq!(usage(), u0, "a top-up does not grow storage");
}

// ---------------------------------------------------------------- views (doc test 7)

#[test]
fn get_anchors_paginates_with_limit_capped_at_100() {
    setup();
    registered(ALICE, NEAR);
    for i in 1..=150 {
        anchor_ok(ALICE, i * 2);
    }
    let page = |args: &str| seqs(&ok(view(get_anchors, args)));
    let first: Vec<u64> = (1..=100).map(|i| i * 2).collect();
    assert_eq!(page(&account_args(ALICE)), first, "defaults: from 0, limit 100");
    assert_eq!(page(r#"{"account":"alice.near","from_index":0,"limit":1000}"#), first, "limit capped");
    assert_eq!(
        page(r#"{"limit":100,"from_index":100,"account":"alice.near"}"#),
        (101..=150).map(|i| i * 2).collect::<Vec<_>>()
    );
    assert_eq!(page(r#"{"account":"alice.near","from_index":149,"limit":5}"#), vec![300]);
    assert_eq!(page(r#"{"account":"alice.near","from_index":10,"limit":2}"#), vec![22, 24]);
    assert_eq!(ok(view(get_anchors, r#"{"account":"alice.near","from_index":150}"#)), "[]");
    assert_eq!(
        ok(view(get_anchors, r#"{"account":"alice.near","from_index":18446744073709551615,"limit":100}"#)),
        "[]"
    );
    assert_eq!(ok(view(get_anchors, r#"{"account":"alice.near","limit":0}"#)), "[]");
    assert_eq!(ok(view(get_anchors, &account_args(BOB))), "[]", "unknown account");
    err(view(get_anchors, "{}"), "missing field");
}

#[test]
fn get_anchors_full_page_of_largest_entries_fits() {
    setup();
    registered(IMPLICIT, NEAR);
    let url = format!("https://x.org/{}", "u".repeat(286));
    set_block(u64::MAX, u64::MAX);
    for i in 0..100 {
        ok(call(anchor, &anchor_args(JS_MAX_SAFE - 100 + i, &head(i), &url), IMPLICIT, 0));
    }
    let out = ok(view(get_anchors, &account_args(IMPLICIT)));
    assert_eq!(seqs(&out).len(), 100);
    assert!(out.len() > 48_000, "{}", out.len());
}

#[test]
fn get_agents_paginates_with_limit_capped_at_100() {
    setup();
    let accts: Vec<String> = (0..120).map(|i| format!("a{i}.near")).collect();
    for a in &accts {
        registered(a, 0);
    }
    assert_eq!(names(&ok(view(get_agents, ""))), accts[..100].to_vec());
    assert_eq!(names(&ok(view(get_agents, r#"{"from_index":0,"limit":500}"#))), accts[..100].to_vec());
    assert_eq!(names(&ok(view(get_agents, r#"{"from_index":100}"#))), accts[100..].to_vec());
    assert_eq!(names(&ok(view(get_agents, r#"{"from_index":5,"limit":3}"#))), accts[5..8].to_vec());
    assert_eq!(ok(view(get_agents, r#"{"from_index":120}"#)), "[]");
    assert_eq!(ok(view(get_agents, r#"{"limit":0}"#)), "[]");
    err(view(get_agents, r#"{"account":"a0.near"}"#), "unknown field");
}

#[test]
fn get_agent_returns_the_last_anchor_or_null() {
    setup();
    assert_eq!(agent_json(ALICE), "null");
    registered(ALICE, NEAR);
    anchor_ok(ALICE, 3);
    set_block(HEIGHT0 + 1, TS0 + 1);
    anchor_ok(ALICE, 9);
    let balance = NEAR - 2 * anchor_cost(ALICE, URL);
    assert_eq!(
        agent_json(ALICE),
        format!(
            r#"{{"agent_id":"{AGENT}","count":2,"storage_balance":"{balance}","last":{{"seq":9,"head":"{}","records_url":"{URL}","block_height":{},"timestamp_ns":"{}"}}}}"#,
            head(9),
            HEIGHT0 + 1,
            TS0 + 1
        )
    );
    for bad in ["", "A.near", "alice..near", ".alice", "alice.", "a", &"a".repeat(65), "alice near", "alice:near"] {
        err(view(get_agent, &account_args(bad)), "account");
    }
    ok(view(get_agent, &account_args(&"a".repeat(64))));
    ok(view(get_agent, &account_args("a-b_c.d-e.near")));
}

#[test]
fn views_only_use_host_functions_allowed_in_view_calls() {
    // `view` sets the mock's view mode: predecessor_account_id, attached_deposit and storage_write then
    // raise a host violation (nearcore: ProhibitedInView), which would fail this test.
    setup();
    registered(ALICE, NEAR);
    anchor_ok(ALICE, 1);
    ok(view(get_agent, &account_args(ALICE)));
    ok(view(get_agent, &account_args(BOB)));
    ok(view(get_anchors, r#"{"account":"alice.near","from_index":0,"limit":10}"#));
    ok(view(get_agents, r#"{"from_index":0,"limit":10}"#));
    err(view(get_agents, "{"), "invalid JSON");
}

// ---------------------------------------------------------------- JSON reader

const F: [Field; 2] =
    [Field { name: b"s", kind: Kind::Str, required: true }, Field { name: b"n", kind: Kind::U64, required: false }];

#[test]
fn json_reader_rejects_malformed_input() {
    for bad in [
        "",
        " ",
        "{",
        "}",
        "[]",
        "[{\"s\":\"x\"}]",
        "null",
        "\"s\"",
        "{\"s\":\"x\"",
        "{\"s\":\"x\",}",
        "{,\"s\":\"x\"}",
        "{\"s\":\"x\" \"n\":1}",
        "{\"s\" \"x\"}",
        "{s:\"x\"}",
        "{'s':'x'}",
        "{\"s\":'x'}",
        "{\"s\":\"x\",\"s\":\"y\"}",
        "{\"s\":\"x\",\"z\":1}",
        "{\"S\":\"x\"}",
        "{\"s \":\"x\"}",
        "{\"s\":\"a\\\"b\"}",
        "{\"s\":\"a\\u0041\"}",
        "{\"s\":\"\u{e9}\"}",
        "{\"s\":\"a\tb\"}",
        "{\"s\":\"a\nb\"}",
        "{\"s\":\"a\u{7f}\"}",
        "{\"s\":null}",
        "{\"s\":1}",
        "{\"s\":true}",
        "{\"s\":[\"x\"]}",
        "{\"s\":{\"t\":\"x\"}}",
        "{\"s\":\"x\",\"n\":\"1\"}",
        "{\"s\":\"x\",\"n\":-1}",
        "{\"s\":\"x\",\"n\":+1}",
        "{\"s\":\"x\",\"n\":01}",
        "{\"s\":\"x\",\"n\":00}",
        "{\"s\":\"x\",\"n\":1.0}",
        "{\"s\":\"x\",\"n\":1e3}",
        "{\"s\":\"x\",\"n\":1E3}",
        "{\"s\":\"x\",\"n\":0x10}",
        "{\"s\":\"x\",\"n\":18446744073709551616}",
        "{\"s\":\"x\",\"n\":99999999999999999999}",
        "{\"s\":\"x\",\"n\":null}",
        "{\"s\":\"x\",\"n\":}",
        "{\"s\":\"x\"}x",
        "{\"s\":\"x\"}{}",
        "{\"s\":\"x\"},",
        "{\"n\":1}",
        "\u{feff}{\"s\":\"x\"}",
        "{\"s\":\"x\"}\u{0}",
        "\u{a0}{\"s\":\"x\"}",
        "{\"s\":\"x\"\u{b}}",
    ] {
        assert!(parse_object(bad.as_bytes(), &F).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn json_reader_accepts_whitespace_and_any_key_order() {
    let v = parse_object(b" {\n \"n\" : 18446744073709551615 ,\t\"s\":\"x y\" }\r\n", &F).unwrap();
    assert!(matches!(v[0], Some(Val::Str(b"x y"))));
    assert!(matches!(v[1], Some(Val::U64(u64::MAX))));
    let v = parse_object(b"{\"s\":\"\"}", &F).unwrap();
    assert!(matches!(v[0], Some(Val::Str(b""))));
    assert!(v[1].is_none());
    let v = parse_object(b"{\"n\":0,\"s\":\"x\"}", &F).unwrap();
    assert!(matches!(v[1], Some(Val::U64(0))));
    // no required fields: empty input and {} both mean "no args"
    const OPT: [Field; 1] = [Field { name: b"n", kind: Kind::U64, required: false }];
    assert!(parse_object(b"", &OPT).unwrap()[0].is_none());
    assert!(parse_object(b"{}", &OPT).unwrap()[0].is_none());
    assert!(parse_object(b" \t\r\n", &OPT).unwrap()[0].is_none());
    assert!(parse_object(b"{ }", &[]).is_ok());
    assert!(parse_object(b"{\"n\":1}", &[]).is_err());
}

#[test]
fn malformed_args_are_a_clean_contract_panic_for_every_method() {
    setup();
    registered(ALICE, NEAR);
    for (name, m) in METHODS {
        for bad in ["{", "[]", "null", "{\"x\":1}", "{\"seq\":1,\"seq\":2}", "{\"agent_id\":\"a\\u0041\"}"] {
            let r = if name.starts_with("get_") { view(m, bad) } else { call(m, bad, ALICE, 0) };
            match r {
                Err(e) => assert!(
                    e.contains("invalid JSON")
                        || e.contains("unknown field")
                        || e.contains("not payable")
                        || e.contains("already"),
                    "{name}({bad}): {e}"
                ),
                Ok(v) => panic!("{name}({bad}) accepted: {v}"),
            }
        }
        let huge = format!("{{\"agent_id\":\"{}\"}}", "a".repeat(5000));
        err(if name.starts_with("get_") { view(m, &huge) } else { call(m, &huge, ALICE, 0) }, "too large");
    }
}

// ---------------------------------------------------------------- API surface (doc test 8)

#[test]
fn no_method_can_remove_or_rewrite_an_anchor() {
    // The host interface (sys.rs) has no storage_remove and no promise functions, so nothing can be deleted
    // and no code can be deployed (the wasm import check in scripts/inspect-wasm.mjs enforces it on the
    // artifact). Here: every method, from every caller, with every deposit and a spread of valid, replayed,
    // hostile and malformed inputs, never changes or removes a stored anchor and never writes an anchor key twice.
    setup();
    registered(ALICE, NEAR);
    registered(BOB, NEAR);
    for s in [1, 2, 3] {
        anchor_ok(ALICE, s);
    }
    anchor_ok(BOB, 10);
    let anchors_before: BTreeMap<Vec<u8>, Vec<u8>> =
        storage().into_iter().filter(|(k, _)| k.starts_with(b"x:")).collect();
    let keys_before: Vec<Vec<u8>> = storage().into_keys().collect();
    let h = head(0xdead);
    let inputs = [
        String::new(),
        "{}".into(),
        anchor_args(1, &h, URL),
        anchor_args(3, &h, URL),
        anchor_args(2, &h, "https://evil.example/r"),
        anchor_args(10, &h, URL),
        anchor_args(11, &h, URL),
        format!(r#"{{"seq":1,"head":"{h}","records_url":"{URL}","index":0}}"#),
        format!(r#"{{"seq":1,"head":"{h}","records_url":"{URL}","account":"alice.near"}}"#),
        reg_args(AGENT),
        reg_args("eip155:1:0xevil"),
        account_args(ALICE),
        r#"{"account":"alice.near","from_index":0,"limit":3}"#.into(),
        r#"{"from_index":0,"limit":100}"#.into(),
        "{\"seq\":".into(),
    ];
    let start = STATE.with(|s| s.borrow().written.len());
    for (name, m) in METHODS {
        for input in &inputs {
            for who in [ALICE, BOB, REGISTRY, IMPLICIT] {
                for deposit in [0, 1, NEAR] {
                    let _ = if name.starts_with("get_") { view(m, input) } else { call(m, input, who, deposit) };
                }
            }
        }
    }
    let now = storage();
    for (k, v) in &anchors_before {
        assert_eq!(now.get(k), Some(v), "anchor {k:?} changed or vanished");
    }
    for k in &keys_before {
        assert!(now.contains_key(k), "key {k:?} was removed");
    }
    let written: Vec<Vec<u8>> = STATE.with(|s| s.borrow().written[start..].to_vec());
    let anchor_writes: Vec<&Vec<u8>> = written.iter().filter(|k| k.starts_with(b"x:")).collect();
    let mut uniq = anchor_writes.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), anchor_writes.len(), "an anchor key was written twice");
    assert!(anchor_writes.iter().all(|k| !anchors_before.contains_key(*k)), "an existing anchor key was rewritten");
    assert!(!anchor_writes.is_empty(), "the valid inputs above do append (seq 11 for bob, carol registers...)");
}
