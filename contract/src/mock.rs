//! In-memory stand-in for the NEAR host (native builds only, used by the tests).
//!
//! Same names and signatures as the real imports in `sys.rs`; pointers are real native pointers. What it
//! models, because the contract depends on it:
//! - registers: `register_len` of an unused register is u64::MAX; reading one is a host error;
//! - storage usage: base + Σ(key + value + 40) over all entries (nearcore `storage_num_extra_bytes_record`
//!   = 40), updated as soon as `storage_write` runs (nearcore updates `current_storage_usage` inline);
//! - view calls: `predecessor_account_id`, `attached_deposit` and `storage_write` are prohibited
//!   (nearcore returns ProhibitedInView); here that is a "host violation" panic, which fails the test;
//! - `panic_utf8` unwinds with a `ContractPanic` payload. Reverting the state of a failed call (NEAR
//!   discards every change of a receipt whose execution fails) is done by the test harness, which
//!   snapshots `State` before each call.
//! - limits checked: storage key ≤ 2048 bytes, total log length ≤ 16384 bytes, logs are UTF-8.

use std::cell::RefCell;
use std::collections::BTreeMap;

pub const EXTRA_BYTES_PER_RECORD: u64 = 40;

#[derive(Clone, Default, Debug)]
pub struct State {
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    pub registers: BTreeMap<u64, Vec<u8>>,
    pub input: Vec<u8>,
    pub predecessor: Vec<u8>,
    pub block_index: u64,
    pub block_timestamp: u64,
    pub attached_deposit: u128,
    /// Account record + code bytes: whatever the account uses besides its storage entries.
    pub base_usage: u64,
    pub logs: Vec<String>,
    pub returned: Option<Vec<u8>>,
    pub view: bool,
    /// Every key written by a call that succeeded, in order (the harness drops the writes of failed calls).
    pub written: Vec<Vec<u8>>,
}

impl State {
    pub fn usage(&self) -> u64 {
        self.base_usage
            + self.storage.iter().map(|(k, v)| k.len() as u64 + v.len() as u64 + EXTRA_BYTES_PER_RECORD).sum::<u64>()
    }
}

thread_local! {
    pub static STATE: RefCell<State> = RefCell::new(State::default());
}

/// What `panic_utf8` unwinds with: the contract's own error message.
#[derive(Debug)]
#[allow(dead_code)] // read by the tests
pub struct ContractPanic(pub String);

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

/// Something the real host would refuse (a view calling a prohibited function, a bad register, ...):
/// an ordinary Rust panic, which the test harness does not catch, so the test fails.
fn violation(msg: String) -> ! {
    panic!("host violation: {msg}")
}

fn not_in_view(name: &str) {
    if with(|s| s.view) {
        violation(format!("ProhibitedInView {{ method_name: {name:?} }}"));
    }
}

unsafe fn mem<'a>(ptr: u64, len: u64) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    std::slice::from_raw_parts(ptr as usize as *const u8, len as usize)
}

pub unsafe fn read_register(register_id: u64, ptr: u64) {
    let data = with(|s| s.registers.get(&register_id).cloned());
    let Some(data) = data else { violation(format!("InvalidRegisterId({register_id})")) };
    std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as usize as *mut u8, data.len());
}

pub unsafe fn register_len(register_id: u64) -> u64 {
    with(|s| s.registers.get(&register_id).map(|d| d.len() as u64).unwrap_or(u64::MAX))
}

pub unsafe fn input(register_id: u64) {
    with(|s| {
        let i = s.input.clone();
        s.registers.insert(register_id, i);
    })
}

pub unsafe fn predecessor_account_id(register_id: u64) {
    not_in_view("predecessor_account_id");
    with(|s| {
        let p = s.predecessor.clone();
        s.registers.insert(register_id, p);
    })
}

pub unsafe fn block_index() -> u64 {
    with(|s| s.block_index)
}

pub unsafe fn block_timestamp() -> u64 {
    with(|s| s.block_timestamp)
}

pub unsafe fn storage_usage() -> u64 {
    with(|s| s.usage())
}

pub unsafe fn attached_deposit(balance_ptr: u64) {
    not_in_view("attached_deposit");
    let d = with(|s| s.attached_deposit).to_le_bytes();
    std::ptr::copy_nonoverlapping(d.as_ptr(), balance_ptr as usize as *mut u8, 16);
}

pub unsafe fn value_return(value_len: u64, value_ptr: u64) {
    let v = mem(value_ptr, value_len).to_vec();
    with(|s| s.returned = Some(v));
}

pub unsafe fn panic_utf8(len: u64, ptr: u64) -> ! {
    let msg = match std::str::from_utf8(mem(ptr, len)) {
        Ok(m) => m.to_string(),
        Err(_) => violation("panic_utf8: BadUTF8".into()),
    };
    std::panic::panic_any(ContractPanic(msg))
}

pub unsafe fn log_utf8(len: u64, ptr: u64) {
    let msg = match std::str::from_utf8(mem(ptr, len)) {
        Ok(m) => m.to_string(),
        Err(_) => violation("log_utf8: BadUTF8".into()),
    };
    with(|s| {
        let total: usize = s.logs.iter().map(|l| l.len()).sum::<usize>() + msg.len();
        if total > 16384 {
            violation("TotalLogLengthExceeded".into());
        }
        s.logs.push(msg);
    })
}

fn check_key(key: &[u8]) {
    if key.len() > 2048 {
        violation(format!("KeyLengthExceeded({})", key.len()));
    }
}

pub unsafe fn storage_write(key_len: u64, key_ptr: u64, value_len: u64, value_ptr: u64, register_id: u64) -> u64 {
    not_in_view("storage_write");
    let key = mem(key_ptr, key_len).to_vec();
    let value = mem(value_ptr, value_len).to_vec();
    check_key(&key);
    with(|s| {
        s.written.push(key.clone());
        match s.storage.insert(key, value) {
            Some(old) => {
                s.registers.insert(register_id, old);
                1
            }
            None => 0,
        }
    })
}

pub unsafe fn storage_read(key_len: u64, key_ptr: u64, register_id: u64) -> u64 {
    let key = mem(key_ptr, key_len);
    check_key(key);
    with(|s| match s.storage.get(key).cloned() {
        Some(v) => {
            s.registers.insert(register_id, v);
            1
        }
        None => 0,
    })
}

pub unsafe fn storage_has_key(key_len: u64, key_ptr: u64) -> u64 {
    let key = mem(key_ptr, key_len);
    check_key(key);
    with(|s| s.storage.contains_key(key) as u64)
}
