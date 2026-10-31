//! NEAR host functions, declared by hand (no near-sys / near-sdk: zero dependencies).
//!
//! Names and signatures follow nearcore `runtime/near-vm-runner/src/imports.rs` and near-sys `src/lib.rs`.
//! Every argument is a u64, pointers included. Only what this contract needs is imported, and on purpose
//! nothing that could delete or rewrite anything: no `storage_remove`, no `promise_*` (so no
//! DeployContract / AddKey / DeleteKey / Transfer from contract code), no `current_account_id`.
//!
//! On wasm32 these are the real imports from module "env". On any other target (`cargo test`) the same
//! functions come from the in-memory mock in `mock.rs`, so the tests drive the exact code that ships.

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    // Registers
    pub fn read_register(register_id: u64, ptr: u64);
    pub fn register_len(register_id: u64) -> u64;
    // Context (predecessor_account_id is prohibited in view calls; views never call it)
    pub fn input(register_id: u64);
    pub fn predecessor_account_id(register_id: u64);
    pub fn block_index() -> u64;
    pub fn block_timestamp() -> u64;
    pub fn storage_usage() -> u64;
    // Economics (attached_deposit is prohibited in view calls; views never call it)
    pub fn attached_deposit(balance_ptr: u64);
    // Misc
    pub fn value_return(value_len: u64, value_ptr: u64);
    pub fn panic_utf8(len: u64, ptr: u64) -> !;
    pub fn log_utf8(len: u64, ptr: u64);
    // Storage (storage_write is prohibited in view calls)
    pub fn storage_write(key_len: u64, key_ptr: u64, value_len: u64, value_ptr: u64, register_id: u64) -> u64;
    pub fn storage_read(key_len: u64, key_ptr: u64, register_id: u64) -> u64;
    pub fn storage_has_key(key_len: u64, key_ptr: u64) -> u64;
}

#[cfg(not(target_arch = "wasm32"))]
pub use crate::mock::{
    attached_deposit, block_index, block_timestamp, input, log_utf8, panic_utf8, predecessor_account_id, read_register,
    register_len, storage_has_key, storage_read, storage_usage, storage_write, value_return,
};
