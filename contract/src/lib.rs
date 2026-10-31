//! blackbox registry: an append-only anchor registry for NEAR.
//!
//! Any number of agents. Each anchoring account registers once (with the CAIP-10 id of the wallet whose
//! decisions it records), then appends chain heads with strictly increasing `seq`. The contract stamps
//! every anchor with the block height and timestamp itself. Nothing can be edited or removed: there is no
//! such method, the wasm does not even import `storage_remove` or any `promise_*` host function, and once
//! the account's last access key is deleted the code can never change either.
//!
//! No SDK and no dependencies: `#![no_std]` on wasm, host functions declared in `sys.rs`, a strict
//! flat-object JSON reader and a small writer in `json.rs`, no allocator. Native builds (`cargo test`)
//! swap the host for the in-memory mock in `mock.rs`.

#![cfg_attr(target_arch = "wasm32", no_std)]

mod sys;

#[cfg(not(target_arch = "wasm32"))]
mod mock;

pub mod contract;
pub mod json;

#[cfg(test)]
mod tests;

/// The complete public API: these seven functions are the only exports besides `memory`
/// (scripts/inspect-wasm.mjs checks that on the built artifact).
#[cfg(target_arch = "wasm32")]
mod exports {
    use crate::contract;

    #[no_mangle]
    pub extern "C" fn new() {
        contract::new()
    }
    #[no_mangle]
    pub extern "C" fn register() {
        contract::register()
    }
    #[no_mangle]
    pub extern "C" fn storage_deposit() {
        contract::storage_deposit()
    }
    #[no_mangle]
    pub extern "C" fn anchor() {
        contract::anchor()
    }
    #[no_mangle]
    pub extern "C" fn get_agent() {
        contract::get_agent()
    }
    #[no_mangle]
    pub extern "C" fn get_anchors() {
        contract::get_anchors()
    }
    #[no_mangle]
    pub extern "C" fn get_agents() {
        contract::get_agents()
    }
}

/// Only reachable through a bug (the contract fails with its own messages via panic_utf8). The message
/// is fixed so no formatting code is linked in.
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    contract::fail(b"internal error")
}
