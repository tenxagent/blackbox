#!/usr/bin/env bash
# Reproducible build of the registry wasm → contract/res/blackbox_registry.wasm, then the artifact checks.
#
#   bash contract/build.sh            (from anywhere)
#
# Needs: rustc/cargo 1.98.1 (stable, official rustup distribution) with the wasm32v1-none target
# (`rustup target add wasm32v1-none`), and node >= 22 for the checks. No crates, no network (--offline),
# no wasm-opt. The code hash depends on the exact toolchain, so a different rustc is refused
# (ALLOW_OTHER_RUSTC=1 builds anyway, for experiments; the hash will then differ from README.md).
set -euo pipefail
cd "$(dirname "$0")"

want='rustc 1.98.1 (48a229cea 2026-09-01)'
have="$(rustc --version)"
if [ "$have" != "$want" ]; then
  echo "toolchain mismatch: have '$have', want '$want'" >&2
  [ "${ALLOW_OTHER_RUSTC:-}" = 1 ] || exit 2
fi

# Flags from the environment would change the output; the build uses only Cargo.toml's release profile.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_TARGET_WASM32V1_NONE_RUSTFLAGS

cargo build --offline --locked --release --target wasm32v1-none
mkdir -p res
cp target/wasm32v1-none/release/blackbox_registry.wasm res/blackbox_registry.wasm
node scripts/inspect-wasm.mjs res/blackbox_registry.wasm
