#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Builds the WebAssembly package @tavrn/crypto into pkg/dist (wasm-bindgen, target "web").
# Installs the wasm-bindgen CLI in the exact version of the wasm-bindgen crate in Cargo.lock into $CARGO_HOME/bin
# and calls it by that path: a wasm-bindgen of another version earlier on PATH (the CI runner image ships one in
# /usr/local/bin) is never used. Honors CARGO_TARGET_DIR (default: target/ in the repository).
# Usage: ./build-wasm.sh [--install-only]   (--install-only prints the path of the selected CLI)
# Tested by scripts/test-build-wasm.sh.
set -euo pipefail
cd "$(dirname "$0")"

version=$(awk '$0 == "name = \"wasm-bindgen\"" { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)
if [ -z "$version" ]; then
  echo "wasm-bindgen not found in Cargo.lock" >&2
  exit 1
fi
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# The version a wasm-bindgen binary reports ("wasm-bindgen 0.2.130 (...)"), empty if it does not run.
bindgen_version() {
  [ -x "$1" ] || return 0
  "$1" --version 2>/dev/null | cut -d' ' -f2 || true
}

# The one on PATH if it has the right version, else the one in $CARGO_HOME/bin, installed there if needed.
wasm_bindgen=$(command -v wasm-bindgen 2>/dev/null || true)
if [ -z "$wasm_bindgen" ] || [ "$(bindgen_version "$wasm_bindgen")" != "$version" ]; then
  wasm_bindgen="$cargo_home/bin/wasm-bindgen"
  if [ "$(bindgen_version "$wasm_bindgen")" != "$version" ]; then
    echo "Installing wasm-bindgen-cli $version into $cargo_home" >&2
    cargo install wasm-bindgen-cli --version "$version" --locked --root "$cargo_home"
  fi
  installed=$(bindgen_version "$wasm_bindgen")
  if [ "$installed" != "$version" ]; then
    echo "error: $wasm_bindgen reports version '${installed:-none}', Cargo.lock needs wasm-bindgen $version" >&2
    exit 1
  fi
fi
if [ "${1:-}" = "--install-only" ]; then
  echo "$wasm_bindgen"
  exit 0
fi

# Local paths must not end up in the published module (panic locations of dependencies): map the cargo home,
# the toolchain and the checkout to neutral prefixes, so the build is the same on every machine.
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="${CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS:-} \
--remap-path-prefix=$rustup_home=/rustup --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$PWD=/tavrn-crypto"

# No wasm-opt pass: measured on this module (binaryen 132), `wasm-opt -Oz` saves 11 % of the raw size but makes the
# gzip transfer 5 % larger (LLVM already optimized for size); compressing the transfer is the bigger win
# (1.87 MB raw, 0.64 MB gzip; tavrn-node#91). The module
# also contains the other ciphersuites of the OpenMLS RustCrypto provider, which dispatches at run time; leaving them
# out needs a provider of our own for 0x0001 (see the README).
cargo build --lib --target wasm32-unknown-unknown --profile wasm --locked
target_dir="${CARGO_TARGET_DIR:-target}"
rm -rf pkg/dist
"$wasm_bindgen" --target web --out-dir pkg/dist --out-name tavrn_crypto \
  "$target_dir/wasm32-unknown-unknown/wasm/tavrn_crypto.wasm"
