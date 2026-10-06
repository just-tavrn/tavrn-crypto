# tavrn-crypto: developer tasks. `just --list` shows all of them.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Every check of the CI: licenses, format, lints (native and wasm32), tests, cargo deny, WASM build, JS tests
check: license-check fmt-check clippy clippy-wasm test deny wasm typecheck test-js

# SPDX headers and the licenses of the JavaScript dependencies (Rust licenses: `just deny`)
license-check: js-install
    scripts/check-spdx.sh
    node scripts/check-js-licenses.mjs

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --all-targets --locked -- -D warnings

# Lints of the WebAssembly bindings (src/wasm.rs is only compiled for wasm32)
clippy-wasm:
    cargo clippy --lib --target wasm32-unknown-unknown --locked -- -D warnings

# Unit tests, scenario tests and the protocol's reference vectors (protocol/testvectors)
test: protocol
    cargo test --locked

# Licenses, advisories, bans and sources of the Rust dependencies (deny.toml)
deny:
    cargo deny --log-level error check

# Build the WebAssembly package @tavrn/crypto into pkg/dist (installs the matching wasm-bindgen-cli if needed)
wasm:
    ./build-wasm.sh

# Type-check the package tests against the built pkg/dist
typecheck: js-install wasm
    pnpm -r typecheck

# Vitest: loads the freshly built WebAssembly module in Node and runs the group lifecycle and the vectors
test-js: js-install wasm protocol
    pnpm -r test

# Dry runs of both publications: the crate (cargo publish) and the npm tarball (npm pack)
publish-dry-run: wasm
    cargo publish --dry-run --locked --allow-dirty
    cd pkg && npm pack --dry-run

# Check out the protocol submodule (test vectors) if it is missing
protocol:
    @[ -f protocol/testvectors/encryption.json ] || git submodule update --init protocol

[private]
js-install:
    @[ -d pkg/node_modules ] || pnpm install --frozen-lockfile
