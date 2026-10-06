# tavrn-crypto

The end-to-end encryption core of [tavrn](https://github.com/just-tavrn), a federated, self-hostable chat
with end-to-end encrypted conversations. One Rust crate implements the encryption part of the protocol
([`ENCRYPTION.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/ENCRYPTION.md) and the identity
sections of [`FEDERATION.md`](https://github.com/just-tavrn/tavrn-protocol/blob/main/FEDERATION.md)) and is
used everywhere the same way: natively from Rust and, compiled to WebAssembly, as the npm package
`@tavrn/crypto` in browsers and Node.js.

## What it does

- **MLS client** on top of [OpenMLS](https://github.com/openmls/openmls) 0.9 (RFC 9420, RustCrypto
  provider): key packages, group creation, external joins and welcomes, two-phase commits (merged only after
  the node accepted them), handshake processing in epoch order, rosters. The whole client state of one
  device exports to a single byte string.
- **Delivery-service checks** (`ds`) for the node: validates commits and GroupInfos against the public group
  state without any secrets, so a node can enforce its membership rules.
- **Key derivation**: the account master secret (key file, BIP-39 words), the identity signing key, the
  backup key, per-device local storage keys and device attestations (HKDF-SHA256, Ed25519).
- **Secret storage**: the master secret wrapped for the home node under a recovery key or a passkey's
  WebAuthn PRF output; the node stores it but can never unwrap it.
- **Identity continuity**: identity key rotation with a wrapped identity key and signed continuity
  statements, safety numbers and the QR verification payload, device signatures on plaintext messages
  (RFC 8785 / JCS).
- **Encrypted formats**: message content (per-epoch key plus device signature), attachments, history
  backups, whiteboard scenes.
- **Sealed boxes** for write-only webhooks into encrypted channels: libsodium-compatible `crypto_box_seal`
  to a per-epoch inbox key that every member can derive.
- **Voice frame keys**: the per-epoch key for encrypting voice and video frames.

Every fallible function returns `CryptoError`; its messages and `code()` never contain secrets. Inputs are
validated, malformed data yields errors, not panics.

## Who uses it

| Consumer | How |
|---|---|
| [`tavrn-js`](https://github.com/just-tavrn/tavrn-js): `@tavrn/e2ee` | the npm package `@tavrn/crypto`: MLS session manager, content codecs and account flows shared by the web client and bots |
| [`tavrn-node`](https://github.com/just-tavrn/tavrn-node) | the Rust crate: delivery-service validation (`ds`), device login proofs, identity continuity chains, plaintext signatures and webhook inbox keys |
| [`tavrn-web`](https://github.com/just-tavrn/tavrn-web) | through `@tavrn/e2ee` (and later the desktop and mobile shells) |
| your client or bot | either of the two, see below |

The protocol it implements lives in [`tavrn-protocol`](https://github.com/just-tavrn/tavrn-protocol),
included here as the git submodule `protocol/` (the test vectors in `protocol/testvectors/` are checked by
the unit tests, so every implementation derives the same keys).

## Building

Requirements: Rust (the toolchain in `rust-toolchain.toml`, with the `wasm32-unknown-unknown` target),
[`just`](https://github.com/casey/just), Node.js 24 and pnpm (for the npm package), optionally
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny).

```sh
git clone --recurse-submodules https://github.com/just-tavrn/tavrn-crypto
cd tavrn-crypto
just test        # Rust tests and the protocol test vectors
just wasm        # WebAssembly build into pkg/dist
just check       # everything the CI runs
```

`just wasm` runs `./build-wasm.sh`: `cargo build --target wasm32-unknown-unknown --profile wasm` followed by
`wasm-bindgen --target web` (it installs the `wasm-bindgen-cli` matching `Cargo.lock` if needed). The script
honors `CARGO_TARGET_DIR` and maps local paths out of the module.

## Rust API (`tavrn_crypto`)

| Item | Purpose |
|---|---|
| `MasterSecret::{generate, from_bytes, to_bytes, to_key_file, from_key_file, identity_signing_key, identity_public_key, backup_key, local_storage_key}` | account master secret, key file (`key:` base64url + checksum, `words:` BIP-39), derived keys (incl. the per-device local storage key) |
| `RecoveryKey::{generate, from_bytes, to_bytes, to_words, to_compact, to_text, from_text, wrapping_key}` | recovery key (24 words, compact `0x02` string, optional file) and its secret storage wrapping key |
| `secret_storage::{wrap_master_secret, unwrap_master_secret, passkey_wrapping_key, passkey_method, secret_storage_aad, valid_method, PRF_INPUT, METHOD_RECOVERY}` | master secret wrapped for the home node (ENCRYPTION.md §2.4) |
| `attest_device`, `verify_device_attestation`, `DeviceAttestation` | identity signature over a device key |
| `Device::{generate, from_secret, secret, identity, public_key, credential_with_key, attest}` | per-device Ed25519 key = MLS signature key |
| `Client::new(device)`, `export_state`, `import_state` | MLS client of one device; state is one secret byte string |
| `create_key_package`, `create_group`, `join_by_external_commit`, `join_by_welcome` | key packages and joining |
| `add_members`, `remove_members`, `self_update` → `CommitOutput { commit, welcome, group_info, epoch }` | commits (pending until merged) |
| `merge_pending_commit`, `discard_pending_commit` | after the node accepted / rejected the commit |
| `process_handshake` → `HandshakeOutcome` | incoming commits in epoch order |
| `current_epoch`, `roster`, `has_group`, `delete_group` | group state (roster for ghost detection) |
| `encrypt_content`, `decrypt_content` | message content (per-epoch key + device signature) |
| `export_epoch_key`, `import_epoch_key`, `known_epochs`, `export_backup`, `import_backup` | history and backup |
| `export_voice_key` | voice frame key of the current epoch (ENCRYPTION.md §5a) |
| `encrypt_file`, `decrypt_file` | attachments |
| `content_header` | plaintext header (version, epoch, nonce) of a `content` value |
| `ds::DsGroup::{create, process_commit, epoch, roster, export_state, import_state}`, `ds::inspect_key_package`, `ds::group_info_epoch` | delivery-service validation for the node |
| `verify::{safety_number, group_safety_number, verify_payload, parse_verify_payload, verify_payload_matches}` | safety numbers and the `tavrn:verify?…` QR payload (FEDERATION.md §10.1) |
| `plaintext::{PlaintextFields, sign_plaintext, verify_plaintext, plaintext_signed_bytes, PlaintextSignature, canonical_content, canonical_json}` | device signatures on plaintext messages with RFC 8785 (JCS) content (FEDERATION.md §10.3) |

Every fallible function returns `CryptoError`; its messages and `code()` never contain secrets. Inputs are
validated (addresses, device ids, conversation ids `<domain>/<ULID>`), malformed data yields errors, not
panics.

## JavaScript (`@tavrn/crypto`)

```ts
import init, { Client, MasterSecret, encryptFile } from "@tavrn/crypto";

await init(); // fetches tavrn_crypto_bg.wasm next to the module (Vite emits it as an asset)
const client = Client.create("alice@node.example", deviceId);
const groupInfo = client.createGroup("node.example/" + conversationUlid);
const content = client.encryptContent(conversation, JSON.stringify({ type: "text", body: "hi" }));
await idb.put("crypto-state", client.exportState()); // after every mutating call
```

In Node.js and Vitest initialize synchronously with the bytes:
`initSync({ module: readFileSync(new URL("…/tavrn_crypto_bg.wasm", import.meta.url)) })`.
If the Vite dev server pre-bundles the package and the `.wasm` request fails, add
`optimizeDeps: { exclude: ["@tavrn/crypto"] }` (a production `vite build` emits the `.wasm` as an asset).

Clients rarely use this package directly: the MLS session manager, the content codecs, the account flows and
the local key storage built on it live in [`@tavrn/e2ee`](https://github.com/just-tavrn/tavrn-js) (shared by
the web client and bots), whose `ensureCrypto()` picks `init()` in browsers and `initSync` in Node.js.

Errors are thrown as `Error` objects whose `name` is the stable code (`stale_epoch`, `unknown_epoch`,
`decryption_failed`, …). Epochs are plain numbers.

Secret storage (ENCRYPTION.md §2.4):

```ts
import { MasterSecret, RecoveryKey, wrapMasterSecret, unwrapMasterSecret, passkeyWrappingKey,
  passkeyMethod, secretStoragePrfInput } from "@tavrn/crypto";

const recovery = RecoveryKey.generate();
show(recovery.toWords(), recovery.toCompact()); // once; optional download: recovery.toText(address)
const entry = wrapMasterSecret(master, recovery.wrappingKey(), address, "recovery"); // PUT …/secret-storage/recovery

// New device: words typed by the user (or a passkey's PRF output with passkeyWrappingKey(prf)).
const master2 = unwrapMasterSecret(entry, RecoveryKey.fromText(words).wrappingKey(), address, "recovery");
// WebAuthn: extensions.prf.eval.first = secretStoragePrfInput(); method = passkeyMethod(credentialIdBase64url)
```

Identity verification and plaintext signatures (FEDERATION.md §10):

```ts
import { safetyNumber, verifyPayload, verifyPayloadMatches, verifyPlaintext } from "@tavrn/crypto";
import { jcs } from "@tavrn/sdk";

const number = safetyNumber(me, myIdentityKey, contact, pinnedKey); // 60 digits, same on both sides
const qr = verifyPayload(me, myIdentityKey, contact, pinnedKey); // tavrn:verify?v=1&a=…
verifyPayloadMatches(scannedText, me, myIdentityKey, contact, pinnedKey); // true / false

const fields = JSON.stringify({ conversation: "node.example/" + ulid, author, device_id, mentions, attachments });
const signature = client.signPlaintext(fields, jcs(content)); // envelope field `signature`
verifyPlaintext(fields, jcs(content), signature, devicePublicKey); // false = wrong signature, throws = malformed
```

## Tests

- `just test` (`cargo test`): unit tests per module, scenario tests (`tests/mls.rs`, `tests/ds.rs`) and the
  reference vectors in `protocol/testvectors/encryption.json` and `protocol/testvectors/federation.json`.
- `just test-js`: builds the WebAssembly module and runs the Vitest suite in `pkg/test` against it in Node
  (several devices with the node simulated in between: add, external join, epoch rotation, backup, removal,
  secret storage, verification vectors).
- `just clippy-wasm` lints the bindings in `src/wasm.rs`, which only compile for `wasm32`.

## Releases

Versions follow the protocol's release train (protocol, then crypto, then the JavaScript packages, the node
and the web client). Until the packages are published to crates.io and npm, other repositories consume this
one directly by tag:

```toml
tavrn-crypto = { git = "https://github.com/just-tavrn/tavrn-crypto", tag = "v0.1.0" }
```

```json
"@tavrn/crypto": "github:just-tavrn/tavrn-crypto#v0.1.0&path:pkg"
```

For the npm side the built `pkg/dist/` is committed, so consumers need no Rust toolchain. For now it is
built locally and committed on `main` and on every release tag; once the CI runs, the release workflow
builds it and `main` stops carrying it.

## Licensing

[MPL-2.0](LICENSE) (Mozilla Public License 2.0), for the crate and the npm package alike. The MPL is a
file-level copyleft: you may embed `tavrn-crypto` in software under any license, open or proprietary;
changes to the files of this repository itself must be published under the MPL-2.0. The dependencies are
permissively licensed (checked by `cargo deny` and `scripts/check-js-licenses.mjs`; no GPL-family code).

The name "tavrn" and the logo are not covered by the license: see [TRADEMARK.md](TRADEMARK.md).

## Security

This code has **not been audited yet**. It builds on OpenMLS and the RustCrypto crates rather than on
primitives of its own, and it is tested against the protocol's reference vectors, but treat it as
pre-release cryptography. Please report vulnerabilities privately through GitHub's private vulnerability
reporting ("Report a vulnerability" on the Security tab), not as public issues; see the
[security policy](https://github.com/just-tavrn/.github/blob/main/SECURITY.md).

## Contributing

Contributions are welcome: see the [contributing guide](https://github.com/just-tavrn/.github/blob/main/CONTRIBUTING.md)
and the [code of conduct](https://github.com/just-tavrn/.github/blob/main/CODE_OF_CONDUCT.md). Changes to the
wire formats start in [`tavrn-protocol`](https://github.com/just-tavrn/tavrn-protocol). Contributions are
accepted under the [contributor license agreement](CLA.md), signed once through the CLA bot on your first
pull request. Run `just check` before opening a pull request.
