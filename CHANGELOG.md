# Changelog

Changes of `tavrn-crypto` (crates.io) and `@tavrn/crypto` (npm, the same code compiled to WebAssembly), newest
first. Both carry the same version; the tags of this repository are `vX.Y.Z`. The protocol behind the formats is
versioned separately in [tavrn-protocol](https://github.com/just-tavrn/tavrn-protocol/blob/main/CHANGELOG.md).

## Unreleased

First public release, published to crates.io and npm.

- **MLS client** on OpenMLS 0.9 (RFC 9420): key packages, groups, external joins and welcomes, two-phase commits,
  handshake processing in epoch order, rosters, the whole device state as one exportable byte string.
- **Delivery-service checks** for nodes: commits and GroupInfos validated against the public group state, without
  secrets.
- **Keys and identity**: the account master secret (key file, BIP-39 words), identity signing key, backup key,
  device storage keys and attestations; identity key rotation with continuity statements; safety numbers and the QR
  verification payload; device signatures on plaintext messages (RFC 8785).
- **Secret storage** under a recovery key or a passkey's WebAuthn PRF output.
- **Encrypted formats**: message content with a signed context (thread and reply), attachments, history backups,
  whiteboard scenes, voice frame keys.
- **Sealed boxes**: write-only webhooks into encrypted channels (strict inbox-key signatures) and history shares of
  format 2, sealed to the share key every device derives next to its device key.
- **Test vectors** of the protocol checked natively and through the WebAssembly package.

### Changed

- The MLS client keeps the groups it loaded (OpenMLS writes every change through to the storage, so the exported
  state stays the same): `has_group`, `current_epoch`, `roster`, `encrypt_content` and `decrypt_content` no longer
  parse the whole group from the storage on every call (100 members: `has_group` 359 µs → under 1 µs).
- `decrypt_content` with the attested key of the author device compares it with the device's leaf in the local group
  itself (`unknown_sender` on a mismatch, ENCRYPTION.md §3.3), so clients need one call per message instead of
  `hasGroup`, `roster` and `decryptContent`.
- `encrypt_content_with_epoch` (WebAssembly: `encryptContentWithEpoch`) returns the content with the epoch it was
  encrypted for; `encryptShare` takes the epoch from the encryption instead of decoding its own output again.
- `continuity_keys` (WebAssembly: `continuityKeys`): every key that leads to the current one through a continuity
  chain, verifying each statement at most once (one walk per key verified O(n²) statements).
- `import_state` loads every group once and refuses a state whose MLS values do not load with `state_malformed`;
  such a state used to import and then panic (a trap in WebAssembly) on first use of the group.
- `export_state` writes into a buffer of the exact size (no reallocation leaving partial copies behind).
- Secrets cross the WebAssembly boundary without plain copies in the module's memory: `importState`, the key inputs
  and the secret outputs (`exportState`, `toBytes`, `backupKey`, `exportEpochKey`, `exportVoiceKey`, …) go through
  buffers that are wiped, and a dropped client wipes its MLS storage.
- `CommitOutput`, `RosterEntry` and `EncryptedFile` copy their bytes once per property read (no clone inside the
  module first); the ciphertext of `encryptFile` is moved, not cloned and wiped.
- Whiteboard scene ids must be canonical ULIDs (first character at most `7`), as everywhere else.
- Redundant weak-key checks before strict Ed25519 verification removed (`verify_strict` refuses small-order keys).

### Security

- A member commit whose update path gives the committer's leaf another identity is refused by the delivery-service
  checks and by clients (a leaf never changes its identity).
- The delivery-service checks refuse a commit after which two leaves share a signature key (an external rejoin must
  replace the device's old leaf).
- `CommitSummary::removed_leaves` reports the signature key of every removed leaf, so a node can tell a leaf whose
  key does not match the device it names.
- `Client::remove_leaves` (WebAssembly: `removeLeaves`) removes leaves by identity and signature key, so a client
  can remove exactly the leaf whose key does not match the device it names, also when the genuine leaf is present.
- `Client::remove_members` refuses an identity that names several leaves (`invalid_input`): such leaves are removed
  by key with `remove_leaves`.
- The crates.io and npm tokens and the provenance permission live only in a publish job of a protected `release`
  environment, which installs and builds nothing and publishes the packages the credential-free build job tested.
- The release workflow no longer pushes tags; only organization owners create release tags.
- The publication check prints only file and line of a private match, never the matching text.

