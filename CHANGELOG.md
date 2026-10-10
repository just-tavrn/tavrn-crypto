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

### Security

- A member commit whose update path gives the committer's leaf another identity is refused by the delivery-service
  checks and by clients (a leaf never changes its identity).
- The delivery-service checks refuse a commit after which two leaves share a signature key (an external rejoin must
  replace the device's old leaf).
- `CommitSummary::removed_leaves` reports the signature key of every removed leaf, so a node can tell a leaf whose
  key does not match the device it names.
