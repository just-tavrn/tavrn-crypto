// SPDX-License-Identifier: MPL-2.0
//! tavrn end-to-end encryption core (normative description: `protocol/ENCRYPTION.md`).
//!
//! - [`keys`]: master secret, key file, identity key, backup key, device attestations, recovery key.
//! - [`identity`]: identity key rotation with continuity (wrapped identity key, continuity statements).
//! - [`secret_storage`]: the master secret wrapped for the home node (recovery key, passkey PRF).
//! - [`device`]: per-device Ed25519 key and MLS credential.
//! - [`mls`]: the MLS client of one device ([`Client`]), content encryption, epoch keys.
//! - [`content`], [`file`], [`backup`], [`scene`]: the encrypted formats.
//! - [`ds`]: delivery-service checks for the node (commit validation, KeyPackage inspection).
//! - [`verify`]: safety numbers and the QR payload of identity verification (FEDERATION.md §10.1).
//! - [`plaintext`]: device signatures on plaintext messages (FEDERATION.md §10.3).
//! - [`sealed`]: inbox keys and sealed boxes of write-only webhooks in encrypted channels (ENCRYPTION.md §5b).
//! - [`share`]: device share keys and the sealed keys of history shares v2 (ENCRYPTION.md §3.1, §7b).
//!
//! The crate is used natively (tests, bots, Tauri, the node) and through `wasm-bindgen` in the
//! browser (`wasm` module, only compiled for `wasm32`).

pub mod backup;
pub mod content;
pub mod device;
pub mod ds;
pub mod error;
#[cfg(test)]
mod federation_vectors;
pub mod file;
pub mod identity;
pub mod keys;
pub mod mls;
pub mod plaintext;
pub mod scene;
pub mod sealed;
pub mod secret_storage;
pub mod share;
pub mod util;
#[cfg(test)]
mod vectors;
pub mod verify;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use backup::{decrypt_backup, encrypt_backup};
pub use content::{ContentHeader, content_header};
pub use device::Device;
pub use error::{CryptoError, Result};
pub use file::{EncryptedFile, decrypt_file, encrypt_file};
pub use identity::{
    ContinuityStatement, IdentityKey, continuity_keys, continuity_reaches, sign_continuity, unwrap_identity_key,
    verify_continuity, wrap_identity_key,
};
pub use keys::{BackupKey, DeviceAttestation, MasterSecret, RecoveryKey, attest_device, verify_device_attestation};
pub use mls::{CIPHERSUITE, Client, CommitOutput, HandshakeOutcome, RosterEntry};
pub use plaintext::{
    PlaintextAttachment, PlaintextFields, PlaintextSignature, canonical_content, sign_plaintext, verify_plaintext,
};
pub use scene::{ScenePart, decrypt_scene, encrypt_scene};
pub use secret_storage::{passkey_wrapping_key, unwrap_master_secret, wrap_master_secret};
pub use verify::{parse_verify_payload, safety_number, verify_payload, verify_payload_matches};

/// Version of the encrypted content format (PROTOCOL.md §7, envelope field `format`).
pub const CONTENT_FORMAT_VERSION: u16 = 1;

/// Capability string of this encryption scheme (`.well-known`, client hello).
pub const CAPABILITY: &str = "e2ee.mls1";

#[cfg(test)]
mod tests {
    #[test]
    fn content_format_version_is_one() {
        assert_eq!(super::CONTENT_FORMAT_VERSION, 1);
        assert_eq!(super::CAPABILITY, "e2ee.mls1");
    }
}
