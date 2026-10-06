// SPDX-License-Identifier: MPL-2.0
//! Per-device signing key and MLS credential (ENCRYPTION.md §3).

use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::{BasicCredential, CredentialWithKey};
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::{DeviceAttestation, MasterSecret, attest_device};
use crate::util::{check_device_id, check_user_address, put_str16, random_array};

/// Context of the device login proof (ENCRYPTION.md §3.4).
pub const DEVICE_LOGIN_CONTEXT: &[u8] = b"tavrn device login v1\0";
/// Longest login nonce a proof may cover (the node's nonces are short JWTs).
pub const MAX_LOGIN_NONCE_LEN: usize = 2048;

/// The bytes a device signs to prove possession of its key at login (ENCRYPTION.md §3.4):
/// `"tavrn device login v1\0" || str16(device_id) || str16(user_address) || str16(nonce)`.
pub fn login_proof_message(device_id: &str, user_address: &str, nonce: &str) -> Result<Vec<u8>> {
    check_device_id(device_id)?;
    check_user_address(user_address)?;
    if nonce.is_empty() || nonce.len() > MAX_LOGIN_NONCE_LEN {
        return Err(CryptoError::InvalidInput("login nonce"));
    }
    let mut msg =
        Vec::with_capacity(DEVICE_LOGIN_CONTEXT.len() + 6 + device_id.len() + user_address.len() + nonce.len());
    msg.extend_from_slice(DEVICE_LOGIN_CONTEXT);
    put_str16(&mut msg, device_id);
    put_str16(&mut msg, user_address);
    put_str16(&mut msg, nonce);
    Ok(msg)
}

/// Verifies a device login proof against the device key the node stored for that device (strict Ed25519).
pub fn verify_login_proof(
    device_public_key: &[u8; 32],
    device_id: &str,
    user_address: &str,
    nonce: &str,
    proof: &[u8],
) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let msg = login_proof_message(device_id, user_address, nonce)?;
    let sig: [u8; 64] = proof.try_into().map_err(|_| CryptoError::BadSignature)?;
    let key = VerifyingKey::from_bytes(device_public_key).map_err(|_| CryptoError::BadSignature)?;
    if key.is_weak() {
        return Err(CryptoError::BadSignature);
    }
    key.verify_strict(&msg, &Signature::from_bytes(&sig)).map_err(|_| CryptoError::BadSignature)
}

/// A device: user address, device ULID and its Ed25519 key pair.
///
/// The device key signs MLS messages (it is the leaf signature key) and encrypted content.
pub struct Device {
    user_address: String,
    device_id: String,
    key: SigningKey,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device").field("identity", &self.identity()).finish_non_exhaustive()
    }
}

impl Device {
    /// Generates a new device key for `user_address` / `device_id`.
    pub fn generate(user_address: &str, device_id: &str) -> Result<Self> {
        let seed = Zeroizing::new(random_array::<32>()?);
        Self::from_secret(user_address, device_id, &seed)
    }

    /// Restores a device from its 32-byte secret key.
    pub fn from_secret(user_address: &str, device_id: &str, secret: &[u8; 32]) -> Result<Self> {
        check_user_address(user_address)?;
        check_device_id(device_id)?;
        Ok(Self {
            user_address: user_address.to_owned(),
            device_id: device_id.to_owned(),
            key: SigningKey::from_bytes(secret),
        })
    }

    /// The device secret key, for local persistence only.
    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.key.to_bytes())
    }

    /// User address `<username>@<domain>`.
    pub fn user_address(&self) -> &str {
        &self.user_address
    }

    /// Device ULID.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// MLS identity `<username>@<domain>/<device_id>`.
    pub fn identity(&self) -> String {
        format!("{}/{}", self.user_address, self.device_id)
    }

    /// Ed25519 public key of the device.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Ed25519 signature with the device key (used for content signatures).
    pub(crate) fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// Basic credential + signature key used for all MLS operations of this device.
    pub fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.identity().into_bytes()).into(),
            signature_key: self.public_key().to_vec().into(),
        }
    }

    /// Device login proof over a nonce the node issued (ENCRYPTION.md §3.4): lets a new session continue
    /// this device instead of creating a new one.
    pub fn sign_login(&self, nonce: &str) -> Result<[u8; 64]> {
        Ok(self.sign_raw(&login_proof_message(&self.device_id, &self.user_address, nonce)?))
    }

    /// Signs this device's key with the account identity key.
    pub fn attest(&self, master: &MasterSecret) -> Result<DeviceAttestation> {
        attest_device(master, &self.user_address, &self.device_id, &self.public_key())
    }
}

impl Signer for Device {
    fn sign(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        Ok(self.sign_raw(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::keys::verify_device_attestation;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const ALICE: &str = "alice@node.example";
    const DEV: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2V4X";

    #[test]
    fn generate_and_restore() {
        let d = Device::generate(ALICE, DEV).expect("device");
        assert_eq!(d.identity(), "alice@node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V4X");
        assert_eq!(d.user_address(), ALICE);
        assert_eq!(d.device_id(), DEV);
        let restored = Device::from_secret(ALICE, DEV, &d.secret()).expect("restore");
        assert_eq!(restored.public_key(), d.public_key());
        assert!(!format!("{d:?}").contains(&format!("{:?}", d.secret().as_slice())));
    }

    #[test]
    fn rejects_bad_identifiers() {
        assert!(Device::generate("alice", DEV).is_err());
        assert!(Device::generate("alice@node.example/x", DEV).is_err());
        assert!(Device::generate(ALICE, "dev/1").is_err());
    }

    #[test]
    fn credential_carries_identity_and_key() {
        let d = Device::generate(ALICE, DEV).expect("device");
        let c = d.credential_with_key();
        let basic = BasicCredential::try_from(c.credential).expect("basic");
        assert_eq!(basic.identity(), d.identity().as_bytes());
        assert_eq!(c.signature_key.as_slice(), d.public_key());
    }

    #[test]
    fn mls_signer_produces_ed25519_signatures() {
        let d = Device::generate(ALICE, DEV).expect("device");
        assert_eq!(d.signature_scheme(), SignatureScheme::ED25519);
        let sig = Signer::sign(&d, b"payload").expect("sign");
        let sig = Signature::from_slice(&sig).expect("sig");
        VerifyingKey::from_bytes(&d.public_key()).expect("vk").verify(b"payload", &sig).expect("verify");
    }

    #[test]
    fn login_proof_binds_device_account_and_nonce() {
        let d = Device::generate(ALICE, DEV).expect("device");
        let proof = d.sign_login("nonce-1").expect("sign");
        verify_login_proof(&d.public_key(), DEV, ALICE, "nonce-1", &proof).expect("valid");
        assert!(verify_login_proof(&d.public_key(), DEV, ALICE, "nonce-2", &proof).is_err(), "other nonce");
        assert!(
            verify_login_proof(&d.public_key(), DEV, "bob@node.example", "nonce-1", &proof).is_err(),
            "other account"
        );
        let other = "01J9ZK3G5M8Q2W4E6R8T0Y2V4Y";
        assert!(verify_login_proof(&d.public_key(), other, ALICE, "nonce-1", &proof).is_err(), "other device id");
        let stranger = Device::generate(ALICE, DEV).expect("device");
        assert!(verify_login_proof(&stranger.public_key(), DEV, ALICE, "nonce-1", &proof).is_err(), "other key");
        assert!(verify_login_proof(&d.public_key(), DEV, ALICE, "nonce-1", &proof[..63]).is_err(), "short proof");
        assert!(d.sign_login("").is_err());
        assert!(d.sign_login(&"n".repeat(MAX_LOGIN_NONCE_LEN + 1)).is_err());
        // The message layout of ENCRYPTION.md §3.4.
        let msg = login_proof_message(DEV, ALICE, "n").expect("msg");
        assert!(
            msg.starts_with(b"tavrn device login v1\0\0\x1a01J9ZK3G5M8Q2W4E6R8T0Y2V4X\0\x12alice@node.example\0\x01n")
        );
        assert_eq!(msg.len(), DEVICE_LOGIN_CONTEXT.len() + 2 + 26 + 2 + 18 + 2 + 1);
    }

    #[test]
    fn attest_binds_device() {
        let m = MasterSecret::from_bytes([1u8; 32]);
        let d = Device::generate(ALICE, DEV).expect("device");
        let att = d.attest(&m).expect("attest");
        assert_eq!(att.device_public_key, d.public_key());
        verify_device_attestation(&att, &m.identity_public_key()).expect("verify");
    }
}
