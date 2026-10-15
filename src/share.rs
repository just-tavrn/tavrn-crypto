// SPDX-License-Identifier: MPL-2.0
//! Device share keys and history shares v2 (ENCRYPTION.md §3.1 "Share key", §7b "Format v2").
//!
//! Every device has an X25519 **share key** next to its Ed25519 device key. This crate derives it from the device
//! secret (`share_secret = HKDF-SHA256(salt = "", IKM = device secret, info = "tavrn device share key v1", L = 32)`),
//! so it is stored and lives exactly like the device key; the device key signs the public half:
//! `Ed25519-Sign(device_sk, "tavrn device share key v1" || 0x00 || share_public(32) || device_public(32) ||
//! str16(device_id))`.
//!
//! A history share v2 is content format 1 (§5.2) under a fresh random 32-byte key instead of the epoch's content key;
//! that key is sealed (libsodium `crypto_box_seal`) to the share key of every recipient device. Only the recipient's
//! devices can open a box, so other members of the group cannot read a share addressed to someone else.

use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::device::Device;
use crate::error::{CryptoError, Result};
use crate::util::{check_device_id, put_str16};

/// HKDF info of the share secret key, and the domain separation prefix (with a 0x00) of its signature.
pub const SHARE_KEY_LABEL: &[u8] = b"tavrn device share key v1";
/// Length of a sealed share key: the 32-byte key plus the sealed box overhead (ephemeral key and tag).
pub const SHARE_BOX_LEN: usize = 32 + crate::sealed::SEAL_OVERHEAD;

/// The share secret key of a device (X25519, unclamped bytes as libsodium stores them).
pub fn share_secret(device_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 output bytes are always within HKDF-SHA256's limit.
    let _ = Hkdf::<Sha256>::new(None, device_secret).expand(SHARE_KEY_LABEL, out.as_mut_slice());
    out
}

/// The X25519 public key of a share secret key.
pub fn share_public_key(share_secret: &[u8; 32]) -> [u8; 32] {
    crypto_box::SecretKey::from_bytes(*share_secret).public_key().to_bytes()
}

/// What the device key signs over its share key:
/// `"tavrn device share key v1" || 0x00 || share_public(32) || device_public(32) || str16(device_id)`.
pub fn share_key_signing_input(share_public: &[u8; 32], device_public: &[u8; 32], device_id: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SHARE_KEY_LABEL.len() + 1 + 64 + 2 + device_id.len());
    msg.extend_from_slice(SHARE_KEY_LABEL);
    msg.push(0);
    msg.extend_from_slice(share_public);
    msg.extend_from_slice(device_public);
    put_str16(&mut msg, device_id);
    msg
}

/// Checks the device signature over a published share key (strict Ed25519, ENCRYPTION.md §0). Nodes check it when a
/// device publishes its share key; clients check it before sealing anything to the key.
pub fn verify_share_key(
    device_public: &[u8; 32],
    device_id: &str,
    share_public: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    check_device_id(device_id)?;
    // `verify_strict` also refuses small-order (weak) keys.
    let key = VerifyingKey::from_bytes(device_public).map_err(|_| CryptoError::BadSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| CryptoError::BadSignature)?;
    key.verify_strict(&share_key_signing_input(share_public, device_public, device_id), &signature)
        .map_err(|_| CryptoError::BadSignature)
}

impl Device {
    /// The share secret key of this device (derived from the device secret).
    pub fn share_secret(&self) -> Zeroizing<[u8; 32]> {
        share_secret(&self.secret())
    }

    /// The share public key of this device.
    pub fn share_public_key(&self) -> [u8; 32] {
        share_public_key(&self.share_secret())
    }

    /// The device key's signature over the share public key, published with it.
    pub fn share_key_signature(&self) -> [u8; 64] {
        self.sign_raw(&share_key_signing_input(&self.share_public_key(), &self.public_key(), self.device_id()))
    }
}

/// Seals a share's fresh key to one recipient device's share public key (`crypto_box_seal`).
pub fn seal_share_key(share_public: &[u8; 32], key: &[u8; 32]) -> Result<Vec<u8>> {
    crate::sealed::seal(share_public, key)
}

/// Opens a sealed share key with the device's share secret key; anything but a box of exactly a 32-byte key fails.
pub fn open_share_box(share_secret: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if sealed.len() != SHARE_BOX_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let plain = crate::sealed::open_with_secret(share_secret, sealed)?;
    let key: [u8; 32] = plain.as_slice().try_into().map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(key))
}

/// Decrypts content format 1 with an explicit key (a history share v2 under its fresh key) and verifies the device
/// signature with `device_public_key`. The key must belong to the epoch in the header; nothing is stored.
pub fn decrypt_content_with_key(
    key: &[u8; 32],
    conversation: &str,
    author: &str,
    device_id: &str,
    content: &str,
    device_public_key: &[u8; 32],
) -> Result<String> {
    crate::util::check_conversation(conversation)?;
    crate::util::check_user_address(author)?;
    check_device_id(device_id)?;
    let (header, ciphertext) = crate::content::decode(content)?;
    crate::content::open(key, conversation, author, device_id, device_public_key, &header, &ciphertext)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    const ALICE: &str = "alice@node.example";
    const DEV: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VA1";
    const CONV: &str = "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V00";

    fn device() -> Device {
        Device::from_secret(ALICE, DEV, &[3u8; 32]).expect("device")
    }

    #[test]
    fn the_share_key_is_derived_from_the_device_secret() {
        let d = device();
        assert_eq!(d.share_secret().as_slice(), share_secret(&[3u8; 32]).as_slice());
        assert_eq!(d.share_public_key(), share_public_key(&d.share_secret()));
        assert_ne!(d.share_public_key(), Device::from_secret(ALICE, DEV, &[4u8; 32]).expect("d").share_public_key());
        // Its own label: neither the device key nor the secret itself.
        assert_ne!(d.share_secret().as_slice(), d.secret().as_slice());
        assert_ne!(d.share_public_key(), d.public_key());
    }

    #[test]
    fn share_key_signatures_bind_share_key_device_key_and_device_id() {
        let d = device();
        let (sk, dk, sig) = (d.share_public_key(), d.public_key(), d.share_key_signature());
        verify_share_key(&dk, DEV, &sk, &sig).expect("valid");
        assert_eq!(verify_share_key(&dk, "01J9ZK3G5M8Q2W4E6R8T0Y2VA2", &sk, &sig), Err(CryptoError::BadSignature));
        assert_eq!(verify_share_key(&dk, DEV, &[9u8; 32], &sig), Err(CryptoError::BadSignature));
        let other = Device::from_secret(ALICE, DEV, &[4u8; 32]).expect("d");
        assert_eq!(verify_share_key(&other.public_key(), DEV, &sk, &sig), Err(CryptoError::BadSignature));
        assert_eq!(verify_share_key(&dk, DEV, &sk, &sig[..63]), Err(CryptoError::BadSignature));
        assert!(verify_share_key(&dk, "not/a-device", &sk, &sig).is_err());
        // The layout of ENCRYPTION.md §3.1.
        let msg = share_key_signing_input(&sk, &dk, DEV);
        assert!(msg.starts_with(b"tavrn device share key v1\0"));
        assert_eq!(&msg[26..58], sk.as_slice());
        assert_eq!(&msg[58..90], dk.as_slice());
        assert_eq!(&msg[90..], b"\0\x1a01J9ZK3G5M8Q2W4E6R8T0Y2VA1");
        // Strict verification: a small-order device key with the trivial signature is refused.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let mut trivial = [0u8; 64];
        trivial[0] = 1;
        assert_eq!(verify_share_key(&weak, DEV, &sk, &trivial), Err(CryptoError::BadSignature));
    }

    #[test]
    fn a_sealed_share_key_opens_only_with_the_recipient_device() {
        let bob = Device::from_secret("bob@other.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VB1", &[5u8; 32]).expect("d");
        let carol = Device::from_secret("carol@other.example", "01J9ZK3G5M8Q2W4E6R8T0Y2VC1", &[6u8; 32]).expect("d");
        let key = [42u8; 32];
        let sealed = seal_share_key(&bob.share_public_key(), &key).expect("seal");
        assert_eq!(sealed.len(), SHARE_BOX_LEN);
        assert_eq!(open_share_box(&bob.share_secret(), &sealed).expect("open").as_slice(), key.as_slice());
        assert_eq!(open_share_box(&carol.share_secret(), &sealed), Err(CryptoError::DecryptionFailed));
        let mut tampered = sealed.clone();
        tampered[50] ^= 1;
        assert_eq!(open_share_box(&bob.share_secret(), &tampered), Err(CryptoError::DecryptionFailed));
        // A box of anything other than a 32-byte key is refused even when it opens.
        let long = crate::sealed::seal(&bob.share_public_key(), &[1u8; 33]).expect("seal");
        assert_eq!(open_share_box(&bob.share_secret(), &long), Err(CryptoError::DecryptionFailed));
        assert_eq!(open_share_box(&bob.share_secret(), &sealed[..79]), Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn content_under_an_explicit_key_round_trips_and_binds_its_context() {
        let d = device();
        let key = [7u8; 32];
        let json = r#"{"type":"history_keys","v":2}"#;
        let content = crate::content::seal(&key, CONV, 42, &d, json).expect("seal");
        let pk = d.public_key();
        assert_eq!(decrypt_content_with_key(&key, CONV, ALICE, DEV, &content, &pk).expect("open"), json);
        assert_eq!(
            decrypt_content_with_key(&[8u8; 32], CONV, ALICE, DEV, &content, &pk),
            Err(CryptoError::DecryptionFailed)
        );
        assert_eq!(
            decrypt_content_with_key(&key, "node.example/01J9ZK3G5M8Q2W4E6R8T0Y2V01", ALICE, DEV, &content, &pk),
            Err(CryptoError::DecryptionFailed)
        );
        let other = Device::from_secret(ALICE, DEV, &[4u8; 32]).expect("d");
        assert_eq!(
            decrypt_content_with_key(&key, CONV, ALICE, DEV, &content, &other.public_key()),
            Err(CryptoError::BadSignature)
        );
        assert!(decrypt_content_with_key(&key, CONV, "nobody", DEV, &content, &pk).is_err());
    }
}
